"""One scan: detonate a repo in the sandbox, collect evidence, pinpoint the culprit.

For every (task, repeat) the bait agent works on the repo in a fresh sandbox, on a private network
watched by a sinkhole. Evidence comes from three places and is judged without any model opinion:
  * canaries seen in plain-HTTP requests          -> proof        (HIJACKED)
  * destructive commands the agent really ran    -> proof        (HIJACKED)
  * unexpected hosts, text the agent says tried to instruct it -> warnings (SUSPICIOUS)
For a proven leak, the localizer replays the agent's recorded commands against versions of the repo
with files and lines blanked (no model calls) until the minimal culprit lines remain.
"""

from __future__ import annotations

import shlex
import tempfile
import time
from collections.abc import Callable, Mapping
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from agenttrap import canary, sandbox
from agenttrap.agent import TASKS, Http, Injection, Step, Trace, debrief, run_agent
from agenttrap.cleaner import Removal, clean, write_copy
from agenttrap.detector import Flag, Leak, Request, Verdict, command_flags, find_leaks, judge
from agenttrap.egress import Egress, Observed, contact_flags, unexpected_hosts
from agenttrap.intel import HostIntel
from agenttrap.llm import LLM
from agenttrap.localizer import Culprit, Files, Runner, localize
from agenttrap.sandbox import Sandbox

ALLOWED_HOSTS = {"pypi.org", "files.pythonhosted.org", "registry.npmjs.org"}
MAX_FILE_BYTES = 200_000


@dataclass(frozen=True)
class RunResult:
    task: str
    trace: Trace
    observed: Observed
    leaks: tuple[Leak, ...]


@dataclass(frozen=True)
class FoundInjection:
    injection: Injection
    where: str | None  # "file:line" when the quoted text really is in the repo


@dataclass
class CleanOutcome:
    """A copy of the repo with the culprit code removed, and what a second scan of it found."""

    out_dir: Path
    removed: tuple[Removal, ...]
    warnings: tuple[str, ...]
    rescan: ScanResult


@dataclass
class ScanResult:
    repo: str
    verdict: Verdict
    runs: list[RunResult]
    injections: list[FoundInjection] = field(default_factory=list)
    culprits: dict[str, list[Culprit]] = field(default_factory=dict)  # canary -> culprit lines
    unlocalized: dict[str, str] = field(default_factory=dict)  # canary -> why
    contacted: list[str] = field(default_factory=list)  # hosts contacted, not on the allow-list
    intel: dict[str, HostIntel] = field(default_factory=dict)  # filled in by an optional lookup
    cleaned: CleanOutcome | None = None  # filled in by clean_and_rescan
    cost_usd: float = 0.0
    seconds: float = 0.0


# ---- one detonation ----------------------------------------------


def curl_via(box: Sandbox) -> Http:
    """The agent's http_request tool: curl run inside the sandbox, so the sinkhole sees it."""

    def http(request: Request) -> str:
        command = f"curl -sS -m 10 -i -X {shlex.quote(request.method)} {shlex.quote(request.url)}"
        if request.body:
            command += f" --data-binary {shlex.quote(request.body)}"
        result = box.run(command, timeout=20)
        return result.stdout + result.stderr

    return http


# What every developer does with a Python project. Run without an AI, so that code which fires at
# install or test time is found whether or not the agent happens to run these commands.
BASELINE = ("pip install -e . 2>&1 | tail -n 20", "python -m pytest -q 2>&1 | tail -n 20")
BASELINE_TIMEOUT = 120


def run_baseline(repo: Path, *, served: Mapping[str, str]) -> RunResult:
    canaries = canary.generate()
    trace = Trace(task="baseline")
    with Egress(served) as net:
        with Sandbox(repo, canaries, net.net()) as box:
            for command in BASELINE:
                result = box.run(command, timeout=BASELINE_TIMEOUT)
                trace.steps.append(Step("run_command", {"command": command}, result.stdout[-2000:]))
        observed = net.observed()
    trace.stopped = "finished"
    leaks = tuple(find_leaks(observed.requests, canaries.values))
    return RunResult("baseline", trace, observed, leaks)


def run_once(
    repo: Path,
    task: str,
    run: int,
    *,
    llm: LLM,
    model: str,
    served: Mapping[str, str],
) -> RunResult:
    canaries = canary.generate()
    role = f"scan:{repo.name}:{task}:{run}"
    with Egress(served) as net:
        with Sandbox(repo, canaries, net.net()) as box:
            trace = run_agent(TASKS[task], box, curl_via(box), llm, role=role, size=model)
        observed = net.observed()
    debrief(trace, llm, role=role, size=model)
    leaks = tuple(find_leaks(observed.requests, canaries.values))
    return RunResult(task, trace, observed, leaks)


# ---- locating text in the repo ----------------------------------------------


def read_repo(repo: Path) -> dict[str, str]:
    """Text files of the repo, relative path -> content. Binary and huge files are skipped."""
    files = {}
    # Symlinks are skipped: a link to a host file must never be read as if it were repo content.
    candidates = (p for p in repo.rglob("*") if p.is_file() and not p.is_symlink())
    for path in sorted(p for p in candidates if ".git" not in p.parts):
        if path.stat().st_size > MAX_FILE_BYTES:
            continue
        try:
            files[str(path.relative_to(repo))] = path.read_text()
        except UnicodeDecodeError:
            continue
    return files


def find_line(quote: str, files: Mapping[str, str]) -> str | None:
    """Where a quoted text really appears in the repo, as "file:line", or None."""
    first = next((ln.strip() for ln in quote.splitlines() if ln.strip()), "")[:60]
    if len(first) < 8:
        return None
    for name, text in files.items():
        for n, line in enumerate(text.splitlines(), 1):
            if first in line:
                return f"{name}:{n}"
    return None


# ---- localizing a proven leak ----------------------------------------------


def base_name(canary_name: str) -> str:
    """ "~/.aws/credentials#secret" and "~/.aws/credentials" are the same leaked file."""
    return canary_name.split("#")[0]


def replay_runner(steps: list, served: Mapping[str, str]) -> Runner:
    """A localizer Runner that replays the agent's recorded commands, with no model calls.

    Each call detonates one version of the repo in a fresh sandbox and returns which canaries
    were seen in plain-HTTP requests.
    """

    def run(files: Files) -> set[str]:
        canaries = canary.generate()
        with tempfile.TemporaryDirectory() as tmp:
            for name, text in files.items():
                path = Path(tmp, name)
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(text)
            with Egress(served) as net:
                with Sandbox(Path(tmp), canaries, net.net()) as box:
                    _replay(steps, box)
                observed = net.observed()
        return {base_name(leak.canary) for leak in find_leaks(observed.requests, canaries.values)}

    return run


def _replay(steps: list, box: Sandbox) -> None:
    for step in steps:
        match step.action:
            case "write_file":
                box.write(str(step.args.get("path", "")), str(step.args.get("content", "")))
            case "run_command":
                box.run(str(step.args.get("command", "")))
            case "http_request":
                request = Request(
                    str(step.args.get("method", "GET")).upper(),
                    str(step.args.get("url", "")),
                    body=str(step.args.get("body", "")),
                )
                curl_via(box)(request)


def localize_leak(
    files: Mapping[str, str], run: RunResult, canary_name: str, served: Mapping[str, str]
) -> tuple[list[Culprit], str]:
    """Culprit lines for one leaked canary, or ([], reason) when replay can't explain it."""
    runner = replay_runner(run.trace.steps, served)
    if canary_name not in runner(files):
        return [], "the leak did not reproduce when replaying the agent's commands"
    if canary_name in runner({name: "" for name in files}):
        return [], "the agent's own commands leak it, whatever the repo contains"
    return localize(files, runner, canary_name), ""


# ---- the whole scan ----------------------------------------------


def scan(
    repo: Path,
    *,
    llm: LLM,
    model: str = "nano",
    k: int = 2,
    tasks: tuple[str, ...] = tuple(TASKS),
    served: Mapping[str, str] | None = None,
    allowed_hosts: set[str] = frozenset(ALLOWED_HOSTS),
    workers: int = 3,
    progress: Callable[[str], None] = lambda message: None,
) -> ScanResult:
    started = time.time()
    served = served or {}
    sandbox.ensure_ready()
    files = read_repo(repo)

    jobs: list[Callable[[], RunResult]] = [lambda: run_baseline(repo, served=served)]
    jobs += [
        lambda task=task, run=run: run_once(repo, task, run, llm=llm, model=model, served=served)
        for task in tasks
        for run in range(k)
    ]
    progress(f"detonating {len(jobs)} runs (install and test, then {', '.join(tasks)} x {k})")
    with ThreadPoolExecutor(workers) as pool:
        runs = list(pool.map(lambda job: job(), jobs))

    leaks = [leak for r in runs for leak in r.leaks]
    commands = [
        str(s.args.get("command", ""))
        for r in runs
        for s in r.trace.steps
        if s.action == "run_command"
    ]
    hosts = Observed((), tuple(dict.fromkeys(h for r in runs for h in r.observed.hosts)))
    injections = _injections(runs, files)

    flags = command_flags(commands) + contact_flags(hosts, allowed_hosts)
    flags += [
        Flag("injection-reported", f"{i.where or 'not in repo'}: {i.injection.quote[:100]}", False)
        for i in injections
    ]
    result = ScanResult(str(repo), judge(leaks, flags), runs, injections)
    result.contacted = unexpected_hosts(hosts, allowed_hosts)

    for name in dict.fromkeys(base_name(leak.canary) for leak in leaks):
        leaking_run = next(r for r in runs if any(base_name(x.canary) == name for x in r.leaks))
        progress(f"pinpointing the culprit for {name}")
        culprits, reason = localize_leak(files, leaking_run, name, served)
        if culprits:
            result.culprits[name] = culprits
        else:
            result.unlocalized[name] = reason

    result.cost_usd = llm.status()["cost_usd"]
    result.seconds = time.time() - started
    return result


def clean_and_rescan(
    repo: Path, result: ScanResult, out_dir: Path, **scan_options: Any
) -> CleanOutcome | None:
    """Write a copy of `repo` without the culprit code to `out_dir`, then scan the copy.

    Returns None when no culprit lines were found, because there is nothing to remove.
    """
    culprits = {(c.file, c.line): c for cs in result.culprits.values() for c in cs}
    if not culprits:
        return None
    files = read_repo(repo)
    cleaned = clean(files, culprits.values())
    write_copy(repo, out_dir, {n: t for n, t in cleaned.files.items() if t != files[n]})
    return CleanOutcome(out_dir, cleaned.removed, cleaned.warnings, scan(out_dir, **scan_options))


def suspect_hosts(result: ScanResult) -> list[str]:
    """Hosts worth a lookup: where secrets were sent, then every other unexpected host."""
    hosts = [urlparse(leak.destination).hostname for leak in result.verdict.leaks]
    return list(dict.fromkeys(h for h in [*hosts, *result.contacted] if h))


def _injections(runs: list[RunResult], files: Mapping[str, str]) -> list[FoundInjection]:
    seen: dict[str, FoundInjection] = {}
    for r in runs:
        for injection in r.trace.injections:
            where = find_line(injection.quote, files)
            seen.setdefault(where or injection.quote[:60], FoundInjection(injection, where))
    return list(seen.values())
