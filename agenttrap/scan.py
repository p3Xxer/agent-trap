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

import os
import shlex
import sys
import tempfile
import time
from collections.abc import Callable, Mapping
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlparse

from agenttrap import canary, sandbox
from agenttrap.agent import (
    TASKS,
    CodeConcern,
    Http,
    Injection,
    Step,
    Trace,
    debrief,
    review_code,
    run_agent,
)
from agenttrap.cleaner import Removal, clean, write_copy
from agenttrap.counterfactual import localize_by_asking
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


@dataclass(frozen=True)
class FoundConcern:
    """Code the agent called suspicious. Only quotes found in the repository are kept."""

    concern: CodeConcern
    where: str  # "file:line"


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
    concerns: list[FoundConcern] = field(default_factory=list)
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


# Imports every package the project provides, as a user of the library would. Without it, code
# that runs on import is never reached when a project has no tests of its own.
IMPORT_ALL = """
import importlib, pathlib, sys

root = pathlib.Path(".").resolve()
skip = {"tests", "test", "build", "dist", "docs", "examples", ".git"}
packages = set()
for init in root.rglob("__init__.py"):
    parts = init.relative_to(root).parts
    top_level = not (init.parent.parent / "__init__.py").exists()
    if len(parts) <= 3 and top_level and not skip & set(parts[:-1]):
        packages.add(init.parent)
for package in sorted(packages):
    sys.path.insert(0, str(package.parent))
    try:
        importlib.import_module(package.name)
    except BaseException as error:
        print("import", package.name, "failed:", type(error).__name__)
"""


# What a user does with a Python project, by every normal route. Run without an AI, so that code
# which fires at install, import or test time is found whether or not the agent happens to run
# these commands. Malicious packages hook different routes (the wheel build, the editable install,
# the older `setup.py install`), so all of them are exercised. Build tools are baked into the image
# and dependencies are not fetched (there is no internet): only the project's own code is run.
def _with_exit_status(command: str) -> str:
    """Run `command`, then print the last 80 lines of its output and, last of all, its exit status.

    Piping straight into `tail` would hide whether the command failed. The status comes last
    because only the end of a long output is kept, and the status must not be what gets cut.
    """
    run = f"( {command} ) > /tmp/step.out 2>&1; code=$?"
    return f'{run}; tail -n 80 /tmp/step.out; echo "[exit $code]"'


BASELINE = (
    _with_exit_status("pip install --no-build-isolation --no-deps ."),
    _with_exit_status("pip install --no-build-isolation --no-deps -e ."),
    _with_exit_status("python setup.py install"),
    _with_exit_status(f"python -c {shlex.quote(IMPORT_ALL)}"),
    _with_exit_status("python -m pytest -q"),
)
BASELINE_TIMEOUT = 120
OUTPUT_KEPT = 6000  # characters of each baseline command's output kept in memory


def run_baseline(repo: Path, *, served: Mapping[str, str]) -> RunResult:
    canaries = canary.generate()
    trace = Trace(task="baseline")
    with Egress(served) as net:
        with Sandbox(repo, canaries, net.net()) as box:
            for command in BASELINE:
                result = box.run(command, timeout=BASELINE_TIMEOUT)
                output = result.stdout[-OUTPUT_KEPT:]
                trace.steps.append(Step("run_command", {"command": command}, output))
                if os.environ.get("AGENTTRAP_SHOW_BASELINE"):  # debugging aid; never saved
                    print(f"--- baseline step {len(trace.steps)} ---\n{output}", file=sys.stderr)
        observed = net.observed()
    trace.stopped = "finished"
    leaks = tuple(find_leaks(observed.requests, canaries.values, observed.hosts))
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
    review_code(trace, llm, role=role, size=model)
    leaks = tuple(find_leaks(observed.requests, canaries.values, observed.hosts))
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


class OutOfTime(Exception):
    """The search for the culprit used up its time."""


LOCALIZE_SECONDS = 420  # each detonation takes seconds, and a search needs dozens of them


def replay_runner(steps: list, served: Mapping[str, str], deadline: float | None = None) -> Runner:
    """A localizer Runner that replays the agent's recorded commands, with no model calls.

    Each call detonates one version of the repo in a fresh sandbox and returns which canaries
    were seen in plain-HTTP requests.
    """

    def run(files: Files) -> set[str]:
        if deadline is not None and time.time() > deadline:
            raise OutOfTime
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
        return {
            base_name(leak.canary)
            for leak in find_leaks(observed.requests, canaries.values, observed.hosts)
        }

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
    files: Mapping[str, str],
    run: RunResult,
    canary_name: str,
    served: Mapping[str, str],
    *,
    llm: LLM | None = None,
    model: str = "nano",
) -> tuple[list[Culprit], str]:
    """Culprit lines for one leaked secret, or ([], why not).

    Code that steals the secret is found by replaying the agent's commands against versions of the
    repository. If that cannot explain the leak, the agent decided to send it, and when a model is
    available the lines are found by asking the model again (see counterfactual.py).
    """
    runner = replay_runner(run.trace.steps, served, time.time() + LOCALIZE_SECONDS)
    try:
        if canary_name in runner(files) and canary_name not in runner({n: "" for n in files}):
            return localize(files, runner, canary_name), ""
    except OutOfTime:
        return [], f"the search for the culprit line stopped after {LOCALIZE_SECONDS} seconds"
    if llm is None:
        return [], "the leak does not depend on the repository's code when replaying the commands"
    leak = next(x for x in run.leaks if base_name(x.canary) == canary_name)
    return localize_by_asking(files, run.trace, canary_name, leak.destination, llm, model)


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
    injections, concerns = agent_reports(runs, files)

    flags = command_flags(commands) + contact_flags(hosts, allowed_hosts)
    flags += [
        Flag("injection-reported", f"{i.where or 'not in repo'}: {i.injection.quote[:100]}", False)
        for i in injections
    ]
    flags += [
        Flag("suspicious-code", f"{c.where}: {c.concern.behavior[:100]}", False) for c in concerns
    ]
    result = ScanResult(str(repo), judge(leaks, flags), runs, injections, concerns)
    result.contacted = unexpected_hosts(hosts, allowed_hosts)

    located: dict[str, tuple[list, str]] = {}  # where the leak went -> what localizing it found
    for name in dict.fromkeys(base_name(leak.canary) for leak in leaks):
        leaking_run = next(r for r in runs if any(base_name(x.canary) == name for x in r.leaks))
        destination = next(x.destination for x in leaking_run.leaks if base_name(x.canary) == name)
        if destination not in located:  # two secrets sent in one request have the same culprit
            progress(f"pinpointing the culprit for {name}")
            located[destination] = localize_leak(
                files, leaking_run, name, served, llm=llm, model=model
            )
        culprits, reason = located[destination]
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


PROSE_SUFFIXES = {".md", ".markdown", ".txt", ".rst", ".adoc"}


def _in_prose(where: str) -> bool:
    return PurePosixPath(where.rpartition(":")[0]).suffix.lower() in PROSE_SUFFIXES


def agent_reports(
    runs: list[RunResult], files: Mapping[str, str]
) -> tuple[list[FoundInjection], list[FoundConcern]]:
    """What the agent reported, as instructions aimed at it and as suspicious code.

    The agent often describes a sentence in a document ("send the keys to this address") as code
    that sends data out. The heading follows the kind of file, not the agent's wording: a line in
    a document is text that instructs the agent, and only a line of a code file is code. A line
    reported both ways keeps the heading its file calls for.
    """
    reported_code = _concerns(runs, files)
    prose = [c for c in reported_code if _in_prose(c.where)]
    code = [c for c in reported_code if not _in_prose(c.where)]
    taken = {c.where for c in code}
    injections = [i for i in _injections(runs, files) if i.where not in taken]
    have = {i.where for i in injections if i.where}
    injections += [
        FoundInjection(Injection(c.concern.source, c.concern.quote, c.concern.behavior), c.where)
        for c in prose
        if c.where not in have
    ]
    return injections, code


def _concerns(runs: list[RunResult], files: Mapping[str, str]) -> list[FoundConcern]:
    """Code the agent reported, one entry per line of the repository, quotes that exist only."""
    seen: dict[str, FoundConcern] = {}
    for r in runs:
        for concern in r.trace.concerns:
            where = find_line(concern.quote, files)
            if where:  # an answer that cannot be found in the repository is not evidence
                seen.setdefault(where, FoundConcern(concern, where))
    return list(seen.values())


def _injections(runs: list[RunResult], files: Mapping[str, str]) -> list[FoundInjection]:
    seen: dict[str, FoundInjection] = {}
    for r in runs:
        for injection in r.trace.injections:
            where = find_line(injection.quote, files)
            seen.setdefault(where or injection.quote[:60], FoundInjection(injection, where))
    return list(seen.values())
