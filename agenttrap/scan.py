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
from agenttrap.canary import IDENTITY_WORDS
from agenttrap.cleaner import Removal, clean, write_copy
from agenttrap.counterfactual import localize_by_asking
from agenttrap.detector import Flag, Leak, Request, Verdict, command_flags, find_leaks, judge
from agenttrap.egress import Egress, EgressPool, Observed, contact_flags, unexpected_hosts
from agenttrap.intel import HostIntel, PackageIntel
from agenttrap.llm import LLM
from agenttrap.localizer import UNCONFIRMED, Culprit, Files, Runner, localize
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
    package: PackageIntel | None = None  # web reports of this package version, when looked up
    cleaned: CleanOutcome | None = None  # filled in by clean_and_rescan
    cost_usd: float = 0.0
    seconds: float = 0.0
    warnings: list[str] = field(default_factory=list)  # parts of the scan that could not run


def agent_warning(runs: list[RunResult]) -> str | None:
    """Why the AI agent could not work on the repository, when none of its runs got a single
    answer from the model (no API key, a wrong one, or the service unreachable). The checks that
    need no AI still ran, so the scan is not wrong, but it is incomplete and must say so."""
    agent_runs = [r for r in runs if r.task != "baseline"]
    stopped = [r.trace.stopped for r in agent_runs]
    if not agent_runs or not all(
        s.startswith("model:") and not r.trace.steps
        for s, r in zip(stopped, agent_runs, strict=True)
    ):
        return None
    reason = stopped[0].removeprefix("model:").strip()
    return (
        f"The AI agent did not run ({reason}). Code that steals when installed, imported or "
        "tested was still checked; text that tricks an AI agent was not."
    )


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


# A folder may hold an already-installed package (an unpacked wheel: the package, a `*.dist-info`
# folder and perhaps a `.pth` file) rather than source code. Malware samples are often kept this
# way, and some attacks only ever existed in the wheel. It is packed back into a wheel and
# installed, so its `.pth` file lands in site-packages and runs whenever Python starts, as it did
# for its victims. A folder with source code (setup.py, pyproject.toml, setup.cfg) is never
# touched by this step.
REWHEEL = r"""
import glob, os, sys, zipfile
if any(os.path.exists(m) for m in ("setup.py", "pyproject.toml", "setup.cfg")):
    sys.exit(0)
infos = glob.glob("*.dist-info")
if not infos:
    sys.exit(0)
info = infos[0]
name, version = info[: -len(".dist-info")].rsplit("-", 1)
files = [os.path.relpath(os.path.join(d, f)) for d, _, fs in os.walk(".") for f in fs]
files = [f for f in files if not f.startswith(".") and f != os.path.join(info, "RECORD")]
wheel = f"/tmp/{name}-{version}-py3-none-any.whl"
with zipfile.ZipFile(wheel, "w") as out:
    for f in files:
        out.write(f, f)
    # no hashes: this copy is installed only to see what it does
    out.writestr(f"{info}/RECORD", "".join(f"{f},,\n" for f in files + [f"{info}/RECORD"]))
print(wheel)
"""
INSTALL_UNPACKED_WHEEL = (
    f"wheel=$(python -c {shlex.quote(REWHEEL)}) && "
    '[ -n "$wheel" ] && pip install --no-deps --force-reinstall "$wheel"'
)

BASELINE = (
    # one step, so the steps keep their places in saved results: for a source project the
    # first part prints nothing and does nothing
    _with_exit_status(f"{INSTALL_UNPACKED_WHEEL}; pip install --no-build-isolation --no-deps ."),
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


MAX_SUSPECTS = 8
TASK_WORDS = {"setup": "set it up", "test": "test it", "summary": "summarize it"}
LOCALIZE_WORKERS = 3  # detonations at once; each needs about 2 GB of the Docker machine's memory
# How long the search for the exact lines may run before falling back to a text search, whose lines
# are shown as "likely". It keeps a scan to a few minutes. `prove=True` (the --prove option) removes
# the limit: the search then ends by itself, which can take up to an hour on real malware, and
# every line it names is proven.
LOCALIZE_SECONDS = 150


def replay_runner(
    steps: list,
    served: Mapping[str, str],
    deadline: float | None = None,
    *,
    pool: EgressPool | None = None,
    until: str | None = None,
    loaded: set[str] | None = None,
) -> Runner:
    """A localizer Runner that replays the agent's recorded commands, with no model calls.

    Each call detonates one version of the repo in a fresh sandbox and returns which canaries
    were seen in plain-HTTP requests. The sandbox is new every time (an installed package must not
    carry over), but the network watcher comes from `pool` when given, and only the traffic of
    this detonation is read from it.

    `until` names a canary: the first call replays step by step and notes the step after which it
    had left. Later calls stop there, since the steps after it cannot change what the search asks.
    A first call in which it does not leave changes nothing. Make that first call before running
    in parallel.

    That first call also notes, in `loaded`, which of the repo's files Python ran. A hint for
    where to search, since a hostile repo could write that list itself; it never decides a verdict.
    """
    learning = until is not None
    kept = steps

    def run(files: Files) -> set[str]:
        nonlocal learning, kept
        if deadline is not None and time.time() > deadline:
            raise OutOfTime
        canaries = canary.generate()
        with tempfile.TemporaryDirectory() as tmp:
            for name, text in files.items():
                path = Path(tmp, name)
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(text)
            with pool.lend() if pool else Egress(served) as net:
                mark = net.mark()

                def leaked() -> set[str]:
                    seen = net.observed(mark)
                    found = find_leaks(seen.requests, canaries.values, seen.hosts)
                    return {base_name(leak.canary) for leak in found}

                watching = learning
                learning = False
                with Sandbox(Path(tmp), canaries, net.net(), trace=watching) as box:
                    stopped = _replay(kept, box, (lambda: until in leaked()) if watching else None)
                    if stopped is not None:
                        kept = steps[: stopped + 1]
                    if watching and loaded is not None:
                        loaded.update(box.read(sandbox.TRACE_LOG).stdout.splitlines())
                return leaked()

    return run


def _replay(steps: list, box: Sandbox, stop: Callable[[], bool] | None = None) -> int | None:
    """Replay the steps. With `stop`, ask after each one whether to end here; returns that step's
    index, or None if the replay ran to the end."""
    for index, step in enumerate(steps):
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
        if stop is not None and stop():
            return index
    return None


def textual_suspects(files: Mapping[str, str], destination: str, canary_name: str) -> list[Culprit]:
    """Lines that name the place the secret went, name the secret itself (`.aws/credentials`,
    `OPENAI_API_KEY`) or read the machine's identity, found by plain text search. A quick
    answer for when the exact search takes too long; it is not confirmed by re-running, and is
    marked so."""
    host = urlparse(destination).hostname or ""
    secret = canary_name.split("#")[0].removeprefix("~/").removeprefix("$").lower()
    words = (*IDENTITY_WORDS.get(canary_name, ()), *([secret] if len(secret) > 4 else []))
    found = []
    for path, text in files.items():
        for number, line in enumerate(text.split("\n"), 1):
            lowered = line.lower()
            if (host and host in lowered) or any(word in lowered for word in words):
                found.append(Culprit(path, number, line, UNCONFIRMED))
    return found[:MAX_SUSPECTS]


def search_scopes(
    files: Mapping[str, str], loaded: set[str], suspects: list[Culprit]
) -> list[list[str]]:
    """The files to look for the culprit in, narrowest first: those Python ran while the secret
    left, plus those the text search suspects. A big repo cannot be searched whole in the time
    allowed, but the code that sent the secret had to run. Files outside the scope stay intact
    during the search, so narrowing never removes code the leak needs. With nothing recorded, or
    when the narrow scope does not hold the culprit, the whole repo is the scope."""
    wanted = loaded | {c.file for c in suspects}
    narrow = [name for name in files if name in wanted]
    everything = list(files)
    return [narrow, everything] if narrow and narrow != everything else [everything]


def localize_leak(
    files: Mapping[str, str],
    run: RunResult,
    canary_name: str,
    served: Mapping[str, str],
    *,
    llm: LLM | None = None,
    model: str = "nano",
    prove: bool = False,
) -> tuple[list[Culprit], str]:
    """Culprit lines for one leaked secret, or ([], why not).

    Code that steals the secret is found by replaying the agent's commands against versions of the
    repository. If that cannot explain the leak, the agent decided to send it, and when a model is
    available the lines are found by asking the model again (see counterfactual.py).
    """
    leak = next(x for x in run.leaks if base_name(x.canary) == canary_name)
    try:
        with EgressPool(served, LOCALIZE_WORKERS) as pool:
            deadline = None if prove else time.time() + LOCALIZE_SECONDS
            loaded: set[str] = set()
            runner = replay_runner(
                run.trace.steps, served, deadline, pool=pool, until=canary_name, loaded=loaded
            )
            # The unmodified repo goes first because it teaches the runner where to stop and which
            # files ran; the blanked one then replays only that far, which saves more than running
            # both at once.
            if canary_name in runner(files):
                suspects = textual_suspects(files, leak.destination, canary_name)
                for scope in search_scopes(files, loaded, suspects):
                    blanked = {n: "" if n in scope else t for n, t in files.items()}
                    # If the leak survives blanking the whole scope, the culprit lies outside it.
                    if canary_name not in runner(blanked):
                        found = localize(
                            files, runner, canary_name, candidates=scope, workers=LOCALIZE_WORKERS
                        )
                        return found, ""
    except OutOfTime:
        found = textual_suspects(files, leak.destination, canary_name)
        if found:
            return found, ""
        return [], f"the search for the culprit line stopped after {LOCALIZE_SECONDS} seconds"
    if llm is None:
        return [], "the leak does not depend on the repository's code when replaying the commands"
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
    on_verdict: Callable[[ScanResult], None] = lambda result: None,
    prove: bool = False,
) -> ScanResult:
    """Detonate the repo and judge it. `on_verdict` gets the result once, as soon as the verdict
    is known and before the (slow) search for the culprit lines begins; its culprits are empty."""
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
    asks = " and ".join(TASK_WORDS.get(task, task) for task in tasks)
    times = f", {k} times each" if k > 1 else ""
    progress(
        f"running the repo in the sandbox: installing it, running its tests, and asking an AI "
        f"agent to {asks}{times}"
    )
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
    if warning := agent_warning(runs):
        result.warnings.append(warning)
    result.cost_usd = llm.status()["cost_usd"]
    result.seconds = time.time() - started
    on_verdict(result)

    located: dict[str, tuple[list, str]] = {}  # where the leak went -> what localizing it found
    for name in dict.fromkeys(base_name(leak.canary) for leak in leaks):
        leaking_run = next(r for r in runs if any(base_name(x.canary) == name for x in r.leaks))
        destination = next(x.destination for x in leaking_run.leaks if base_name(x.canary) == name)
        if destination not in located:  # two secrets sent in one request have the same culprit
            progress(f"finding the lines that leaked {canary.plain_name(name)}")
            located[destination] = localize_leak(
                files, leaking_run, name, served, llm=llm, model=model, prove=prove
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
