"""The findings of a scan, in one neutral form that every output (SARIF, GitHub annotations, the
run summary) is rendered from, so they cannot disagree with each other or with the report."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal
from urllib.parse import urlparse

from agenttrap.canary import IDENTITY_WORDS, plain_name
from agenttrap.localizer import UNCONFIRMED, Culprit, sends_over_network
from agenttrap.scan import ScanResult, base_name

Level = Literal["error", "warning", "note"]

# rule id -> (short name, what it means, level, security severity 0-10)
RULES: dict[str, tuple[str, str, Level, str]] = {
    "agent-trap/secret-leak": (
        "Secret leaves the sandbox",
        "A planted fake secret was seen leaving the sandbox. Something in this repository, either "
        "its own code or text that an AI agent obeyed, sends the secret out.",
        "error",
        "9.0",
    ),
    "agent-trap/destructive-command": (
        "Destructive command ran",
        "The AI agent ran a clearly destructive command (for example a recursive delete or a "
        "download piped into a shell) while working on this repository.",
        "error",
        "9.0",
    ),
    "agent-trap/agent-instruction": (
        "Text that instructs an AI agent",
        "The AI agent reported text in this repository that tries to give it instructions that "
        "are not part of the user's task. No secret was seen leaving.",
        "warning",
        "5.0",
    ),
    "agent-trap/suspicious-code": (
        "Code the AI agent found suspicious",
        "The AI agent reported this code as doing something a normal library would not, such as "
        "sending the user's data to a server. It is the agent's opinion, not proof, and the "
        "quoted line was found in the repository.",
        "warning",
        "5.0",
    ),
    "agent-trap/unexpected-host": (
        "Unexpected network contact",
        "The sandbox tried to contact a host that is not on the allow-list.",
        "note",
        "3.0",
    ),
}


@dataclass(frozen=True)
class Location:
    file: str
    line: int
    text: str = ""


@dataclass(frozen=True)
class Finding:
    rule: str
    message: str
    locations: tuple[Location, ...] = ()  # the lines to look at
    related: tuple[Location, ...] = ()  # lines that are also part of it

    @property
    def level(self) -> Level:
        return RULES[self.rule][2]

    @property
    def title(self) -> str:
        return RULES[self.rule][0]


_SCAFFOLDING = re.compile(
    r"import\s.*|from\s+\S+\s+import\s.*|try:|except\b.*:|finally:|else:|pass|[)\]}]+,?"
)


def split_culprits(
    culprits: list[Culprit], canary: str, destination: str
) -> tuple[list[Culprit], list[Culprit]]:
    """Separate the lines that touch the secret, name the destination or send something over the
    network from supporting lines.

    The localizer returns every line the leak needs (including `try:` and `pass`). Only some of
    them are what a reviewer should look at; the rest are scaffolding around them, and plain
    scaffolding (imports, try/except, closing brackets) is left out of the supporting lines.
    """
    host = urlparse(destination).hostname or destination
    words = IDENTITY_WORDS.get(canary, ())
    markers = [m for m in (host, canary.removeprefix("~/").removeprefix("$"), *words) if m]
    key = [
        c
        for c in culprits
        if any(m.lower() in c.text.lower() for m in markers) or sends_over_network(c.text)
    ]
    if not key:
        return culprits, []
    support = [c for c in culprits if c not in key and not _SCAFFOLDING.fullmatch(c.text.strip())]
    return key, support


Phase = Literal["install", "agent", "both"]
INSTALL_TASK = "baseline"  # the run without an AI agent: install, import and test the repository


@dataclass(frozen=True)
class LeakGroup:
    """Everything that was sent to one destination host, told once."""

    host: str
    destination: str
    canaries: tuple[str, ...]  # canary names (sorted), as the scanner knows them
    phase: Phase
    tasks: tuple[str, ...]  # the AI agent's tasks during which it happened
    tricked: bool  # an AI agent obeyed text in the repository
    lines: tuple[Location, ...]  # the key lines of every secret sent here, without duplicates
    unconfirmed: bool  # some lines come from a text search, not from re-running the repository
    why_not: tuple[str, ...]  # why a line could not be found, when it could not


def _host(destination: str) -> str:
    return urlparse(destination).hostname or destination


def _phase(tasks: list[str]) -> tuple[Phase, tuple[str, ...]]:
    """When it happened, from the names of the runs that leaked. Without run information the
    leak is reported as the agent's, the wording used before runs were recorded."""
    agent = tuple(dict.fromkeys(t for t in tasks if t != INSTALL_TASK))
    if INSTALL_TASK in tasks:
        return ("both" if agent else "install"), agent
    return "agent", agent


def leak_groups(result: ScanResult) -> list[LeakGroup]:
    groups = []
    hosts = dict.fromkeys(_host(x.destination) for x in result.verdict.leaks)
    for host in hosts:
        leaks = [x for x in result.verdict.leaks if _host(x.destination) == host]
        names = sorted({base_name(x.canary) for x in leaks})
        lines: dict[tuple[str, int], Culprit] = {}
        why_not = []
        for name in names:
            destination = next(x.destination for x in leaks if base_name(x.canary) == name)
            key, _ = split_culprits(result.culprits.get(name, []), name, destination)
            lines.update({(c.file, c.line): c for c in key})
            if name in result.unlocalized and not key:
                why_not.append(result.unlocalized[name])
        chosen = [lines[k] for k in sorted(lines)]
        runs = [r.task for r in result.runs if any(_host(x.destination) == host for x in r.leaks)]
        phase, tasks = _phase(runs)
        groups.append(
            LeakGroup(
                host=host,
                destination=leaks[0].destination,
                canaries=tuple(names),
                phase=phase,
                tasks=tasks,
                tricked=any(c.tag == "agent-instruction" for c in chosen),
                lines=tuple(Location(c.file, c.line, c.text) for c in chosen),
                unconfirmed=any(c.tag == UNCONFIRMED for c in chosen),
                why_not=tuple(dict.fromkeys(why_not)),
            )
        )
    return groups


def _leaking_runs(result: ScanResult, canary: str) -> list[str]:
    return [r.task for r in result.runs if any(base_name(x.canary) == canary for x in r.leaks)]


def findings(result: ScanResult) -> list[Finding]:
    out: list[Finding] = []

    for name in sorted({base_name(x.canary) for x in result.verdict.leaks}):
        evidence = next(x for x in result.verdict.leaks if base_name(x.canary) == name)
        key, support = split_culprits(result.culprits.get(name, []), name, evidence.destination)
        phase, tasks = _phase(_leaking_runs(result, name))
        message = _leak_message(
            name, evidence.destination, key, result.unlocalized.get(name, ""), phase, tasks
        )
        out.append(
            Finding(
                "agent-trap/secret-leak",
                message,
                tuple(Location(c.file, c.line, c.text) for c in key),
                tuple(Location(c.file, c.line, c.text) for c in support),
            )
        )

    out += [
        Finding(
            "agent-trap/destructive-command", f"The agent ran a destructive command: {f.detail}"
        )
        for f in result.verdict.flags
        if f.hard
    ]

    for item in result.injections:
        asked = item.injection.asked_for.strip() or "something outside its task"
        location = _parse_where(item.where, item.injection.quote)
        out.append(
            Finding(
                "agent-trap/agent-instruction",
                f"The AI agent reported this text as instructions aimed at it. It asks the agent "
                f"to: {asked}",
                (location,) if location else (),
            )
        )

    for item in result.concerns:
        file, _, line = item.where.rpartition(":")
        behavior = item.concern.behavior.strip() or "something a normal library would not"
        out.append(
            Finding(
                "agent-trap/suspicious-code",
                f"The AI agent flagged this code as suspicious: {behavior}",
                (Location(file, int(line), item.concern.quote.strip()),),
            )
        )

    for host in result.contacted:
        out.append(Finding("agent-trap/unexpected-host", _host_message(host, result)))
    return out


def _parse_where(where: str | None, quote: str) -> Location | None:
    """ "src/config.py:2" -> Location. None when the quoted text was not found in the repo."""
    if not where:
        return None
    file, _, line = where.rpartition(":")
    return Location(file, int(line), quote.strip()) if file and line.isdigit() else None


def _host_message(host: str, result: ScanResult) -> str:
    message = f"The sandbox contacted {host}, which is not on the allow-list."
    info = result.intel.get(host)
    if info and info.registered:
        message += f" The domain was registered {info.registered.isoformat()}."
    if info and info.reports:
        message += f" Public pages mention it alongside malware or phishing: {info.reports[0].url}"
    return message


def when_leaked(phase: Phase, tasks: tuple[str, ...] = ()) -> str:
    """Who was running when the secret left, as the start of a sentence."""
    if phase == "install":
        return "While the project was installed and tested (no AI involved),"
    if phase == "both":  # an AI agent installing it sets off the same code
        return "While the project was installed and tested,"
    task = f" (task: {', '.join(tasks)})" if tasks else ""
    return f"While an AI agent was working on this repository{task},"


def _leak_message(
    canary: str,
    destination: str,
    key: list[Culprit],
    why_not: str,
    phase: Phase = "agent",
    tasks: tuple[str, ...] = (),
) -> str:
    what = plain_name(canary)
    if any(c.tag == "agent-instruction" for c in key):
        return (
            f"An AI agent was tricked by text in this repository into sending {what} "
            f"to {destination}. Shown on their own, these lines were enough to make it do so."
        )
    message = f"{when_leaked(phase, tasks)} {what} was sent to {destination}."
    if any(c.tag == UNCONFIRMED for c in key):
        return message + (
            " These lines mention the address or read the machine's identity (found by searching "
            "the code; the full re-run search ran out of time, so this is not confirmed)."
        )
    if key:
        return message + " These lines make that happen."
    return message + f" Agent Trap could not pinpoint the line ({why_not})."
