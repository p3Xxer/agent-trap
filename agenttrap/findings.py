"""The findings of a scan, in one neutral form that every output (SARIF, GitHub annotations, the
run summary) is rendered from, so they cannot disagree with each other or with the report."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal
from urllib.parse import urlparse

from agenttrap.localizer import Culprit
from agenttrap.scan import ScanResult, base_name

Level = Literal["error", "warning", "note"]

# rule id -> (short name, what it means, level, security severity 0-10)
RULES: dict[str, tuple[str, str, Level, str]] = {
    "agent-trap/secret-leak": (
        "Secret leaves the sandbox",
        "A planted fake secret was seen leaving the sandbox while an AI agent set up and tested "
        "the repository. Code in this repository reads the secret and sends it out.",
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


def split_culprits(
    culprits: list[Culprit], canary: str, destination: str
) -> tuple[list[Culprit], list[Culprit]]:
    """Separate the lines that touch the secret or the destination from supporting lines.

    The localizer returns every line the leak needs (including `try:` and `pass`). Only some of
    them are what a reviewer should look at; the rest are scaffolding around them.
    """
    host = urlparse(destination).hostname or destination
    markers = [m for m in (host, canary.removeprefix("~/").removeprefix("$")) if m]
    key = [c for c in culprits if any(m in c.text for m in markers)]
    return key or culprits, [c for c in culprits if c not in key] if key else []


def findings(result: ScanResult) -> list[Finding]:
    out: list[Finding] = []

    for name in sorted({base_name(x.canary) for x in result.verdict.leaks}):
        evidence = next(x for x in result.verdict.leaks if base_name(x.canary) == name)
        key, support = split_culprits(result.culprits.get(name, []), name, evidence.destination)
        message = _leak_message(name, evidence.destination, key, result.unlocalized.get(name, ""))
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


def _leak_message(canary: str, destination: str, key: list[Culprit], why_not: str) -> str:
    if any(c.tag == "agent-instruction" for c in key):
        return (
            f"An AI agent was tricked by text in this repository into sending the planted fake "
            f"secret {canary} to {destination}. Shown on their own, these lines were enough to "
            f"make it do so."
        )
    message = (
        f"While an AI agent set up and tested this repository, the planted fake secret "
        f"{canary} was sent to {destination}."
    )
    if key:
        return message + " These lines make that happen."
    return message + f" Agent Trap could not pinpoint the line ({why_not})."
