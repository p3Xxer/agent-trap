"""Print a scan result for a human."""

from __future__ import annotations

from urllib.parse import urlparse

from rich.console import Console
from rich.panel import Panel

from agenttrap.detector import Status
from agenttrap.localizer import Culprit
from agenttrap.scan import ScanResult, base_name

STYLE = {Status.SAFE: "bold green", Status.SUSPICIOUS: "bold yellow", Status.HIJACKED: "bold red"}
HEADLINE = {
    Status.SAFE: "SAFE: nothing tried to leak a secret or instruct the agent.",
    Status.SUSPICIOUS: "SUSPICIOUS: warning signs, but no secret was seen leaving.",
    Status.HIJACKED: "HIJACKED: a planted secret was seen leaving the sandbox.",
}
NOTES = {
    "base64": "hidden as base64: a text scanner sees only random characters",
    "runtime-fetch": "network call made by the repo's own code while it runs",
    "unicode": "hidden with invisible unicode characters",
}


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


def render(result: ScanResult, console: Console | None = None) -> None:
    console = console or Console()
    status = result.verdict.status
    console.print(
        f"\n[bold]AGENT TRAP[/] scan of [cyan]{result.repo}[/]  ({len(result.runs)} runs)\n"
    )
    console.print(Panel(HEADLINE[status], style=STYLE[status], expand=False))

    for leak in sorted({base_name(x.canary) for x in result.verdict.leaks}):
        evidence = next(x for x in result.verdict.leaks if base_name(x.canary) == leak)
        console.print(f"\n[bold red]leaked[/] {leak}  ->  {evidence.destination}")
        key, support = split_culprits(result.culprits.get(leak, []), leak, evidence.destination)
        for culprit in key:
            console.print(f"    culprit : [bold]{culprit.file}:{culprit.line}[/]")
            console.print(f"    line    : {culprit.text.strip()[:100]}")
            if note := NOTES.get(culprit.tag):
                console.print(f"    note    : {note}")
        if support:
            lines = ", ".join(f"{c.file}:{c.line}" for c in support)
            console.print(f"    also needed for the leak: {lines}")
        if leak in result.unlocalized:
            console.print(f"    culprit : not pinpointed ({result.unlocalized[leak]})")

    hard = [f for f in result.verdict.flags if f.hard]
    soft = [f for f in result.verdict.flags if not f.hard and f.kind != "injection-reported"]
    for flag in hard:
        console.print(f"\n[bold red]{flag.kind}[/] {flag.detail}")

    if result.injections:
        console.print(
            "\n[bold yellow]Text that tried to instruct the AI agent[/] (the agent's report)"
        )
        for item in result.injections:
            where = item.where or "quoted text not found in repo"
            console.print(f"    [bold]{where}[/]")
            console.print(f'    "{item.injection.quote.strip()[:100]}"')
            console.print(f"    asked for: {item.injection.asked_for.strip()[:100]}")
    if soft:
        console.print("\n[yellow]Hosts contacted that are not on the allow-list[/]")
        for flag in soft:
            console.print(f"    {flag.detail.removeprefix('sandbox contacted ')}")
    console.print(f"\n[dim]cost ${result.cost_usd:.4f}, {result.seconds:.0f}s[/]\n")
