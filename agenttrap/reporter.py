"""Print a scan result for a human."""

from __future__ import annotations

from urllib.parse import urlparse

from rich.console import Console
from rich.markup import escape
from rich.panel import Panel

from agenttrap.detector import Status
from agenttrap.intel import HostIntel
from agenttrap.localizer import Culprit
from agenttrap.scan import CleanOutcome, ScanResult, base_name

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


def render_intel(intel: dict[str, HostIntel], console: Console) -> None:
    """Public lookups on flagged hosts. All of this text came from the internet: it is shown as
    data, escaped, and never acted on."""
    console.print("\n[bold]Who is behind these hosts[/] [dim](public lookups, untrusted)[/]")
    for host, info in intel.items():
        console.print(f"    [bold]{escape(host)}[/]")
        console.print(f"      registered : {_registration(info)}")
        if info.reports is None:
            console.print("      web reports: unknown (search did not run)")
        elif not info.reports:
            console.print("      web reports: none found")
        else:
            console.print(f"      web reports: {len(info.reports)} page(s) mention it")
            for report in info.reports:
                console.print(f"        - {escape(report.title)}  {escape(report.url)}")
                console.print(f"          {escape(report.snippet)}")


def _registration(info: HostIntel) -> str:
    if info.registered is None or info.age_days is None:
        return "unknown"
    recent = "  [yellow](recent)[/]" if info.is_recent else ""
    return f"{info.registered.isoformat()} ({info.age_days:,} days ago){recent}"


def render_clean(cleaned: CleanOutcome, console: Console) -> None:
    rescan = cleaned.rescan.verdict
    still_leaking = sorted({base_name(x.canary) for x in rescan.leaks})
    console.print(f"\n[bold]Cleaned copy[/] written to [cyan]{escape(str(cleaned.out_dir))}[/]")
    console.print(f"    removed : {escape(', '.join(str(r) for r in cleaned.removed))}")
    for warning in cleaned.warnings:
        console.print(f"    [yellow]warning : {escape(warning)}[/]")
    console.print(f"    re-scan : [{STYLE[rescan.status]}]{rescan.status.value}[/]", end="")
    if still_leaking:
        console.print(
            f"  still leaks {escape(', '.join(still_leaking))}: those lines were not all of it"
        )
    elif rescan.status is Status.SAFE:
        console.print("  the secret no longer leaves the sandbox")
    else:
        console.print("  no secret leaked, but there are still warnings")
    console.print("    [dim]Removing code can change what the repo does. Review it before use.[/]")


def render(result: ScanResult, console: Console | None = None) -> None:
    console = console or Console()
    status = result.verdict.status
    console.print(
        f"\n[bold]AGENT TRAP[/] scan of [cyan]{result.repo}[/]  ({len(result.runs)} runs)\n"
    )
    console.print(Panel(HEADLINE[status], style=STYLE[status], expand=False))

    for leak in sorted({base_name(x.canary) for x in result.verdict.leaks}):
        evidence = next(x for x in result.verdict.leaks if base_name(x.canary) == leak)
        console.print(f"\n[bold red]leaked[/] {escape(leak)}  ->  {escape(evidence.destination)}")
        key, support = split_culprits(result.culprits.get(leak, []), leak, evidence.destination)
        for culprit in key:
            console.print(f"    culprit : [bold]{escape(culprit.file)}:{culprit.line}[/]")
            console.print(f"    line    : {escape(culprit.text.strip()[:100])}")
            if note := NOTES.get(culprit.tag):
                console.print(f"    note    : {note}")
        if support:
            lines = ", ".join(f"{c.file}:{c.line}" for c in support)
            console.print(f"    also needed for the leak: {escape(lines)}")
        if leak in result.unlocalized:
            console.print(f"    culprit : not pinpointed ({escape(result.unlocalized[leak])})")

    hard = [f for f in result.verdict.flags if f.hard]
    for flag in hard:
        console.print(f"\n[bold red]{flag.kind}[/] {escape(flag.detail)}")

    if result.injections:
        console.print(
            "\n[bold yellow]Text that tried to instruct the AI agent[/] (the agent's report)"
        )
        for item in result.injections:
            where = item.where or "quoted text not found in repo"
            console.print(f"    [bold]{escape(where)}[/]")
            console.print(f'    "{escape(item.injection.quote.strip()[:100])}"')
            console.print(f"    asked for: {escape(item.injection.asked_for.strip()[:100])}")
    if result.contacted:
        console.print("\n[yellow]Hosts contacted that are not on the allow-list[/]")
        for host in result.contacted:
            console.print(f"    {escape(host)}")
    if result.intel:
        render_intel(result.intel, console)
    if result.cleaned:
        render_clean(result.cleaned, console)
    console.print(f"\n[dim]cost ${result.cost_usd:.4f}, {result.seconds:.0f}s[/]\n")
