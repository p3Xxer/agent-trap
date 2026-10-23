"""Print a scan result for a human."""

from __future__ import annotations

from rich.console import Console
from rich.markup import escape
from rich.panel import Panel

from agenttrap.detector import Status, label
from agenttrap.findings import split_culprits
from agenttrap.intel import HostIntel, PackageIntel
from agenttrap.scan import CleanOutcome, ScanResult, base_name

STYLE = {Status.SAFE: "bold green", Status.SUSPICIOUS: "bold yellow", Status.HIJACKED: "bold red"}
HEADLINE = {
    Status.SAFE: (
        "SAFE: no theft found. No planted secret left the sandbox, "
        "and nothing instructed the agent."
    ),
    Status.SUSPICIOUS: "SUSPICIOUS: warning signs, but no secret was seen leaving.",
    Status.HIJACKED: "MALICIOUS: a planted secret was seen leaving the sandbox.",
}
NOTES = {
    "base64": "hidden as base64: a text scanner sees only random characters",
    "runtime-fetch": "network call made by the repo's own code while it runs",
    "unicode": "hidden with invisible unicode characters",
    "unconfirmed": "likely line, found by reading the code (run with --prove to confirm)",
    "agent-instruction": "an AI agent obeyed this text; on its own it was enough",
}


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


def render_package(info: PackageIntel, console: Console) -> None:
    """Web reports of this package version. Context from the internet, not part of the verdict."""
    what = f"{escape(info.name)} {escape(info.version)}"
    console.print(f"\n[bold]Has {what} already been reported?[/] [dim](web search, untrusted)[/]")
    if info.reports is None:
        console.print("    unknown (search did not run)")
    elif not info.reports:
        console.print("    no public reports found")
    else:
        count = len(info.reports)
        console.print(f"    [yellow]{count} page(s) describe it as malicious or compromised[/]")
        for report in info.reports:
            console.print(f"      - {escape(report.title)}  {escape(report.url)}")
            console.print(f"        {escape(report.snippet)}")


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
    console.print(f"    re-scan : [{STYLE[rescan.status]}]{label(rescan.status)}[/]", end="")
    if still_leaking:
        console.print(
            f"  still leaks {escape(', '.join(still_leaking))}: those lines were not all of it"
        )
    elif rescan.status is Status.SAFE:
        console.print("  the secret no longer leaves the sandbox")
    else:
        console.print("  no secret leaked, but there are still warnings")
    console.print("    [dim]Removing code can change what the repo does. Review it before use.[/]")


def render_verdict(result: ScanResult, console: Console) -> None:
    """Just the verdict and where each secret went: what is known before the culprit search."""
    status = result.verdict.status
    console.print(Panel(HEADLINE[status], style=STYLE[status], expand=False))
    for leak in sorted({base_name(x.canary) for x in result.verdict.leaks}):
        evidence = next(x for x in result.verdict.leaks if base_name(x.canary) == leak)
        console.print(f"[bold red]leaked[/] {escape(leak)}  ->  {escape(evidence.destination)}")


def render(result: ScanResult, console: Console | None = None) -> None:
    console = console or Console()
    status = result.verdict.status
    console.print(
        f"\n[bold]AGENT TRAP[/] scan of [cyan]{result.repo}[/]  ({len(result.runs)} runs)\n"
    )
    console.print(Panel(HEADLINE[status], style=STYLE[status], expand=False))
    for warning in result.warnings:
        console.print(f"[bold yellow]warning[/] {escape(warning)}")

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
    if result.concerns:
        console.print(
            "\n[bold yellow]Code the AI agent found suspicious[/] "
            "(its opinion, checked only to exist in the repository)"
        )
        for item in result.concerns:
            console.print(f"    [bold]{escape(item.where)}[/]")
            console.print(f"    {escape(item.concern.quote.strip()[:100])}")
            console.print(f"    it does: {escape(item.concern.behavior.strip()[:100])}")
    if result.contacted:
        console.print("\n[yellow]Hosts contacted that are not on the allow-list[/]")
        for host in result.contacted:
            console.print(f"    {escape(host)}")
    if result.intel:
        render_intel(result.intel, console)
    if result.package:
        render_package(result.package, console)
    if result.cleaned:
        render_clean(result.cleaned, console)
    console.print(f"\n[dim]cost ${result.cost_usd:.4f}, {result.seconds:.0f}s[/]\n")
