"""Output for GitHub Actions: annotations on the lines of a pull request, and a run summary.

Everything here is built from text that came out of the scanned repository or from the agent,
so it is untrusted. A workflow command is one line, and a stray newline in it could start a
second command, so every value is escaped the way GitHub specifies before it is printed.
"""

from __future__ import annotations

import os
import secrets
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from agenttrap.findings import Finding
from agenttrap.reporter import HEADLINE
from agenttrap.scan import ScanResult

COMMAND = {"error": "error", "warning": "warning", "note": "notice"}
MAX_TEXT = 600


def _escape_data(text: str) -> str:
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _escape_property(text: str) -> str:
    return _escape_data(text).replace(":", "%3A").replace(",", "%2C")


def annotation_lines(findings: list[Finding], prefix: str = "") -> list[str]:
    """One `::error file=...,line=...::message` line per place to look at.

    `prefix` is the scanned folder inside the repository: GitHub places an annotation by its path
    from the repository root, while findings give paths from the scanned folder."""
    lines = []
    for finding in findings:
        title = _escape_property(f"Agent Trap: {finding.title}")
        message = _escape_data(finding.message[:MAX_TEXT])
        command = COMMAND[finding.level]
        if not finding.locations:
            lines.append(f"::{command} title={title}::{message}")
        for loc in finding.locations:
            path = f"{prefix}/{loc.file}" if prefix else loc.file
            where = f"file={_escape_property(path)},line={max(loc.line, 1)}"
            lines.append(f"::{command} {where},title={title}::{message}")
    return lines


def _code(text: str, limit: int = 120) -> str:
    """Untrusted text as an inline code span that cannot break a table or the markdown."""
    flat = " ".join(text.replace("`", "'").replace("|", "\\|").split())
    return f"`{flat[:limit]}`" if flat else ""


def summary_markdown(result: ScanResult, findings: list[Finding]) -> str:
    status = result.verdict.status
    lines = [f"## Agent Trap: {status.value}", "", HEADLINE[status], ""]
    if findings:
        lines += ["| Finding | Where | Details |", "| --- | --- | --- |"]
        for f in findings:
            where = ", ".join(_code(f"{loc.file}:{loc.line}") for loc in f.locations) or "-"
            details = " ".join(f.message[:MAX_TEXT].replace("|", "\\|").split())
            lines.append(f"| {f.title} | {where} | {details} |")
        lines.append("")
    lines.append(f"Scanned {len(result.runs)} runs in {result.seconds:.0f}s.")
    return "\n".join(lines) + "\n"


def emit_github(result: ScanResult, findings: list[Finding]) -> None:
    """Print annotations to stdout and append the summary, when running inside GitHub Actions."""
    for line in annotation_lines(findings, scanned_folder(result.repo)):
        print(line, flush=True)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with Path(summary).open("a") as file:
            file.write(summary_markdown(result, findings))


@contextmanager
def commands_disabled() -> Iterator[None]:
    """Make the runner ignore workflow commands in everything printed inside the block.

    The human report contains text from the scanned repo; a line of it that started with `::`
    would otherwise be run as a command. The runner resumes only on our random token.
    """
    token = secrets.token_hex(16)
    print(f"::stop-commands::{token}", flush=True)
    try:
        yield
    finally:
        print(f"::{token}::", flush=True)


def scanned_folder(repo: str, workspace: str | None = None) -> str:
    """The scanned folder's path from the workspace root ("" for the root itself or a folder
    outside the workspace)."""
    root = Path(workspace or os.environ.get("GITHUB_WORKSPACE") or os.getcwd()).resolve()
    try:
        relative = Path(repo).resolve().relative_to(root).as_posix()
    except ValueError:
        return ""
    return "" if relative == "." else relative


def running_in_github() -> bool:
    return os.environ.get("GITHUB_ACTIONS") == "true"
