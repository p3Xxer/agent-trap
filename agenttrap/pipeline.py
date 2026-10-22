"""The whole job for one repository: scan, look up flagged hosts, optionally clean and re-scan.

The CLI and the web server both call this, so they cannot drift apart.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from pathlib import Path

from agenttrap.agent import TASKS
from agenttrap.intel import api_key, lookup
from agenttrap.llm import LLM
from agenttrap.scan import ScanResult, clean_and_rescan, scan, suspect_hosts


def full_scan(
    repo: Path,
    *,
    llm: LLM,
    model: str = "nano",
    k: int = 2,
    tasks: tuple[str, ...] = tuple(TASKS),
    served: Mapping[str, str] | None = None,
    clean_dir: Path | None = None,
    progress: Callable[[str], None] = lambda message: None,
    on_verdict: Callable[[ScanResult], None] = lambda result: None,
    prove: bool = False,
) -> ScanResult:
    """`on_verdict` is told about the first scan's verdict as soon as it is known, before the
    culprit lines are searched for. The re-scan of a cleaned copy does not call it."""
    options = {"llm": llm, "model": model, "k": k, "tasks": tasks, "served": served or {}}
    result = scan(repo, **options, progress=progress, on_verdict=on_verdict, prove=prove)
    progress("checking who is behind the websites it contacted")
    result.intel = lookup(suspect_hosts(result), key=api_key())
    if clean_dir and result.culprits:
        progress("removing those lines and scanning the cleaned copy to confirm it is safe")
        result.cleaned = clean_and_rescan(repo, result, clean_dir, **options, progress=progress)
    return result
