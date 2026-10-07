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
) -> ScanResult:
    options = {"llm": llm, "model": model, "k": k, "tasks": tasks, "served": served or {}}
    result = scan(repo, **options, progress=progress)
    progress("looking up flagged hosts")
    result.intel = lookup(suspect_hosts(result), key=api_key())
    if clean_dir and result.culprits:
        progress("cleaning the repo and scanning the copy")
        result.cleaned = clean_and_rescan(repo, result, clean_dir, **options, progress=progress)
    return result
