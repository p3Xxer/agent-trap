"""Scan every project in a folder and summarize, for folders of code somebody else wrote.

Nothing in the folder is installed or run outside the sandbox. By default no line of the scanned
code is written into the saved results, so the results can be kept or shared without copying the
code itself.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

from agenttrap.llm import LLM
from agenttrap.pipeline import full_scan
from agenttrap.results import ResultStore, result_document

MARKERS = ("setup.py", "pyproject.toml", "setup.cfg")
MAX_DEPTH = 12  # an unpacked archive can keep a long absolute path of its own


@dataclass(frozen=True)
class BatchItem:
    name: str
    status: str  # SAFE, SUSPICIOUS, HIJACKED, or ERROR when the scan itself failed
    seconds: float
    findings: int
    error: str | None = None


def _is_project(directory: Path) -> bool:
    return any((directory / marker).is_file() for marker in MARKERS)


def _subdirectories(directory: Path) -> list[Path]:
    return sorted(p for p in directory.iterdir() if p.is_dir() and not p.is_symlink())


def _projects_inside(directory: Path, depth: int = 0) -> list[Path]:
    """Every directory at or below `directory` that looks like a Python project.

    A project is not searched further, so its own sub-packages are not counted again.
    """
    if _is_project(directory):
        return [directory]
    if depth >= MAX_DEPTH:
        return []
    return [p for child in _subdirectories(directory) for p in _projects_inside(child, depth + 1)]


def find_projects(root: Path) -> list[Path]:
    """The projects under `root`: all of them, in order. A folder with no recognizable project
    in it is scanned as it is, so unusual layouts are not silently skipped."""
    if _is_project(root):
        return [root]
    found = []
    for child in _subdirectories(root):
        found += _projects_inside(child) or [child]
    return found


def scan_project(
    project: Path, name: str, *, store: ResultStore, k: int, model: str, include_code: bool
) -> BatchItem:
    started = time.time()
    try:
        result = full_scan(project, llm=LLM(), model=model, k=k)
        document = result_document(result, name=name, include_code=include_code)
        store.save(document)
    except Exception as error:  # noqa: BLE001 - one broken project must not stop the batch
        reason = f"{type(error).__name__}: {str(error)[:100]}"
        return BatchItem(name, "ERROR", time.time() - started, 0, reason)
    return BatchItem(name, result.verdict.status.value, result.seconds, len(document["findings"]))


def run_batch(
    root: Path,
    *,
    store: ResultStore,
    k: int = 2,
    model: str = "nano",
    workers: int = 2,
    include_code: bool = False,
    on_done: Callable[[BatchItem], None] = lambda item: None,
    scan: Callable[..., BatchItem] = scan_project,
) -> list[BatchItem]:
    """Scan every project under `root`, `workers` at a time. Results come back in folder order."""
    projects = find_projects(root)

    def one(project: Path) -> BatchItem:
        name = "batch/" + (project.relative_to(root).as_posix() if project != root else root.name)
        item = scan(project, name, store=store, k=k, model=model, include_code=include_code)
        on_done(item)
        return item

    with ThreadPoolExecutor(workers) as pool:
        return list(pool.map(one, projects))
