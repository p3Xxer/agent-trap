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
from datetime import UTC, datetime
from pathlib import Path

from agenttrap.llm import LLM
from agenttrap.pipeline import full_scan
from agenttrap.results import ResultStore, result_document
from agenttrap.scan import ScanResult

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
    project: Path,
    name: str,
    *,
    store: ResultStore,
    k: int,
    model: str,
    include_code: bool,
    on_verdict: Callable[[BatchItem], None] = lambda item: None,
) -> BatchItem:
    """Scan one project. A proven leak is saved as soon as the verdict is known, with its culprit
    lines still pending, and the same saved result is completed when the search for them ends."""
    started = time.time()
    created = datetime.now(UTC)  # one timestamp for both versions of the document
    early: dict = {}  # the document saved early, and its id

    def document_of(result: ScanResult, pending: bool = False) -> dict:
        return result_document(
            result, name=name, created=created, include_code=include_code, culprits_pending=pending
        )

    def verdict_known(result: ScanResult) -> None:
        if not result.verdict.leaks:  # no culprit search follows
            return
        early["document"] = document_of(result, pending=True)
        early["id"] = store.save(early["document"])
        findings = len(early["document"]["findings"])
        on_verdict(BatchItem(name, result.verdict.status.value, time.time() - started, findings))

    try:
        result = full_scan(project, llm=LLM(), model=model, k=k, on_verdict=verdict_known)
        document = document_of(result)
        if early:
            store.overwrite(early["id"], document)
        else:
            store.save(document)
    except Exception as error:  # noqa: BLE001 - one broken project must not stop the batch
        if early:  # the early document must not claim a search that will never finish
            store.overwrite(early["id"], {**early["document"], "culprits_pending": False})
        reason = f"{type(error).__name__}: {str(error)[:100]}"
        return BatchItem(name, "ERROR", time.time() - started, 0, reason)
    return BatchItem(name, result.verdict.status.value, result.seconds, len(document["findings"]))


def _short_name(project: Path, root: Path) -> str:
    """The folder under `root` plus the project's own folder, without the long path in between
    that an unpacked archive keeps."""
    if project == root:
        return root.name
    parts = project.relative_to(root).parts
    return "/".join(parts if len(parts) <= 2 else (parts[0], parts[-1]))


def run_batch(
    root: Path,
    *,
    store: ResultStore,
    k: int = 2,
    model: str = "nano",
    workers: int = 2,
    include_code: bool = False,
    on_verdict: Callable[[BatchItem], None] = lambda item: None,
    on_done: Callable[[BatchItem], None] = lambda item: None,
    scan: Callable[..., BatchItem] = scan_project,
) -> list[BatchItem]:
    """Scan every project under `root`, `workers` at a time. Results come back in folder order.

    `on_verdict` hears about a project whose verdict is known while its culprit lines are still
    being searched for; `on_done` hears about every project when it is completely finished."""
    projects = find_projects(root)

    def one(project: Path) -> BatchItem:
        name = "batch/" + _short_name(project, root)
        item = scan(
            project, name, store=store, k=k, model=model, include_code=include_code,
            on_verdict=on_verdict,
        )  # fmt: skip
        on_done(item)
        return item

    with ThreadPoolExecutor(workers) as pool:
        return list(pool.map(one, projects))
