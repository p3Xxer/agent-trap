"""The saved form of a scan: one JSON document that the CLI, the web page and the exported demo
all read. It holds no absolute paths and no secrets, so it is safe to commit and publish.

Every string in a document can come from a scanned repository or from the agent, so it is
untrusted. Readers must show it as text, never as markup.
"""

from __future__ import annotations

import copy
import json
import re
import shutil
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from agenttrap.baseline_static import scan as static_scan
from agenttrap.findings import Finding, findings
from agenttrap.llm import STATE_DIR
from agenttrap.reporter import HEADLINE
from agenttrap.scan import ScanResult, base_name, read_repo

FORMAT = 1
DEFAULT_DIR = STATE_DIR / "results"
SITE_PAGE = Path(__file__).with_name("web") / "index.html"
EXCERPT_CONTEXT = 15  # lines shown around a finding
EXCERPT_MAX = 300
STATIC_SHOWN = 20
_ID = re.compile(r"[a-z0-9][a-z0-9._-]{0,120}")


def result_document(
    result: ScanResult,
    *,
    name: str,
    source: str | None = None,
    created: datetime | None = None,
    include_code: bool = True,
) -> dict[str, Any]:
    """`include_code=False` leaves out every line of the scanned code, for repos whose code should
    not be copied into a file (for example real malware samples)."""
    created = created or datetime.now(UTC)
    found = findings(result)
    repo_files = read_repo(Path(result.repo))
    static = static_scan(Path(result.repo))
    status = result.verdict.status
    document = {
        "format": FORMAT,
        "name": name,
        "source": source,
        "created": created.isoformat(timespec="seconds"),
        "status": status.value,
        "headline": HEADLINE[status],
        "leaks": sorted({base_name(x.canary) for x in result.verdict.leaks}),
        "flags": [
            {"kind": f.kind, "detail": f.detail, "hard": f.hard} for f in result.verdict.flags
        ],
        "findings": [_finding(f) for f in found],
        "culprits": {
            canary: [{"file": c.file, "line": c.line, "text": c.text, "tag": c.tag} for c in cs]
            for canary, cs in result.culprits.items()
        },
        "unlocalized": result.unlocalized,
        "files": _excerpts(found, repo_files),
        "injections": [
            {"where": i.where, "quote": i.injection.quote, "asked_for": i.injection.asked_for}
            for i in result.injections
        ],
        "concerns": [
            {"where": c.where, "quote": c.concern.quote, "behavior": c.concern.behavior}
            for c in result.concerns
        ],
        "contacted_hosts": result.contacted,
        "host_intel": {
            host: {
                "registered": info.registered.isoformat() if info.registered else None,
                "age_days": info.age_days,
                "reports": None if info.reports is None else [asdict(r) for r in info.reports],
            }
            for host, info in result.intel.items()
        },
        "cleaned": _cleaned(result),
        "static_scan": {
            "count": len(static),
            "flagged": [asdict(f) for f in static[:STATIC_SHOWN]],
        },
        "baseline": _baseline(result),
        "runs": len(result.runs),
        "cost_usd": round(result.cost_usd, 5),
        "seconds": round(result.seconds, 1),
        "code_saved": include_code,
    }
    return document if include_code else _without_code(document)


def _without_code(document: dict[str, Any]) -> dict[str, Any]:
    """The same document with no line of the scanned code in it (file names and lines remain)."""
    stripped = copy.deepcopy(document)
    stripped["files"] = {}
    for finding in stripped["findings"]:
        for location in (*finding["locations"], *finding["related"]):
            location["text"] = ""
    for culprits in stripped["culprits"].values():
        for culprit in culprits:
            culprit["text"] = ""
    for item in (*stripped["injections"], *stripped["concerns"]):
        item["quote"] = ""
    for item in stripped["static_scan"]["flagged"]:
        item["text"] = ""
    return stripped


_TEST_COUNTS = re.compile(r"\d+ (?:passed|failed|errors?|skipped|deselected|xfailed|xpassed)")


def _baseline(result: ScanResult) -> dict[str, Any] | None:
    """Did the project install, and what did its tests do? Without this a SAFE verdict cannot be
    told apart from "nothing of the project ever ran"."""
    run = next((r for r in result.runs if r.task == "baseline"), None)
    if run is None or not run.trace.steps:
        return None
    installs = run.trace.steps[:2]
    summary = _TEST_COUNTS.findall(run.trace.steps[-1].observation)
    return {
        "installed": any("Successfully installed" in step.observation for step in installs),
        "tests": ", ".join(summary),  # only the counts, never a line of the project's output
    }


def to_json(document: dict[str, Any]) -> str:
    return json.dumps(document, indent=2)


def _finding(finding: Finding) -> dict[str, Any]:
    return {
        "rule": finding.rule,
        "level": finding.level,
        "title": finding.title,
        "message": finding.message,
        "locations": [asdict(loc) for loc in finding.locations],
        "related": [asdict(loc) for loc in finding.related],
    }


def _cleaned(result: ScanResult) -> dict[str, Any] | None:
    if result.cleaned is None:
        return None
    rescan = result.cleaned.rescan.verdict
    return {
        "removed": [str(r) for r in result.cleaned.removed],
        "warnings": list(result.cleaned.warnings),
        "rescan_status": rescan.status.value,
        "rescan_leaks": sorted({base_name(x.canary) for x in rescan.leaks}),
    }


def _excerpts(found: list[Finding], repo_files: dict[str, str]) -> dict[str, dict[str, Any]]:
    """The lines around every finding, so the page can show code without the whole repo."""
    wanted: dict[str, list[int]] = {}
    for finding in found:
        for loc in (*finding.locations, *finding.related):
            wanted.setdefault(loc.file, []).append(loc.line)
    out = {}
    for file, lines in wanted.items():
        if file not in repo_files:
            continue
        text = repo_files[file].split("\n")
        start = max(1, min(lines) - EXCERPT_CONTEXT)
        end = min(len(text), max(lines) + EXCERPT_CONTEXT, start + EXCERPT_MAX - 1)
        out[file] = {"start": start, "total_lines": len(text), "lines": text[start - 1 : end]}
    return out


def make_id(name: str, created: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:60] or "scan"
    stamp = re.sub(r"[^0-9]", "", created)[:14]
    return f"{slug}-{stamp[:8]}-{stamp[8:]}"


class ResultStore:
    """A folder of result documents, one JSON file per scan, named by a safe id."""

    def __init__(self, directory: Path = DEFAULT_DIR) -> None:
        self.directory = directory

    def save(self, document: dict[str, Any]) -> str:
        base = make_id(document["name"], document["created"])
        result_id, n = base, 1
        while (self.directory / f"{result_id}.json").exists():
            n += 1
            result_id = f"{base}-{n}"
        self.directory.mkdir(parents=True, exist_ok=True)
        saved = {**document, "id": result_id}
        temp = self.directory / f".{result_id}.tmp"
        temp.write_text(to_json(saved))
        temp.replace(self.directory / f"{result_id}.json")
        return result_id

    def get(self, result_id: str) -> dict[str, Any] | None:
        if not _ID.fullmatch(result_id):  # never build a path from anything else
            return None
        path = self.directory / f"{result_id}.json"
        try:
            return json.loads(path.read_text())
        except (OSError, ValueError):
            return None

    def summaries(self) -> list[dict[str, Any]]:
        """Short descriptions of every saved scan, newest first."""
        found = []
        for path in self.directory.glob("*.json") if self.directory.is_dir() else []:
            document = self.get(path.stem)
            if document:
                found.append(_summary(document))
        return sorted(found, key=lambda s: s["created"], reverse=True)


def _summary(document: dict[str, Any]) -> dict[str, Any]:
    keys = ("id", "name", "source", "created", "status", "seconds", "cost_usd")
    return {key: document.get(key) for key in keys}


def export_site(store: ResultStore, out_dir: Path, ids: list[str] | None = None) -> list[str]:
    """Write the page and saved results as plain files that any static host can serve."""
    chosen = [s for s in store.summaries() if ids is None or s["id"] in ids]
    results = out_dir / "results"
    results.mkdir(parents=True, exist_ok=True)
    for summary in chosen:
        document = store.get(summary["id"])
        (results / f"{summary['id']}.json").write_text(to_json(document or {}))
    (results / "index.json").write_text(json.dumps(chosen, indent=2))
    shutil.copyfile(SITE_PAGE, out_dir / "index.html")
    return [s["id"] for s in chosen]
