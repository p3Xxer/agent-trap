"""SARIF 2.1.0 output, the format GitHub reads to show a warning on a line of a pull request.

GitHub requires every result to have a location. A finding that names no line is kept only when
it is serious (a leak or a destructive command): it is anchored to the file most likely to run
at install time, with a note saying the anchor is not the cause. Lesser findings without a line
are left out; they still appear in the report and the run summary.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from agenttrap import __version__
from agenttrap.findings import RULES, Finding, Location
from agenttrap.scan import ScanResult

SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
INFO_URI = "https://github.com/p3Xxer/agent-trap"
ANCHORS = ("setup.py", "pyproject.toml", "package.json", "Makefile", "README.md")
MAX_LOCATIONS = 10  # GitHub reads at most this many per result
ANCHOR_NOTE = " (Agent Trap could not name the line; this file is only an anchor, not the cause.)"


def anchor_file(repo: Path) -> str | None:
    return next((name for name in ANCHORS if (repo / name).is_file()), None)


def to_sarif(findings: list[Finding], anchor: str | None = None) -> dict[str, Any]:
    return {
        "$schema": SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Agent Trap",
                        "version": __version__,
                        "informationUri": INFO_URI,
                        "rules": [_rule(rule_id) for rule_id in RULES],
                    }
                },
                "results": [r for f in findings if (r := _result(f, anchor))],
            }
        ],
    }


def write_sarif(result: ScanResult, findings: list[Finding], path: Path) -> None:
    path.write_text(json.dumps(to_sarif(findings, anchor_file(Path(result.repo))), indent=2))


def _rule(rule_id: str) -> dict[str, Any]:
    name, description, level, severity = RULES[rule_id]
    return {
        "id": rule_id,
        "name": name,
        "shortDescription": {"text": name},
        "fullDescription": {"text": description},
        "defaultConfiguration": {"level": level},
        "helpUri": INFO_URI,
        "properties": {"tags": ["security"], "security-severity": severity},
    }


def _result(finding: Finding, anchor: str | None) -> dict[str, Any] | None:
    locations, message = list(finding.locations[:MAX_LOCATIONS]), finding.message
    if not locations:
        if finding.level != "error" or not anchor:
            return None
        locations, message = [Location(anchor, 1)], message + ANCHOR_NOTE
    result: dict[str, Any] = {
        "ruleId": finding.rule,
        "level": finding.level,
        "message": {"text": message},
        "locations": [_location(loc) for loc in locations],
    }
    if finding.related:
        result["relatedLocations"] = [
            {**_location(loc), "id": i, "message": {"text": "also needed for this to happen"}}
            for i, loc in enumerate(finding.related[:MAX_LOCATIONS], 1)
        ]
    return result


def _location(loc: Location) -> dict[str, Any]:
    region: dict[str, Any] = {"startLine": max(loc.line, 1)}
    if loc.text.strip():
        region["snippet"] = {"text": loc.text}
    return {
        "physicalLocation": {
            "artifactLocation": {"uri": Path(loc.file).as_posix(), "uriBaseId": "%SRCROOT%"},
            "region": region,
        }
    }
