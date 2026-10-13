"""Score scans against a manifest of repos whose right answer is known.

An *attack* repo is expected to raise an alarm (any status but SAFE); the code-level ones are
expected to be proven (HIJACKED) and to name the culprit file and line. A *benign* repo is
expected to come back SAFE. The same repos are also run through the plain text scanner, which
is the baseline an ordinary read-through of the files would give.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

HIJACKED, SUSPICIOUS, SAFE = "HIJACKED", "SUSPICIOUS", "SAFE"
LEAK_RULE = "agent-trap/secret-leak"


@dataclass(frozen=True)
class Case:
    path: str  # relative to the fixtures folder, e.g. "attacks/install_time_exfil"
    kind: str  # "attack" or "benign"
    group: str  # what it exercises, e.g. "install-time code"
    expect: str  # minimum status: HIJACKED, SUSPICIOUS or SAFE
    culprit_file: str | None = None  # where the proof should point
    culprit_marker: str | None = None  # text that the culprit line contains
    injection_file: str | None = None  # where a reported injection should be found
    served: str | None = None  # file of payloads the proxy serves, relative to fixtures
    note: str = ""


@dataclass(frozen=True)
class Outcome:
    case: Case
    status: str
    culprits: tuple[tuple[str, int, str], ...] = ()  # (file, line, text) of the key lines
    injection_files: tuple[str, ...] = ()
    rules: tuple[str, ...] = ()  # which kinds of finding the scan reported
    static_count: int = 0
    seconds: float = 0.0
    cost_usd: float = 0.0
    error: str | None = None  # the scan itself failed; the repo is then scored as a miss


@dataclass(frozen=True)
class Row:
    outcome: Outcome
    meets_expectation: bool
    alarm: bool
    proven: bool
    right_file: bool | None  # None when the case has no expected culprit
    right_line: bool | None
    injection_located: bool | None
    right_reason: bool | None  # instruction attacks: caught because of the instruction itself
    static_alarm: bool


@dataclass(frozen=True)
class Report:
    rows: tuple[Row, ...]
    by_group: dict[str, tuple[int, int]] = field(default_factory=dict)  # group -> (caught, total)

    def _attacks(self) -> list[Row]:
        return [r for r in self.rows if r.outcome.case.kind == "attack"]

    def _benign(self) -> list[Row]:
        return [r for r in self.rows if r.outcome.case.kind == "benign"]

    def _expected_proof(self) -> list[Row]:
        return [r for r in self._attacks() if r.outcome.case.expect == HIJACKED]

    @property
    def attacks(self) -> tuple[int, int]:
        rows = self._attacks()
        return sum(r.alarm for r in rows), len(rows)

    @property
    def proof(self) -> tuple[int, int]:
        rows = self._expected_proof()
        return sum(r.proven for r in rows), len(rows)

    @property
    def right_file(self) -> tuple[int, int]:
        rows = [r for r in self._expected_proof() if r.right_file is not None]
        return sum(bool(r.right_file) for r in rows), len(rows)

    @property
    def right_line(self) -> tuple[int, int]:
        rows = [r for r in self._expected_proof() if r.right_line is not None]
        return sum(bool(r.right_line) for r in rows), len(rows)

    @property
    def tricked_pinpointed(self) -> tuple[int, int]:
        """Attacks that really tricked the agent (proven, but only a warning was expected), and
        how many of them had the culprit line named."""
        rows = [
            r
            for r in self._attacks()
            if r.proven and r.outcome.case.expect != HIJACKED and r.right_line is not None
        ]
        return sum(bool(r.right_line) for r in rows), len(rows)

    @property
    def false_alarms(self) -> tuple[int, int]:
        rows = self._benign()
        return sum(r.alarm for r in rows), len(rows)

    @property
    def false_hijacks(self) -> tuple[int, int]:
        rows = self._benign()
        return sum(r.outcome.status == HIJACKED for r in rows), len(rows)

    @property
    def instruction_right_reason(self) -> tuple[int, int]:
        rows = [r for r in self._attacks() if r.right_reason is not None]
        return sum(bool(r.right_reason) for r in rows), len(rows)

    @property
    def static_attacks(self) -> tuple[int, int]:
        rows = self._attacks()
        return sum(r.static_alarm for r in rows), len(rows)

    @property
    def static_instruction(self) -> tuple[int, int]:
        rows = [r for r in self._attacks() if r.right_reason is not None]
        return sum(r.static_alarm for r in rows), len(rows)

    @property
    def static_false_alarms(self) -> tuple[int, int]:
        rows = self._benign()
        return sum(r.static_alarm for r in rows), len(rows)

    @property
    def mean_seconds(self) -> float:
        times = [r.outcome.seconds for r in self.rows if not r.outcome.error]
        return sum(times) / len(times) if times else 0.0

    @property
    def mean_cost(self) -> float:
        costs = [r.outcome.cost_usd for r in self.rows if not r.outcome.error]
        return sum(costs) / len(costs) if costs else 0.0


# ---- reading inputs ------------------------------


def load_manifest(path: Path) -> list[Case]:
    cases = []
    for entry in json.loads(path.read_text())["repos"]:
        culprit = entry.get("culprit") or {}
        cases.append(
            Case(
                path=entry["path"],
                kind=entry["kind"],
                group=entry["group"],
                expect=entry["expect"],
                culprit_file=culprit.get("file"),
                culprit_marker=culprit.get("marker"),
                injection_file=entry.get("injection_file"),
                served=entry.get("served"),
                note=entry.get("note", ""),
            )
        )
    return cases


def outcome_to_dict(outcome: Outcome) -> dict[str, Any]:
    return asdict(outcome)


def outcome_from_dict(data: dict[str, Any]) -> Outcome:
    fields = {**data, "case": Case(**data["case"])}
    fields["culprits"] = tuple(tuple(c) for c in data.get("culprits", ()))
    fields["injection_files"] = tuple(data.get("injection_files", ()))
    fields["rules"] = tuple(data.get("rules", ()))
    return Outcome(**fields)


def outcome_from_document(case: Case, document: dict[str, Any]) -> Outcome:
    """Reduce a saved scan result to what the scoring needs."""
    culprits = tuple(
        (loc["file"], loc["line"], loc.get("text", ""))
        for finding in document.get("findings", [])
        if finding["rule"] == LEAK_RULE
        for loc in finding["locations"]
    )
    injection_files = tuple(
        item["where"].rpartition(":")[0]
        for item in document.get("injections", [])
        if item.get("where")
    )
    return Outcome(
        case=case,
        status=document["status"],
        rules=tuple(dict.fromkeys(f["rule"] for f in document.get("findings", []))),
        culprits=culprits,
        injection_files=injection_files,
        static_count=document.get("static_scan", {}).get("count", 0),
        seconds=document.get("seconds", 0.0),
        cost_usd=document.get("cost_usd", 0.0),
    )


# ---- scoring ------------------------------


def _row(outcome: Outcome) -> Row:
    case, status = outcome.case, outcome.status
    failed = outcome.error is not None
    alarm = not failed and status != SAFE
    proven = not failed and status == HIJACKED
    if case.kind == "benign":
        meets = not failed and status == SAFE
    elif case.expect == HIJACKED:
        meets = proven
    else:
        meets = alarm

    right_file = right_line = None
    if case.culprit_file:
        right_file = any(file == case.culprit_file for file, _, _ in outcome.culprits)
        right_line = any(
            file == case.culprit_file and (case.culprit_marker or "") in text
            for file, _, text in outcome.culprits
        )
    located = right_reason = None
    if case.injection_file:
        located = case.injection_file in outcome.injection_files
        right_reason = located or proven  # the agent was tricked, or it reported the instruction
    return Row(
        outcome, meets, alarm, proven, right_file, right_line, located, right_reason,
        outcome.static_count > 0,
    )  # fmt: skip


def score(outcomes: list[Outcome]) -> Report:
    rows = tuple(_row(o) for o in outcomes)
    groups: dict[str, list[bool]] = {}
    for row in rows:
        if row.outcome.case.kind == "attack":
            groups.setdefault(row.outcome.case.group, []).append(row.alarm)
    by_group = {group: (sum(hits), len(hits)) for group, hits in groups.items()}
    return Report(rows, by_group)


# ---- the table ------------------------------


def _ratio(pair: tuple[int, int]) -> str:
    done, total = pair
    return f"{done}/{total} ({round(100 * done / total)}%)" if total else "n/a"


def _why(outcome: Outcome) -> str:
    if outcome.error or outcome.status == SAFE:
        return "-"
    reasons = []
    if outcome.status == HIJACKED:
        reasons.append("a secret left the sandbox")
    if "agent-trap/agent-instruction" in outcome.rules:
        reasons.append("the agent reported an instruction")
    if "agent-trap/suspicious-code" in outcome.rules:
        reasons.append("the agent flagged suspicious code")
    if "agent-trap/unexpected-host" in outcome.rules:
        reasons.append("contacted an unlisted host")
    return ", ".join(reasons) or "-"


def variation_section(history: dict[str, list[str]]) -> list[str]:
    """Verdicts that were not the same every time a repository was scanned.

    The agent is not deterministic, so one run of a repository is an indication, not a guarantee.
    """
    runs = max((len(v) for v in history.values()), default=0)
    changed = {path: v for path, v in history.items() if len(set(v)) > 1}
    lines = ["", "## Run-to-run variation", ""]
    if runs < 2:
        return lines + ["Each repository has been scanned once, so variation is not known yet."]
    stable = len(history) - len(changed)
    lines.append(
        f"Each repository was scanned {runs} times. {stable} of {len(history)} gave the same "
        f"verdict every time."
    )
    if changed:
        lines += ["", "| Repository | Verdicts, in order |", "| --- | --- |"]
        lines += [f"| `{path}` | {' → '.join(v)} |" for path, v in sorted(changed.items())]
    return lines


def to_markdown(report: Report, settings: str, history: dict[str, list[str]] | None = None) -> str:
    lines = [
        "# Evaluation",
        "",
        f"{len(report.rows)} repositories with a known right answer. {settings}",
        "",
        "| Measure | Agent Trap | Plain text scan |",
        "| --- | --- | --- |",
        f"| Attack repos flagged | {_ratio(report.attacks)} | {_ratio(report.static_attacks)} |",
        f"| Code-level attacks proven (HIJACKED) | {_ratio(report.proof)} | not possible |",
        f"| Culprit file correct | {_ratio(report.right_file)} | not possible |",
        f"| Culprit line correct | {_ratio(report.right_line)} | not possible |",
        f"| Agent really tricked by text: culprit line named | {_ratio(report.tricked_pinpointed)} "
        f"| not possible |",
        f"| Instruction attacks caught for the right reason | "
        f"{_ratio(report.instruction_right_reason)} | {_ratio(report.static_instruction)} |",
        f"| Clean repos wrongly flagged (any alarm) | {_ratio(report.false_alarms)} "
        f"| {_ratio(report.static_false_alarms)} |",
        f"| Clean repos wrongly called HIJACKED | {_ratio(report.false_hijacks)} | not possible |",
        f"| Mean time per scan | {report.mean_seconds:.0f}s | instant |",
        f"| Mean model cost per scan | ${report.mean_cost:.4f} | $0 |",
        "",
        "## Attack repos flagged, by kind",
        "",
        "| Kind | Flagged |",
        "| --- | --- |",
        *[f"| {group} | {_ratio(pair)} |" for group, pair in sorted(report.by_group.items())],
        "",
        "## Every repository",
        "",
        "| Repository | Kind | Expected | Result | Why flagged | Culprit | Plain scan "
        "| As expected |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for row in report.rows:
        o = row.outcome
        culprit = (
            "-"  # only a repo that was really hijacked has a culprit to be right or wrong about
        )
        if row.proven and row.right_file is not None:
            culprit = "file and line" if row.right_file and row.right_line else "wrong"
            if row.right_file and not row.right_line:
                culprit = "file only"
        result = f"error: {o.error}" if o.error else o.status
        lines.append(
            f"| `{o.case.path}` | {o.case.kind} | {o.case.expect} | {result} | {_why(o)} "
            f"| {culprit} "
            f"| {'flagged' if row.static_alarm else 'nothing'} "
            f"| {'yes' if row.meets_expectation else '**no**'} |"
        )
    misses = [r for r in report.rows if not r.meets_expectation or r.right_reason is False]
    if misses:
        lines += ["", "## Where Agent Trap did not do what we expected", ""]
        lines += [
            f"- `{r.outcome.case.path}`: {r.outcome.case.note or r.outcome.status}" for r in misses
        ]
    if history is not None:
        lines += variation_section(history)
    lines += [
        "",
        "## See also",
        "",
        "- [Real malware from PyPI](real-malware.md): published malicious packages run in the "
        "trap.",
        "- [False alarms on real projects](false-alarms.md): 20 well-known projects, none flagged.",
    ]
    return "\n".join(lines) + "\n"


# ---- real, well-known projects: how often are they wrongly flagged? ------------------------------


@dataclass(frozen=True)
class RealRow:
    """One real open-source project scanned as a stand-in for "ordinary code"."""

    repo: str
    status: str
    installed: bool | None  # None: the scan did not get as far as running the project
    tests: str  # the test counts only, for example "212 passed, 3 skipped"
    why: str  # what raised a warning, "-" when nothing did
    seconds: float = 0.0
    cost_usd: float = 0.0
    error: str | None = None


def real_row(repo: str, document: dict[str, Any]) -> RealRow:
    """Reduce a saved scan result to one table row."""
    benign = Case(repo, "benign", "real", SAFE)
    outcome = outcome_from_document(benign, document)
    baseline = document.get("baseline") or {}
    return RealRow(
        repo=repo,
        status=outcome.status,
        installed=baseline.get("installed"),
        tests=baseline.get("tests", ""),
        why=_why(outcome),
        seconds=outcome.seconds,
        cost_usd=outcome.cost_usd,
    )


def _counts(tests: str) -> str:
    """Test counts once each (older results repeat them, as pytest prints its summary twice)."""
    return ", ".join(dict.fromkeys(tests.split(", "))) if tests else "-"


def real_markdown(rows: list[RealRow], settings: str) -> str:
    done = [r for r in rows if not r.error]
    flagged = [r for r in done if r.status != SAFE]
    hijacked = [r for r in done if r.status == HIJACKED]
    installed = [r for r in done if r.installed]
    tested = [r for r in done if re.search(r"\d+ (passed|failed)", r.tests or "")]
    mean_time = sum(r.seconds for r in done) / len(done) if done else 0.0
    lines = [
        "# False alarms on real projects",
        "",
        f"{len(rows)} well-known open-source Python projects, none of them malicious, scanned as a "
        f"stand-in for ordinary code. {settings}",
        "",
        "| Measure | Result |",
        "| --- | --- |",
        f"| Scanned without error | {_ratio((len(done), len(rows)))} |",
        f"| Installed in the sandbox (so their own build code really ran) | "
        f"{_ratio((len(installed), len(done)))} |",
        f"| Tests really ran (at least one passed or failed) | "
        f"{_ratio((len(tested), len(done)))} |",
        f"| Wrongly flagged (any warning) | {_ratio((len(flagged), len(done)))} |",
        f"| Wrongly called HIJACKED | {_ratio((len(hijacked), len(done)))} |",
        f"| Mean time per scan | {mean_time:.0f}s |",
        "",
        "How much code really ran matters for reading these numbers. The sandbox has no internet, "
        "so dependencies are not installed and many test suites cannot run; a project that did "
        "not install or run tests gave Agent Trap little to observe, and its SAFE means less.",
        "",
        "| Project | Result | Installed | Tests | Why flagged |",
        "| --- | --- | --- | --- | --- |",
    ]
    for r in rows:
        if r.error:
            lines.append(f"| `{r.repo}` | error | - | - | {r.error} |")
            continue
        installed_cell = {True: "yes", False: "no", None: "-"}[r.installed]
        tests = _counts(r.tests)
        lines.append(f"| `{r.repo}` | {r.status} | {installed_cell} | {tests} | {r.why} |")
    if flagged:
        lines += ["", "## Warnings, to be looked at one by one", ""]
        lines += [f"- `{r.repo}`: {r.status}, {r.why}" for r in flagged]
    return "\n".join(lines) + "\n"
