import json
from pathlib import Path

from agenttrap.evaluation import (
    Case,
    Outcome,
    load_manifest,
    outcome_from_dict,
    outcome_from_document,
    outcome_to_dict,
    score,
    to_markdown,
)

STEALER = Case(
    "attacks/a",
    "attack",
    "install-time",
    "HIJACKED",
    culprit_file="setup.py",
    culprit_marker="evil",
)
INJECTION = Case("attacks/b", "attack", "readme", "SUSPICIOUS", injection_file="README.md")
CLEAN = Case("benign/c", "benign", "clean", "SAFE")
TRICKY = Case("benign/d", "benign", "clean", "SAFE", note="calls its own service")


def outcome(case, status, **fields):
    return Outcome(case, status, **fields)


def rows_by_path(report):
    return {r.outcome.case.path: r for r in report.rows}


# ---- reading a scan result ------------------------------------------


def test_an_outcome_is_read_from_a_saved_result():
    document = {
        "status": "HIJACKED",
        "findings": [
            {
                "rule": "agent-trap/secret-leak",
                "locations": [{"file": "setup.py", "line": 11, "text": "evil()"}],
            },
            {"rule": "agent-trap/unexpected-host", "locations": []},
            {
                "rule": "agent-trap/agent-instruction",
                "locations": [{"file": "README.md", "line": 3}],
            },
        ],
        "injections": [{"where": "README.md:11"}, {"where": None}],
        "static_scan": {"count": 2},
        "seconds": 90.0,
        "cost_usd": 0.01,
    }
    result = outcome_from_document(STEALER, document)
    assert result.status == "HIJACKED"
    assert result.culprits == (("setup.py", 11, "evil()"),)  # only the leak finding counts
    assert result.injection_files == ("README.md",)
    assert (result.static_count, result.seconds, result.cost_usd) == (2, 90.0, 0.01)


def test_the_manifest_is_read(tmp_path):
    manifest = tmp_path / "m.json"
    manifest.write_text(
        json.dumps(
            {
                "repos": [
                    {"path": "attacks/a", "kind": "attack", "group": "g", "expect": "HIJACKED",
                     "culprit": {"file": "setup.py", "marker": "evil"}, "served": "x.json"},
                    {"path": "benign/b", "kind": "benign", "group": "clean", "expect": "SAFE"},
                ]
            }
        )
    )  # fmt: skip
    first, second = load_manifest(manifest)
    assert (first.culprit_file, first.culprit_marker, first.served) == (
        "setup.py",
        "evil",
        "x.json",
    )
    assert second.culprit_file is None and second.note == ""


def test_the_shipped_manifest_points_at_real_fixtures():
    fixtures = Path(__file__).resolve().parent.parent / "fixtures"
    cases = load_manifest(fixtures / "manifest.json")
    assert {c.kind for c in cases} == {"attack", "benign"}
    for case in cases:
        assert (fixtures / case.path).is_dir(), case.path
        if case.served:
            assert (fixtures / case.served).is_file()
        if case.culprit_file:
            assert (fixtures / case.path / case.culprit_file).is_file()


# ---- scoring ------------------------------------------


def test_a_proven_attack_with_the_right_culprit_scores_fully():
    good = outcome(
        STEALER, "HIJACKED", culprits=(("setup.py", 10, "urlopen('evil')"),), static_count=0
    )
    row = rows_by_path(score([good]))["attacks/a"]
    assert (row.alarm, row.proven, row.right_file, row.right_line) == (True, True, True, True)
    assert row.meets_expectation and not row.static_alarm


def test_the_right_file_but_the_wrong_line_is_only_half_right():
    row = rows_by_path(
        score([outcome(STEALER, "HIJACKED", culprits=(("setup.py", 3, "import os"),))])
    )["attacks/a"]
    assert (row.right_file, row.right_line) == (True, False)


def test_a_culprit_in_another_file_is_wrong():
    row = rows_by_path(score([outcome(STEALER, "HIJACKED", culprits=(("other.py", 1, "evil"),))]))[
        "attacks/a"
    ]
    assert (row.right_file, row.right_line) == (False, False)


def test_a_warning_is_not_proof_for_a_code_level_attack():
    row = rows_by_path(score([outcome(STEALER, "SUSPICIOUS")]))["attacks/a"]
    assert row.alarm and not row.proven and not row.meets_expectation


def test_an_instruction_attack_is_met_by_any_alarm_and_located_by_its_file():
    flagged = rows_by_path(
        score([outcome(INJECTION, "SUSPICIOUS", injection_files=("README.md",))])
    )
    assert flagged["attacks/b"].meets_expectation and flagged["attacks/b"].injection_located
    missed = rows_by_path(score([outcome(INJECTION, "SAFE")]))["attacks/b"]
    assert not missed.alarm and not missed.meets_expectation


def test_a_failed_scan_counts_as_a_miss_and_never_as_a_pass():
    broken = [outcome(STEALER, "SAFE", error="docker failed"), outcome(CLEAN, "SAFE", error="boom")]
    report = score(broken)
    assert not any(r.meets_expectation for r in report.rows)
    assert report.mean_seconds == 0.0  # failed scans do not count towards the averages


def test_benign_repos_are_judged_on_false_alarms_and_false_hijacks():
    report = score([
        outcome(CLEAN, "SAFE"), outcome(TRICKY, "SUSPICIOUS", static_count=1),
        outcome(Case("benign/e", "benign", "clean", "SAFE"), "HIJACKED"),
    ])  # fmt: skip
    assert report.false_alarms == (2, 3)
    assert report.false_hijacks == (1, 3)
    assert report.static_false_alarms == (1, 3)


def test_the_headline_numbers():
    other = Case("attacks/a2", "attack", "install-time", "HIJACKED", "setup.py", "evil")
    key = (("setup.py", 10, "evil"),)
    report = score(
        [
            outcome(STEALER, "HIJACKED", culprits=key, seconds=100, cost_usd=0.02),
            outcome(other, "SAFE", seconds=50, cost_usd=0.0),
            outcome(INJECTION, "SUSPICIOUS", static_count=1),
            outcome(CLEAN, "SAFE"),
        ]
    )
    assert report.attacks == (2, 3)
    assert report.proof == (1, 2)
    assert report.right_file == (1, 2) and report.right_line == (1, 2)
    assert report.static_attacks == (1, 3)
    assert report.by_group == {"install-time": (1, 2), "readme": (1, 1)}
    assert report.mean_seconds == 37.5 and round(report.mean_cost, 3) == 0.005


def test_an_empty_report_does_not_divide_by_zero():
    report = score([])
    assert report.attacks == (0, 0) and report.mean_seconds == 0.0
    assert "n/a" in to_markdown(report, "")


# ---- the table ------------------------------------------


def test_the_table_states_results_and_lists_every_miss():
    report = score([
        outcome(STEALER, "HIJACKED", culprits=(("setup.py", 10, "evil"),), seconds=60),
        outcome(INJECTION, "SAFE"),
        outcome(TRICKY, "SUSPICIOUS"),
    ])  # fmt: skip
    text = to_markdown(report, "k=2")
    assert "k=2" in text and "| Attack repos flagged | 1/2 (50%) | 0/2 (0%) |" in text
    assert "| Code-level attacks proven (HIJACKED) | 1/1 (100%) |" in text
    assert (
        "`attacks/a` | attack | HIJACKED | HIJACKED | a secret left the sandbox | file and line"
        in text
    )
    assert "## Where Agent Trap did not do what we expected" in text
    assert "`benign/d`: calls its own service" in text
    assert "| `attacks/b` | attack | SUSPICIOUS | SAFE | - | - | nothing | **no** |" in text


def test_a_clean_run_has_no_misses_section():
    text = to_markdown(score([outcome(CLEAN, "SAFE")]), "")
    assert "did not do what we expected" not in text


def test_an_outcome_survives_being_saved_and_loaded():
    original = outcome(
        STEALER,
        "HIJACKED",
        culprits=(("setup.py", 10, "evil"),),
        injection_files=("README.md",),
        static_count=1,
        seconds=12.5,
        cost_usd=0.01,
    )
    saved = json.loads(json.dumps(outcome_to_dict(original)))
    assert outcome_from_dict(saved) == original
    failed = outcome(CLEAN, "SAFE", error="boom")
    assert outcome_from_dict(json.loads(json.dumps(outcome_to_dict(failed)))) == failed


# ---- why a repo was flagged ---------------------------------------------------------------------


def right_reason(status, **fields):
    return rows_by_path(score([outcome(INJECTION, status, **fields)]))["attacks/b"].right_reason


def test_an_instruction_attack_counts_when_the_agent_reported_the_instruction():
    assert right_reason("SUSPICIOUS", injection_files=("README.md",)) is True


def test_an_instruction_attack_counts_when_the_agent_was_actually_tricked():
    assert right_reason("HIJACKED") is True


def test_flagging_a_repo_for_some_other_reason_is_not_the_right_reason():
    only_a_host = right_reason("SUSPICIOUS", rules=("agent-trap/unexpected-host",))
    elsewhere = right_reason("SUSPICIOUS", injection_files=("docs/other.md",))
    assert only_a_host is False and elsewhere is False
    assert right_reason("SAFE") is False


def test_cases_without_an_expected_injection_have_no_right_reason():
    assert rows_by_path(score([outcome(STEALER, "HIJACKED")]))["attacks/a"].right_reason is None
    assert rows_by_path(score([outcome(CLEAN, "SAFE")]))["benign/c"].right_reason is None


def test_the_table_separates_being_flagged_from_being_flagged_for_the_right_reason():
    other = Case("attacks/b2", "attack", "readme", "SUSPICIOUS", injection_file="R.md")
    report = score(
        [
            outcome(INJECTION, "SUSPICIOUS", rules=("agent-trap/unexpected-host",)),
            outcome(other, "HIJACKED"),
        ]
    )
    assert report.attacks == (2, 2)  # both flagged ...
    assert report.instruction_right_reason == (1, 2)  # ... but only one for the right reason
    text = to_markdown(report, "")
    assert "| Instruction attacks caught for the right reason | 1/2 (50%) |" in text
    assert "| SUSPICIOUS | contacted an unlisted host |" in text
    assert "| HIJACKED | a secret left the sandbox |" in text


def test_every_kind_of_finding_is_named_in_the_why_column():
    rules = ("agent-trap/agent-instruction", "agent-trap/unexpected-host")
    report = score([outcome(INJECTION, "SUSPICIOUS", rules=rules)])
    assert "| the agent reported an instruction, contacted an unlisted host |" in to_markdown(
        report, ""
    )


def test_the_rules_come_from_the_saved_findings_in_order_without_repeats():
    document = {
        "status": "SUSPICIOUS",
        "findings": [
            {"rule": "agent-trap/agent-instruction", "locations": []},
            {"rule": "agent-trap/unexpected-host", "locations": []},
            {"rule": "agent-trap/agent-instruction", "locations": []},
        ],
    }
    result = outcome_from_document(INJECTION, document)
    assert result.rules == ("agent-trap/agent-instruction", "agent-trap/unexpected-host")


def test_an_outcome_saved_before_rules_existed_still_loads():
    old = json.loads(json.dumps(outcome_to_dict(outcome(CLEAN, "SAFE"))))
    del old["rules"]
    assert outcome_from_dict(old).rules == ()


def test_a_repo_flagged_for_the_wrong_reason_is_listed_among_the_misses():
    hidden = Case(
        "attacks/h", "attack", "hidden", "SUSPICIOUS", injection_file="a.md", note="never decoded"
    )
    report = score([outcome(hidden, "SUSPICIOUS", rules=("agent-trap/unexpected-host",))])
    assert report.rows[0].meets_expectation  # it was flagged ...
    assert "- `attacks/h`: never decoded" in to_markdown(
        report, ""
    )  # ... but not for the right reason
