import json

from agenttrap.detector import Flag, judge
from agenttrap.findings import RULES, Finding, Location, findings
from agenttrap.sarif import MAX_LOCATIONS, anchor_file, to_sarif, write_sarif
from tests.scan_results import (
    hard_flag_result,
    injection,
    intel_for,
    leak,
    leaking_result,
)

FULL = leaking_result(injections=[injection("README.md:11")], intel=intel_for())


def run_of(sarif):
    [run] = sarif["runs"]
    return run


def test_the_document_has_the_shape_github_requires():
    sarif = to_sarif(findings(FULL))
    assert sarif["version"] == "2.1.0"
    assert sarif["$schema"].endswith("sarif-2.1.0.json")
    driver = run_of(sarif)["tool"]["driver"]
    assert driver["name"] == "Agent Trap"
    assert driver["version"]
    for rule in driver["rules"]:
        assert rule["id"] in RULES
        assert rule["shortDescription"]["text"] and rule["fullDescription"]["text"]
        assert rule["defaultConfiguration"]["level"] in ("error", "warning", "note")
        assert float(rule["properties"]["security-severity"]) > 0


def test_every_result_references_a_declared_rule_and_has_a_line():
    sarif = to_sarif(findings(FULL), anchor="setup.py")
    declared = {r["id"] for r in run_of(sarif)["tool"]["driver"]["rules"]}
    results = run_of(sarif)["results"]
    assert results
    for result in results:
        assert result["ruleId"] in declared
        assert result["message"]["text"]
        for location in result["locations"]:
            physical = location["physicalLocation"]
            assert physical["region"]["startLine"] >= 1
            uri = physical["artifactLocation"]["uri"]
            assert not uri.startswith("/") and ".." not in uri
            assert physical["artifactLocation"]["uriBaseId"] == "%SRCROOT%"


def test_a_leak_points_at_its_key_lines_with_the_rest_as_related_locations():
    sarif = to_sarif(findings(leaking_result()))
    [result] = [r for r in run_of(sarif)["results"] if r["ruleId"] == "agent-trap/secret-leak"]
    lines = [loc["physicalLocation"]["region"]["startLine"] for loc in result["locations"]]
    related = [loc["physicalLocation"]["region"]["startLine"] for loc in result["relatedLocations"]]
    assert (lines, related) == ([10, 11], [2, 13])
    assert [loc["id"] for loc in result["relatedLocations"]] == [1, 2]
    assert result["level"] == "error"
    assert "snippet" in result["locations"][0]["physicalLocation"]["region"]


def test_a_serious_finding_without_a_line_is_anchored_with_an_honest_note():
    sarif = to_sarif(findings(hard_flag_result()), anchor="setup.py")
    [result] = run_of(sarif)["results"]
    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "setup.py"
    assert "only an anchor" in result["message"]["text"]


def written_rules(result, anchor="setup.py"):
    sarif = to_sarif(findings(result), anchor=anchor)
    return {r["ruleId"] for r in run_of(sarif)["results"]}


def test_without_an_anchor_a_finding_with_no_line_is_dropped():
    assert written_rules(hard_flag_result(), anchor=None) == set()


def test_serious_findings_without_a_line_are_anchored_but_lesser_ones_are_dropped():
    both = judge([leak()], [Flag("destructive-command", "rm -rf ~", hard=True)])
    result = leaking_result(
        culprits={}, verdict=both, injections=[injection(None)], contacted=["setup-check.io"]
    )
    assert written_rules(result) == {"agent-trap/secret-leak", "agent-trap/destructive-command"}


def test_at_most_ten_locations_are_written():
    many = Finding(
        "agent-trap/secret-leak",
        "m",
        tuple(Location("a.py", n) for n in range(1, 30)),
        tuple(Location("b.py", n) for n in range(1, 30)),
    )
    [result] = run_of(to_sarif([many]))["results"]
    assert len(result["locations"]) == len(result["relatedLocations"]) == MAX_LOCATIONS


def test_the_anchor_is_the_first_install_time_file_that_exists(tmp_path):
    assert anchor_file(tmp_path) is None
    (tmp_path / "README.md").write_text("x")
    assert anchor_file(tmp_path) == "README.md"
    (tmp_path / "setup.py").write_text("x")
    assert anchor_file(tmp_path) == "setup.py"


def test_write_sarif_writes_valid_json_anchored_in_the_scanned_repo(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "pyproject.toml").write_text("x")
    result = hard_flag_result()
    result.repo = str(repo)
    out = tmp_path / "out.sarif"
    write_sarif(result, findings(result), out)
    [sarif_result] = json.loads(out.read_text())["runs"][0]["results"]
    assert sarif_result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == (
        "pyproject.toml"
    )
