"""The verdict is announced as soon as it is known, before the slow search for the culprit lines."""

from agenttrap import scan
from agenttrap.agent import Trace
from agenttrap.detector import Leak, Request, Status
from agenttrap.egress import Observed

CANARY = "~/.aws/credentials"
LEAK = Leak(CANARY, "https://x.test/", Request("POST", "https://x.test/"))


class FakeLLM:
    def status(self):
        return {"cost_usd": 0.25}


def run_result(task, leaks=()):
    return scan.RunResult(task, Trace(task=task), Observed((), ()), tuple(leaks))


def detonation_free(monkeypatch, events, leaks):
    monkeypatch.setattr(scan.sandbox, "ensure_ready", lambda: None)
    monkeypatch.setattr(scan, "run_baseline", lambda repo, served: run_result("baseline", leaks))
    monkeypatch.setattr(scan, "run_once", lambda *a, **k: run_result("task"))

    def localize(files, run, name, served, **options):
        events.append("localizing")
        return [], "stub"

    monkeypatch.setattr(scan, "localize_leak", localize)


def test_the_callback_runs_once_before_the_culprit_search_starts(tmp_path, monkeypatch):
    (tmp_path / "setup.py").write_text("x = 1\n")
    events = []
    detonation_free(monkeypatch, events, [LEAK])

    def heard(result):
        events.append(("verdict", result.verdict.status, dict(result.culprits)))

    result = scan.scan(tmp_path, llm=FakeLLM(), k=1, tasks=("setup",), on_verdict=heard)
    assert events == [("verdict", Status.HIJACKED, {}), "localizing"]
    assert result.unlocalized == {CANARY: "stub"}  # the search still ran and filled the result in
    assert result.cost_usd == 0.25


def test_the_callback_defaults_to_doing_nothing(tmp_path, monkeypatch):
    (tmp_path / "setup.py").write_text("x = 1\n")
    detonation_free(monkeypatch, [], [])
    result = scan.scan(tmp_path, llm=FakeLLM(), k=1, tasks=("setup",))
    assert result.verdict.status is Status.SAFE


def test_the_full_pipeline_hands_the_callback_to_the_first_scan_only(tmp_path, monkeypatch):
    from agenttrap import pipeline

    seen = []
    monkeypatch.setattr(pipeline, "lookup", lambda hosts, key: {})
    monkeypatch.setattr(pipeline, "suspect_hosts", lambda result: [])
    monkeypatch.setattr(pipeline, "api_key", lambda: None)

    def clean(repo, result, out_dir, **options):
        seen.append(options)

    monkeypatch.setattr(pipeline, "clean_and_rescan", clean)
    result = scan.ScanResult("/r", scan.judge([]), [], culprits={"a": ["x"]})
    monkeypatch.setattr(pipeline, "scan", lambda repo, **options: seen.append(options) or result)
    heard = []
    pipeline.full_scan(tmp_path, llm=None, clean_dir=tmp_path / "c", on_verdict=heard.append)
    assert "on_verdict" in seen[0] and "on_verdict" not in seen[1]
