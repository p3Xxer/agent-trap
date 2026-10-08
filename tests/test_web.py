import json
import threading
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from agenttrap.fetch import FetchError
from agenttrap.results import ResultStore
from agenttrap.web.server import create_app, discover_demos

HOST = "http://127.0.0.1:8765"
GUARD = {"X-Agenttrap": "1"}
DOC = {
    "name": "demo",
    "created": "2026-10-07T14:30:05+00:00",
    "status": "SAFE",
    "seconds": 1.0,
    "cost_usd": 0.01,
}


def sse(text):
    """Parse a server-sent event stream into a list of (event, data)."""
    events = []
    for block in text.strip().split("\n\n"):
        lines = [line for line in block.splitlines() if not line.startswith(":")]
        if lines:
            name = lines[0].removeprefix("event: ")
            events.append((name, json.loads(lines[1].removeprefix("data: "))))
    return events


@pytest.fixture
def store(tmp_path):
    store = ResultStore(tmp_path / "results")
    store.save(DOC)
    return store


def make_client(store, work, demos=None):
    app = create_app(store, work=work, demos={"attacks/x": Path("/x")} if demos is None else demos)
    return TestClient(app, base_url=HOST)


def quick_work(request, progress):
    progress("one")
    progress("two")
    return "result-1"


@pytest.fixture
def client(store):
    return make_client(store, quick_work)


def finish(client, job):
    return sse(client.get(f"/api/jobs/{job}/events").text)


# ---- pages and data ------------------------------


def test_the_page_is_served_and_not_cached(client):
    response = client.get("/")
    assert response.status_code == 200 and "Agent Trap" in response.text
    assert response.headers["cache-control"] == "no-store"


def test_config_lists_the_demos_and_limits(client):
    config = client.get("/api/config").json()
    assert config["live"] is True and config["demos"] == ["attacks/x"]
    assert config["limits"]["max_repo_mb"] > 0 and config["limits"]["max_files"] > 0


def test_results_are_listed_and_fetched(client, store):
    [summary] = client.get("/api/results").json()
    assert summary["name"] == "demo"
    assert client.get(f"/api/results/{summary['id']}").json()["status"] == "SAFE"


@pytest.mark.parametrize(
    "path", ["missing", "..%2Fsecret", "%2e%2e%2f%2e%2e%2fetc%2fpasswd", "a%00b"]
)
def test_unknown_or_dangerous_result_ids_are_404(client, path):
    assert client.get(f"/api/results/{path}").status_code == 404


def test_the_api_docs_pages_are_not_exposed(client):
    assert client.get("/docs").status_code == 404
    assert client.get("/openapi.json").status_code == 404


# ---- who may talk to the server ------------------------------


@pytest.mark.parametrize(
    "host", ["evil.com", "evil.com:8765", "127.0.0.1.evil.com", "192.168.1.5:8765"]
)
def test_requests_for_other_host_names_are_refused(client, host):
    assert client.get("/api/results", headers={"Host": host}).status_code == 403
    assert client.get("/", headers={"Host": host}).status_code == 403


def test_localhost_by_name_works_too(store):
    client = TestClient(make_client(store, quick_work).app, base_url="http://localhost:8765")
    assert client.get("/api/results").status_code == 200


def test_a_post_without_our_header_is_refused(client):
    response = client.post("/api/scan", json={"demo": "attacks/x"})
    assert response.status_code == 403


@pytest.mark.parametrize("origin", ["http://evil.com", "https://127.0.0.1.evil.com", "null"])
def test_a_post_from_another_site_is_refused(client, origin):
    response = client.post(
        "/api/scan", json={"demo": "attacks/x"}, headers={**GUARD, "Origin": origin}
    )
    assert response.status_code == 403


@pytest.mark.parametrize("origin", ["http://127.0.0.1:8765", "http://localhost:8765"])
def test_a_post_from_our_own_page_is_accepted(client, origin):
    response = client.post(
        "/api/scan", json={"demo": "attacks/x"}, headers={**GUARD, "Origin": origin}
    )
    assert response.status_code == 200
    finish(client, response.json()["job"])


# ---- starting a scan ------------------------------


def post(client, body):
    return client.post("/api/scan", json=body, headers=GUARD)


def test_nothing_to_scan_is_a_clear_error(client):
    response = post(client, {})
    assert response.status_code == 400 and "GitHub URL" in response.json()["error"]


@pytest.mark.parametrize("url", ["", "hello", "https://evil.com/a/b", "file:///etc/passwd"])
def test_a_bad_url_is_refused_before_any_work_starts(store, url):
    started = []
    client = make_client(store, lambda request, progress: started.append(request) or "id")
    response = post(client, {"url": url})
    assert response.status_code == 400 and response.json()["error"]
    assert started == []


def test_an_unknown_demo_is_refused_and_never_becomes_a_path(client):
    for demo in ("attacks/missing", "../../etc", "/etc/passwd"):
        assert post(client, {"demo": demo}).status_code == 400


def test_a_scan_streams_progress_then_the_result(client):
    job = post(client, {"url": "https://github.com/octocat/Hello-World"}).json()["job"]
    events = finish(client, job)
    assert [(name, data.get("message") or data.get("result")) for name, data in events] == [
        ("progress", "one"),
        ("progress", "two"),
        ("done", "result-1"),
    ]


def test_the_request_the_job_receives_is_what_was_asked(store):
    seen = []

    def work(request, progress):
        seen.append((request.kind, request.value))
        return "r"

    client = make_client(store, work)
    finish(client, post(client, {"demo": "attacks/x"}).json()["job"])
    finish(client, post(client, {"url": "github.com/octocat/Hello-World"}).json()["job"])
    assert seen == [("demo", "attacks/x"), ("url", "github.com/octocat/Hello-World")]


def test_only_one_scan_runs_at_a_time(store):
    release, started = threading.Event(), threading.Event()

    def slow(request, progress):
        started.set()
        release.wait(5)
        return "r"

    client = make_client(store, slow)
    first = post(client, {"demo": "attacks/x"})
    assert first.status_code == 200
    assert started.wait(5)
    busy = post(client, {"demo": "attacks/x"})
    assert busy.status_code == 409 and "already running" in busy.json()["error"]
    release.set()
    finish(client, first.json()["job"])
    assert post(client, {"demo": "attacks/x"}).status_code == 200  # free again


def test_a_user_facing_error_is_passed_on(store):
    def fails(request, progress):
        raise FetchError("octocat/missing was not found. It may be private or misspelled.")

    client = make_client(store, fails)
    events = finish(client, post(client, {"demo": "attacks/x"}).json()["job"])
    assert events == [
        (
            "error",
            {
                "event": "error",
                "message": "octocat/missing was not found. It may be private or misspelled.",
            },
        )
    ]


def test_an_unexpected_error_does_not_leak_its_details_and_frees_the_lock(store):
    def crashes(request, progress):
        raise RuntimeError("secret internals: /Users/someone/key")

    client = make_client(store, crashes)
    events = finish(client, post(client, {"demo": "attacks/x"}).json()["job"])
    [(name, data)] = events
    assert name == "error" and "secret internals" not in json.dumps(data)
    assert post(client, {"demo": "attacks/x"}).status_code == 200


def test_an_unknown_job_is_404(client):
    assert client.get("/api/jobs/nope/events").status_code == 404


# ---- finding our own demo repositories ------------------------------


def test_demos_are_the_repo_folders_under_attacks_and_benign(tmp_path):
    for path in ("attacks/a", "attacks/group/b", "benign/c"):
        (tmp_path / path).mkdir(parents=True)
        (tmp_path / path / "README.md").write_text("x")
    (tmp_path / "attacks" / "group" / "NOTICE").write_text("not a repo")
    (tmp_path / "attacks" / "a.served.json").write_text("{}")
    (tmp_path / "elsewhere").mkdir()
    (tmp_path / "elsewhere" / "README.md").write_text("x")
    assert list(discover_demos(tmp_path)) == ["attacks/a", "attacks/group/b", "benign/c"]


def test_no_fixtures_folder_means_no_demos(tmp_path):
    assert discover_demos(tmp_path / "missing") == {}
