"""The local web server: serves the page and saved results, and runs scans one at a time.

It is meant to run on the user's own machine and listens on 127.0.0.1 only. A web page the user
happens to open in another tab can still send requests to a local server, so every request is
checked: the `Host` must be a local name (this blocks DNS rebinding), a POST must carry our own
header (a cross-site page cannot add one without a preflight we never grant) and any `Origin`
must be local.
"""

from __future__ import annotations

import asyncio
import json
import logging
import tempfile
import threading
import uuid
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from pydantic import BaseModel

from agenttrap.fetch import MAX_FILES, MAX_REPO_KB, FetchError, fetch_repo, parse_github_url
from agenttrap.llm import LLM
from agenttrap.pipeline import full_scan
from agenttrap.reporter import HEADLINE
from agenttrap.results import ResultStore, result_document

log = logging.getLogger("agenttrap.web")

PAGE = Path(__file__).with_name("index.html")
FIXTURES = Path(__file__).resolve().parents[2] / "fixtures"  # only present in a source checkout
LOCAL_HOSTS = frozenset({"127.0.0.1", "localhost"})
GUARD_HEADER = "x-agenttrap"
JOBS_KEPT = 20
HEARTBEAT_SECONDS = 10


@dataclass(frozen=True)
class ScanRequest:
    kind: str  # "url" or "demo"
    value: str


@dataclass
class Job:
    id: str
    events: list[dict[str, Any]] = field(default_factory=list)
    finished: bool = False

    def emit(self, event: str, **data: Any) -> None:
        self.events.append({"event": event, **data})


Work = Callable[[ScanRequest, Callable[[str], None]], str]  # -> id of the saved result


class JobRunner:
    """Runs one scan at a time, in a background thread, and records its events."""

    def __init__(self, work: Work) -> None:
        self._work = work
        self._lock = threading.Lock()
        self.jobs: dict[str, Job] = {}

    def start(self, request: ScanRequest) -> Job | None:
        """The new job, or None when a scan is already running."""
        if not self._lock.acquire(blocking=False):
            return None
        job = Job(uuid.uuid4().hex[:12])
        self.jobs[job.id] = job
        for old in list(self.jobs)[:-JOBS_KEPT]:
            del self.jobs[old]
        threading.Thread(target=self._run, args=(job, request), daemon=True).start()
        return job

    def _run(self, job: Job, request: ScanRequest) -> None:
        try:
            result_id = self._work(request, lambda message: job.emit("progress", message=message))
            job.emit("done", result=result_id)
        except FetchError as error:
            job.emit("error", message=str(error))
        except Exception:  # noqa: BLE001 - shown to the user as a generic message, logged in full
            log.exception("scan failed")
            job.emit("error", message="The scan failed unexpectedly. See the terminal for details.")
        finally:
            job.finished = True
            self._lock.release()


def discover_demos(fixtures: Path = FIXTURES) -> dict[str, Path]:
    """Our own test repos, by id like `attacks/install_time_exfil`. Empty outside a checkout."""
    markers = ("setup.py", "pyproject.toml", "README.md")
    found = {}
    for kind in ("attacks", "benign"):
        for marker in markers:
            for path in sorted((fixtures / kind).glob(f"**/{marker}")):
                found.setdefault(path.parent.relative_to(fixtures).as_posix(), path.parent)
    return dict(sorted(found.items()))


def default_work(store: ResultStore, demos: dict[str, Path], k: int) -> Work:
    def work(request: ScanRequest, progress: Callable[[str], None]) -> str:
        with tempfile.TemporaryDirectory(prefix="agenttrap-") as tmp:
            workdir = Path(tmp)
            served: dict[str, str] = {}
            if request.kind == "url":
                progress("checking the repository with GitHub")
                (workdir / "repo").mkdir()
                ref, repo = fetch_repo(request.value, workdir / "repo")
                progress(f"downloaded {ref.slug}")
                name, source = ref.slug, f"https://github.com/{ref.slug}"
            else:
                repo, name, source = demos[request.value], request.value, None
                served_file = repo.with_name(f"{repo.name}.served.json")
                served = json.loads(served_file.read_text()) if served_file.exists() else {}
            result = full_scan(
                repo,
                llm=LLM(),
                k=k,
                served=served,
                clean_dir=workdir / "cleaned",
                progress=progress,
                public=source is not None,  # downloaded from a public GitHub link
                on_verdict=lambda r: progress(
                    HEADLINE[r.verdict.status]
                    + (" Finding the exact lines..." if r.verdict.leaks else "")
                ),
            )
            return store.save(result_document(result, name=name, source=source))

    return work


class ScanBody(BaseModel):
    url: str | None = None
    demo: str | None = None


def create_app(
    store: ResultStore,
    *,
    port: int = 8765,
    work: Work | None = None,
    demos: dict[str, Path] | None = None,
    allowed_hosts: frozenset[str] = LOCAL_HOSTS,
    k: int = 1,
) -> FastAPI:
    demos = discover_demos() if demos is None else demos
    runner = JobRunner(work or default_work(store, demos, k))
    app = FastAPI(title="Agent Trap", docs_url=None, redoc_url=None, openapi_url=None)

    @app.middleware("http")
    async def guard(request: Request, call_next: Callable) -> Any:
        host = (request.headers.get("host") or "").rsplit(":", 1)[0].strip("[]")
        if host not in allowed_hosts:
            return JSONResponse({"error": "This server only answers on localhost."}, 403)
        if request.method == "POST":
            origin = request.headers.get("origin")
            if origin is not None and urlparse(origin).hostname not in allowed_hosts:
                return JSONResponse({"error": "Requests from other sites are refused."}, 403)
            if request.headers.get(GUARD_HEADER) != "1":
                return JSONResponse({"error": "Missing the Agent Trap request header."}, 403)
        return await call_next(request)

    @app.get("/")
    def page() -> FileResponse:
        return FileResponse(PAGE, media_type="text/html", headers={"Cache-Control": "no-store"})

    @app.get("/api/config")
    def config() -> dict[str, Any]:
        return {
            "live": True,
            "demos": list(demos),
            "limits": {"max_repo_mb": MAX_REPO_KB // 1000, "max_files": MAX_FILES},
        }

    @app.get("/api/results")
    def results() -> list[dict[str, Any]]:
        return store.summaries()

    @app.get("/api/results/{result_id}")
    def result(result_id: str) -> dict[str, Any]:
        document = store.get(result_id)
        if document is None:
            raise HTTPException(404, "No such result.")
        return document

    @app.post("/api/scan")
    def start_scan(body: ScanBody) -> Any:
        if body.demo is not None:
            if body.demo not in demos:
                return JSONResponse({"error": "Unknown demo repository."}, 400)
            request = ScanRequest("demo", body.demo)
        elif body.url is not None:
            try:
                parse_github_url(body.url)  # fast, offline check; the rest happens in the job
            except FetchError as error:
                return JSONResponse({"error": str(error)}, 400)
            request = ScanRequest("url", body.url)
        else:
            return JSONResponse({"error": "Paste a GitHub URL or pick a demo."}, 400)
        job = runner.start(request)
        if job is None:
            return JSONResponse({"error": "A scan is already running. Wait for it to finish."}, 409)
        return {"job": job.id}

    @app.get("/api/jobs/{job_id}/events")
    async def events(job_id: str) -> StreamingResponse:
        job = runner.jobs.get(job_id)
        if job is None:
            raise HTTPException(404, "No such job.")
        return StreamingResponse(_stream(job), media_type="text/event-stream")

    return app


async def _stream(job: Job) -> AsyncIterator[str]:
    """Server-sent events: every event of the job in order, then the stream ends."""
    sent, idle = 0, 0.0
    while True:
        finished = job.finished  # read first, so an event added right after is not lost
        while sent < len(job.events):
            event = job.events[sent]
            yield f"event: {event['event']}\ndata: {json.dumps(event)}\n\n"
            sent, idle = sent + 1, 0.0
        if finished:
            return
        await asyncio.sleep(0.25)
        idle += 0.25
        if idle >= HEARTBEAT_SECONDS:
            yield ": keep-alive\n\n"
            idle = 0.0
