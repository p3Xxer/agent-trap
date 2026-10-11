"""The `agenttrap` command: scan a repo, serve the web page, export saved results."""

from __future__ import annotations

import argparse
import json
import sys
from contextlib import nullcontext
from pathlib import Path

from rich.console import Console

from agenttrap.agent import TASKS
from agenttrap.batch import run_batch
from agenttrap.ci import commands_disabled, emit_github, running_in_github
from agenttrap.detector import Status
from agenttrap.findings import findings
from agenttrap.llm import LLM
from agenttrap.pipeline import full_scan
from agenttrap.reporter import render, render_verdict
from agenttrap.results import DEFAULT_DIR, ResultStore, export_site, result_document, to_json
from agenttrap.sarif import write_sarif
from agenttrap.scan import ScanResult

EXIT_CODE = {Status.SAFE: 0, Status.SUSPICIOUS: 0, Status.HIJACKED: 1}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agenttrap", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser(
        "scan", help="detonate a repo in a sandbox and report whether it hijacks an agent"
    )
    scan.add_argument("repo", type=Path)
    scan.add_argument(
        "--k", type=int, default=2, help="runs per task (agents are not deterministic)"
    )
    scan.add_argument("--model", choices=["nano", "super", "ultra"], default="nano")
    scan.add_argument("--tasks", nargs="+", choices=list(TASKS), default=list(TASKS))
    scan.add_argument("--served", type=Path, help="JSON file: URL -> body the proxy serves")
    scan.add_argument("--json", type=Path, dest="json_out", help="also write the result as JSON")
    scan.add_argument(
        "--sarif",
        type=Path,
        metavar="FILE",
        help="write the findings as SARIF, which GitHub shows as warnings on pull request lines",
    )
    scan.add_argument(
        "--clean",
        type=Path,
        metavar="OUT_DIR",
        help="if HIJACKED, write a copy of the repo without the culprit code to OUT_DIR "
        "(must not exist or be empty) and scan the copy",
    )
    scan.add_argument("--results", type=Path, default=DEFAULT_DIR, help="where results are saved")

    serve = sub.add_parser("serve", help="run the web page on this machine")
    serve.add_argument("--port", type=int, default=8765)
    serve.add_argument("--results", type=Path, default=DEFAULT_DIR, help="saved results folder")

    batch = sub.add_parser(
        "batch", help="scan every project in a folder (for code somebody else wrote)"
    )
    batch.add_argument("folder", type=Path)
    batch.add_argument("--k", type=int, default=2, help="runs per task")
    batch.add_argument("--workers", type=int, default=2, help="projects scanned at once")
    batch.add_argument("--keep-code", action="store_true", help="save code excerpts in the results")
    batch.add_argument("--results", type=Path, default=DEFAULT_DIR, help="where results are saved")

    export = sub.add_parser("export", help="write the page and saved results as static files")
    export.add_argument("out_dir", type=Path)
    export.add_argument("--id", action="append", dest="ids", help="only this result (repeatable)")
    export.add_argument("--results", type=Path, default=DEFAULT_DIR, help="saved results folder")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "serve":
        return _serve(args)
    if args.command == "export":
        return _export(args)
    if args.command == "batch":
        return _batch(args, parser)
    return _scan(args, parser)


def _scan(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    repo = args.repo.resolve()
    if not repo.is_dir():
        parser.error(f"{repo} is not a directory")
    if args.clean and args.clean.exists() and any(args.clean.iterdir()):
        parser.error(f"{args.clean} already exists and is not empty")
    served = json.loads(args.served.read_text()) if args.served else {}

    console = Console(stderr=True)

    def verdict_known(result: ScanResult) -> None:
        render_verdict(result, console)
        if result.verdict.leaks:
            console.print("[dim]pinpointing the culprit lines (this can take a few minutes)...[/]")

    with console.status("starting") as status:
        result = full_scan(
            repo,
            llm=LLM(),
            model=args.model,
            k=args.k,
            tasks=tuple(args.tasks),
            served=served,
            clean_dir=args.clean,
            progress=status.update,
            on_verdict=verdict_known,
        )

    in_github = running_in_github()
    with commands_disabled() if in_github else nullcontext():
        render(result, Console())
    found = findings(result)
    if in_github:  # also inside GitHub Actions: annotations on the lines, and a run summary
        emit_github(result, found)
    if args.sarif:
        write_sarif(result, found, args.sarif)

    document = result_document(result, name=repo.name)
    result_id = ResultStore(args.results).save(document)
    console.print(f"[dim]saved as {result_id} (view it with: agenttrap serve)[/]")
    if args.json_out:
        args.json_out.write_text(to_json({**document, "id": result_id}))
    return EXIT_CODE[result.verdict.status]


def _batch(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    folder = args.folder.resolve()
    if not folder.is_dir():
        parser.error(f"{folder} is not a directory")
    console = Console()
    console.print(
        f"Scanning every project in {folder} inside the sandbox; nothing is installed here."
    )
    items = run_batch(
        folder,
        store=ResultStore(args.results),
        k=args.k,
        workers=args.workers,
        include_code=args.keep_code,
        on_verdict=lambda item: console.print(
            f"  {item.status:<10} {item.name}  (pinpointing culprit lines...)", highlight=False
        ),
        on_done=lambda item: console.print(f"  {item.status:<10} {item.name}", highlight=False),
    )
    counts = {
        s: sum(i.status == s for i in items) for s in ("HIJACKED", "SUSPICIOUS", "SAFE", "ERROR")
    }
    console.print(f"\n{len(items)} projects: " + ", ".join(f"{n} {s}" for s, n in counts.items()))
    console.print("[dim]Results saved; view them with: agenttrap serve[/]")
    return 0


def _serve(args: argparse.Namespace) -> int:
    try:
        import uvicorn

        from agenttrap.web.server import create_app
    except ImportError:
        print("The web page needs extra packages: pip install 'agent-trap[web]'", file=sys.stderr)
        return 2
    app = create_app(ResultStore(args.results), port=args.port)
    print(f"Agent Trap is running at http://127.0.0.1:{args.port}  (Ctrl+C to stop)")
    uvicorn.run(app, host="127.0.0.1", port=args.port, log_level="warning")
    return 0


def _export(args: argparse.Namespace) -> int:
    exported = export_site(ResultStore(args.results), args.out_dir, args.ids)
    print(f"Wrote {len(exported)} result(s) and the page to {args.out_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
