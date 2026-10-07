"""`agenttrap scan <repo>`."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from rich.console import Console

from agenttrap.agent import TASKS
from agenttrap.detector import Status
from agenttrap.intel import api_key, lookup
from agenttrap.llm import LLM
from agenttrap.reporter import render
from agenttrap.scan import scan, suspect_hosts, to_json

EXIT_CODE = {Status.SAFE: 0, Status.SUSPICIOUS: 0, Status.HIJACKED: 1}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="agenttrap", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser(
        "scan", help="detonate a repo in a sandbox and report whether it hijacks an agent"
    )
    p.add_argument("repo", type=Path)
    p.add_argument("--k", type=int, default=2, help="runs per task (agents are not deterministic)")
    p.add_argument("--model", choices=["nano", "super", "ultra"], default="nano")
    p.add_argument("--tasks", nargs="+", choices=list(TASKS), default=list(TASKS))
    p.add_argument("--served", type=Path, help="JSON file: http URL -> body the sinkhole serves")
    p.add_argument("--json", type=Path, dest="json_out", help="also write the result as JSON")
    p.add_argument(
        "--lookup",
        action="store_true",
        help="look up flagged hosts on the public web (sends only host names; uses TAVILY_API_KEY)",
    )
    args = parser.parse_args(argv)

    repo = args.repo.resolve()
    if not repo.is_dir():
        parser.error(f"{repo} is not a directory")
    served = json.loads(args.served.read_text()) if args.served else {}

    console = Console(stderr=True)
    with console.status("starting") as status:
        result = scan(
            repo,
            llm=LLM(),
            model=args.model,
            k=args.k,
            tasks=tuple(args.tasks),
            served=served,
            progress=lambda message: status.update(message),
        )
        if args.lookup:
            status.update("looking up flagged hosts")
            result.intel = lookup(suspect_hosts(result), key=api_key())
    render(result, Console())
    if args.json_out:
        args.json_out.write_text(to_json(result))
    return EXIT_CODE[result.verdict.status]


if __name__ == "__main__":
    sys.exit(main())
