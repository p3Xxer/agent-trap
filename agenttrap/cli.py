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
from agenttrap.scan import clean_and_rescan, scan, suspect_hosts, to_json

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
        "--clean",
        type=Path,
        metavar="OUT_DIR",
        help="if HIJACKED, write a copy of the repo without the culprit code to OUT_DIR "
        "(must not exist or be empty) and scan the copy",
    )
    args = parser.parse_args(argv)

    repo = args.repo.resolve()
    if not repo.is_dir():
        parser.error(f"{repo} is not a directory")
    served = json.loads(args.served.read_text()) if args.served else {}
    if args.clean and args.clean.exists() and any(args.clean.iterdir()):
        parser.error(f"{args.clean} already exists and is not empty")
    options = dict(llm=LLM(), model=args.model, k=args.k, tasks=tuple(args.tasks), served=served)

    console = Console(stderr=True)
    with console.status("starting") as status:
        result = scan(repo, **options, progress=status.update)
        status.update("looking up flagged hosts")
        result.intel = lookup(suspect_hosts(result), key=api_key())
        if args.clean and result.culprits:
            status.update("cleaning the repo and scanning the copy")
            result.cleaned = clean_and_rescan(repo, result, args.clean, **options)
    render(result, Console())
    if args.json_out:
        args.json_out.write_text(to_json(result))
    return EXIT_CODE[result.verdict.status]


if __name__ == "__main__":
    sys.exit(main())
