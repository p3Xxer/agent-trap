"""Scan well-known open-source projects and report how often Agent Trap wrongly flags them.

    python eval/run_real.py                      # every project in eval/real_repos.json
    python eval/run_real.py --only click         # just the repos whose name contains this

Each project is downloaded with the same checks the web page uses (public GitHub repository, size
and file limits, a time limit, no symlinks), scanned like any other repository, and deleted again.
Saved results hold no code (they are other people's work); the table goes to docs/false-alarms.md.
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agenttrap.evaluation import RealRow, real_markdown, real_row  # noqa: E402
from agenttrap.fetch import FetchError, fetch_repo  # noqa: E402
from agenttrap.llm import LLM  # noqa: E402
from agenttrap.pipeline import full_scan  # noqa: E402
from agenttrap.results import ResultStore, result_document  # noqa: E402

MANIFEST = ROOT / "eval" / "real_repos.json"
RESULTS = ROOT / "eval" / "real_results"
OUTCOMES = ROOT / "eval" / "real_outcomes.json"
TABLE = ROOT / "docs" / "false-alarms.md"


def run_repo(repo: str, *, k: int) -> RealRow:
    try:
        with tempfile.TemporaryDirectory(prefix="agenttrap-real-") as tmp:
            ref, path = fetch_repo(f"https://github.com/{repo}", Path(tmp))
            result = full_scan(path, llm=LLM(), k=k)
            document = result_document(
                result, name=ref.slug, source=f"https://github.com/{ref.slug}", include_code=False
            )
    except FetchError as error:
        return RealRow(repo, "SAFE", None, "", "-", error=str(error))
    except Exception as error:  # noqa: BLE001 - one broken scan must not stop the others
        return RealRow(
            repo, "SAFE", None, "", "-", error=f"{type(error).__name__}: {str(error)[:100]}"
        )
    ResultStore(RESULTS).save(document)
    return real_row(repo, document)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--k", type=int, default=2, help="runs per task")
    parser.add_argument("--workers", type=int, default=2, help="projects scanned at once")
    parser.add_argument("--only", help="only repos whose name contains this text")
    parser.add_argument("--rescore", help="rebuild the table from saved outcomes on this date")
    args = parser.parse_args()

    repos = [
        r for r in json.loads(MANIFEST.read_text())["repos"] if not args.only or args.only in r
    ]
    saved = json.loads(OUTCOMES.read_text()) if OUTCOMES.exists() else {}

    if args.rescore:
        repos = []  # nothing is scanned; the table is rebuilt from what was saved
    started = time.time()
    with ThreadPoolExecutor(args.workers) as pool:
        futures = {pool.submit(run_repo, repo, k=args.k): repo for repo in repos}
        for done, future in enumerate(as_completed(futures), 1):
            row = future.result()
            saved[row.repo] = asdict(row)
            OUTCOMES.write_text(json.dumps(saved, indent=2))
            print(f"[{done}/{len(repos)}] {row.repo:<34} {row.error or row.status:<11} "
                  f"installed={row.installed} tests={row.tests or '-'}", flush=True)  # fmt: skip

    everything = [r for r in json.loads(MANIFEST.read_text())["repos"] if r in saved]
    rows = [RealRow(**saved[r]) for r in everything]
    when = args.rescore or date.today()
    settings = f"{args.k} runs per task plus the install-and-test run. Run on {when}."
    TABLE.write_text(real_markdown(rows, settings))
    print(f"\nscanned {len(repos)} projects in {time.time() - started:.0f}s; table: {TABLE}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
