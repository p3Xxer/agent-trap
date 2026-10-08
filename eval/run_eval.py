"""Run every repository in fixtures/manifest.json through Agent Trap and write the results table.

    python eval/run_eval.py                      # everything
    python eval/run_eval.py --only benign/       # just the repos whose path contains this
    python eval/run_eval.py --k 3 --workers 2

Each scan is saved to eval/results/ (the web page can show them), the outcomes to
eval/outcomes.json, and the table to docs/evaluation.md. A run with --only updates just those
repos and re-scores everything saved, so one repo can be repeated without losing the others.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agenttrap.evaluation import (  # noqa: E402
    Case,
    Outcome,
    load_manifest,
    outcome_from_dict,
    outcome_from_document,
    outcome_to_dict,
    score,
    to_markdown,
)
from agenttrap.llm import LLM  # noqa: E402
from agenttrap.pipeline import full_scan  # noqa: E402
from agenttrap.results import ResultStore, result_document  # noqa: E402

FIXTURES = ROOT / "fixtures"
RESULTS = ROOT / "eval" / "results"
OUTCOMES = ROOT / "eval" / "outcomes.json"
HISTORY = ROOT / "eval" / "history.json"  # every verdict a repository has ever received
TABLE = ROOT / "docs" / "evaluation.md"


def run_case(case: Case, *, k: int, model: str) -> Outcome:
    served = json.loads((FIXTURES / case.served).read_text()) if case.served else {}
    try:
        result = full_scan(FIXTURES / case.path, llm=LLM(), model=model, k=k, served=served)
    except Exception as error:  # noqa: BLE001 - one broken scan must not stop the others
        return Outcome(case, "SAFE", error=f"{type(error).__name__}: {str(error)[:120]}")
    document = result_document(result, name=case.path)
    ResultStore(RESULTS).save(document)
    return outcome_from_document(case, document)


def rescore_from_saved_scans(cases: list[Case]) -> dict[str, dict]:
    """The newest saved scan of each repo, read again with today's scoring rules."""
    store = ResultStore(RESULTS)
    newest: dict[str, dict] = {}
    for summary in store.summaries():  # newest first
        newest.setdefault(summary["name"], store.get(summary["id"]))
    return {
        case.path: outcome_to_dict(outcome_from_document(case, newest[case.path]))
        for case in cases
        if case.path in newest
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--k", type=int, default=2, help="runs per task")
    parser.add_argument("--model", default="nano", choices=["nano", "super", "ultra"])
    parser.add_argument("--workers", type=int, default=2, help="repositories scanned at once")
    parser.add_argument("--only", help="only repos whose path contains this text")
    parser.add_argument(
        "--rescore", action="store_true", help="rebuild the table from saved scans, run nothing"
    )
    args = parser.parse_args()

    cases = load_manifest(FIXTURES / "manifest.json")
    chosen = [c for c in cases if not args.only or args.only in c.path]
    saved = json.loads(OUTCOMES.read_text()) if OUTCOMES.exists() else {}
    history = json.loads(HISTORY.read_text()) if HISTORY.exists() else {}

    if args.rescore:
        saved = rescore_from_saved_scans(cases)
        chosen = []
    started = time.time()
    with ThreadPoolExecutor(args.workers) as pool:
        futures = {pool.submit(run_case, c, k=args.k, model=args.model): c for c in chosen}
        for done, future in enumerate(as_completed(futures), 1):
            outcome = future.result()
            saved[outcome.case.path] = outcome_to_dict(outcome)
            history.setdefault(outcome.case.path, []).append(
                outcome.error and "ERROR" or outcome.status
            )
            HISTORY.write_text(json.dumps(history, indent=2) + "\n")
            OUTCOMES.write_text(json.dumps(saved, indent=2))  # keep progress if interrupted
            shown = outcome.error or outcome.status
            print(f"[{done}/{len(chosen)}] {outcome.case.path:<44} {shown:<11} "
                  f"{outcome.seconds:>5.0f}s", flush=True)  # fmt: skip

    outcomes = [outcome_from_dict(saved[c.path]) for c in cases if c.path in saved]
    settings = (
        f"Settings: model {args.model}, {args.k} runs per task plus the install-and-test run. "
        f"Run on {date.today().isoformat()}."
    )
    TABLE.write_text(to_markdown(score(outcomes), settings, history))
    print(f"\nscanned {len(chosen)} repos in {time.time() - started:.0f}s; table: {TABLE}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
