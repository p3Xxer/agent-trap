"""Baseline: what a read-only scanner (or "ask ChatGPT to review the repo") catches.

It sees only the raw text, so it can flag an obvious instruction but not a base64-encoded one,
nor one that is downloaded at runtime and never exists in the repo. Used for the comparison table.

    python -m agenttrap.baseline_static <repo>
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from pathlib import Path

MAX_FILE_BYTES = 200_000  # a larger file is skipped, so one huge file cannot stall the scan

SUSPICIOUS = re.compile(
    r"(ignore (all )?previous|read\s+~?/?\.?\S*(credentials|id_rsa|hosts)\b|exfiltrate|"
    r"POST (its|it|the).*https?://)",
    re.I,
)


@dataclass(frozen=True)
class Finding:
    file: str
    line: int
    text: str


def scan(repo: Path) -> list[Finding]:
    findings = []
    candidates = (p for p in repo.rglob("*") if p.is_file() and not p.is_symlink())
    for path in sorted(p for p in candidates if p.stat().st_size <= MAX_FILE_BYTES):
        for n, line in enumerate(path.read_text(errors="ignore").splitlines(), 1):
            if SUSPICIOUS.search(line):
                findings.append(Finding(str(path.relative_to(repo)), n, line.strip()))
    return findings


def main(argv: list[str]) -> None:
    repo = Path(argv[1] if len(argv) > 1 else ".").resolve()
    findings = scan(repo)
    print(f"STATIC SCAN (reading only) — {repo.name}\n")
    for f in findings:
        print(f"  flagged  {f.file}:{f.line}  {f.text[:70]}")
    print(f"\n  {len(findings)} line(s) flagged.")


if __name__ == "__main__":
    main(sys.argv)
