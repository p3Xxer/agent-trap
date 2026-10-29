"""Compare Agent Trap with two well-known code scanners, Bandit and Semgrep.

Both tools run with their standard rules (nothing tuned) over every repository in `fixtures/`
and only read the files; no code is executed. A repository counts as flagged when the tool
reports anything on it. One Bandit rule is left out: B101 (`assert` used) fires on every
repository that has a test, so counting it would make Bandit "flag" everything.

    pip install bandit semgrep
    python eval/compare_scanners.py

The Agent Trap numbers come from docs/evaluation.md; this script only measures the two tools.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ATTACKS = [
    "install_time_exfil",
    "install_time_exfil_https",
    "env_secret_exfil",
    "import_time_exfil",
    "test_time_exfil",
    "agentdojo/direct",
    "agentdojo/ignore_previous",
    "agentdojo/system_message",
    "agentdojo/injecagent",
    "agentdojo/important_instructions",
    "sample_multi",
]
CODE_ATTACKS = ATTACKS[:5]  # the other six hide their instructions in text
NOISE = {"B101"}  # Bandit: assert_used


def run(command: list[str]) -> dict:
    done = subprocess.run(command, capture_output=True, text=True, check=False)
    try:
        return json.loads(done.stdout)
    except json.JSONDecodeError:
        sys.exit(f"{command[0]} gave no JSON output:\n{done.stderr[-400:]}")


def bandit_flags(repo: Path) -> bool:
    found = run(["bandit", "-r", str(repo), "-f", "json", "-q"]).get("results", [])
    return any(item["test_id"] not in NOISE for item in found)


def semgrep_flags(repo: Path) -> bool:
    command = ["semgrep", "scan", "--config", "p/python", "--config", "p/security-audit"]
    command += ["--metrics", "off", "--json", "--quiet", str(repo)]
    return bool(run(command).get("results"))


def main() -> None:
    for tool in ("bandit", "semgrep"):
        if not shutil.which(tool):
            sys.exit(f"{tool} is not installed: pip install bandit semgrep")
    attacks = [ROOT / "fixtures/attacks" / name for name in ATTACKS]
    clean = sorted(p for p in (ROOT / "fixtures/benign").iterdir() if p.is_dir())
    tools = {"Bandit": bandit_flags, "Semgrep": semgrep_flags}
    print("| Tool | Attack repos flagged | Code attacks flagged | Clean repos flagged |")
    print("| --- | --- | --- | --- |")
    for name, flags in tools.items():
        hit = {repo: flags(repo) for repo in [*attacks, *clean]}
        total = sum(hit[repo] for repo in attacks)
        code = sum(hit[ROOT / "fixtures/attacks" / n] for n in CODE_ATTACKS)
        wrong = sum(hit[repo] for repo in clean)
        row = [f"{total}/{len(attacks)}", f"{code}/{len(CODE_ATTACKS)}", f"{wrong}/{len(clean)}"]
        print(f"| {name} | " + " | ".join(row) + " |")


if __name__ == "__main__":
    main()
