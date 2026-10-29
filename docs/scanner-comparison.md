# Compared with Bandit and Semgrep

Bandit and Semgrep are two well-known code scanners. We ran both, with their standard rules and
nothing tuned, over the same 19 test repositories as the [evaluation](evaluation.md): 11 attacks
and 8 clean repos. They only read the files; no code is executed.

| | Attack repos flagged | Code attacks flagged | README attacks flagged | Clean repos flagged |
| --- | --- | --- | --- | --- |
| **Agent Trap** | **11/11** | **5/5** | **5/5** | 1/8 (SUSPICIOUS), 0/8 MALICIOUS |
| Bandit | 6/11 | 5/5 | 0/5 | 3/8 |
| Semgrep | 4/11 | 4/5 | 0/5 | 1/8 |

"Code attacks" are the five repos that steal from code (at install, import or test time).
"README attacks" are the five that hide an instruction in a README, using published AgentDojo
text. The eleventh repo hides its instructions in base64 and a download.

## What this shows

- **The README attacks contain no code, so a code scanner has nothing to read.** All five came
  back clean from both tools, and Agent Trap flagged all five.
- **On code that steals, Bandit finds the network call, but cannot say whether a secret left.**
  It reports an `urlopen` call. The same warning fires on 3 of the 8 harmless repos, because they
  make ordinary network calls too. Agent Trap shows the request that was actually caught, with the
  planted keys inside it.
- **Semgrep missed the repo that steals when its tests start**, and the base64 one.

## Limits

- These tools find coding mistakes and risky patterns; they were not built to detect malware.
- We used their standard rules. A team could write rules for each attack, and tuned rules would do
  better on these exact repos.
- The repos are our own demo set: simple, readable code. Disguised real malware is harder for a
  code scanner still, but we did not measure that.

One Bandit rule is left out: `B101` (`assert` used) fires on every repository that has a test, so
counting it would make Bandit flag everything.

## Reproduce

```bash
pip install bandit semgrep
python eval/compare_scanners.py
```

Semgrep downloads its standard rule packs (`p/python`, `p/security-audit`) when it runs.
