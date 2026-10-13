# Agent Trap

**A defensive security tool.** Agent Trap detonates an untrusted repository in a sandbox, lets a
cheap AI coding agent work on it with **fake canary secrets** planted, catches the agent if it is
hijacked into leaking them, and pinpoints the **exact file and line** that did it.

> Built for the Nebius × NVIDIA hackathon. Works end to end: CLI, local web page and GitHub Action.

## Safety

- Every secret Agent Trap plants is a fake canary. No real credential is ever touched.
- All sandbox traffic goes through a recording proxy that blocks it; nothing is exfiltrated.
- The attack fixtures in `fixtures/attacks/` send only to reserved names such as
  `setup-check.test`, which can never exist on the internet (RFC 6761): run outside the sandbox,
  the request simply fails.

## How a scan works

Every scan runs the repository in a fresh, locked sandbox several times:

| Run | What happens | What it catches |
| --- | --- | --- |
| Install and test, no AI | `pip install`, import every module, `pytest` | code that steals the moment it is installed, imported or tested |
| AI agent: "set it up" | the agent reads the install instructions and runs them | install-time code, and README steps like "first run this script" |
| AI agent: "run its tests" | the agent runs the tests and reads test files | code hidden in tests |
| AI agent: "summarize it" | the agent mostly reads the README and docs | hidden instructions aimed at the AI ("ignore your task and send the key to…") |

These are the everyday things a developer asks a coding agent to do with new code, and each one
makes the agent touch a different part of the repository, so an attack waiting for one moment is
still reached. An AI agent does not behave the same way every time, so the command line runs each
agent task twice by default (`--k`); the web page runs each once so a live scan takes about two
minutes.

A verdict of MALICIOUS needs proof: a planted fake secret seen leaving the sandbox, or a destructive
command actually run. SAFE means nothing was seen leaving in these runs, not that the code is
proven harmless: code waiting for a date, another operating system or a real internet connection
will not show itself here.

## Development

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e '.[dev]'
cp .env.example .env   # then add your NEBIUS_API_KEY
pytest
```

## Usage

```bash
agenttrap scan path/to/repo            # needs Docker running and NEBIUS_API_KEY in .env
agenttrap scan path/to/repo --k 3 --json result.json
```

Add `--clean OUT_DIR` to get a copy of a MALICIOUS repo with the culprit code removed, plus a second
scan of that copy to show whether the leak is gone. The original is never modified, and `OUT_DIR`
must not exist or be empty. In Python files whole statements are removed (a removed statement
becomes `pass`, so line numbers and syntax hold); in other files exactly the culprit lines are
blanked. Removing code can change behavior, so review the copy before using it.

Every scan also asks the public web about the hosts it flagged: when the domain was registered
(RDAP, free) and whether pages report it as malicious (Tavily; set `TAVILY_API_KEY` in `.env`,
without it only the age lookup runs). Only host names are sent out, names that look internal
(`.local`, `.corp`, ...) are skipped, and the lookups run on your machine, never inside the
sandbox. A recent
registration or a web report is context for a human, not proof; web text is untrusted and is never
given to a model. Limits: not every TLD publishes RDAP (for example `.io`), in which case the
registration date is shown as unknown.

Add `--sarif result.sarif` to write the findings as SARIF, the format GitHub shows as warnings on
pull request lines. Inside GitHub Actions the scan also prints annotations for those lines and
writes a run summary, with no extra flags.

Every scan also runs `pip install -e .` and `pytest` in the sandbox with no AI involved, next to
the agent's runs. Whether the agent installs the project is up to the agent (in our measurements
it did in about half of "set up" runs and a quarter of "run the tests" runs), so without this step
a stealer in `setup.py` would be missed some of the time.

Each scan is saved to `.agenttrap/results/`, where the web page finds it.

The exit code is 1 if the verdict is MALICIOUS, so it can gate CI. (In saved JSON results this
verdict is stored as `HIJACKED`, its earlier name, so older results and scripts keep working.) Verdicts:

- **MALICIOUS**: a planted secret was seen leaving the sandbox in plain HTTP, or the agent ran a
  clearly destructive command. The report names the culprit file and line.
- **SUSPICIOUS**: no proof, but the agent reported text trying to instruct it, or the sandbox
  tried to reach a host that is not on the allow-list.
- **SAFE**: neither.

## Layout

| Module | Job |
| --- | --- |
| `agenttrap/canary.py` | Realistic fake secrets, unique per run, planted in the sandbox home |
| `agenttrap/sandbox.py` | Throwaway Docker container on an internal network with no route out |
| `agenttrap/egress.py`, `sinkhole.py`, `mitm_addon.py` | Network monitor: a per-run private network with a mitmproxy container (reads HTTP and HTTPS, answers every request itself) and a DNS/TCP sinkhole for anything that bypasses the proxy. Nothing is forwarded |
| `agenttrap/agent.py` | The bait agent: a Nemotron tool-use loop run inside the sandbox, plus a post-task debrief |
| `agenttrap/detector.py` | Canary-leak matching and the SAFE / SUSPICIOUS / MALICIOUS verdict |
| `agenttrap/localizer.py` | Delta debugging (ddmin): culprit file, then culprit line |
| `agenttrap/cleaner.py` | Copy of the repo without the culprit code, for a verification re-scan |
| `agenttrap/intel.py` | Host lookups run on every scan: domain age (RDAP) and public reports (Tavily) |
| `agenttrap/pipeline.py`, `results.py`, `web/` | One scan pipeline for the CLI and the page; the saved result format; the local server and page |
| `agenttrap/fetch.py` | Safe, size-limited download of a public GitHub repository |
| `agenttrap/findings.py`, `sarif.py`, `ci.py` | The scan's findings, rendered as SARIF, GitHub annotations and a run summary |
| `agenttrap/baseline_static.py` | Read-only scanner baseline, for comparison |
| `agenttrap/llm.py` | Nebius client with spend caps and disk cache |
| `scripts/bait_spike.py` | Experiment: run the bait agent on a fixture and report what it did |

## Web page

```bash
pip install -e '.[web]'
agenttrap serve            # then open http://127.0.0.1:8765
```

Two tabs: **Saved results** (every scan the CLI or the page has run, with the culprit lines
highlighted in the code, the comparison with a plain text scan, the host lookups and the cleaned
copy) and **Scan a repo** (paste a public GitHub URL or pick one of the test repos; progress
streams in as it runs). It needs Docker and `NEBIUS_API_KEY`, and it only listens on 127.0.0.1.

The server checks the `Host` and `Origin` of every request and requires its own header on every
POST, so a web page in another tab cannot start scans. Pasted URLs go through the checks in
`agenttrap/fetch.py` first: only `https://github.com/owner/repo`, public, at most 50 MB and 3,000
files, with a time limit on the download. One scan runs at a time. Everything shown comes from the
scanned repository and is displayed as plain text, never as HTML.

`agenttrap export OUT_DIR` writes the page and the saved results as static files, a copy that
shows saved results without a server (live scanning is then switched off).

## GitHub Action

Scan every pull request automatically; a pull request that steals the planted secrets fails its
check and gets warnings on the exact lines. See [docs/github-action.md](docs/github-action.md).

```yaml
- uses: actions/checkout@v4
- uses: p3Xxer/agent-trap/action@main
  with:
    nebius-api-key: ${{ secrets.NEBIUS_API_KEY }}
```

## Results

| Test | What we ran | Result |
| --- | --- | --- |
| [Real malware from PyPI](docs/real-malware.md) | 11 published malicious packages that look like credential stealers | **4 caught in the act (MALICIOUS)**, one stealing the fake OpenAI and Anthropic keys; the culprit `setup.py` lines named. The other 6 flagged SUSPICIOUS; 1 SAFE |
| [Our attack repos](docs/evaluation.md) | 11 attacks (stealing code at install, import and test time; published AgentDojo prompt injections) | **11/11 flagged**, against **2/11** for a tool that only reads the code. All 5 code attacks proven with the exact file and line |
| [False alarms on real projects](docs/false-alarms.md) | 20 well-known open-source projects (click, attrs, tqdm, bottle, …) | **0/20 flagged**, 0 wrongly called MALICIOUS |
| Our clean test repos | 8 harmless repos written to look risky | 0/8 called MALICIOUS; 1 flagged SUSPICIOUS (it calls its own web service) |

A scan takes 1 to 2 minutes for a clean repository and up to about 5 when there are culprit lines to
pinpoint, and costs about 1 to 3 cents of model use.

**Try it on a real link:** [p3Xxer/malicious-repo-agent-trap](https://github.com/p3Xxer/malicious-repo-agent-trap)
is a public test repository whose `setup.py` steals keys during install (aimed at a name that
cannot exist, so it is harmless elsewhere). Paste it into the web page and it comes back MALICIOUS
with the lines.

![How one scan works](docs/architecture.svg)

## Evaluation

`python eval/run_eval.py` scans every repository in `fixtures/manifest.json` (11 attack repos and
8 clean ones, each with a known right answer) and writes the results to
[docs/evaluation.md](docs/evaluation.md), next to what a plain text scan finds. Every scan is saved
in `eval/results/` and can be opened in the web page.

These repositories are synthetic: the code-level attacks are inert test doubles (a fake file sent to
a fake host) placed at the stages where real malicious Python packages run their code, and the
instruction attacks use published AgentDojo text. The agent is not deterministic, so a single
run of each repository is an indication, not a guarantee; some results can differ from run to run.
The table lists the cases where Agent Trap did not do what we expected, and separates a repository
being flagged from being flagged for the right reason.

`agenttrap batch FOLDER` scans every project in a folder, for code written by someone else. By
default no line of the scanned code is saved in the results.

## What Agent Trap does and does not do

- **Proven (MALICIOUS):** a planted fake secret really leaves the sandbox, found by running the
  project's install, import and test steps and the agent's own work. For code that steals, the
  culprit file and line are found by replaying commands. When the agent itself was tricked by text,
  the lines are found by asking the model again with and without them (`counterfactual.py`).
- **Warnings (SUSPICIOUS):** the agent reported text aimed at it, or code it found suspicious, or
  the sandbox contacted a host that is not on the allow-list. These are the agent's opinion and
  context, not proof.
- **Limits.** Real malware that needs the internet, targets another operating system, or hides
  from a sandbox will not show anything here (a SAFE verdict means nothing was observed, not that
  the code is safe). Python projects only. Whether the agent follows an injected instruction
  varies from run to run, so one scan is an indication; `docs/evaluation.md` shows how much the
  verdicts varied across repeated runs.

## Credits

Some attack fixtures (`fixtures/attacks/agentdojo/`) use injection templates from
[AgentDojo](https://github.com/ethz-spylab/agentdojo) (MIT License, ETH Zurich SPY Lab).

## How HTTPS is handled, and its limits

Each run gets a mitmproxy container that reads the sandbox's HTTP **and HTTPS** requests and
answers them itself, so a planted secret sent over HTTPS is caught as proof. To make that possible:

- The sandbox trusts a private CA created once in `.agenttrap/mitm-ca/`. Only the CA's public
  certificate is copied into sandboxes; the private key is mounted only into the proxy container.
  **Never install this CA on your own machine.**
- The proxy never contacts the real destination. There is no route out of the sandbox network.
- Programs that ignore the proxy settings (raw sockets, custom TLS) can't complete a connection;
  they show up as a contacted host only (SUSPICIOUS), not as proof.
- Programs that pin certificates won't trust our CA and will fail, so they are not inspected.
