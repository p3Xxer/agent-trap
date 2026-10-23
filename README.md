# Agent Trap

**Is this repo safe to give your AI coding agent?** Agent Trap runs an untrusted repository in a
locked sandbox with **fake keys** planted, lets an AI coding agent (NVIDIA Nemotron on Nebius Token
Factory) work on it, and says **MALICIOUS** only when it sees a planted key leave — then names the
**exact lines** that sent it.

It catches two kinds of attack: code that steals the moment it is installed, imported or tested,
and the new kind that only exists because we hand repos to AI agents — text in a README that talks
the agent into sending your keys.

![A result: the repo steals secrets, the request caught in transit, and the lines that do it](docs/images/result.png)

## Judge quick start

| | |
| --- | --- |
| **See real results, no setup** | Demo site: <https://p3xxer.github.io/agent-trap/> — real PyPI malware caught, the README attack, clean projects |
| **Scan a repo yourself** | Docker + Python 3.11 + a Nebius Token Factory key, then the [Quick start](#quick-start) (5 commands) |
| **A repo to try** | <https://github.com/p3Xxer/malicious-repo-agent-trap> — harmless outside the sandbox, steals planted keys inside it |
| **On a pull request** | [Agent Trap failing a PR](https://github.com/p3Xxer/agent-trap/pull/1) that adds "build telemetry" |
| **Results in numbers** | [Real PyPI malware: 4 caught stealing, 6 flagged as suspicious](docs/real-malware.md) · [11/11 test attacks](docs/evaluation.md) · [0 of 20 popular projects falsely flagged](docs/false-alarms.md) |

**Contents:** [Built with Nemotron and Token Factory](#built-with-nvidia-nemotron-on-nebius-token-factory) ·
[How a scan works](#how-a-scan-works) · [Quick start](#quick-start) · [Usage](#usage) ·
[Web page](#web-page) · [GitHub Action](#github-action) · [Results](#results) ·
[What Agent Trap does and does not do](#what-agent-trap-does-and-does-not-do) · [Safety](#safety)

<table>
<tr>
<td width="50%"><img src="docs/images/readme-trick.png" alt="A README sentence that tricked the AI agent into sending the AWS key"><br><sub><b>The new attack:</b> one sentence in a README (line 17) talked the AI agent into sending the AWS key.</sub></td>
<td width="50%"><img src="docs/images/landing.png" alt="The Agent Trap web page with real malware caught"><br><sub><b>The web page:</b> paste a GitHub link; real malware from PyPI caught in the trap.</sub></td>
</tr>
</table>

## Safety

- Every secret Agent Trap plants is a fake canary. No real credential is ever touched.
- All sandbox traffic goes through a recording proxy that blocks it; nothing is exfiltrated.
- The attack fixtures in `fixtures/attacks/` send only to reserved names such as
  `setup-check.test`, which can never exist on the internet (RFC 6761): run outside the sandbox,
  the request simply fails.

## Built with NVIDIA Nemotron on Nebius Token Factory

Every model call in Agent Trap goes to **NVIDIA Nemotron 3 Nano**
(`nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B`) through **Nebius Token Factory**'s OpenAI-compatible API
(`https://api.tokenfactory.nebius.com/v1/`). Nemotron is not a reviewer added on top: it *is* the
coding agent being put in the trap.

| Where Nemotron is used | What it does | Model calls |
| --- | --- | --- |
| **The coding agent in the sandbox** ([`agenttrap/agent.py`](agenttrap/agent.py)) | Works on the repository like a developer's coding assistant: reads files, runs commands, installs and tests the project. It gets three everyday tasks ("set this project up", "run the tests", "summarize what this repo does") and answers each step with one JSON action that is carried out inside the sandbox. | Up to 15 per task. 3 tasks, run once each on the web page and twice each from the command line. |
| **Two questions after each task** ([`agenttrap/agent.py`](agenttrap/agent.py)) | "Did anything you read try to give *you* instructions?" and "Did you see code that does something risky?" A quote only counts if it is found in the repository, and the answers are shown as warnings, never as proof. | 2 per task |
| **Finding the sentence that tricked the agent** ([`agenttrap/counterfactual.py`](agenttrap/counterfactual.py)) | When text in the repository (a README line, say) talked the agent into sending a key, Agent Trap hides some lines and **asks Nemotron again** what its next step would be — 12 times, because its answers vary. If at least 3 of the 12 still reach for the key, the trick is in the lines it can still see. Repeating this with different lines hidden leaves only the sentence that did it. | Up to 12 per try, stopping as soon as the answer is clear (often after 4); at most 40 tries; only when the agent was tricked |

Code that steals by itself (a `setup.py` that sends your keys when installed) is pinpointed
without any model call: the repository is simply re-run with lines removed, and the lines whose
removal stops the leak are the culprits. `--model super` or `--model ultra` switches the agent to Nemotron 3 Super or
Ultra on Token Factory.

**How Nebius Token Factory made this practical**

- **Evidence from many answers, not one.** To prove which sentence tricked the agent, Agent Trap
  asks Nemotron the same question up to 12 times and counts the answers. Fast, inexpensive calls on
  Token Factory make that practical, even inside a pull-request check.
- **Room to read everything.** A coding agent re-reads its files and command output at every step,
  so most of its work is reading. Inexpensive input on Nemotron 3 Nano lets it read a repository
  fully, as a real assistant would — which matters here, because an attack can hide in any file.
- **The whole Nemotron family, one switch away.** Token Factory serves Nemotron 3 Nano, Super and
  Ultra behind the same standard OpenAI-style API, so Agent Trap talks to all of them through the
  ordinary `openai` library. Nano is the default: fast enough to scan every pull request. One option
  (`--model super` or `--model ultra`) puts a larger, more capable Nemotron in the trap instead,
  with no code change — so a team can test a repository against an agent closer to the one it
  really uses. (The results in this README were measured with Nano.)

**Tavily.** For every host the sandbox contacted that is not on the allow-list, Agent Trap makes a
Tavily search at scan time to see whether the public web reports it as malicious, next to the
domain's registration date from RDAP. Only host names are sent.

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

## Quick start

You need **Python 3.11+**, **Docker** (running) and a **Nebius Token Factory API key**. A Tavily key
is optional.

```bash
git clone https://github.com/p3Xxer/agent-trap && cd agent-trap
python3 -m venv .venv && source .venv/bin/activate
pip install -e '.[dev]'
cp .env.example .env        # then put your NEBIUS_API_KEY (and optionally TAVILY_API_KEY) in .env
agenttrap serve             # the web page, at http://localhost:8765
```

On the web page, paste `https://github.com/p3Xxer/malicious-repo-agent-trap` (a harmless
test repository that steals keys during install) and press Scan. The first scan builds the sandbox
image and downloads mitmproxy, so it takes a few extra minutes.

### Keys

| Key | Needed? | Where to get it | What it is used for |
| --- | --- | --- | --- |
| `NEBIUS_API_KEY` | For the full scan | [Nebius Token Factory](https://tokenfactory.nebius.com) → API keys | The AI coding agent (NVIDIA Nemotron) that works on the repository |
| `TAVILY_API_KEY` | Optional | [Tavily](https://app.tavily.com) | Web reports on the servers a repository contacted |
| GitHub login | **Not needed** | — | Public repositories are downloaded anonymously |

Keys go in `.env` (copied from `.env.example`), which git ignores; they are never written into
results. **Without a Nebius key** a scan still installs, imports and tests the repository, so code
that steals at those moments is still caught with its lines; only the AI agent's part is skipped,
and the result says so in a warning. Spend is capped before every model call: $0.50 per scan and
$20 in total by default (`MAX_USD_PER_CHECK`, `TOTAL_BUDGET_USD` in `.env`); a scan typically costs
1 to 3 cents.

From the terminal instead:

```bash
agenttrap scan fixtures/attacks/install_time_exfil     # one of our own test attacks
```

## Development

```bash
pip install -e '.[dev]'
pytest                      # no Docker or API key needed
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

Every scan also installs the project (`pip install`, `pip install -e`, `setup.py install`), imports
every module and runs `pytest` in the sandbox with no AI involved, next to the agent's runs. Whether the agent installs the project is up to the agent (in our measurements
it did in about half of "set up" runs and a quarter of "run the tests" runs), so without this step
a stealer in `setup.py` would be missed some of the time.

Each scan is saved to `.agenttrap/results/`, where the web page finds it.

The exit code is 1 if the verdict is MALICIOUS, so it can gate CI. (In saved JSON results this
verdict is stored as `HIJACKED`, its earlier name, so older results and scripts keep working.) Verdicts:

- **MALICIOUS**: a planted secret was seen leaving the sandbox (in a web request or a DNS lookup),
  or the agent ran a clearly destructive command. The report names the culprit file and line.
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
| [Real malware from PyPI](docs/real-malware.md) | 11 published malicious packages that look like credential stealers | **4 caught in the act (MALICIOUS)**, one stealing the fake OpenAI and Anthropic keys; the culprit `setup.py` lines named. 6 flagged as suspicious; 1 came back SAFE |
| [Our attack repos](docs/evaluation.md) | 11 attacks (stealing code at install, import and test time; published AgentDojo prompt injections) | **11/11 flagged**, against **2/11** for a tool that only reads the code. All 5 code attacks proven with the exact file and line |
| [False alarms on real projects](docs/false-alarms.md) | 20 well-known open-source projects (click, attrs, tqdm, bottle, …) | **0/20 flagged**, 0 wrongly called MALICIOUS |
| Our clean test repos | 8 harmless repos written to look risky | 0/8 called MALICIOUS; 1 flagged SUSPICIOUS (it calls its own web service) |

A scan takes 1 to 2 minutes for a clean repository and a few minutes more when there are culprit
lines to pinpoint, and costs about 1 to 3 cents of model use. The search for the exact lines stops
after about two and a half minutes; lines it could not prove in that time are found by reading the
code and shown as *likely*. Add `--prove` (to `scan` or `batch`) to let the search run until every
line is proven: on real malware that can take up to an hour.

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
