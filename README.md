# Agent Trap

**Is this repo safe to give your AI coding agent?** Agent Trap runs an untrusted repository in a
locked sandbox with **fake keys** planted, lets an AI coding agent (NVIDIA Nemotron on Nebius Token
Factory) work on it, and says **MALICIOUS** only when it sees a planted key leave — then names the
**exact lines** that sent it.

It catches two kinds of attack: code that steals the moment it is installed, imported or tested,
and the new kind that only exists because we hand repos to AI agents — text in a README that talks
the agent into sending your keys.

> Submitted to the **Nebius × NVIDIA Global AI Hackathon**, Coding and Agentic Engineering track.

![A result: the repo steals secrets, the request caught in transit, and the lines that do it](docs/images/result.png)

## Why this matters

Developers now hand new code straight to AI coding agents — "set this up", "run the tests".
Attackers have noticed:

- **Oct 2026, LiteLLM.** A backdoored release of LiteLLM, a popular Python library for calling AI
  models, was on PyPI for about two hours. It added a file that Python runs at every start, which
  collected SSH keys, cloud credentials and **AI provider keys** and sent them to the attackers.
  ([StepSecurity](https://www.stepsecurity.io/blog/litellm-1-107-0-compromised-pypi-backdoored-wheels-credential-stealer))
- **Aug 2025, the `nx` attack.** Malicious releases of Nx, a popular build tool on npm, stole
  GitHub tokens, SSH keys and npm credentials from developers' machines, and were the first known
  malware to **use the victims' own AI command-line tools** (Claude, Gemini, Q) to hunt for more
  secrets. Over a thousand valid GitHub tokens leaked.
  ([Wiz](https://www.wiz.io/blog/s1ngularity-supply-chain-attack))
- **May 2025, a GitHub issue that hijacks an agent.** Researchers showed that a malicious issue in
  a public repository could take over an AI agent asked to "check the open issues", making it leak
  data from the user's **private** repositories.
  ([Invariant Labs](https://invariantlabs.ai/blog/mcp-github-vulnerability))
- **Mar 2025, the "Rules File Backdoor".** Hidden, invisible instructions in the configuration
  files that guide Cursor and GitHub Copilot made the AI quietly insert malicious code.
  ([The Hacker News](https://thehackernews.com/2025/03/new-rules-file-backdoor-attack-lets.html))

Reading the code doesn't catch these: the stealing code looks like ordinary "telemetry", and the
instructions are plain English or invisible. Agent Trap tests the repository side of this threat —
code and text in a repo that make an agent leak your keys — the opposite way: **run it, with an AI
agent at the keyboard, and watch what tries to leave.**

## Judge quick start

| | |
| --- | --- |
| **See real results, no setup** | Demo site: <https://p3xxer.github.io/agent-trap/> — real PyPI malware caught, the README attack, clean projects |
| **Scan a repo yourself** | Docker + Python 3.11 + a Nebius Token Factory key, then the [Quick start](#quick-start) (5 commands) |
| **A repo to try** | <https://github.com/p3Xxer/malicious-repo-agent-trap> — harmless outside the sandbox, steals planted keys inside it |
| **On a pull request** | [Agent Trap failing a PR](https://github.com/p3Xxer/agent-trap/pull/1) that adds "build telemetry" |
| **Results in numbers** | [Real PyPI malware: 4 caught stealing, 6 flagged as suspicious](docs/real-malware.md) · [11/11 test attacks](docs/evaluation.md) · [0 of 20 popular projects falsely flagged](docs/false-alarms.md) |

**Contents:** [Why this matters](#why-this-matters) · [Safety](#safety) ·
[Built with Nemotron and Token Factory](#built-with-nvidia-nemotron-on-nebius-token-factory) ·
[How a scan works](#how-a-scan-works) · [Quick start](#quick-start) · [Running the tests](#running-the-tests) ·
[Usage](#usage) · [Layout](#layout) · [Web page](#web-page) · [GitHub Action](#github-action) ·
[Results](#results) · [Reproducing the results](#reproducing-the-results) ·
[What Agent Trap does and does not do](#what-agent-trap-does-and-does-not-do) ·
[How HTTPS is handled](#how-https-is-handled-and-its-limits) · [Credits](#credits) · [License](#license)

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
removal stops the leak are the culprits.

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

**Tavily.** Agent Trap uses Tavily search at scan time for two questions:
- **Who is on the other end?** For every server the sandbox contacted that is not on the
  allow-list, whether the public web reports it as malicious, next to the domain's registration
  date from RDAP. Only host names are sent.
- **Has this package already been reported?** A search for the package's exact name and version
  (for example "litellm 1.107.0"), shown as "Already reported online" next to the verdict. Only
  for published packages and public GitHub links, so a private project's name is never sent.

What Tavily finds is context for the reader; the verdict comes only from what the trap caught.

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
agent task twice by default; the web page runs each once so a live scan takes about two
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
| `TAVILY_API_KEY` | Optional | [Tavily](https://app.tavily.com) | Web reports on the servers a repository contacted, and on the package itself |
| GitHub login | **Not needed** | — | Public repositories are downloaded anonymously |

Keys go in `.env` (copied from `.env.example`), which git ignores; they are never written into
results. **Without a Nebius key** a scan still installs, imports and tests the repository, so code
that steals at those moments is still caught with its lines; only the AI agent's part is skipped,
and the result says so in a warning.

## Running the tests

```bash
pytest        # 453 tests, about 3 seconds; no Docker or API key needed
```

They cover leak detection, the network watcher, the fake keys, the AI agent loop, the search for
the exact lines, the safe download of GitHub repositories, the web page's safety, the GitHub Action
output and the results format. The full pipeline, with Docker and Nemotron, is exercised by the
evaluation in [docs/evaluation.md](docs/evaluation.md).

## Usage

| Command | What it does |
| --- | --- |
| `agenttrap serve` | The web page, at http://localhost:8765 |
| `agenttrap scan path/to/repo` | Scan one repository from the terminal |
| `agenttrap batch path/to/folder` | Scan every project in a folder (results keep no code) |
| `agenttrap export out/` | Save the web page and results as a static site |

To scan from the terminal, download the repository first, then scan the folder:

```bash
git clone https://github.com/p3Xxer/malicious-repo-agent-trap /tmp/trap-test
agenttrap scan /tmp/trap-test
```

Useful options for `scan`:

| Option | What it does |
| --- | --- |
| `--clean OUT_DIR` | Also write a copy without the stealing code, and scan it again to confirm |
| `--sarif FILE` | Write findings in the format GitHub shows on pull request lines |
| `--json FILE` | Write the full result as JSON |
| `--prove` | Prove every line instead of showing *likely* ones (slow) |
| `--model super` | Use a larger Nemotron for the agent |

**Verdicts:** **MALICIOUS** — a planted key was seen leaving the sandbox, or a destructive command
ran (the exit code is then 1, so it can fail a CI job). **SUSPICIOUS** — warning signs, no proof.
**SAFE** — no theft found.

## Layout

| Code | What it does |
| --- | --- |
| `agenttrap/sandbox.py` | The locked room: a throwaway Docker container with no route to the internet |
| `agenttrap/canary.py` | The fake keys, machine name and user name, new for every run |
| `agenttrap/egress.py`, `mitm_addon.py`, `sinkhole.py` | The trap: a private network where a proxy reads HTTP and HTTPS and a fake DNS answers every lookup; nothing is ever forwarded |
| `agenttrap/agent.py` | The AI coding agent (Nemotron) that works inside the sandbox, and the two questions asked after each task |
| `agenttrap/detector.py` | Spots a planted key leaving, and decides MALICIOUS, SUSPICIOUS or SAFE |
| `agenttrap/localizer.py`, `counterfactual.py` | Finds the exact lines: by re-running with lines removed, or by asking Nemotron again |
| `agenttrap/cleaner.py` | Makes a copy without the stealing code, for the fix check |
| `agenttrap/intel.py` | Looks up the servers contacted (Tavily web reports, domain age) and web reports of the package itself |
| `agenttrap/fetch.py` | Safely downloads a public GitHub repository, with size and time limits |
| `agenttrap/pipeline.py`, `results.py`, `web/` | Runs a whole scan, saves the result, and serves the web page |
| `agenttrap/findings.py`, `sarif.py`, `ci.py` | Turns findings into GitHub pull-request warnings and a summary |
| `agenttrap/llm.py` | The Nebius Token Factory client, with spend limits |
| `action/` | The GitHub Action |

## Web page

Run `agenttrap serve` and open http://localhost:8765. **Scan a repo** takes a public GitHub link
and streams the scan as it runs; **Past scans** lists every result. `agenttrap export out/` saves a
read-only copy, which is how the [demo site](https://p3xxer.github.io/agent-trap/) is made.

**The page is built to be safe to run:**

- It only listens on your own computer, and other websites can't start scans through it.
- It only accepts public `github.com` links, up to 50 MB and 3,000 files, with a download time
  limit.
- Everything from a scanned repository is shown as plain text, so a malicious repo can't inject
  anything into the page.
- One scan runs at a time.

## GitHub Action

Scan every pull request automatically: a pull request that steals the planted keys fails its check
and gets warnings on the exact lines — [see it on a real pull request](https://github.com/p3Xxer/agent-trap/pull/1).
Add your Nebius key as a repository secret named `NEBIUS_API_KEY`, then add this step to a workflow
(full setup in [docs/github-action.md](docs/github-action.md)):

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
| [Our clean test repos](docs/evaluation.md) | 8 harmless repos written to look risky | **0/8 called MALICIOUS**; 1 flagged SUSPICIOUS — a harmless library that downloads exchange rates from its own website. Agent Trap warns about any unknown server, even when nothing is stolen |

A scan takes 1–2 minutes, and a few more when there are lines to pinpoint. Lines it cannot prove
in that time are shown as *likely*; `--prove` proves them all, but slowly.

![How one scan works](docs/architecture.svg)

## Reproducing the results

| Test | How to re-run it |
| --- | --- |
| Our 19 test repositories (11 attacks, 8 clean) | `python eval/run_eval.py` → [docs/evaluation.md](docs/evaluation.md) |
| 20 popular open-source projects | `python eval/run_real.py` → [docs/false-alarms.md](docs/false-alarms.md) |
| Real malware from PyPI | `scripts/fetch_samples.sh` downloads and unpacks the samples (nothing runs outside the sandbox), then `agenttrap batch ~/malware-samples/extracted2` |

Our attack repositories are our own: they steal fake keys and send them to names that cannot exist,
and the instruction attacks use published AgentDojo text. The AI agent does not behave the same way
on every run, so results can differ slightly; [docs/evaluation.md](docs/evaluation.md) shows how
much.

## What Agent Trap does and does not do

- **Proven (MALICIOUS):** a planted fake secret really leaves the sandbox, found by running the
  project's install, import and test steps and the agent's own work. For code that steals, the
  culprit file and line are found by replaying commands. When the agent itself was tricked by text,
  the lines are found by asking the model again with and without them (`counterfactual.py`).
- **Warnings (SUSPICIOUS):** the agent reported text aimed at it, or code it found suspicious, or
  the sandbox contacted a host that is not on the allow-list. These are the agent's opinion and
  context, not proof.
- **Limits.**
  - **Some malware stays hidden.** Code that waits for a real internet connection, only runs on
    another operating system, or notices it is in a sandbox won't do anything here. So SAFE means
    no theft was seen during the scan, not that the code is proven harmless.
  - **Python only,** for now.
  - **AI agents aren't predictable.** An agent may obey a hidden instruction in one run and ignore
    it in the next, so a single scan of that kind of attack can miss it.
    [docs/evaluation.md](docs/evaluation.md) shows how often verdicts changed across repeated runs.

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

## Credits

Some attack fixtures (`fixtures/attacks/agentdojo/`) use injection templates from
[AgentDojo](https://github.com/ethz-spylab/agentdojo) (MIT License, ETH Zurich SPY Lab).

## License

[MIT](LICENSE).
