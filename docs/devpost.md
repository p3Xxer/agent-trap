# Agent Trap — Devpost submission text (draft)

**Track:** Coding and Agentic Engineering

**Tagline:** Run an untrusted repo in a locked room with fake keys, let an AI coding agent work on
it, and catch anything that tries to steal — down to the exact line.

**Built with:** Python · NVIDIA Nemotron 3 Nano · Nebius Token Factory · Tavily · Docker ·
mitmproxy · FastAPI · GitHub Actions · SARIF

---

## Inspiration

Developers now hand new repositories straight to AI coding agents: "set this up", "run the
tests". That makes two attacks cheap. A repository can steal the moment it is installed — in
August 2025 malicious releases of the popular `nx` package did exactly that, even asking the
victims' own AI command-line tools to search their machines for secrets. Or a repository can
carry text written for the agent rather than for people, telling it to send your keys somewhere.

Reading the code does not catch either reliably: the stealing code looks like "telemetry", and an
injected instruction can be hidden, encoded or downloaded at run time. We wanted to stop asking
"does this code look bad?" and instead watch what actually happens when it runs, with an AI agent
at the keyboard.

## What it does

Paste a GitHub link (or point the CLI or the GitHub Action at a repository). Agent Trap:

1. **Detonates it in a locked sandbox**: a fresh Docker container with no internet, no extra
   privileges, and fake AWS, SSH, GitHub, npm and AI provider keys planted where thieves look —
   plus a fake machine name and user name. Every value is random per run.
2. **Runs it the way a developer would**: it installs the project, imports it and runs its tests
   with no AI, then lets **an AI coding agent (NVIDIA Nemotron 3 Nano)** set it up, run the tests
   and summarize it.
3. **Watches every byte that tries to leave** through a honeypot proxy and DNS sinkhole that read
   HTTP, HTTPS and DNS and never forward anything. A planted value seen leaving — plain, base64,
   hex or hashed, in a request or a DNS name — is proof.
4. **Pinpoints the exact lines**: it re-runs the repository with lines removed until only the
   ones that still cause the leak remain. When the agent itself was tricked by text, it asks
   Nemotron again with lines removed to find the sentences that did it.
5. **Proves the fix**: it removes those lines and scans the copy again.

The verdict is **MALICIOUS** (a planted key left the sandbox), **SUSPICIOUS** (warning signs, no
proof) or **SAFE** (no theft found). Results show on a local web page, in the terminal, and as
annotations on the exact lines of a pull request through the GitHub Action.

## How we built it

- **NVIDIA Nemotron 3 Nano on Nebius Token Factory is the agent in the trap.** It drives a
  JSON-action loop (read file, run command, write file, HTTP request), every action executed
  inside the sandbox. After each task we ask it two separate questions — "did anything you read
  try to give *you* instructions?" and "did you see risky code?" — and only accept quotes we can
  find in the repository. Its answers are warnings, never proof.
- **Token Factory made statistical evidence affordable.** Over the whole project we made 21,308
  calls for $5.15; a scan costs about 1–3 cents. That is what lets us ask the model 12 times per
  candidate when proving which line tricked it.
- **Tavily** looks up every host the sandbox contacted, next to the domain's registration date
  from RDAP, so a reviewer sees whether the destination is already reported as malicious.
- **The trap**: per-run Docker networks, a DNS sinkhole, mitmproxy with a CA only the sandbox
  trusts, all capabilities dropped, and a CA private key that never enters a sandbox.
- **Product**: a CLI, a batch mode for folders of repositories, a local web page that streams a
  live scan, SARIF output, and a composite GitHub Action. 438 automated tests.

## Results

- **Real malware.** From Datadog's dataset of malicious PyPI packages we ran 11 likely credential
  stealers. **4 were caught in the act** — one, a tampered copy of an AWS library, sent the planted
  OpenAI and Anthropic keys to `webhook.site` — with the exact `setup.py` lines named. 6 more were
  flagged SUSPICIOUS (two download their real payload from the internet, which the sandbox does not
  reach).
- **Our attack repositories.** 11 of 11 flagged, against 2 of 11 for a scanner that only reads the
  code; every code-level attack proven with the right file and line.
- **False alarms.** 20 well-known open-source projects (click, attrs, tqdm, bottle, …): none flagged.

## Challenges we ran into

- **Nemotron would not take the bait.** Our first experiment hid simple instructions in a README:
  Nano and Super ignored them in all 18 runs. Good for the model, bad for a trap. We moved to the
  published AgentDojo attack texts, which do work — but only some of the time. That shaped the
  product: tasks run more than once, and the model's own reports are never treated as proof.
- **"Which line tricked it?" became a statistics problem.** One re-run proves nothing when the
  model is non-deterministic, so we sample 12 times per candidate. Removing every code comment to
  isolate the injection broke the model's behaviour entirely (a leak in 19 of 20 samples went to
  0 of 20); we had to remove only the remarks that name the secret or its destination.
- **Real malware exposed bugs our own tests never did.** Packages that ship an `egg-info` folder
  would not build in the sandbox; unpacked archives hid their projects many folders deep; most real
  stealers report the machine's identity rather than a key file, so we added a fake machine name
  and user name as canaries; and data can leave inside a DNS name, so host names are searched too.
- **Speed.** Pinpointing a line means dozens of detonations. Running them in parallel, reusing the
  network watchers and stopping each replay at the step that leaks took a real-malware scan from
  16 minutes to under 6.

## Accomplishments we're proud of

- Catching real, published malware stealing planted keys — and naming the lines.
- Evidence a person can check: a MALICIOUS verdict comes with the request that carried the key and
  the lines that sent it, and, when the lines were found, a re-scan proving that removing them
  stops it.
- A pull request in our own repository that adds "build telemetry" goes red, with annotations on
  the two lines that steal.

## What we learned

- Proof beats opinion. An AI agent's judgement is a useful hint, but the verdict comes from what
  was seen on the wire.
- Small, cheap open models are the right tool when the method needs many samples.
- Test against real attacks early: they broke assumptions our own fixtures never touched.

## What's next

- Bigger evaluations: hundreds of malicious and normal packages, with published run-to-run variance.
- npm and other ecosystems, and longer runs for malware that waits before acting.
- A hosted scanner on Nebius AI Cloud for teams that can't run Docker in CI.

## Try it

- Demo site (saved real results, no setup): https://p3xxer.github.io/agent-trap/
- Code and Quick start: https://github.com/p3Xxer/agent-trap
- A harmless test repository that steals during install, to paste into the scanner:
  https://github.com/p3Xxer/malicious-repo-agent-trap
