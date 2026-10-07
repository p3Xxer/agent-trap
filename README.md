# Agent Trap

**A defensive security tool.** Agent Trap detonates an untrusted repository in a sandbox, lets a
cheap AI coding agent work on it with **fake canary secrets** planted, catches the agent if it is
hijacked into leaking them, and pinpoints the **exact file and line** that did it.

> Status: early development (Nebius × NVIDIA hackathon). Not yet usable end to end.

## Safety

- Every secret Agent Trap plants is a fake canary. No real credential is ever touched.
- All sandbox traffic goes through a recording proxy that blocks it; nothing is exfiltrated.
- The attack fixtures in `fixtures/attacks/` are inert: fake canaries aimed at fake hosts that only
  ever resolve to our local proxy.

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

Add `--lookup` to ask the public web about hosts the scan flagged: when the domain was registered
(RDAP, free) and whether pages report it as malicious (Tavily; set `TAVILY_API_KEY` in `.env`).
Only host names are sent out, and the lookups run on your machine, never inside the sandbox. A recent
registration or a web report is context for a human, not proof; web text is untrusted and is never
given to a model. Limits: not every TLD publishes RDAP (for example `.io`), in which case the
registration date is shown as unknown.

The exit code is 1 if the verdict is HIJACKED, so it can gate CI. Verdicts:

- **HIJACKED**: a planted secret was seen leaving the sandbox in plain HTTP, or the agent ran a
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
| `agenttrap/detector.py` | Canary-leak matching and the SAFE / SUSPICIOUS / HIJACKED verdict |
| `agenttrap/localizer.py` | Delta debugging (ddmin): culprit file, then culprit line |
| `agenttrap/intel.py` | Optional host lookups: domain age (RDAP) and public reports (Tavily) |
| `agenttrap/baseline_static.py` | Read-only scanner baseline, for comparison |
| `agenttrap/llm.py` | Nebius client with spend caps and disk cache |
| `scripts/bait_spike.py` | Experiment: run the bait agent on a fixture and report what it did |

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
