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

## Layout

| Module | Job |
| --- | --- |
| `agenttrap/canary.py` | Realistic fake secrets, unique per run, planted in the sandbox home |
| `agenttrap/sandbox.py` | Throwaway Docker container on an internal network with no route out |
| `agenttrap/egress.py`, `agenttrap/sinkhole.py` | Network monitor: a per-run private network whose only neighbour is a logging sinkhole (DNS + ports 80/443). Plain HTTP is read in full; HTTPS is **not** decrypted, only the host name is logged. Nothing is forwarded |
| `agenttrap/agent.py` | The bait agent: a Nemotron tool-use loop run inside the sandbox, plus a post-task debrief |
| `agenttrap/detector.py` | Canary-leak matching and the SAFE / SUSPICIOUS / HIJACKED verdict |
| `agenttrap/localizer.py` | Delta debugging (ddmin): culprit file, then culprit line |
| `agenttrap/baseline_static.py` | Read-only scanner baseline, for comparison |
| `agenttrap/llm.py` | Nebius client with spend caps and disk cache |
| `scripts/bait_spike.py` | Experiment: run the bait agent on a fixture and report what it did |

## Credits

Some attack fixtures (`fixtures/attacks/agentdojo/`) use injection templates from
[AgentDojo](https://github.com/ethz-spylab/agentdojo) (MIT License, ETH Zurich SPY Lab).

## Known limits of network monitoring

- HTTPS contents are not inspected, so a secret sent over HTTPS shows up only as a contact with an
  unexpected host (SUSPICIOUS), not as proof (HIJACKED). Proof requires plain HTTP.
- Fixture payloads can only be served over plain HTTP, so runtime-fetch fixtures use `http://`.
