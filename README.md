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
| `agenttrap/detector.py` | Canary-leak matching and the SAFE / SUSPICIOUS / HIJACKED verdict |
| `agenttrap/localizer.py` | Delta debugging (ddmin): culprit file, then culprit line |
| `agenttrap/baseline_static.py` | Read-only scanner baseline, for comparison |
| `agenttrap/llm.py` | Nebius client with spend caps and disk cache |
