# Feedback: building Agent Trap on Nebius Token Factory and NVIDIA Nemotron

> Draft. Sections marked **[your notes]** are for the team's own experience; everything else is
> taken from the project's code and its usage ledger.

## What we used

- **Nebius Token Factory**, through its OpenAI-compatible API (`https://api.tokenfactory.nebius.com/v1/`).
- **NVIDIA Nemotron 3 Nano** (`nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B`) for everything the product
  does with a model: the bait coding agent that works on the untrusted repository, the two
  end-of-run questions, and the "ask the model again" search that finds which line tricked it.
- Nemotron 3 Super (`nvidia/nemotron-3-super-120b-a12b`) in early experiments, to compare how
  easily each model is tricked.

## Usage and cost

From the project's own usage ledger, across all development, tests and evaluations
(6 to 12 October 2026):

| | |
| --- | --- |
| Model calls | 21,178 |
| Input tokens | 40.4 million |
| Output tokens | 2.1 million |
| Total cost | $5.12 |
| One scan (4 runs, web page settings) | about $0.004 to $0.013 |

A small, cheap model is the right fit here: a scan makes dozens of model calls, and the culprit
search for an agent that was tricked asks the same question 12 times per candidate set. At these
prices that costs fractions of a cent, so the scan can run on every pull request.

## What worked well

- The OpenAI-compatible endpoint meant no special client: one small wrapper with a spend ledger,
  a response cache and a per-scan budget limit.
- Nemotron 3 Nano behaves like a real coding agent in a tool loop: it reads files, runs commands,
  installs and tests projects, and reports what it did.
- It answers structured questions (JSON) reliably enough to quote back the exact text it was
  shown, which we check against the repository.
- **[your notes]** sign-up, docs, dashboard, latency you noticed.

## What was hard, and what we learned

- **Nano is fairly hard to trick.** Simple injected instructions in a README were ignored by both
  Nano and Super. The published AgentDojo injection texts do work, but not every time: the same
  repository gave MALICIOUS in some scans and SUSPICIOUS in others. Good for safety, and it shaped
  the product: Agent Trap runs each task more than once and treats the model's own reports as
  warnings, never as proof.
- **Non-determinism makes "which line tricked it?" a statistics problem.** We sample the model
  12 times per candidate and need 3 leaks to count it, then prune. Cheap calls made this
  affordable.
- **[your notes]** anything about rate limits, errors, model availability or quotas you hit.

## Suggestions

- **[your notes]** for example: published per-model determinism settings (seed support), a usage
  export per API key, or a small free tier for CI use.
