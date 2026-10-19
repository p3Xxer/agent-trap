# Feedback: building Agent Trap on Nebius Token Factory and NVIDIA Nemotron

Everything below comes from building and evaluating Agent Trap: its code, its usage ledger and the
experiments we ran. Where we are not sure of something, we say so.

## What we used

- **Nebius Token Factory**, through its OpenAI-compatible API (`https://api.tokenfactory.nebius.com/v1/`).
- **NVIDIA Nemotron 3 Nano** (`nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B`) for everything the product
  does with a model: the coding agent that works on the untrusted repository, the two questions
  asked after each task, and the "ask the model again" search that finds which line tricked it.
- **NVIDIA Nemotron 3 Super** (`nvidia/nemotron-3-super-120b-a12b`) in our first experiment, to
  compare how easily each model is tricked.

## Usage and cost

From the project's usage ledger (`.agenttrap/spend.json`), covering all development, tests and
evaluations from 6 to 16 October 2026:

| | |
| --- | --- |
| Model calls | 21,308 |
| Input tokens | 40.7 million |
| Output tokens | 2.1 million |
| Total cost | $5.15 |
| One scan, as recorded by each scan | about 1 to 3 cents |

Our input-to-output ratio is about 19 to 1: an agent re-reads its whole conversation (files it
opened, command output) at every step and answers with one short JSON action. Input price is
therefore what decides whether a product like ours is affordable, and at Token Factory's price
for Nano it is.

## What worked well

- **No special client.** The endpoint speaks the OpenAI API, so one small wrapper
  ([`agenttrap/llm.py`](../agenttrap/llm.py)) covers everything: JSON mode, a response cache and
  spend limits. Switching to Nemotron 3 Super or Ultra is a one-word change (`--model super`).
- **Nano works as a real coding agent.** In a plain JSON-action loop it reads files, runs
  commands, installs projects and runs their tests, which is exactly what we needed: a realistic
  agent to put in the trap.
- **It quotes accurately.** Asked after each task to quote any text that tried to instruct it,
  Nano gives quotes that we can find in the repository. We only accept quotes we can find there,
  so an invented quote would simply be dropped, and the answers have been usable.
- **Cheap enough to sample.** Finding which line tricked the agent means asking the same
  question 12 times for each candidate version of the repository. At this price that is a
  fraction of a cent, so a statistically careful method costs nothing worth worrying about.

## What was hard, and what we learned

- **Nemotron is hard to trick, which changed the product.** Our first experiment put simple
  injected instructions in a README: Nano and Super ignored them in all 18 runs (0 of 9 each,
  $0.06 in total). The published AgentDojo injection texts do work on Nano, but not every time:
  the same repository came back MALICIOUS in one scan and SUSPICIOUS in the next. That is good
  news about the model's safety, and it shaped Agent Trap: each task runs more than once, and the
  model's own reports are shown as warnings, never as proof.
- **Non-determinism turns "which line tricked it?" into statistics.** A single re-run proves
  nothing, so we sample 12 times per candidate and count a version as still tricked when at
  least 3 samples reach for the secret.
- **The model's behaviour depends on context in ways that are easy to break.** When we removed
  every code comment from a repository to isolate the injected text, a leak that happened in
  19 of 20 samples happened in 0 of 20. Blanking only the remarks that name the secret or its
  destination kept the behaviour, and the search then named the right lines.
- **Hidden "thinking" has to be switched off through a template option.** To keep replies short
  and the agent loop fast we pass `chat_template_kwargs: {"enable_thinking": false}` in
  `extra_body`: a model-specific setting rather than a regular API parameter, and easy to miss.

## Suggestions

These come from what an agent that runs untrusted code, on every pull request, and has to produce
evidence a person can trust, needs from the platform underneath it.

**1. Make repeated context cheap: prompt (prefix) caching for agent loops.** *(Token Factory)*
An agent re-sends its whole conversation at every step, so most of what we pay for is input we
already sent: 40.7 million input tokens against 2.1 million output. Our culprit search goes further
and sends the *same* prompt 12 times to sample the model. Discounted, automatic reuse of a repeated
prompt prefix, and a way to see when it was used, would cut the cost and latency of agent workloads
more than any per-token price change. If it already exists, it deserves a prominent place in the
docs for agent builders; we did not rely on it.

**2. A reproducible mode for evidence and CI.** *(Token Factory and Nemotron)*
A security check that says MALICIOUS on one run and SUSPICIOUS on the next is hard to use as a
pull-request gate, and hard to defend to the person whose code it flagged. We had to design around
this: every task runs more than once, and proving which line tricked the agent takes 12 samples per
candidate. We send a `seed`, but could not confirm it makes runs repeatable. A documented
deterministic setting per model (what it guarantees, and on which hardware) would let tools like
ours re-run a finding and show the same result.

**3. Help agents tell data from instructions.** *(Nemotron)*
Coding agents read files written by strangers. In our tests Nemotron ignored plain injected
instructions entirely, which is a strong result, but it sometimes followed the published AgentDojo
attack texts, and the same input could go either way. Two things would help everyone building
agents on Nemotron: a way to mark content as untrusted data (a message role or field the model is
trained never to take orders from), and published attack-success rates per model size on a public
benchmark such as AgentDojo, including how much they vary between runs.

**4. Spend limits enforced on the server, per key.** *(Token Factory)*
Running a scan on every pull request means an API key stored in CI, which is exactly the kind of
secret our tool exists to protect. Our spend limits live in our own client, so they do nothing if
that key leaks or a bug loops. A hard monthly or daily cap per API key, set in the console and
enforced by Token Factory, would let teams put an agent in CI without an open-ended bill.

**5. First-class controls for agent settings.** *(Token Factory)*
To keep agent steps short we switch off Nemotron's hidden reasoning with a chat-template option
passed through `extra_body`. Settings like this decide cost and speed for agents; documenting them as
regular, per-model API parameters, with examples, would save every team the search.
