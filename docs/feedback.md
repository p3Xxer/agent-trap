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

For **Nebius Token Factory**:

1. **Return the cost of each request in the response**, or offer a pricing endpoint. To enforce
   spend limits before each call we hard-code prices per model and keep them deliberately high,
   because a wrong price is a budget that does not hold.
2. **Support (or document) `n` for multiple samples from one prompt.** We send the same prompt
   12 times and pay for its input tokens 12 times; with `n=12` the prompt would be read once.
3. **Document model-specific switches**, such as turning Nemotron's thinking on or off, as
   first-class API parameters with examples.
4. **Say whether `seed` is honoured per model.** We send a seed, but we could not confirm it
   makes results repeatable, so our evaluation repeats each scan and reports how often the
   verdict changed instead.

For **NVIDIA Nemotron**:

5. **Publish prompt-injection robustness numbers** for each model size, for example on
   AgentDojo. Builders deciding which model to give tools to need that number, and in our tests
   Nano held up better than we expected.
6. **Publish the reproducibility story for agent workloads**: what changes between two
   identical calls, and which settings reduce it.
