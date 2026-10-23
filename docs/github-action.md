# Agent Trap as a GitHub Action

The Action scans the repository it runs in. If code in a pull request reads a secret and sends it
out while the project is being set up or tested, the check fails and the exact lines are marked on
the pull request.

## Set up

1. Add your Nebius key as a repository secret named `NEBIUS_API_KEY`
   (Settings, Secrets and variables, Actions).
2. Add `.github/workflows/agent-trap.yml`:

```yaml
name: Agent Trap
on:
  pull_request:

permissions:
  contents: read
  security-events: write   # lets the Action upload findings to code scanning

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: p3Xxer/agent-trap/action@main
        with:
          nebius-api-key: ${{ secrets.NEBIUS_API_KEY }}
```

3. Optional: in Settings, Branches, make the `scan` check required, so a pull request that fails
   it cannot be merged.

## What you see

- The check fails (red) when the verdict is MALICIOUS. SUSPICIOUS does not fail it.
- Markers on the lines involved, in the pull request's Files changed tab. They come from workflow
  annotations and work on every repository.
- A summary table on the run page.
- The same findings in the repository's Security tab, from the SARIF upload.

## Things to know

- **Time.** A scan takes a few minutes on GitHub's runners.
- **Pull requests from forks** do not receive repository secrets, so the Action prints a notice
  and skips the scan instead of failing. Do not "fix" this with `pull_request_target`: it runs
  with secrets and would hand them to untrusted code's neighbourhood.
- **Private repositories.** Code scanning uploads need GitHub Advanced Security there. Set
  `upload-sarif: "false"`; annotations and the summary still work.
- **Untrusted code never runs on the runner directly.** It runs inside the Agent Trap sandbox,
  a container with no route to the internet.
- **Spend limits.** The $0.50 per scan limit applies. The $20 lifetime limit is kept in a file
  that does not survive between runs, so it does not apply across runs; watch your usage.

## Inputs

| Input | Default | Meaning |
| --- | --- | --- |
| `nebius-api-key` | | Nebius Token Factory key. Without it the scan is skipped. |
| `tavily-api-key` | | Adds web reports about flagged hosts. |
| `path` | `.` | Directory to scan. |
| `runs` | `2` | Runs per task. |
| `upload-sarif` | `true` | Upload findings to code scanning. |

Output: `verdict` (`MALICIOUS`, `SUSPICIOUS`, `SAFE` or `skipped`).
