# Fenzi GitHub Action

Run an AI coding agent in a CI job, inside a sandbox, under the same Fenzi policy your laptops run. Nobody sits at its terminal, so nothing approves itself. The agent's commits come back as a branch for review, and the job summary names every call the policy refused.

Claude Code, Codex, OpenCode and Grok today. Agents run with an API key.

## Use it

```yaml
on:
  workflow_dispatch:

permissions:
  contents: read

jobs:
  agent:
    runs-on: ubuntu-24.04
    timeout-minutes: 45
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: fenzi-inc/fenzi/action@main # pin a commit
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
        with:
          agent: claude
          task-file: .github/agent-task.md
          timeout: 30m
          team-token: ${{ secrets.FENZI_TEAM_TOKEN }} # leave out for Free
```

The step does five things, each in its own log group:

1. Installs `fenzi`, with the installer next to this action, which checks the binary's sha256.
2. Runs `fenzi setup --runtime`: installs the sandbox runtime at the release this `fenzi` is built for, with no questions, and waits for its gateway.
3. Fetches the full history when the checkout is shallow (`git fetch --unshallow`). The agent's commits come back as a branch only from a full clone.
4. Signs in to your team with `fenzi login --token-stdin`, when `team-token` is set. The token goes on standard input, never on a command line. The runner signs out when the step ends.
5. Runs `fenzi run --headless` with your task and keeps `summary.json`, `summary.md`, `branch.bundle` and the run's output as an artifact. `summary.md` becomes the job summary.

## The model key

Put it in the step's `env`, from a secret: `ANTHROPIC_API_KEY` for Claude Code and OpenCode, `OPENAI_API_KEY` for Codex, `XAI_API_KEY` for Grok. Fenzi gives it to the sandbox runtime, and the agent sees a placeholder. The real key is added only to requests for the model API it is bound to. A subscription sign-in needs a person at a browser, so it does not work here.

## The team token

Without `team-token` the run is on Free: the policy is the repository's `fenzi.yaml` over `developer-default`, and nobody answers the agent's requests.

With it, the run uses your team's signed policy, the same revision your laptops run, and the agent's requests go to the team console for a reviewer. Make the token on your own machine and store it as a secret:

```bash
fenzi login --token-for github-actions | gh secret set FENZI_TEAM_TOKEN
```

You approve the code in your browser, so the runner is a machine of yours and its runs count against your seat. The token is printed once and not stored on your machine. Signing the machine out in the console ends it.

## Inputs

| Input | Default | Meaning |
| --- | --- | --- |
| `agent` | `claude` | `claude`, `codex`, `opencode` or `grok`. |
| `task` | | The task, as text. Set this or `task-file`. |
| `task-file` | | A file that holds the task, relative to the workspace. |
| `timeout` | `30m` | Time limit for the whole run. `0` for none. |
| `request-timeout` | until the time limit | How long a request waits for a reviewer before it stays refused. |
| `team-token` | | A token from `fenzi login --token-for`. Empty runs on Free. |
| `team-server` | `https://fenzi.dev` | The team server. |
| `fenzi-version` | latest | The `fenzi` release to install. |
| `fenzi-path` | | A `fenzi` binary to use instead, relative to the workspace. |
| `working-directory` | `.` | The project the agent gets a copy of: the root of a git repository. |
| `artifact-name` | `fenzi-run` | The artifact's name. |

## Outputs and exit status

| Output | Meaning |
| --- | --- |
| `outcome` | `finished`, `agent failed`, `timed out` or `request unanswered`. Empty when the run did not start. |
| `exit-status` | `fenzi run`'s exit status, below. |
| `branch` | The branch with the agent's commits, in the runner's checkout. |
| `refused` | How many distinct calls the policy refused. |
| `out` | The folder with the summary and the bundle. |

The step fails unless the agent finished: `4` the agent exited with an error, `5` the time limit came first, `6` a request had no answer, `1` to `3` the run did not start (an error, a policy the prover refused, a runtime that is not ready). Refused calls do not fail the step by themselves; they are in the summary.

## Requests

When the agent needs a host the policy does not allow, it can file a request. On Team a reviewer answers it in the console while the job runs; with no answer by `request-timeout`, Fenzi refuses it with a reason the agent reads, and the agent carries on without the access. On Free nobody can answer, the agent is told not to file one, and the policy refuses what it always refuses. Nothing is approved without a person.

## What comes back

The agent works on a branch of its own in the sandbox. Its commits land in the runner's checkout under that branch, with the same ids, and the branch you checked out is not moved. To keep them, push the branch in a later step with your workflow's own token, or fetch them from the artifact:

```bash
git fetch branch.bundle fenzi/my-repo-4f2a:fenzi/my-repo-4f2a
```

The sandbox never holds a git token.

## Where it runs

GitHub's Ubuntu runners, and Linux runners of your own with Docker. Not macOS runners: the runtime's installer there needs Homebrew and a password. On a runner of your own, the step signs out at the end; the images it built stay in Docker.
