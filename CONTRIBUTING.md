# Contributing

Thank you for looking. Issues and pull requests are welcome. Security problems go to security@fenzi.dev instead: see [SECURITY.md](SECURITY.md).

## Before you write code

Open an issue first for anything bigger than a small fix, so we can agree on the shape before you spend the time. Say which agent, operating system and container runtime you use, and paste `fenzi doctor` when it is about a machine.

## Build and test

You need Go at the version in `go.mod`.

```bash
make build   # writes bin/fenzi
make test    # replays recorded runtime output, no gateway needed
make vet
```

`make test` must pass on Linux and macOS; the Test workflow runs it on Linux for every pull request. `make prove` checks the golden policies against their boundaries and needs the policy prover that ships with the sandbox runtime.

## Rules the code keeps

- Users type `fenzi`. A message or a doc that tells a person to run the runtime's own command is a bug.
- `cli/internal/openshell` is the only package that starts the runtime or its prover. The compiler starts no process and imports nothing else from this module; a test enforces it.
- When a wrapper reads runtime output the runtime's docs do not show, its comment names the runtime version the output came from, and its test holds that recorded output. Do not guess a format.
- A change to the compiler's output updates the golden files with `make golden`. Review that diff in the pull request.
- The sandbox enforces; Fenzi does not add enforcement of its own. A refusal reaches the agent in the runtime's own words.

## Adding an agent

Each agent is a folder in `agents/` with three files:

- `agent.yaml`: the command, the image, the binary path the sandbox matches, the model host, and how the agent resumes, runs headless and reads MCP servers. Every field that comes from the agent's behaviour cites where it was read: its `--help` at the pinned version, or its docs page. Look at `agents/claude/agent.yaml` for the form.
- `Dockerfile`: pins the agent's version. We do not ship agent binaries.
- `profile.yaml`: where the sandbox puts the model key, and for which hosts.

Add the folder name to the `go:embed` line in `agents/agents.go`. The Agent images workflow builds the image for amd64 and arm64 and checks every binary `agent.yaml` names. A new agent starts with `status: testing` and `verified: false`; it is marked verified after a full run with a real key, a refused host, a request and an approval.

Agents named by the sandbox runtime that are not in the catalog yet: GitHub Copilot CLI and OpenClaw. An agent that keeps its key somewhere the sandbox cannot replace with a placeholder, or that is a desktop app, does not fit.

## Pull requests

One change per pull request, with tests. Write the description for a reviewer who has not read the issue: what changes for a person typing `fenzi`, and how you checked it. By sending a contribution you agree it is licensed under Apache-2.0, as the rest of this repository is.
