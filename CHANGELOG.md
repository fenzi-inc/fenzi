# Changelog

One entry per published release of `fenzi`. Each release is a tag on this repository, and its binaries and checksums are on the [release page](https://github.com/fenzi-inc/fenzi/releases) and at `https://fenzi.dev/dl/`. `fenzi update` installs the newest.

## 0.1.47

The sandbox runtime is OpenShell 0.1.8. `fenzi setup` installs it and checks the installer's sha256, and the policy check uses its prover.

- A sandbox made by an older runtime does not start after an upgrade, and the older runtime does not start again on the upgraded state. So setup upgrades an older 0.1 patch only when no sandbox is left, and names the ones in the way: `fenzi stop <sandbox>` brings a sandbox's changes back. `fenzi doctor` says the same.
- OpenShell 0.1.8 puts a stored key or token only where its profile says. An MCP server's token profile names the server's `token_header`, and `fenzi run` replaces a profile stored for another header. A refusal by the runtime's credential check is a line in `fenzi log`, with its reason.
- A headless task is at most 32 KiB.
- Agent images are built on the Docker socket the gateway's config names, so a `docker` command that points at another runtime no longer stops `fenzi run`. `doctor`'s image check asks the daemon there and fails with Docker's own words when nothing answers.

Since 0.1.38:

- `fenzi branch` and `run --branch` pick the branch a sandbox starts from.
- `fenzi tools`: a project's languages get their commands in the sandbox, in a copy of the agent's image, checked when the sandbox starts.
- Claude Code starts in `bypassPermissions`: the sandbox's policy decides.
- A request the sandbox's own draft took over is listed as the agent's. Connections the sandbox blocked on its own are called that, not drafts.
- The php stack opens Packagist's security advisory API and nothing else on packagist.org.
- A project's stack is never read from the home folder.

## 0.1.38

`developer-default` reads GitHub: `git` can clone and fetch from github.com, and push stays refused. On the Free plan a project's files add its language's package hosts, read-only. `fenzi requests` offers Approve and save first. In 0.1.37: `fenzi setup --runtime` starts a stopped container runtime.

## 0.1.36

Your own MCP servers on a team.

## 0.1.35

`fenzi uninstall`. Policy hosts and paths can be edited from the command line.

## 0.1.33

OpenShell 0.1.4. Agents in CI with `fenzi run --headless`, and the GitHub Action in `action/`.

## 0.1.30

`fenzi stop` and an attached `fenzi run` no longer race when they copy a sandbox out, so stopping keeps the agent's work.

## 0.1.29

A sandbox whose container stopped is listed as stopped, and `stop` and `rm` handle it. Short DNS lifetimes.

## 0.1.28

Claude's account connectors, allowed per tool.

## 0.1.26

Secrets for local MCP servers. Scoped npm packages.

## 0.1.25

Importing MCP servers never writes a secret into the policy.

## 0.1.24

A preview before MCP servers are imported.

## 0.1.23

MCP servers for every agent, from one list, checked per tool by the sandbox.

## 0.1.20 to 0.1.22

Claude Code can sign in with a Claude subscription, also when a key is stored.

## 0.1.16

Approve and add to policy. Requests answered on the machine leave the team console's list.

## 0.1.15

`fenzi run` forwards decisions to the team console while the agent runs.

## 0.1.14

`fenzi status` shows the team role.

## 0.1.13

Per-team boundaries, drift compare, a warning for secrets in the project, `approve --save`, `policy apply`.

## 0.1.12

`fenzi rm`. Key removal per agent. The team policy in `policy check`.

## 0.1.11

The Team client is in this repository: `login`, `logout`, `status`, `sync`, `forward` and `policy publish`.

## 0.1.10

`--version` works as an alias for `version`.
