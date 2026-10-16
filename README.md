# Boundlane

Run the agent you already use. Keep it in bounds.

The model will make bad calls. That is ordinary. Boundlane starts that agent inside a sandbox on your machine. You choose the files, the hosts, and whether a credential ever enters the sandbox. A bad prompt does not move the boundary. When a call is blocked, you get a log line.

The sandbox is [OpenShell](https://github.com/NVIDIA/OpenShell). This repository is the Free plan in front of it: the command you type, the policy it compiles, and the log on that one machine. One machine is free. No account. The license is Apache-2.0.

```bash
cd ~/code/your-project
curl -fsSL https://boundlane.dev/install.sh | sh
```

The installer is for macOS and Linux, arm64 and amd64. It checks the download's sha256, installs `boundlane`, and starts a guided setup in your terminal:

```text
  ■ This machine  1 of 5

  ✓ Runtime           OpenShell 0.1.2
  ✓ Gateway           connected
  ✓ Sandbox driver    docker
  ✓ Approvals         a person approves each request
  ...

  ? Which agent should run in the sandbox?
    ❯ Claude Code  2.1.288
      Codex        0.160.1
      OpenCode     1.18.34
      Grok         1.0.46
    ↑↓ to move, enter to choose
```

Five steps: this machine, agent, model key, project folder, agent image. If the sandbox runtime is missing, setup offers to install the pinned release. If the gateway is stopped, it offers to start it. Nothing is installed or changed without a yes from you. At the end it shows what the agent can reach and offers to start it. Next time:

```bash
boundlane run claude
```

Run `boundlane setup` again at any time. `BOUNDLANE_NO_SETUP=1` installs the command and stops. If the install folder is not on your `PATH`, the installer adds one marked line to your shell profile; `BOUNDLANE_NO_MODIFY_PATH=1` prevents that. `boundlane update` installs a newer release, and commands mention one at most once a day (`BOUNDLANE_NO_UPDATE_CHECK=1` turns that off).

Your code and your model key stay on this machine. The agent sees a placeholder. The real key is added on the way out, only for the model's own API.

## Docs

The product is explained at [boundlane.dev/docs](https://boundlane.dev/docs). Start there if you want to run an agent. This repository is the program those pages describe.

The site also has the [argument](https://boundlane.dev/beliefs), the [price](https://boundlane.dev/price), and [questions](https://boundlane.dev/questions).

### Start

| | |
| --- | --- |
| [Getting started](https://boundlane.dev/docs) | Install, check the machine, set a key, run an agent, read a deny, approve a request, take the changes back. |
| [How it works](https://boundlane.dev/docs/how-it-works) | What runs where: the gateway, the supervisor inside the sandbox, and the agent. What a laptop cannot enforce. |
| [Install and platforms](https://boundlane.dev/docs/install) | Apple Silicon, Linux, and Windows through WSL 2. Which runtime the sandbox needs. |
| [Security model](https://boundlane.dev/docs/security-model) | What the sandbox stops, which layer stops it, and what Boundlane does not claim. |

### Use

| | |
| --- | --- |
| [Policy file](https://boundlane.dev/docs/policy) | `boundlane.yaml`: fields, host access, and the check before a sandbox starts. |
| [Default access](https://boundlane.dev/docs/default-access) | What a new sandbox can read, write, and reach when the folder has no policy file. |
| [Requests and approvals](https://boundlane.dev/docs/approvals) | A person decides when the agent wants a host the policy does not name. |
| [Agents](https://boundlane.dev/docs/agents) | Claude Code, Codex, OpenCode, and Grok. Cursor CLI and Muse are listed as next. |
| [Agent images](https://boundlane.dev/docs/images) | Each agent runs from an image you build on your machine, from a pinned Dockerfile. |
| [Model keys](https://boundlane.dev/docs/keys) | Where the key is stored, what the agent sees, and why a subscription login is not enough. |
| [Workspace and changes](https://boundlane.dev/docs/workspace) | What is copied in, what is left out, and how changes come back through `diff` and `apply`. |
| [Decision log](https://boundlane.dev/docs/log) | Every allow and deny `boundlane log` can show, and what the log never holds. |

### A team

Free is this CLI on one machine, with the default policy and the log on that machine. No account. Team is one signed policy, one decision log, and approvals in one console across many machines. The console is hosted at https://boundlane.dev and is opened by invitation; [request access](https://boundlane.dev/request-access) for a new team. License is that control plane in your own network. See [Price](https://boundlane.dev/price).

The Team client is in this repository: `boundlane login` signs a machine in, `status` shows the sign-in, `sync` and `forward` keep it in step with the console, and `policy publish` publishes from an admin's machine. The control plane itself is not in this repository.

| | |
| --- | --- |
| [Team plan](https://boundlane.dev/docs/team) | One policy on every machine, one log, approvals in one place. |
| [Enroll machines](https://boundlane.dev/docs/enroll) | How a machine signs in and what it keeps locally. |
| [Publish and revisions](https://boundlane.dev/docs/revisions) | How a policy is checked, numbered, signed, and delivered. |
| [Forwarding decisions](https://boundlane.dev/docs/forwarder) | Decisions leave the machine outbound. Gaps are shown. |
| [Drift](https://boundlane.dev/docs/drift) | A sandbox that is not on the published policy, or an approval made somewhere else. |
| [When something is down](https://boundlane.dev/docs/offline) | What keeps working from the last policy the machine accepted. |
| [License plan](https://boundlane.dev/docs/license) | The control plane in your network, single sign-on, and a SIEM export. |

### Reference

| | |
| --- | --- |
| [CLI reference](https://boundlane.dev/docs/cli) | Every command, its flags, and its exit codes. You only type `boundlane`. |
| [Troubleshooting](https://boundlane.dev/docs/troubleshooting) | `doctor` failed, a host was denied, a package install failed, changes did not come back. |
| [Known limits](https://boundlane.dev/docs/limits) | What the sandbox does not stop. |
| [Versions and upgrades](https://boundlane.dev/docs/versions) | The pinned runtime and the pinned agent versions. |
| [Glossary](https://boundlane.dev/docs/glossary) | Sandbox, gateway, supervisor, boundary, revision. |

## What is in this repository

```
cli/          the boundlane command
compiler/     policy document to sandbox policy
policies/     the built-in developer-default policy
agents/       one folder per agent: image, catalog entry, key profile
install.sh    the installer published at boundlane.dev/install.sh
```

### `cli/`

The program you run. `boundlane setup` is the guided first run. `boundlane doctor` checks the machine. `boundlane init` writes a starter `boundlane.yaml`. `boundlane run claude` starts Claude Code in a new sandbox. `requests`, `approve`, and `deny` are how a person grants a host the policy did not name. `log` shows allows and denies. `diff` and `apply` bring the agent's edits back into your repo. `policy compile` and `policy check` show what a policy file becomes, and whether it stays inside its boundary. `agents` lists the catalog. `agents build claude` builds that agent's image.

`cli/internal/openshell` is the only package that talks to the sandbox runtime.

`login`, `logout`, `status`, `sync`, `forward`, and `policy publish` are the Team client. A machine that has not signed in uses the policy on the machine. A signed-in machine uses its team's signed policy, checks the signature against the team's key with `teamapi`, and refuses a bad signature or an older revision. `server`, a local control plane, is not in this build and says so.

### `compiler/`

A short policy document goes in. Sandbox policy YAML comes out, plus the boundary a prover checks that policy against. Golden files live in `compiler/testdata/golden`. `make golden` rewrites them after an intended change. Review that diff.

The compiler does not start a process and does not import the CLI. The policy language you edit is the YAML document, not a second language for the agent.

### `policies/`

`developer-default.yaml` is the policy a Free machine uses when the folder has no `boundlane.yaml`. The workspace is read-write. A few hosts, including the GitHub API and the package registries, are read-only. Anything else waits for a person. The compiler also adds the model hosts for the agent you run. [Default access](https://boundlane.dev/docs/default-access) is the readable form of the result.

### `agents/`

One folder per agent. `agent.yaml` names the command, the image, the binary path the sandbox matches, and the model host. A `Dockerfile` pins the agent version. `boundlane agents build` builds that image on your machine. We do not ship agent binaries.

| Folder | Agent | In this tree |
| --- | --- | --- |
| `agents/claude/` | Claude Code | Catalog entry, pinned image, reviewed key profile. |
| `agents/codex/` | Codex | Catalog entry, pinned image, and reviewed key profile. |
| `agents/opencode/` | OpenCode | Catalog entry, pinned image, and reviewed key profile. Anthropic only. |
| `agents/grok/` | Grok | Catalog entry, pinned image, and reviewed key profile. xAI API key only. |

`agents/guide.md` is the note the CLI can hand the agent so it knows how to ask for a host. Cursor CLI and Muse are not in this tree. Cursor CLI exchanges its API key for tokens it stores, so it is not shipped here.

### `install.sh`

The script at `https://boundlane.dev/install.sh`. It picks a binary for the machine you are on, checks the sha256, installs `boundlane`, and starts `boundlane setup` when a person is at the terminal. `make dist` builds those binaries into `dist/`: darwin and linux, arm64 and amd64.

## Build from this tree

You need Go 1.27.1.

```bash
make build   # writes bin/boundlane
make test    # replays recorded runtime output
make vet
make prove   # checks every golden policy against its boundary
make dist    # the binaries the installer downloads
```

`make test` does not need a gateway; it replays runtime output recorded in the tests. `make prove` needs the policy prover that ships with the sandbox runtime.

Which agents and platforms have been checked is on the [Agents](https://boundlane.dev/docs/agents) and [Install](https://boundlane.dev/docs/install) pages.

## Security

Report a vulnerability privately to security@boundlane.dev, not in a public issue. See [SECURITY.md](SECURITY.md).

## License

Apache-2.0. See [LICENSE](LICENSE).
