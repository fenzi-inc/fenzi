# Security

## Report a vulnerability

Email **security@fenzi.dev**. Do not open a public issue or post details anywhere public.

Send what you can: the Fenzi version (`fenzi version`), the operating system and container runtime, the agent, and the steps or a proof of concept. A way for an agent to reach a file, host, or credential its policy does not grant is the kind of report we most want.

Fenzi runs agents inside the OpenShell sandbox runtime. If the problem turns out to be in the runtime itself, we report it upstream and tell you we did.

## Scope

This repository: the `fenzi` CLI, the policy compiler, the default policy, the agent catalog and its images, and the installer served at https://fenzi.dev/install.sh.

For questions and ordinary bugs, use the issue tracker.
