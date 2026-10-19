#!/usr/bin/env bash
# The Fenzi GitHub Action: installs fenzi and the sandbox runtime on the
# runner, signs in to the team when a token is given, runs the agent with
# fenzi run --headless, and writes the job summary. action.yml passes the
# inputs as FENZI_ACTION_* and the token as FENZI_TEAM_TOKEN; the runner's
# working directory is the project. Every step that is not a fenzi command
# is named in the log.
set -uo pipefail

out="${RUNNER_TEMP:?not running in GitHub Actions}/fenzi-out"
bin="$RUNNER_TEMP/fenzi-bin"
rm -rf "$out"
mkdir -p "$out" "$bin"

note() { printf '::notice title=fenzi::%s\n' "$*"; }
fail() {
	printf '::error title=fenzi::%s\n' "$*"
	{
		printf '### fenzi run did not start\n\n%s\n' "$*"
	} >>"${GITHUB_STEP_SUMMARY:-/dev/null}"
	echo "exit-status=1" >>"$GITHUB_OUTPUT"
	exit 1
}
group() { printf '::group::%s\n' "$*"; }
endgroup() { printf '::endgroup::\n'; }
# Paths in inputs are relative to the workspace, as in other actions.
abs() {
	case "$1" in
	/*) printf '%s' "$1" ;;
	*) printf '%s/%s' "${GITHUB_WORKSPACE:-$PWD}" "$1" ;;
	esac
}

echo "out=$out" >>"$GITHUB_OUTPUT"

case "$(uname -s)" in
Linux) ;;
*) fail "This action runs on Linux runners. The sandbox runtime on a Mac needs Homebrew and a person at the keyboard." ;;
esac
command -v docker >/dev/null 2>&1 || fail "Docker is not installed on this runner. GitHub's Ubuntu runners have it."

# The task, written to a file so it never sits on a command line.
task="$RUNNER_TEMP/fenzi-task.md"
if [ -n "${FENZI_ACTION_TASK_FILE:-}" ] && [ -n "${FENZI_ACTION_TASK:-}" ]; then
	fail "Set task or task-file, not both."
elif [ -n "${FENZI_ACTION_TASK_FILE:-}" ]; then
	src=$(abs "$FENZI_ACTION_TASK_FILE")
	[ -f "$src" ] || fail "task-file $FENZI_ACTION_TASK_FILE is not a file."
	cp "$src" "$task"
elif [ -n "${FENZI_ACTION_TASK:-}" ]; then
	printf '%s\n' "$FENZI_ACTION_TASK" >"$task"
else
	fail "Set task or task-file: what the agent should do."
fi

# 1. fenzi.
group "Install fenzi"
if [ -n "${FENZI_ACTION_PATH:-}" ]; then
	given=$(abs "$FENZI_ACTION_PATH")
	[ -x "$given" ] || fail "fenzi-path $FENZI_ACTION_PATH is not an executable."
	cp "$given" "$bin/fenzi"
	echo "Using $FENZI_ACTION_PATH"
else
	# The installer next to this action, at the same ref. It checks the
	# binary's sha256 before it installs it.
	FENZI_INSTALL_DIR="$bin" FENZI_NO_MODIFY_PATH=1 FENZI_NO_SETUP=1 FENZI_VERSION="${FENZI_ACTION_VERSION:-}" \
		sh "$GITHUB_ACTION_PATH/../install.sh" || fail "Installing fenzi failed."
fi
export PATH="$bin:$PATH"
echo "$bin" >>"$GITHUB_PATH"
fenzi version
endgroup

# 2. The sandbox runtime at the release this fenzi is built for.
group "Install the sandbox runtime"
fenzi setup --runtime || fail "The sandbox runtime is not ready. The output above says why."
fenzi doctor || note "fenzi doctor found something to look at; the run checks what it needs."
endgroup

# 3. The history. actions/checkout clones one commit by default, and the
# round trip that brings the agent's commits back as a branch needs the
# whole history. Not a fenzi command: git, with the checkout's credentials.
if [ "$(git rev-parse --is-shallow-repository 2>/dev/null)" = true ]; then
	group "Fetch the full history (git fetch --unshallow)"
	if ! git fetch --unshallow --quiet --no-tags; then
		note "The full history could not be fetched, so the agent's changes come back as files, not commits. Set fetch-depth: 0 on actions/checkout."
	fi
	endgroup
fi

# 4. The team. The token goes on standard input, never on a command line.
signed_in=no
if [ -n "${FENZI_TEAM_TOKEN:-}" ]; then
	group "Sign in to the team"
	printf '%s\n' "$FENZI_TEAM_TOKEN" | fenzi login --token-stdin --server "$FENZI_ACTION_SERVER" ||
		fail "Signing in with team-token failed. The output above says why."
	signed_in=yes
	endgroup
fi
unset FENZI_TEAM_TOKEN
# A self-hosted runner keeps its files between jobs; the sign-in does not
# outlive this one.
cleanup() {
	if [ "$signed_in" = yes ]; then
		fenzi logout >/dev/null 2>&1 || true
	fi
}
trap cleanup EXIT

# 5. The run.
args=(run --headless --new --task "$task" --timeout "${FENZI_ACTION_TIMEOUT:-30m}" --out "$out")
if [ -n "${FENZI_ACTION_REQUEST_TIMEOUT:-}" ]; then
	args+=(--request-timeout "$FENZI_ACTION_REQUEST_TIMEOUT")
fi
args+=("${FENZI_ACTION_AGENT:-claude}")
echo "fenzi ${args[*]}"
# Standard input from /dev/null, as on the runner where every agent first
# started without a terminal.
fenzi "${args[@]}" </dev/null 2>&1 | tee "$out/run.log"
status=${PIPESTATUS[0]}
echo "exit-status=$status" >>"$GITHUB_OUTPUT"

# 6. The job summary and the outputs, from the summary fenzi wrote.
if [ -f "$out/summary.md" ]; then
	cat "$out/summary.md" >>"${GITHUB_STEP_SUMMARY:-/dev/null}"
	if command -v python3 >/dev/null 2>&1; then
		python3 - "$out/summary.json" >>"$GITHUB_OUTPUT" <<'EOF'
import json, sys
s = json.load(open(sys.argv[1]))
print("outcome=" + s.get("outcome", ""))
print("branch=" + (s.get("branch") or {}).get("name", ""))
print("refused=" + str(len(s.get("refused") or [])))
EOF
	fi
else
	{
		printf '### fenzi run stopped before the agent finished\n\nExit status %s. The run'"'"'s output is in the job log and in run.log in the %s artifact.\n' "$status" "${FENZI_ACTION_ARTIFACT:-fenzi-run}"
	} >>"${GITHUB_STEP_SUMMARY:-/dev/null}"
fi
exit "$status"
