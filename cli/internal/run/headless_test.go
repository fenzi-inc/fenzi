package run

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"fenzi/agents"
	"fenzi/cli/internal/openshell"
	"fenzi/cli/internal/workspace"
)

// slowAgent is the fake gateway with an agent that runs until release is
// closed or the run's context ends. The real exec is killed at the
// context's end, and the killed process has no exit status.
type slowAgent struct {
	*openshell.Fake
	release chan struct{}
}

func (s *slowAgent) Attach(ctx context.Context, args ...string) error {
	if len(args) > 1 && args[0] == "sandbox" && args[1] == "exec" {
		if err := s.Fake.Attach(ctx, args...); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return &openshell.Error{Bin: "openshell", Args: args, ExitCode: -1, Stderr: "signal: killed"}
		case <-s.release:
			return nil
		}
	}
	return s.Fake.Attach(ctx, args...)
}

// Denies recorded from OpenShell 0.1.2 (json_test.go in the cli), the
// first one twice.
const deniedLines = `[1791059150.996] [sandbox] [OCSF ] [ocsf] HTTP:POST [MED] DENIED POST http://api.github.com:443/markdown [policy:allow_api_github_com_443 engine:l7] [reason:L7_REQUEST deny POST api.github.com:443/markdown reason=POST /markdown not permitted by policy]
[1791059151.200] [sandbox] [OCSF ] [ocsf] HTTP:POST [MED] DENIED POST http://api.github.com:443/markdown [policy:allow_api_github_com_443 engine:l7] [reason:L7_REQUEST deny POST api.github.com:443/markdown reason=POST /markdown not permitted by policy]
[1791059085.948] [sandbox] [OCSF ] [ocsf] NET:REFUSE [MED] DENIED paste.example.net [reason:policy_dns_ineligible]
`

// A request a Claude Code session filed through policy.local, then a
// draft the supervisor made from a refusal, recorded from OpenShell 0.1.2
// (openshell/rules_test.go, recordedMixed).
const agentRequest = `  Chunk: ccd96a39-17bd-4710-af49-c88725b0540f
  Status: pending
  Rule: example_home_read
  Binary: /usr/bin/curl
  Confidence: 75%
  Rationale: User asked to see what is on the example.com homepage. Need a single read-only GET of the homepage with curl.
  Prover: prover: no new findings
  Candidate: 4dea2e771f03
  Endpoints: www.example.com:443 [L7 rest, allow GET /]
  Binaries: /usr/bin/curl

  Chunk: 59b83e6d-8a8a-43e4-a597-066a5d16fc36
  Status: pending
  Rule: allow_github_com_443
  Binary: /usr/lib/git-core/git-remote-http
  Confidence: 65%
  Rationale: Allow git-remote-http to connect to github.com:443 (HTTPS).
  Prover: prover: no new findings
  Candidate: 1fd6084bd0f7
  Endpoints: github.com:443 [L4]
  Binaries: /usr/lib/git-core/git-remote-http
`

// Recorded from OpenShell 0.1.2 for a sandbox with nothing pending.
const noneLeft = "No network rules for sandbox 'fenzi-test-0001'\n"

func headless(t *testing.T, task string) *harness {
	t.Helper()
	h := setup(t)
	h.opts.Args = nil
	h.opts.Headless = &Headless{Task: task, PollEvery: time.Millisecond}
	h.os.Replies["logs"] = openshell.Reply{Out: settingsLine + deniedLines}
	h.os.Replies["rule get"] = openshell.Reply{Out: noneLeft}
	return h
}

func (h *harness) exec(t *testing.T) string {
	t.Helper()
	for _, c := range h.os.Calls {
		if strings.HasPrefix(c, "sandbox exec -n fenzi-test-0001 --tty ") {
			return c
		}
	}
	t.Fatalf("the agent was not started:\n%s", strings.Join(h.os.Calls, "\n"))
	return ""
}

// An unattended run on Free: the agent's own -p mode with the task last,
// the note that nobody answers requests, the refused calls from the log,
// and the sandbox deleted.
func TestHeadlessRunOnFree(t *testing.T) {
	h := headless(t, "Fix the failing test.\n")
	res, err := Run(context.Background(), h.deps, h.opts)
	if err != nil {
		t.Fatalf("%v\n%s", err, h.out)
	}
	call := h.exec(t)
	if !strings.Contains(call, " -- claude --permission-mode bypassPermissions -p --append-system-prompt ") || !strings.HasSuffix(call, " Fix the failing test.") {
		t.Errorf("exec = %s", call)
	}
	if !strings.Contains(call, unattendedFree) {
		t.Error("the agent was not told that nobody answers requests")
	}
	out := h.out.String()
	for _, want := range []string{
		"requests  nobody answers them on Free; a request the agent files stays refused and fails the run",
		"start     claude --permission-mode bypassPermissions -p <task, 21 characters>",
		"agent     exited with status 0",
		"result    finished, exit 0",
		"refused   2 calls",
		"POST api.github.com/markdown: L7_REQUEST deny POST api.github.com:443/markdown reason=POST /markdown not permitted by policy (2 times)",
		"sandbox   fenzi-test-0001, deleted",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "Choose Yes for the key") {
		t.Error("the interactive start note was printed")
	}
	s := res.Summary
	if s == nil || s.Outcome != OutcomeFinished || s.ExitStatus != 0 || *s.AgentExit != 0 || len(s.Requests) != 0 {
		t.Fatalf("summary = %+v", s)
	}
	if len(s.Refused) != 2 || s.Refused[0].Count != 2 || s.Refused[1].Destination != "paste.example.net" || s.Refused[1].Reason != "policy_dns_ineligible" {
		t.Errorf("refused = %+v", s.Refused)
	}
	if s.FilesOnly != "the folder is not a git repository" || s.Changes != 3 {
		t.Errorf("files only %q, changes %d", s.FilesOnly, s.Changes)
	}
	if h.called("rule reject") || h.called("rule approve") {
		t.Error("a request was answered with none filed")
	}
}

// The agent's own exit status fails the run.
func TestHeadlessAgentFailed(t *testing.T) {
	h := headless(t, "task")
	h.os.Replies["sandbox exec -n fenzi-test-0001 --tty"] = openshell.Reply{Exit: 3}
	res, err := Run(context.Background(), h.deps, h.opts)
	if err != nil {
		t.Fatalf("%v\n%s", err, h.out)
	}
	if s := res.Summary; s.Outcome != OutcomeFailed || s.ExitStatus != ExitAgentFailed || *s.AgentExit != 3 {
		t.Errorf("summary = %+v", s)
	}
	if !strings.Contains(h.out.String(), "result    agent failed with status 3, exit 4") {
		t.Errorf("output:\n%s", h.out)
	}
}

// At the time limit the agent is stopped, and its work still comes back
// before the sandbox goes.
func TestHeadlessTimeLimit(t *testing.T) {
	h := headless(t, "task")
	slow := &slowAgent{Fake: h.os, release: make(chan struct{})}
	h.deps.OpenShell = openshell.Client{R: slow}
	h.opts.Headless.Timeout = 50 * time.Millisecond
	res, err := Run(context.Background(), h.deps, h.opts)
	if err != nil {
		t.Fatalf("%v\n%s", err, h.out)
	}
	s := res.Summary
	if s.Outcome != OutcomeTimedOut || s.ExitStatus != ExitTimedOut || s.AgentExit != nil || s.Timeout != "50ms" {
		t.Errorf("summary = %+v", s)
	}
	if !h.called("sandbox download fenzi-test-0001") || !h.called("sandbox delete fenzi-test-0001") || res.Kept {
		t.Errorf("the work did not come back, or the sandbox stayed:\n%s", strings.Join(h.os.Calls, "\n"))
	}
	if !strings.Contains(h.out.String(), "agent     stopped at the 50ms time limit") {
		t.Errorf("output:\n%s", h.out)
	}
}

// A limit that passes before the agent starts is a timeout, and the
// sandbox is deleted.
func TestHeadlessTimeLimitBeforeStart(t *testing.T) {
	h := headless(t, "task")
	h.opts.Headless.Timeout = time.Nanosecond
	time.Sleep(time.Millisecond)
	_, err := Run(context.Background(), h.deps, h.opts)
	var te *TimeoutError
	if !errors.As(err, &te) {
		t.Fatalf("err = %v", err)
	}
	if h.called("sandbox exec -n fenzi-test-0001 --tty") {
		t.Error("the agent started after the limit")
	}
}

// A request with no answer is refused after the request timeout, with a
// reason the agent reads, and the run fails. Fenzi never approves; the
// supervisor's draft is left alone.
func TestHeadlessRequestTimesOut(t *testing.T) {
	h := headless(t, "task")
	slow := &slowAgent{Fake: h.os, release: make(chan struct{})}
	h.deps.OpenShell = openshell.Client{R: slow}
	var mu sync.Mutex
	tick := 0
	h.deps.Now = func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		tick++
		return time.Unix(0, 0).Add(time.Duration(tick) * time.Minute)
	}
	h.opts.Headless.RequestTimeout = 3 * time.Minute
	h.opts.Policy.TeamRevision = 7
	var rejected []string
	h.os.Answer = func(args []string) (string, bool) {
		if args[0] == "rule" && args[1] == "get" {
			if len(rejected) > 0 {
				return agentRequest[strings.Index(agentRequest, "  Chunk: 59b8"):], true
			}
			return agentRequest, true
		}
		if args[0] == "rule" && args[1] == "reject" {
			rejected = append(rejected, strings.Join(args, " "))
			close(slow.release)
			return "", true
		}
		return "", false
	}
	res, err := Run(context.Background(), h.deps, h.opts)
	if err != nil {
		t.Fatalf("%v\n%s", err, h.out)
	}
	if len(rejected) != 1 || !strings.Contains(rejected[0], "--chunk-id ccd96a39-17bd-4710-af49-c88725b0540f --reason No answer within 3m0s. This run is unattended, so the call stays refused.") {
		t.Errorf("rejected = %q", rejected)
	}
	if h.called("rule approve") {
		t.Error("a request was approved without a person")
	}
	s := res.Summary
	if s.Outcome != OutcomeUnanswered || s.ExitStatus != ExitUnanswered || len(s.Requests) != 1 {
		t.Fatalf("summary = %+v", s)
	}
	if r := s.Requests[0]; r.Answer != AnswerExpired || r.Destination != "www.example.com:443" || r.Process != "/usr/bin/curl" {
		t.Errorf("request = %+v", r)
	}
	out := h.out.String()
	for _, want := range []string{
		"requests  sent to the team console; each waits 3m0s for a reviewer, then stays refused",
		"request   www.example.com:443 by curl: no answer, refused",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if !strings.Contains(h.exec(t), "Each request waits at most 3m0s for an answer") {
		t.Error("the agent was not told how long a request waits")
	}
}

// From the log: a request the console approved, and one still pending
// when the agent exited.
func TestHeadlessRequestAnswers(t *testing.T) {
	h := headless(t, "task")
	h.opts.Policy.TeamRevision = 7
	h.os.Replies["logs"] = openshell.Reply{Out: settingsLine + `[1791297778.239] [sandbox] [OCSF ] [ocsf] CONFIG:PROPOSED [INFO] agent_authored proposal chunk:fad7c2ed-3aca-4fb7-bb37-495820dd7562 on example.com:443 HEAD / by /usr/bin/curl
[1791297802.289] [sandbox] [OCSF ] [ocsf] CONFIG:APPROVED [INFO] chunk:fad7c2ed-3aca-4fb7-bb37-495820dd7562 approved on example.com:443 HEAD / by /usr/bin/curl
`}
	h.os.Replies["rule get"] = openshell.Reply{Out: agentRequest}
	res, err := Run(context.Background(), h.deps, h.opts)
	if err != nil {
		t.Fatalf("%v\n%s", err, h.out)
	}
	got := map[string]string{}
	for _, r := range res.Summary.Requests {
		got[r.Chunk[:8]] = r.Answer
	}
	if len(got) != 2 || got["fad7c2ed"] != AnswerApproved || got["ccd96a39"] != AnswerPending {
		t.Errorf("answers = %v", got)
	}
	if res.Summary.ExitStatus != ExitUnanswered {
		t.Errorf("a request left pending must fail the run: %+v", res.Summary)
	}
}

// An unattended run needs a key, even for an agent that can sign in.
func TestHeadlessNeedsAKey(t *testing.T) {
	h := headless(t, "task")
	h.deps.Getenv = func(string) string { return "" }
	_, err := Run(context.Background(), h.deps, h.opts)
	if err == nil || !strings.Contains(err.Error(), "an unattended run needs a key for claude: export ANTHROPIC_API_KEY") {
		t.Fatalf("err = %v", err)
	}
	h.opts.SignIn = true
	if _, err := Run(context.Background(), h.deps, h.opts); err == nil || !strings.Contains(err.Error(), "Signing in takes a person") {
		t.Errorf("--sign-in: %v", err)
	}
	if h.called("sandbox create") {
		t.Error("a sandbox was created")
	}
}

func TestHeadlessRefusesAnEmptyTask(t *testing.T) {
	h := headless(t, " \n")
	if _, err := Run(context.Background(), h.deps, h.opts); err == nil || err.Error() != "the task is empty" {
		t.Errorf("err = %v", err)
	}
	if h.called("sandbox create") {
		t.Error("a sandbox was created")
	}
}

func TestHeadlessRefusesAnAgentWithoutAMode(t *testing.T) {
	h := headless(t, "task")
	h.opts.Agent.Headless = &agents.Headless{Refused: "it has no mode without its screen"}
	if _, err := Run(context.Background(), h.deps, h.opts); !errors.Is(err, agents.ErrNoHeadless) {
		t.Errorf("err = %v", err)
	}
}

// The round trip at the end of an unattended run: the agent's commits land
// as a branch, the checkout is untouched, and WriteOut keeps the branch as
// a bundle another clone can fetch, beside the summary.
func TestHeadlessLandsABranch(t *testing.T) {
	repo, g := hostRepo(t)
	g("checkout", "-q", "--", "main.go")
	testHeadlessRoundTrip(t, repo, g)
}

// actions/checkout makes a shallow clone with one commit. The round trip
// leaves those to files only, so the run says why there is no branch and
// WriteOut writes no bundle; the GitHub Action deepens the clone first.
func TestHeadlessInAShallowCloneIsFilesOnly(t *testing.T) {
	src, sg := hostRepo(t)
	sg("commit", "-qam", "second")
	repo := t.TempDir()
	if real, err := filepath.EvalSymlinks(repo); err == nil {
		repo = real
	}
	if out, err := exec.Command("git", "clone", "-q", "--depth", "1", "--branch", "main", "file://"+src, repo).CombinedOutput(); err != nil {
		t.Fatalf("clone: %v %s", err, out)
	}
	g := func(args ...string) string {
		t.Helper()
		out, err := exec.Command("git", append([]string{"-C", repo}, args...)...).CombinedOutput()
		if err != nil {
			t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
		}
		return strings.TrimSpace(string(out))
	}
	if g("rev-parse", "--is-shallow-repository") != "true" {
		t.Fatal("the clone is not shallow")
	}
	h := headless(t, "task")
	h.opts.Repo = repo
	h.deps.Filter = workspace.GitFilter
	res, err := Run(context.Background(), h.deps, h.opts)
	if err != nil {
		t.Fatalf("%v\n%s", err, h.out)
	}
	s := res.Summary
	if s.Branch != nil || s.FilesOnly != "the repository is a shallow clone" {
		t.Fatalf("summary = %+v", s)
	}
	out := t.TempDir()
	if err := WriteOut(out, repo, s); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(out, BranchBundle)); err == nil {
		t.Error("a bundle was written with no branch")
	}
	if md, _ := os.ReadFile(filepath.Join(out, SummaryMD)); !strings.Contains(string(md), "| Branch | none: the repository is a shallow clone |") {
		t.Errorf("summary.md:\n%s", md)
	}
}

func testHeadlessRoundTrip(t *testing.T, repo string, g func(...string) string) {
	t.Helper()
	h := headless(t, "Add new.go.")
	h.opts.Repo = repo
	h.deps.Filter = workspace.GitFilter
	fs := &sandboxFS{t: t, root: t.TempDir(), agent: func(project string) {
		os.WriteFile(filepath.Join(project, "new.go"), []byte("package new\n"), 0o644)
		for _, args := range [][]string{{"add", "-A"}, {"commit", "-qm", "agent: add new"}} {
			if out, err := exec.Command("git", append([]string{"-C", project}, args...)...).CombinedOutput(); err != nil {
				t.Fatalf("agent git: %v %s", err, out)
			}
		}
	}}
	h.os.Hook = fs.hook
	h.os.Answer = fs.answer
	head := g("rev-parse", "HEAD")
	res, err := Run(context.Background(), h.deps, h.opts)
	if err != nil {
		t.Fatalf("%v\n%s", err, h.out)
	}
	s := res.Summary
	if s.Branch == nil || s.Branch.Name != "fenzi/test-0001" || s.Branch.Commits != 1 || s.Branch.Start != head || s.FilesOnly != "" {
		t.Fatalf("summary = %+v\n%s", s, h.out)
	}
	// Never applied: the checkout is where it was.
	if g("rev-parse", "HEAD") != head || g("branch", "--show-current") != "main" || g("status", "--porcelain") != "" {
		t.Errorf("the checkout changed:\n%s", g("status"))
	}
	if _, err := os.Stat(filepath.Join(repo, "new.go")); err == nil {
		t.Error("the agent's file is in the checkout")
	}

	out := t.TempDir()
	if err := WriteOut(out, repo, s); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{SummaryJSON, SummaryMD, BranchBundle} {
		if _, err := os.Stat(filepath.Join(out, f)); err != nil {
			t.Error(err)
		}
	}
	md, _ := os.ReadFile(filepath.Join(out, SummaryMD))
	for _, want := range []string{"### fenzi run: Claude Code finished", "| Branch | `fenzi/test-0001`, 1 commit since " + head[:7], "git fetch branch.bundle fenzi/test-0001:fenzi/test-0001", "#### Refused calls: 2"} {
		if !strings.Contains(string(md), want) {
			t.Errorf("missing %q in:\n%s", want, md)
		}
	}
	// Another clone that has the start commit fetches the branch.
	other := t.TempDir()
	for _, args := range [][]string{
		{"clone", "-q", "file://" + repo, other},
		{"-C", other, "fetch", "-q", filepath.Join(out, BranchBundle), "fenzi/test-0001:fenzi/test-0001"},
	} {
		if o, err := exec.Command("git", args...).CombinedOutput(); err != nil {
			t.Fatalf("git %s: %v %s", strings.Join(args, " "), err, o)
		}
	}
	if tip, _ := exec.Command("git", "-C", other, "rev-parse", "fenzi/test-0001").Output(); strings.TrimSpace(string(tip)) != s.Branch.Tip {
		t.Errorf("fetched tip %s, want %s", tip, s.Branch.Tip)
	}
}

func TestSummaryMarkdownKeepsCellsWhole(t *testing.T) {
	code := 0
	s := &Summary{Agent: "Codex", Outcome: OutcomeFinished, AgentExit: &code, Policy: "acme r3 (signed)", Revision: "local-1",
		Started: time.Unix(0, 0), Ended: time.Unix(65, 0), Timeout: "30m0s",
		Refused: []RefusedCall{{Process: "/usr/bin/curl", Destination: "a|b.example", Reason: "line\nbreak", Count: 1}}}
	md := s.Markdown()
	for _, want := range []string{"| Time | 1m5s of 30m0s |", `| /usr/bin/curl | a\|b.example | line break | 1 |`, "#### Requests: 0"} {
		if !strings.Contains(md, want) {
			t.Errorf("missing %q in:\n%s", want, md)
		}
	}
}
