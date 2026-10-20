package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"fenzi/agents"
	"fenzi/cli/internal/config"
)

// lastCall is the last call to the fake runtime that starts with prefix.
func lastCall(t *testing.T, prefix string) string {
	t.Helper()
	calls := runtimeCalls(t)
	for i := len(calls) - 1; i >= 0; i-- {
		if strings.HasPrefix(calls[i], prefix) {
			return calls[i]
		}
	}
	t.Fatalf("no %q call in %q", prefix, calls)
	return ""
}

// The script fenzi connect runs in the sandbox, run here by sh.
func TestResumeOrStartFallsBackOnlyWhenResumeFailsAtOnce(t *testing.T) {
	cases := []struct {
		name   string
		resume []string
		when   string
		want   string
		code   int
	}{
		{"nothing to resume", []string{"sh", "-c", "echo 'No session found'; exit 1"}, "", "No session found\n\nNo Grok session to resume here yet; starting a new one.\nnew session it's\n", 0},
		{"resumed and left", []string{"sh", "-c", "echo resumed"}, "", "resumed\n", 0},
		// With a resume_when test: no session means no resume attempt.
		{"test says none", []string{"sh", "-c", "echo 'should not run'; exit 1"}, "false", "No Grok session to resume here yet; starting a new one.\nnew session it's\n", 0},
		{"test says one", []string{"sh", "-c", "echo resumed"}, "true", "resumed\n", 0},
	}
	for _, c := range cases {
		argv := resumeOrStart(c.resume, []string{"echo", "new session it's"}, "Grok", c.when)
		out, err := exec.Command(argv[0], argv[1:]...).CombinedOutput()
		code := 0
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else if err != nil {
			t.Fatal(err)
		}
		if string(out) != c.want || code != c.code {
			t.Errorf("%s: exit %d, output %q", c.name, code, out)
		}
	}
}

// Claude Code's test finds a conversation by its folder name, as 2.1.288
// names it; run here by sh against a temporary home.
func TestClaudeResumeWhenFindsTheConversation(t *testing.T) {
	a, err := agents.Get("claude")
	if err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	work := filepath.Join(home, "sandbox", "my.project")
	if err := os.MkdirAll(work, 0o755); err != nil {
		t.Fatal(err)
	}
	test := func() bool {
		cmd := exec.Command("sh", "-c", a.ResumeWhen)
		cmd.Dir = work
		cmd.Env = []string{"HOME=" + home, "PATH=" + os.Getenv("PATH")}
		return cmd.Run() == nil
	}
	if test() {
		t.Fatal("found a conversation in an empty home")
	}
	real, _ := filepath.EvalSymlinks(work)
	folder := filepath.Join(home, ".claude", "projects", regexp.MustCompile(`[^A-Za-z0-9]`).ReplaceAllString(real, "-"))
	if err := os.MkdirAll(folder, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(folder, "a1b2.jsonl"), []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !test() {
		t.Fatalf("missed the conversation in %s", folder)
	}
}

func TestConnectResumesTheAgentByDefault(t *testing.T) {
	fakeRuntime(t, map[string]reply{"sandbox list": {out: "fenzi-web-1a2b\n"}}, "")
	seedState(t, config.Sandbox{Name: "fenzi-web-1a2b", Agent: "claude", Repo: t.TempDir(), Created: time.Now(), Running: true})
	if out, code := runCLI(t, "", "connect", "fenzi-web-1a2b"); code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	exec := lastCall(t, "sandbox exec")
	if !strings.Contains(exec, "'claude' '--continue'") || !strings.Contains(exec, "sh -c") {
		t.Errorf("connect ran %q", exec)
	}

	if out, code := runCLI(t, "", "connect", "--new", "fenzi-web-1a2b"); code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	if exec := lastCall(t, "sandbox exec"); strings.Contains(exec, "--continue") || strings.Contains(exec, "sh -c") {
		t.Errorf("connect --new ran %q", exec)
	}
}
