package main

import (
	"os/exec"
	"strings"
	"testing"
	"time"

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
		want   string
		code   int
	}{
		{"nothing to resume", []string{"sh", "-c", "echo 'No session found'; exit 1"}, "No session found\n\nfenzi: no Grok session to resume here; starting a new one.\nnew session it's\n", 0},
		{"resumed and left", []string{"sh", "-c", "echo resumed"}, "resumed\n", 0},
	}
	for _, c := range cases {
		argv := resumeOrStart(c.resume, []string{"echo", "new session it's"}, "Grok")
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

func TestConnectResumesTheAgentByDefault(t *testing.T) {
	fakeRuntime(t, map[string]reply{"sandbox list": {out: "bl-web-1a2b\n"}}, "")
	seedState(t, config.Sandbox{Name: "bl-web-1a2b", Agent: "claude", Repo: t.TempDir(), Created: time.Now(), Running: true})
	if out, code := runCLI(t, "", "connect", "bl-web-1a2b"); code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	exec := lastCall(t, "sandbox exec")
	if !strings.Contains(exec, "'claude' '--continue'") || !strings.Contains(exec, "sh -c") {
		t.Errorf("connect ran %q", exec)
	}

	if out, code := runCLI(t, "", "connect", "--new", "bl-web-1a2b"); code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	if exec := lastCall(t, "sandbox exec"); strings.Contains(exec, "--continue") || strings.Contains(exec, "sh -c") {
		t.Errorf("connect --new ran %q", exec)
	}
}
