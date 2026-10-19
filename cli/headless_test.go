package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The flags of an unattended run are checked before the runtime is called.
func TestRunHeadlessFlags(t *testing.T) {
	calls := recordingRuntime(t)
	t.Chdir(t.TempDir())
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"run", "--task-text", "x", "claude"}, "go with --headless"},
		{[]string{"run", "--timeout", "5m", "claude"}, "go with --headless"},
		{[]string{"run", "--headless", "claude"}, "--headless needs the task: --task <file> or --task-text"},
		{[]string{"run", "--headless", "--task", "t.md", "--task-text", "x", "claude"}, "--task or --task-text, not both"},
		{[]string{"run", "--headless", "--task-text", "x", "--sign-in", "claude"}, "signing in takes a person at a browser"},
		{[]string{"run", "--headless", "--task", "missing.md", "claude"}, "--task: open missing.md"},
		{[]string{"run", "--headless", "--task-text", "x", "--timeout", "-1s", "claude"}, "cannot be negative"},
	} {
		out, code := runCLI(t, "", tc.args...)
		if code != 1 || !strings.Contains(out, tc.want) {
			t.Errorf("%q: exit %d:\n%s", tc.args, code, out)
		}
	}
	if b, err := os.ReadFile(calls); err == nil && len(b) > 0 {
		t.Errorf("the runtime was called:\n%s", b)
	}
	out, _ := runCLI(t, "", "run", "--help")
	for _, f := range []string{"--headless", "--task", "--task-text", "--timeout", "--request-timeout", "--out"} {
		if !strings.Contains(out, f) {
			t.Errorf("run --help does not list %s", f)
		}
	}
}

func TestReadTask(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "task.md")
	os.WriteFile(file, []byte("- fix the test\n"), 0o600)
	e := env{stdin: strings.NewReader("from stdin\n")}
	for _, tc := range []struct{ file, text, want string }{
		{file, "", "- fix the test\n"},
		{"-", "", "from stdin\n"},
		{"", "inline", "inline"},
	} {
		got, err := readTask(e, tc.file, tc.text)
		if err != nil || got != tc.want {
			t.Errorf("readTask(%q, %q) = %q, %v", tc.file, tc.text, got, err)
		}
	}
}

// fenzi setup --runtime on a machine that has OpenShell asks nothing and
// installs nothing: it checks the version and the gateway (answers in the
// shapes recorded from 0.1.2).
func TestSetupRuntimeChecksWhatIsInstalled(t *testing.T) {
	fakeRuntime(t, map[string]reply{
		"--version": {out: "openshell 0.1.2\n"},
		"status":    {out: doctorStatus},
	}, "")
	out, code := runCLI(t, "", "setup", "--runtime")
	if code != 0 || !strings.Contains(out, "OpenShell 0.1.2") || !strings.Contains(out, "connected") {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	if strings.Contains(out, "Installing") {
		t.Errorf("it installed over an installed runtime:\n%s", out)
	}
}

func TestSetupRuntimeRefusesAReleaseOutsideThePin(t *testing.T) {
	fakeRuntime(t, map[string]reply{
		"--version": {out: "openshell 0.2.0\n"},
		"status":    {out: doctorStatus},
	}, "")
	out, code := runCLI(t, "", "setup", "--runtime")
	if code != 3 || !strings.Contains(out, "is outside 0.1.x") {
		t.Fatalf("exit %d:\n%s", code, out)
	}
}

func TestSetupRuntimeWaitsForTheGateway(t *testing.T) {
	defer func(w time.Duration) { runtimeWait = w }(runtimeWait)
	runtimeWait = 0
	fakeRuntime(t, map[string]reply{
		"--version": {out: "openshell 0.1.2\n"},
		"status":    {out: `{"status":"disconnected"}`},
	}, "")
	out, code := runCLI(t, "", "setup", "--runtime")
	if code != 3 || !strings.Contains(out, "the gateway is not ready") || !strings.Contains(out, "fenzi doctor") {
		t.Fatalf("exit %d:\n%s", code, out)
	}
}
