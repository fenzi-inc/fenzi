package main

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"fenzi/cli/internal/config"
	"fenzi/cli/internal/workspace"
)

const sandboxName = "fenzi-web-1a2b"

// stagedFixture makes a project, a snapshot of it, and a staged copy in
// which the agent edited one file, added one, and deleted one.
func stagedFixture(t *testing.T) (repo string) {
	t.Helper()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	repo = t.TempDir()
	files := map[string]string{
		"app.py":    "import os\n\n\ndef main():\n    print('hi')\n\n\nmain()\n",
		"old.txt":   "remove me\n",
		"README.md": "# web\n",
	}
	for p, body := range files {
		if err := os.WriteFile(filepath.Join(repo, p), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	dirs, err := config.Default()
	if err != nil {
		t.Fatal(err)
	}
	base, err := workspace.Snapshot(repo, workspace.All)
	if err != nil {
		t.Fatal(err)
	}
	stage := dirs.Staging(sandboxName)
	staged := filepath.Join(stage, "files")
	if err := os.MkdirAll(staged, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := base.Save(filepath.Join(stage, "base.json")); err != nil {
		t.Fatal(err)
	}
	after := map[string]string{
		"app.py":    "import os\nimport sys\n\n\ndef main():\n    print('hello', sys.argv)\n\n\nmain()\n",
		"new.py":    "VALUE = 1\n",
		"README.md": "# web\n",
	}
	for p, body := range after {
		if err := os.WriteFile(filepath.Join(staged, p), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	s := &config.State{}
	s.Put(config.Sandbox{Name: sandboxName, Agent: "claude", Repo: repo, Created: time.Now()})
	if err := dirs.SaveState(s); err != nil {
		t.Fatal(err)
	}
	return repo
}

func runCLI(t *testing.T, input string, args ...string) (string, int) {
	t.Helper()
	var out bytes.Buffer
	code := cli(args, strings.NewReader(input), &out, &out)
	return out.String(), code
}

func TestDiffShowsSummaryAndLines(t *testing.T) {
	stagedFixture(t)
	out, code := runCLI(t, "", "diff", "--sandbox", sandboxName)
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	for _, want := range []string{
		"3 files changed from the agent",
		"edited  app.py", "+2 −1",
		"new     new.py", "deleted old.txt",
		"── app.py  edited",
		"    1   import os",
		"    2 + import sys",
		"    5 -     print('hi')",
		"    6 +     print('hello', sys.argv)",
		"fenzi apply --sandbox " + sandboxName,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "\x1b") {
		t.Error("colour without a terminal")
	}
}

func TestApplyKeepsChangesUnlessYes(t *testing.T) {
	repo := stagedFixture(t)
	out, code := runCLI(t, "\n", "apply", "--sandbox", sandboxName)
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	if _, err := os.Stat(filepath.Join(repo, "old.txt")); err != nil {
		t.Fatal("a file was deleted without a yes")
	}
	for _, want := range []string{"Kept for later", "fenzi apply --sandbox " + sandboxName} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}

	out, code = runCLI(t, "y\n", "apply", "--sandbox", sandboxName)
	if code != 0 || !strings.Contains(out, "Applied") {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	b, _ := os.ReadFile(filepath.Join(repo, "app.py"))
	if !strings.Contains(string(b), "import sys") {
		t.Error("app.py was not updated")
	}
	if _, err := os.Stat(filepath.Join(repo, "old.txt")); err == nil {
		t.Error("old.txt was not removed")
	}

	// The sandbox may still run. Its snapshot now matches what was applied,
	// so a later stop compares against that instead of finding nothing.
	dirs, _ := config.Default()
	base, err := workspace.Load(filepath.Join(dirs.Staging(sandboxName), "base.json"))
	if err != nil {
		t.Fatalf("the snapshot is gone after apply: %v", err)
	}
	now, err := workspace.Snapshot(repo, workspace.All)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(base, now) {
		t.Errorf("snapshot after apply = %v, want the applied folder %v", base, now)
	}
	if _, err := os.Stat(filepath.Join(dirs.Staging(sandboxName), "files")); err == nil {
		t.Error("the applied copy is still staged")
	}
	out, code = runCLI(t, "", "apply", "--sandbox", sandboxName)
	if code != 1 || !strings.Contains(out, "its changes were applied") {
		t.Errorf("apply again: exit %d:\n%s", code, out)
	}
}

func TestApplyRefusesOverwritingEdits(t *testing.T) {
	repo := stagedFixture(t)
	if err := os.WriteFile(filepath.Join(repo, "app.py"), []byte("mine\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out, code := runCLI(t, "", "apply", "--yes", "--sandbox", sandboxName)
	if code != 1 || !strings.Contains(out, "Not applied") || !strings.Contains(out, "app.py") {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	if b, _ := os.ReadFile(filepath.Join(repo, "app.py")); string(b) != "mine\n" {
		t.Error("your edit was overwritten")
	}
}

// A staged copy that is missing without an apply on record is not reported
// as applied: that is how the work lost on 18 October 2026 looked.
func TestMissingCopyIsNotCalledApplied(t *testing.T) {
	repo := stagedFixture(t)
	dirs, _ := config.Default()
	if err := os.RemoveAll(filepath.Join(dirs.Staging(sandboxName), "files")); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"diff"}, {"apply", "--yes"}} {
		out, code := runCLI(t, "", append(args, "--sandbox", sandboxName)...)
		if code != 1 || strings.Contains(out, "were applied") || !strings.Contains(out, "the copy of its files is missing and no apply was recorded") {
			t.Errorf("%s: exit %d:\n%s", args[0], code, out)
		}
	}
	if b, _ := os.ReadFile(filepath.Join(repo, "app.py")); strings.Contains(string(b), "import sys") {
		t.Error("the project changed")
	}
}
