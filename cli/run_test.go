package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// recordingRuntime puts an openshell and an openshell-prover on PATH that
// print nothing and append each command line to the file it returns.
func recordingRuntime(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	calls := filepath.Join(dir, "calls.txt")
	for _, bin := range []string{"openshell", "openshell-prover", "docker", "podman"} {
		script := "#!/bin/sh\necho \"" + bin + " $*\" >> '" + calls + "'\n"
		if err := os.WriteFile(filepath.Join(dir, bin), []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	return calls
}

func TestRunRefusesTheHomeFolder(t *testing.T) {
	calls := recordingRuntime(t)
	root := t.TempDir()
	home := filepath.Join(root, "Users", "ana")
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	for dir, want := range map[string]string{
		home:                         "that is your home folder",
		filepath.Join(root, "Users"): "that folder holds your home folder",
	} {
		t.Chdir(dir)
		out, code := runCLI(t, "", "run", "claude")
		if code != 1 || !strings.Contains(out, want) || !strings.Contains(out, "cd into one project folder first") {
			t.Errorf("%s: exit %d:\n%s", dir, code, out)
		}
	}
	if b, err := os.ReadFile(calls); err == nil && len(b) > 0 {
		t.Errorf("the runtime was called from the home folder:\n%s", b)
	}
}
