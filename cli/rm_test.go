package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"fenzi/cli/internal/config"
	"fenzi/cli/internal/run"
)

// rmFixture is a machine with one running sandbox and two finished ones:
// fenzi-old-1111 with staged changes and a saved log, fenzi-old-2222 with a saved
// log only. The fake gateway lists only the running one, as a real one does.
func rmFixture(t *testing.T) config.Dirs {
	t.Helper()
	fakeRuntime(t, map[string]reply{"sandbox list": {out: "fenzi-live-0000\n"}}, "")
	now := time.Now()
	dirs := seedState(t,
		config.Sandbox{Name: "fenzi-live-0000", Agent: "claude", Repo: "/Users/ana/web", Created: now, Running: true},
		config.Sandbox{Name: "fenzi-old-1111", Agent: "codex", Repo: "/Users/ana/web", Created: now.Add(-time.Hour)},
		config.Sandbox{Name: "fenzi-old-2222", Agent: "claude", Repo: "/Users/ana/api", Created: now.Add(-2 * time.Hour)},
	)
	for _, name := range []string{"fenzi-live-0000", "fenzi-old-1111", "fenzi-old-2222"} {
		if err := os.MkdirAll(dirs.Run(name), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dirs.Run(name), run.LogFile), []byte(decisionLines), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	files := filepath.Join(dirs.Staging("fenzi-old-1111"), "files")
	if err := os.MkdirAll(files, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dirs.Staging("fenzi-old-1111"), "base.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(files, "app.py"), []byte("print(1)\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return dirs
}

func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func names(t *testing.T, dirs config.Dirs) []string {
	t.Helper()
	s, err := dirs.LoadState()
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, sb := range s.Sandboxes {
		out = append(out, sb.Name)
	}
	return out
}

func TestRmRemovesAFinishedSandbox(t *testing.T) {
	dirs := rmFixture(t)
	out, code := runCLI(t, "", "rm", "fenzi-old-1111")
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	for _, want := range []string{"1 sandbox removed", "✓ fenzi-old-1111", "record, staged changes, saved log"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if got := strings.Join(names(t, dirs), " "); got != "fenzi-live-0000 fenzi-old-2222" {
		t.Errorf("state = %q", got)
	}
	if exists(dirs.Staging("fenzi-old-1111")) || exists(dirs.Run("fenzi-old-1111")) {
		t.Error("the staging or run folder is still there")
	}
	if !exists(dirs.Run("fenzi-old-2222")) || !exists(dirs.Run("fenzi-live-0000")) {
		t.Error("another sandbox's folder went too")
	}
	// Gone from the list, and no longer an answer for fenzi log.
	var errOut bytes.Buffer
	var out2 bytes.Buffer
	if code := cli([]string{"log", "--sandbox", "fenzi-old-1111"}, strings.NewReader(""), &out2, &errOut); code == 0 {
		t.Errorf("log still reads the removed sandbox:\n%s", out2.String())
	}
}

func TestRmRefusesARunningSandbox(t *testing.T) {
	dirs := rmFixture(t)
	out, code := runCLI(t, "", "rm", "fenzi-live-0000")
	if code != 1 {
		t.Fatalf("exit %d, want 1:\n%s", code, out)
	}
	if !strings.Contains(out, "Nothing removed") || !strings.Contains(out, "! fenzi-live-0000") || !strings.Contains(out, "is running; fenzi stop fenzi-live-0000 ends it first") {
		t.Errorf("output:\n%s", out)
	}
	if len(names(t, dirs)) != 3 || !exists(dirs.Run("fenzi-live-0000")) {
		t.Error("something was removed")
	}
	// A sandbox the gateway runs that the state never saw counts as running too.
	fakeRuntime(t, map[string]reply{"sandbox list": {out: "fenzi-other-9999\n"}}, "")
	out, code = runCLI(t, "", "rm", "fenzi-other-9999")
	if code != 1 || !strings.Contains(out, "! fenzi-other-9999") || !strings.Contains(out, "is running; fenzi stop fenzi-other-9999 ends it first") {
		t.Errorf("exit %d:\n%s", code, out)
	}
}

func TestRmUnknownNameIsAnError(t *testing.T) {
	dirs := rmFixture(t)
	var out, errOut bytes.Buffer
	if code := cli([]string{"rm", "fenzi-old-1111", "fenzi-nope-0000"}, strings.NewReader(""), &out, &errOut); code != 1 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(errOut.String(), "fenzi-nope-0000 is not a sandbox on this machine") {
		t.Errorf("stderr %q", errOut.String())
	}
	if len(names(t, dirs)) != 3 || !exists(dirs.Staging("fenzi-old-1111")) {
		t.Error("a sandbox was removed although one name was unknown")
	}
	errOut.Reset()
	if code := cli([]string{"rm"}, strings.NewReader(""), &out, &errOut); code != 1 || !strings.Contains(errOut.String(), "--finished") {
		t.Errorf("rm with nothing: exit %d, stderr %q", code, errOut.String())
	}
	errOut.Reset()
	if code := cli([]string{"rm", "--finished", "fenzi-old-1111"}, strings.NewReader(""), &out, &errOut); code != 1 || !strings.Contains(errOut.String(), "not both") {
		t.Errorf("rm --finished with a name: exit %d, stderr %q", code, errOut.String())
	}
}

func TestRmFinished(t *testing.T) {
	dirs := rmFixture(t)
	out, code := runCLI(t, "", "rm", "--finished")
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	for _, want := range []string{"2 sandboxes removed", "✓ fenzi-old-1111", "✓ fenzi-old-2222", "record, saved log"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "fenzi-live-0000") {
		t.Errorf("the running sandbox is mentioned:\n%s", out)
	}
	if got := strings.Join(names(t, dirs), " "); got != "fenzi-live-0000" {
		t.Errorf("state = %q", got)
	}
	if exists(dirs.Run("fenzi-old-2222")) || !exists(dirs.Run("fenzi-live-0000")) {
		t.Error("wrong folders removed")
	}
	// Nothing left to remove.
	out, code = runCLI(t, "", "rm", "--finished")
	if code != 0 || !strings.Contains(out, "No finished sandboxes") {
		t.Errorf("exit %d:\n%s", code, out)
	}
}

func TestJSONRm(t *testing.T) {
	dirs := rmFixture(t)
	var doc jsonRm
	stderr, code := runJSON(t, &doc, "rm", "fenzi-old-2222", "fenzi-live-0000", "--json")
	if code != 1 || stderr != "" {
		t.Fatalf("exit %d, want 1 for the refusal; stderr %q", code, stderr)
	}
	if len(doc.Removed) != 1 || doc.Removed[0] != (jsonRemoved{Name: "fenzi-old-2222", SavedLog: true}) {
		t.Errorf("removed = %+v", doc.Removed)
	}
	if len(doc.Refused) != 1 || doc.Refused[0] != (jsonRefused{Name: "fenzi-live-0000", Reason: "fenzi-live-0000 is running; fenzi stop fenzi-live-0000 ends it first"}) {
		t.Errorf("refused = %+v", doc.Refused)
	}
	if got := strings.Join(names(t, dirs), " "); got != "fenzi-live-0000 fenzi-old-1111" {
		t.Errorf("state = %q", got)
	}
	doc = jsonRm{}
	if stderr, code := runJSON(t, &doc, "rm", "--finished", "--json"); code != 0 || stderr != "" {
		t.Fatalf("--finished: exit %d stderr %q", code, stderr)
	}
	if len(doc.Removed) != 1 || doc.Removed[0] != (jsonRemoved{Name: "fenzi-old-1111", StagedChanges: true, SavedLog: true}) || doc.Refused == nil || len(doc.Refused) != 0 {
		t.Errorf("--finished = %+v", doc)
	}
	// Empty lists, not null, when there is nothing.
	var raw json.RawMessage
	if _, code := runJSON(t, &raw, "rm", "--finished", "--json"); code != 0 || string(raw) != "{\n  \"removed\": [],\n  \"refused\": []\n}" {
		t.Errorf("exit %d, doc %s", code, raw)
	}
	// An unknown name is an error on standard error, with nothing on standard output.
	raw = nil
	if stderr, code := runJSON(t, &raw, "rm", "fenzi-nope-0000", "--json"); code != 1 || raw != nil || !strings.Contains(stderr, "not a sandbox on this machine") {
		t.Errorf("unknown: exit %d stdout %q stderr %q", code, raw, stderr)
	}
}

func TestKeyRemoveNamesTheRunningSandbox(t *testing.T) {
	fakeRuntime(t, map[string]reply{"sandbox list": {out: "fenzi-live-0000\n"}}, "")
	seedState(t,
		config.Sandbox{Name: "fenzi-live-0000", Agent: "claude", Repo: "/Users/ana/web", Created: time.Now(), Running: true},
		config.Sandbox{Name: "fenzi-old-1111", Agent: "codex", Repo: "/Users/ana/web", Created: time.Now().Add(-time.Hour)},
	)
	var out, errOut bytes.Buffer
	if code := cli([]string{"key", "remove", "claude"}, strings.NewReader(""), &out, &errOut); code != 1 {
		t.Fatalf("exit %d:\n%s%s", code, out.String(), errOut.String())
	}
	if !strings.Contains(errOut.String(), "fenzi-live-0000 is running with the Claude Code key; stop it first (fenzi stop fenzi-live-0000)") {
		t.Errorf("stderr %q", errOut.String())
	}
	// Codex has no running sandbox, so its key can go.
	out.Reset()
	errOut.Reset()
	if code := cli([]string{"key", "remove", "codex"}, strings.NewReader(""), &out, &errOut); code != 0 || !strings.Contains(out.String(), "Removed") || !strings.Contains(out.String(), "the Codex key is gone from this machine") {
		t.Errorf("exit %d:\n%s%s", code, out.String(), errOut.String())
	}
}

// A hand-edited record whose name is empty or a path must not turn into a
// RemoveAll of the cache root or of a folder outside it.
func TestRmRefusesANameThatIsAPath(t *testing.T) {
	dirs := rmFixture(t)
	keep := filepath.Join(dirs.Cache, "runs", "fenzi-old-1111")
	for _, bad := range []string{"", ".", "..", "../runs", `a\b`} {
		s, err := dirs.LoadState()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := removeSandbox(dirs, s, bad); err == nil {
			t.Fatalf("removeSandbox(%q) succeeded", bad)
		}
		if _, err := os.Stat(keep); err != nil {
			t.Fatalf("removeSandbox(%q) touched another sandbox: %v", bad, err)
		}
	}
}
