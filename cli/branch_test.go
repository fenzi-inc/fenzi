package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// A repository with one commit on main, as the working directory.
func chdirRepo(t *testing.T) string {
	t.Helper()
	repo := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", repo, "-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false"}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run("init", "-q", "-b", "main")
	if err := os.WriteFile(filepath.Join(repo, "a.txt"), []byte("a\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	run("add", "a.txt")
	run("commit", "-qm", "a")
	t.Chdir(repo)
	return repo
}

func TestBranchListsSwitchesAndCreates(t *testing.T) {
	chdirRepo(t)
	var out bytes.Buffer
	e := env{stdin: strings.NewReader(""), stdout: &out, stderr: &out}

	if code, err := cmdBranch(e, []string{"--json"}); code != 0 || err != nil {
		t.Fatalf("list: %d %v\n%s", code, err, out.String())
	}
	var got struct {
		Repo    bool
		Current string
		Dirty   bool
		Local   []string
	}
	if err := json.Unmarshal(out.Bytes(), &got); err != nil || !got.Repo || got.Current != "main" || got.Dirty || strings.Join(got.Local, ",") != "main" {
		t.Fatalf("list: %+v %v\n%s", got, err, out.String())
	}

	out.Reset()
	if code, err := cmdBranch(e, []string{"--new", "--from", "main", "feature"}); code != 0 || err != nil || !strings.Contains(out.String(), "feature, created from main") {
		t.Fatalf("create: %d %v\n%s", code, err, out.String())
	}
	out.Reset()
	if code, err := cmdBranch(e, []string{"main"}); code != 0 || err != nil || !strings.Contains(out.String(), "main") {
		t.Fatalf("switch: %d %v\n%s", code, err, out.String())
	}
	out.Reset()
	if code, err := cmdBranch(e, nil); code != 0 || err != nil || !strings.Contains(out.String(), "Also here: feature") {
		t.Fatalf("plain list: %d %v\n%s", code, err, out.String())
	}

	// Refusals in words.
	for _, args := range [][]string{{"nope"}, {"--from", "main", "x"}, {"--new"}, {"a", "b"}} {
		out.Reset()
		if code, err := cmdBranch(e, args); code == 0 && err == nil {
			t.Errorf("%v was accepted:\n%s", args, out.String())
		}
	}
}

func TestBranchOutsideARepository(t *testing.T) {
	t.Chdir(t.TempDir())
	var out bytes.Buffer
	e := env{stdin: strings.NewReader(""), stdout: &out, stderr: &out}
	if code, _ := cmdBranch(e, nil); code != 3 || !strings.Contains(out.String(), "not a git repository") {
		t.Errorf("code %d:\n%s", code, out.String())
	}
	out.Reset()
	if code, err := cmdBranch(e, []string{"--json"}); code != 0 || err != nil || !strings.Contains(out.String(), `"repo": false`) {
		t.Errorf("json outside: %d %v\n%s", code, err, out.String())
	}
}

// fenzi run --branch: an existing branch is switched to, a new one created
// from --from or HEAD, and --from alone or with an existing branch refused.
func TestRunSwitchesTheBranchFirst(t *testing.T) {
	repo := chdirRepo(t)
	if created, err := switchBranch(repo, "", ""); created || err != nil {
		t.Errorf("no branch: %v %v", created, err)
	}
	if _, err := switchBranch(repo, "", "main"); err == nil {
		t.Error("--from alone was accepted")
	}
	if created, err := switchBranch(repo, "work", ""); !created || err != nil {
		t.Errorf("new branch: %v %v", created, err)
	}
	if created, err := switchBranch(repo, "main", ""); created || err != nil {
		t.Errorf("existing branch: %v %v", created, err)
	}
	if _, err := switchBranch(repo, "work", "main"); err == nil {
		t.Error("--from with an existing branch was accepted")
	}
	if created, err := switchBranch(repo, "from-main", "main"); !created || err != nil {
		t.Errorf("from main: %v %v", created, err)
	}
	if _, err := switchBranch(t.TempDir(), "x", ""); err == nil {
		t.Error("a plain folder accepted --branch")
	}
}
