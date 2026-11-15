package workspace

import (
	"strings"
	"testing"
)

func TestReadBranchesAndSwitch(t *testing.T) {
	repo, g := gitRepo(t)
	b := ReadBranches(repo)
	if !b.Repo || b.Current != "main" || b.Detached || b.Dirty || strings.Join(b.Local, ",") != "main" {
		t.Errorf("clean repo: %+v", b)
	}
	if b := ReadBranches(t.TempDir()); b.Repo {
		t.Error("a plain folder has branches")
	}

	// A new branch from the checked-out commit, then one from another branch.
	if err := Switch(repo, "feature/x", "", true); err != nil {
		t.Fatal(err)
	}
	if b := ReadBranches(repo); b.Current != "feature/x" || strings.Join(b.Local, ",") != "feature/x,main" {
		t.Errorf("after creating: %+v", b)
	}
	write(t, repo, "x.txt", "x\n")
	g("add", "x.txt")
	g("commit", "-qm", "x")
	if err := Switch(repo, "from-main", "main", true); err != nil {
		t.Fatal(err)
	}
	if g("rev-parse", "HEAD") != g("rev-parse", "main") {
		t.Error("from-main did not start at main")
	}
	if !HasBranch(repo, "from-main") || HasBranch(repo, "nope") {
		t.Error("HasBranch")
	}

	// Switching to an existing branch; refusals in words.
	if err := Switch(repo, "feature/x", "", false); err != nil {
		t.Fatal(err)
	}
	if b := ReadBranches(repo); b.Current != "feature/x" {
		t.Errorf("after switching: %+v", b)
	}
	if err := Switch(repo, "nope", "", false); err == nil || !strings.Contains(err.Error(), "no local branch nope") {
		t.Errorf("missing branch: %v", err)
	}
	if err := Switch(repo, "bad name", "", true); err == nil || !strings.Contains(err.Error(), "not a branch name") {
		t.Errorf("bad name: %v", err)
	}
	if err := Switch(repo, "from-nowhere", "nowhere", true); err == nil || !strings.Contains(err.Error(), "not a branch or commit") {
		t.Errorf("bad source: %v", err)
	}
	if err := Switch(repo, "", "", false); err == nil {
		t.Error("an empty name switched")
	}

	// Uncommitted edits come along; the folder reads as dirty.
	dirty(t, repo, g)
	if err := Switch(repo, "main", "", false); err != nil {
		t.Fatal(err)
	}
	if b := ReadBranches(repo); b.Current != "main" || !b.Dirty {
		t.Errorf("edits did not come along: %+v", b)
	}

	// Detached HEAD reads as such.
	g("checkout", "-q", "--detach")
	if b := ReadBranches(repo); !b.Detached || b.Current != "" {
		t.Errorf("detached: %+v", b)
	}
}
