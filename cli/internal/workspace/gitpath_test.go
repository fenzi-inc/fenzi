package workspace

import (
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
)

func TestIsGitPath(t *testing.T) {
	for rel, want := range map[string]bool{
		".git":                      true,
		".git/HEAD":                 true,
		".GIT/hooks/pre-commit":     true,
		".Git/config":               true,
		"sub/.git":                  true, // a gitlink file
		"sub/.git/config":           true,
		"a/b/.gIt/hooks/x":          true,
		".git./config":              true, // NTFS drops the trailing dot
		".git /config":              true,
		"GIT~1/config":              true, // NTFS short name
		".g\u200cit/hooks/pre-push": true, // HFS+ ignores the joiner
		"\ufeff.git/config":         true,
		".github/workflows/ci.yml":  false,
		".gitignore":                false,
		".gitmodules":               false,
		".gitattributes":            false,
		"git/config":                false,
		"x.git/config":              false,
		"src/.git-blame-ignore":     false,
		"docs/dot.git":              false,
	} {
		if got := isGitPath(rel); got != want {
			t.Errorf("isGitPath(%q) = %v, want %v", rel, got, want)
		}
	}
}

// The agent makes sub/.git with a core.fsmonitor command. If it came back
// as ordinary files, a plain git status in sub/ would run that command on
// this machine.
func TestNestedGitIsNeverCopied(t *testing.T) {
	repo, staged := t.TempDir(), t.TempDir()
	write(t, repo, "sub/main.go", "package main\n")
	base, err := Snapshot(repo, All)
	if err != nil {
		t.Fatal(err)
	}
	copyTree(t, repo, staged)
	marker := filepath.Join(t.TempDir(), "ran")
	write(t, staged, "sub/.git/HEAD", "ref: refs/heads/main\n")
	// The # drops the arguments git adds, which touch would make files of.
	write(t, staged, "sub/.git/config", "[core]\n\trepositoryformatversion = 0\n\tfsmonitor = \"touch "+marker+" #\"\n")
	write(t, staged, "sub/.git/objects/info/packs", "")
	write(t, staged, "sub/.git/refs/heads/.keep", "")
	write(t, staged, "sub/.git/hooks/pre-commit", "#!/bin/sh\ntouch "+marker+"\n")
	os.Chmod(filepath.Join(staged, "sub/.git/hooks/pre-commit"), 0o755)
	write(t, staged, "vendor/lib/.git", "gitdir: ../../sub/.git\n")
	write(t, staged, "sub/main.go", "package main\n\nfunc main() {}\n")

	// The staged sub/ is a live repository: git status there runs the
	// command. That is what must not reach the project.
	_, err = exec.LookPath("git")
	hasGit := err == nil
	if hasGit {
		exec.Command("git", "-C", filepath.Join(staged, "sub"), "status").Run()
		if _, err := os.Stat(marker); err != nil {
			t.Fatal("the fixture's fsmonitor did not run in the staged copy; the test proves nothing")
		}
		os.Remove(marker)
	}

	// A Filter that keeps everything must not let them in either.
	keepAll := func(rels []string) ([]string, error) { return rels, nil }
	for name, filter := range map[string]Filter{"All": All, "keepAll": keepAll} {
		changes, err := Changes(base, staged, filter)
		if err != nil {
			t.Fatal(err)
		}
		if want := []Change{{"sub/main.go", Modified}}; !reflect.DeepEqual(changes, want) {
			t.Fatalf("%s: changes = %v, want %v", name, changes, want)
		}
	}
	changes, _ := Changes(base, staged, All)
	if err := Apply(repo, staged, changes); err != nil {
		t.Fatal(err)
	}
	for _, rel := range []string{"sub/.git", "vendor/lib/.git", "vendor"} {
		if _, err := os.Lstat(filepath.Join(repo, rel)); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("%s was written to the project", rel)
		}
	}
	if hasGit {
		exec.Command("git", "-C", filepath.Join(repo, "sub"), "status").Run()
		if _, err := os.Stat(marker); err == nil {
			t.Fatal("git status in sub/ ran the agent's fsmonitor command")
		}
	}
}

// From the case-sensitive Linux sandbox, .GIT is a folder of its own. On a
// case-insensitive disk it is the project's .git, so the agent's pre-commit
// would become the real hook.
func TestCaseVariantGitIsNeverCopied(t *testing.T) {
	repo, staged := t.TempDir(), t.TempDir()
	write(t, repo, ".git/HEAD", "ref: refs/heads/main\n")
	write(t, repo, "app.py", "print(1)\n")
	base, err := Snapshot(repo, All)
	if err != nil {
		t.Fatal(err)
	}
	write(t, staged, "app.py", "print(2)\n")
	write(t, staged, ".GIT/hooks/pre-commit", "#!/bin/sh\necho owned\n")
	write(t, staged, ".Git/config", "[core]\n\tfsmonitor = echo owned\n")

	changes, err := Changes(base, staged, All)
	if err != nil {
		t.Fatal(err)
	}
	if want := []Change{{"app.py", Modified}}; !reflect.DeepEqual(changes, want) {
		t.Fatalf("changes = %v, want %v", changes, want)
	}
	if err := Apply(repo, staged, changes); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(repo, ".git", "hooks", "pre-commit")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("the agent's hook landed in the project's .git")
	}
	if b, _ := os.ReadFile(filepath.Join(repo, ".git", "HEAD")); string(b) != "ref: refs/heads/main\n" {
		t.Fatalf(".git/HEAD = %q", b)
	}
}

// Apply refuses git internals even in a change list it is handed directly,
// and refuses the whole list before it writes any of it.
func TestApplyRefusesGitInternals(t *testing.T) {
	for _, bad := range []Change{
		{".GIT/hooks/pre-commit", Added},
		{"sub/.git/config", Added},
		{"sub/.git", Modified},
		{".git/index", Deleted},
	} {
		repo, staged := t.TempDir(), t.TempDir()
		write(t, staged, "a.txt", "agent")
		write(t, staged, bad.Path, "x")
		write(t, repo, ".git/index", "keep")
		if err := Apply(repo, staged, []Change{{"a.txt", Added}, bad}); err == nil {
			t.Errorf("%s: Apply did not refuse", bad.Path)
		}
		if _, err := os.Stat(filepath.Join(repo, "a.txt")); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("%s: a.txt was written before the refusal", bad.Path)
		}
		if b, _ := os.ReadFile(filepath.Join(repo, ".git", "index")); string(b) != "keep" {
			t.Errorf("%s: .git/index = %q", bad.Path, b)
		}
	}
}

// A snapshot saved before nested .git was skipped can list a submodule's
// gitlink. That is not a file the agent deleted.
func TestOldSnapshotGitEntriesAreNotDeleted(t *testing.T) {
	repo, staged := t.TempDir(), t.TempDir()
	write(t, repo, "lib/.git", "gitdir: ../.git/modules/lib\n")
	write(t, repo, "lib/a.c", "1")
	write(t, staged, "lib/a.c", "1")
	base := Manifest{"lib/.git": "old", "lib/a.c": mustHash(t, filepath.Join(repo, "lib/a.c"))}
	changes, err := Changes(base, staged, All)
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 0 {
		t.Fatalf("changes = %v, want none", changes)
	}
	next, err := Applied(base, staged, changes)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := next["lib/.git"]; ok {
		t.Error("the next snapshot still lists lib/.git")
	}
}

func mustHash(t *testing.T, path string) string {
	t.Helper()
	sum, err := hashFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return sum
}
