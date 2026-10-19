package main

import (
	"bytes"
	"os"
	"os/exec"
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

// Files another tool runs on this machine once applied are labelled in the
// summary and the patch. They are still applied.
func TestDiffLabelsFilesThatRunOnThisMachine(t *testing.T) {
	repo := stagedFixture(t)
	dirs, _ := config.Default()
	staged := filepath.Join(dirs.Staging(sandboxName), "files")
	for p, body := range map[string]string{
		".envrc":                "export PATH=$PWD/bin:$PATH\n",
		".husky/pre-commit":     "npx lint-staged\n",
		".vscode/tasks.json":    `{"tasks":[{"runOptions":{"runOn":"folderOpen"}}]}` + "\n",
		"web/package.json":      `{"scripts":{"postinstall":"node setup.js"}}` + "\n",
		"web/package-lock.json": "{}\n",
	} {
		path := filepath.Join(staged, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	out, code := runCLI(t, "", "diff", "--sandbox", sandboxName)
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	for _, want := range []string{
		"! direnv runs it when you enter the folder",
		"! a git hook; git runs it on commit or push",
		"! VS Code can run its tasks when the folder opens",
		"! its scripts changed; npm runs them on install",
		"── .envrc  new  +1  ! direnv runs it",
		"4 files marked ! run on this machine once applied",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "package-lock.json") && strings.Contains(line, "!") || strings.Contains(line, "app.py") && strings.Contains(line, "!") {
			t.Errorf("labelled a file that runs nothing: %q", line)
		}
	}

	out, code = runCLI(t, "", "apply", "--yes", "--sandbox", sandboxName)
	if code != 0 || !strings.Contains(out, "Applied") {
		t.Fatalf("apply: exit %d:\n%s", code, out)
	}
	for _, p := range []string{".envrc", ".husky/pre-commit", ".vscode/tasks.json", "web/package.json"} {
		if _, err := os.Stat(filepath.Join(repo, filepath.FromSlash(p))); err != nil {
			t.Errorf("%s was not applied: %v", p, err)
		}
	}
}

// landedFixture is stagedFixture for a sandbox that round-tripped the
// history: a real repository on main with an uncommitted edit, the agent's
// commits landed as claude/fix, and the files staged for the diff.
func landedFixture(t *testing.T) (repo string, g func(...string) string, rec *config.Git) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	cfg := filepath.Join(t.TempDir(), "gitconfig")
	os.WriteFile(cfg, []byte("[user]\n\tname = Michael Host\n\temail = m@host.invalid\n[init]\n\tdefaultBranch = main\n"), 0o600)
	t.Setenv("GIT_CONFIG_GLOBAL", cfg)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	repo = t.TempDir()
	if real, err := filepath.EvalSymlinks(repo); err == nil {
		repo = real
	}
	g = func(args ...string) string {
		t.Helper()
		out, err := exec.Command("git", append([]string{"-C", repo}, args...)...).CombinedOutput()
		if err != nil {
			t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
		}
		return strings.TrimSpace(string(out))
	}
	g("init", "-q")
	os.WriteFile(filepath.Join(repo, "app.py"), []byte("print('hi')\n"), 0o644)
	os.WriteFile(filepath.Join(repo, "old.txt"), []byte("remove me\n"), 0o644)
	g("add", "-A")
	g("commit", "-qm", "base")
	head := g("rev-parse", "HEAD")
	// The developer's uncommitted edit, which the start commit holds.
	os.WriteFile(filepath.Join(repo, "app.py"), []byte("print('hi')\n# mine\n"), 0o644)
	start, _, err := workspace.Start(repo, sandboxName)
	if err != nil {
		t.Fatal(err)
	}
	// The agent's work, made in a clone of the start.
	sb := t.TempDir()
	sg := func(args ...string) string {
		t.Helper()
		out, err := exec.Command("git", append([]string{"-C", sb}, args...)...).CombinedOutput()
		if err != nil {
			t.Fatalf("sandbox git %s: %v\n%s", strings.Join(args, " "), err, out)
		}
		return strings.TrimSpace(string(out))
	}
	sg("init", "-q")
	sg("fetch", "-q", repo, start)
	sg("switch", "-qc", "claude/fix", start)
	sg("config", "user.name", "Claude (fenzi sandbox)")
	sg("config", "user.email", "claude@sandbox.fenzi.dev")
	os.WriteFile(filepath.Join(sb, "app.py"), []byte("import sys\nprint('hello', sys.argv)\n# mine\n"), 0o644)
	os.WriteFile(filepath.Join(sb, "new.py"), []byte("VALUE = 1\n"), 0o644)
	os.Remove(filepath.Join(sb, "old.txt"))
	sg("add", "-A")
	sg("commit", "-qm", "agent")
	tip := sg("rev-parse", "HEAD")
	bundle := filepath.Join(t.TempDir(), "out.bundle")
	sg("bundle", "create", "-q", bundle, "HEAD", "--branches", "--not", start)
	fetched, err := workspace.FetchOut(repo, sandboxName, bundle, "fenzi/web-1a2b")
	if err != nil {
		t.Fatal(err)
	}
	landed, err := workspace.Land(repo, sandboxName, "main", fetched[0])
	if err != nil {
		t.Fatal(err)
	}
	rec = &config.Git{Branch: "main", Head: head, Dirty: true, History: true, Start: start, AgentBranch: "fenzi/web-1a2b", Landed: landed, Tip: tip, Commits: 1}

	// The files, staged as the download leaves them.
	dirs, _ := config.Default()
	stage := dirs.Staging(sandboxName)
	staged := filepath.Join(stage, "files")
	os.MkdirAll(staged, 0o700)
	base, _ := workspace.Snapshot(repo, workspace.All)
	base.Save(filepath.Join(stage, "base.json"))
	os.WriteFile(filepath.Join(staged, "app.py"), []byte("import sys\nprint('hello', sys.argv)\n# mine\n"), 0o644)
	os.WriteFile(filepath.Join(staged, "new.py"), []byte("VALUE = 1\n"), 0o644)
	s := &config.State{}
	s.Put(config.Sandbox{Name: sandboxName, Agent: "claude", Repo: repo, Created: time.Now(), Git: rec})
	if err := dirs.SaveState(s); err != nil {
		t.Fatal(err)
	}
	return repo, g, rec
}

// With the agent's commits landed, apply fast-forwards the branch and never
// copies files; a second apply finds them merged, so a change never exists
// twice.
func TestApplyMergesTheLandedBranch(t *testing.T) {
	repo, g, rec := landedFixture(t)
	out, code := runCLI(t, "", "diff", "--sandbox", sandboxName)
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	for _, want := range []string{"3 files changed in 1 commit by Claude Code on claude/fix", "not merged yet", "main is unchanged; the commits are on claude/fix", "fast-forwards main to them"} {
		if !strings.Contains(out, want) {
			t.Errorf("diff: missing %q in:\n%s", want, out)
		}
	}
	out, code = runCLI(t, "\n", "apply", "--sandbox", sandboxName)
	if code != 0 || !strings.Contains(out, "Merge claude/fix into main? [y/N]") || !strings.Contains(out, "main is unchanged") {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	if g("rev-parse", "HEAD") != rec.Head {
		t.Fatal("main moved without a yes")
	}
	out, code = runCLI(t, "", "apply", "--sandbox", sandboxName, "--yes")
	if code != 0 || !strings.Contains(out, "Merged") || !strings.Contains(out, "main is at "+rec.Tip[:7]+", 1 commit by Claude Code") {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	if g("rev-parse", "HEAD") != rec.Tip || g("branch", "--show-current") != "main" || g("status", "--porcelain") != "" {
		t.Errorf("main at %s, status %q", g("rev-parse", "HEAD"), g("status", "--porcelain"))
	}
	if b, _ := os.ReadFile(filepath.Join(repo, "app.py")); string(b) != "import sys\nprint('hello', sys.argv)\n# mine\n" {
		t.Errorf("app.py = %q", b)
	}
	if _, err := os.Stat(filepath.Join(repo, "old.txt")); err == nil {
		t.Error("old.txt is still there")
	}
	if g("log", "--format=%s", "-3") != "agent\nUncommitted changes when fenzi run started\nbase" {
		t.Errorf("log:\n%s", g("log", "--format=%s", "-3"))
	}
	dirs, _ := config.Default()
	if _, err := os.Stat(filepath.Join(dirs.Staging(sandboxName), "files")); err == nil {
		t.Error("the staged copy is still there")
	}
	s, _ := dirs.LoadState()
	if sb, _ := s.Find(sandboxName); sb.Git.Merged != rec.Tip {
		t.Errorf("record = %+v", sb.Git)
	}
	out, code = runCLI(t, "", "apply", "--sandbox", sandboxName, "--yes")
	if code != 1 || !strings.Contains(out, "its changes were applied") {
		t.Errorf("apply again: exit %d:\n%s", code, out)
	}
}

// The wrong branch is checked out at apply time: nothing is written.
func TestApplyRefusesOnAnotherBranch(t *testing.T) {
	repo, g, rec := landedFixture(t)
	g("stash", "-q")
	g("switch", "-qc", "other")
	out, code := runCLI(t, "", "apply", "--sandbox", sandboxName, "--yes")
	if code != 1 || !strings.Contains(out, "Not merged") || !strings.Contains(out, "the sandbox started on main and you are on other now") || !strings.Contains(out, "Next: git switch") || !strings.Contains(out, "or git merge claude/fix") {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	if g("rev-parse", "main") != rec.Head || g("rev-parse", "HEAD") != rec.Head {
		t.Error("a branch moved")
	}
	if _, err := os.Stat(filepath.Join(repo, "new.py")); err == nil {
		t.Error("a file was written")
	}
	// Back on main with the same edits: it works.
	g("switch", "-q", "main")
	g("stash", "pop", "-q")
	out, code = runCLI(t, "", "apply", "--sandbox", sandboxName, "--yes")
	if code != 0 || !strings.Contains(out, "Merged") {
		t.Fatalf("exit %d:\n%s", code, out)
	}
}

// The developer merged the branch themselves: apply says so and copies
// nothing, so the change is not applied a second time as edits.
func TestApplyFindsTheBranchAlreadyMerged(t *testing.T) {
	repo, g, rec := landedFixture(t)
	g("stash", "-q")
	g("merge", "-q", "--ff-only", "claude/fix")
	out, code := runCLI(t, "", "apply", "--sandbox", sandboxName, "--yes")
	if code != 0 || !strings.Contains(out, "Already merged") {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	if g("rev-parse", "HEAD") != rec.Tip || g("status", "--porcelain") != "" {
		t.Error("the folder was changed")
	}
	_ = repo
}
