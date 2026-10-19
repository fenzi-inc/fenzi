package workspace

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// gitRepo makes a repository with one commit on main, and isolates git from
// the developer's own configuration. It returns the repository and a
// function that runs git in it and fails the test on an error.
func gitRepo(t *testing.T) (string, func(args ...string) string) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	cfg := filepath.Join(t.TempDir(), "gitconfig")
	os.WriteFile(cfg, []byte("[user]\n\tname = Michael Host\n\temail = m@host.invalid\n[init]\n\tdefaultBranch = main\n"), 0o600)
	t.Setenv("GIT_CONFIG_GLOBAL", cfg)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	t.Setenv("GIT_AUTHOR_DATE", "2026-10-17T10:00:00Z")
	t.Setenv("GIT_COMMITTER_DATE", "2026-10-17T10:00:00Z")
	repo := t.TempDir()
	// macOS gives a /var path that resolves to /private/var; use the real one.
	if real, err := filepath.EvalSymlinks(repo); err == nil {
		repo = real
	}
	g := func(args ...string) string {
		t.Helper()
		out, err := git(repo, args...)
		if err != nil {
			t.Fatalf("git %s: %v", strings.Join(args, " "), err)
		}
		return out
	}
	g("init", "-q")
	write(t, repo, "a.txt", "a\n")
	write(t, repo, "b.txt", "b\n")
	write(t, repo, ".gitignore", ".env\n")
	write(t, repo, ".env", "SECRET=1\n")
	write(t, repo, "config.local", "cfg\n")
	g("add", "-A")
	g("commit", "-qm", "base")
	write(t, repo, ".gitignore", ".env\nconfig.local\n")
	g("commit", "-qam", "ignore a tracked file")
	return repo, g
}

// dirty makes the working tree of the scenario: an unstaged edit, a staged
// edit, an untracked file, an edit to a tracked file .gitignore matches.
func dirty(t *testing.T, repo string, g func(...string) string) {
	t.Helper()
	write(t, repo, "a.txt", "a2\n")
	write(t, repo, "b.txt", "b2\n")
	g("add", "b.txt")
	write(t, repo, "notes.txt", "n\n")
	write(t, repo, "config.local", "cfg2\n")
}

func TestReadRepo(t *testing.T) {
	repo, g := gitRepo(t)
	st := ReadRepo(repo)
	if !st.Repo || st.Branch != "main" || st.Head != g("rev-parse", "HEAD") || st.Dirty || st.FilesOnly != "" {
		t.Errorf("clean repo: %+v", st)
	}
	dirty(t, repo, g)
	if st := ReadRepo(repo); !st.Dirty {
		t.Error("edits were not seen")
	}
	if st := ReadRepo(filepath.Join(repo, "sub")); st.FilesOnly == "" {
		os.MkdirAll(filepath.Join(repo, "sub"), 0o755)
		st = ReadRepo(filepath.Join(repo, "sub"))
		if !st.Repo || !strings.Contains(st.FilesOnly, "not at its root") {
			t.Errorf("a subfolder: %+v", st)
		}
	}
	if st := ReadRepo(t.TempDir()); st.Repo {
		t.Error("a plain folder is not a repository")
	}
	g("checkout", "-q", "--detach")
	if st := ReadRepo(repo); st.Branch != "" || !st.Repo {
		t.Errorf("detached: %+v", st)
	}
	g("switch", "-q", "main")
	empty := t.TempDir()
	if _, err := git(empty, "init", "-q"); err != nil {
		t.Fatal(err)
	}
	if st := ReadRepo(empty); !st.Repo || !strings.Contains(st.FilesOnly, "no commit") {
		t.Errorf("unborn: %+v", st)
	}
	// A merge in progress.
	g("switch", "-qc", "side")
	write(t, repo, "a.txt", "side\n")
	g("commit", "-qam", "side")
	g("switch", "-q", "main")
	write(t, repo, "a.txt", "main\n")
	g("commit", "-qam", "main")
	exec.Command("git", "-C", repo, "merge", "side").Run()
	if st := ReadRepo(repo); !strings.Contains(st.FilesOnly, "merge is in progress") {
		t.Errorf("merge in progress: %+v", st)
	}
	g("merge", "--abort")
}

// Start pins HEAD when the folder is clean, and otherwise a commit holding
// the folder as it is: tracked files as on disk, the ignored tracked file
// included, untracked files that are not ignored, and nothing .gitignore
// matches. The same state gives the same commit twice, and the real index
// is not touched.
func TestStartCommit(t *testing.T) {
	repo, g := gitRepo(t)
	head := g("rev-parse", "HEAD")
	start, isDirty, err := Start(repo, "sb1")
	if err != nil || isDirty || start != head {
		t.Fatalf("clean start = %s %v %v, want HEAD", start, isDirty, err)
	}
	if g("rev-parse", StartRef("sb1")) != head {
		t.Error("the start ref does not pin HEAD")
	}

	dirty(t, repo, g)
	index1, _ := os.ReadFile(filepath.Join(repo, ".git", "index"))
	start, isDirty, err = Start(repo, "sb2")
	if err != nil || !isDirty || start == head {
		t.Fatalf("dirty start = %s %v %v", start, isDirty, err)
	}
	index2, _ := os.ReadFile(filepath.Join(repo, ".git", "index"))
	if string(index1) != string(index2) {
		t.Error("the real index changed")
	}
	if g("rev-parse", start+"^") != head {
		t.Error("the start commit is not on top of HEAD")
	}
	files := strings.Fields(g("ls-tree", "-r", "--name-only", start))
	if want := ".gitignore a.txt b.txt config.local notes.txt"; strings.Join(files, " ") != want {
		t.Errorf("start tree = %q, want %q", files, want)
	}
	if g("show", start+":a.txt") != "a2" || g("show", start+":config.local") != "cfg2" {
		t.Error("the start commit does not hold the files as they are on disk")
	}
	if g("log", "-1", "--format=%an <%ae> %cI", start) != "Michael Host <m@host.invalid> 2026-10-17T10:00:00Z" {
		t.Errorf("author and date: %s", g("log", "-1", "--format=%an <%ae> %cI", start))
	}
	again, _, err := Start(repo, "sb3")
	if err != nil || again != start {
		t.Errorf("the same state gave another commit: %s, %v", again, err)
	}
	if got := g("status", "--porcelain"); !strings.Contains(got, "M a.txt") || !strings.Contains(got, "M  b.txt") || !strings.Contains(got, "?? notes.txt") {
		t.Errorf("the working tree or index changed:\n%s", got)
	}
}

// agentWorks is the sandbox side done by hand in a second repository built
// from the bundle, as the rebuild script does it: the agent commits on a
// branch and leaves one file uncommitted, which becomes a checkpoint. It
// returns the sandbox repository and the bundle it made.
func agentWorks(t *testing.T, repo, sandbox, start string, g func(...string) string) (sb, bundle string) {
	t.Helper()
	in := filepath.Join(t.TempDir(), "start.bundle")
	if _, err := BundleIn(repo, sandbox, in); err != nil {
		t.Fatal(err)
	}
	sb = t.TempDir()
	run := func(args ...string) string {
		t.Helper()
		out, err := git(sb, args...)
		if err != nil {
			t.Fatalf("sandbox git %s: %v", strings.Join(args, " "), err)
		}
		return out
	}
	if _, err := exec.Command("git", "init", "-q", sb).Output(); err != nil {
		t.Fatal(err)
	}
	run("fetch", "-q", "--no-tags", in, StartRef(sandbox)+":refs/fenzi/start")
	run("update-ref", "refs/heads/fenzi/x", start)
	run("symbolic-ref", "HEAD", "refs/heads/fenzi/x")
	run("reset", "-q", "--hard")
	run("config", "user.name", "Claude (fenzi sandbox)")
	run("config", "user.email", "claude@sandbox.fenzi.dev")
	if run("rev-parse", "HEAD") != start {
		t.Fatal("the sandbox is not at the start commit")
	}
	run("switch", "-qc", "claude/fix")
	write(t, sb, "a.txt", "a3\n")
	write(t, sb, "z.txt", "z\n")
	run("add", "-A")
	run("commit", "-qm", "agent: fix a, add z")
	write(t, sb, "left.txt", "left\n")
	run("add", "-A")
	run("commit", "-qm", "Changes left uncommitted when Claude exited")
	bundle = filepath.Join(t.TempDir(), "out.bundle")
	run("bundle", "create", "-q", bundle, "HEAD", "--branches", "--not", start)
	return sb, bundle
}

func TestRoundTripLandsTheSameCommits(t *testing.T) {
	repo, g := gitRepo(t)
	dirty(t, repo, g)
	head := g("rev-parse", "HEAD")
	start, _, err := Start(repo, "sb")
	if err != nil {
		t.Fatal(err)
	}
	sb, bundle := agentWorks(t, repo, "sb", start, g)
	tip, _ := git(sb, "rev-parse", "HEAD")

	fetched, err := FetchOut(repo, "sb", bundle, "fenzi/x")
	if err != nil {
		t.Fatal(err)
	}
	if len(fetched) != 1 || fetched[0].Name != "claude/fix" || fetched[0].Head != tip {
		t.Fatalf("fetched %+v, want claude/fix at %s", fetched, tip)
	}
	landed, err := Land(repo, "sb", "main", fetched[0])
	if err != nil || landed != "claude/fix" {
		t.Fatalf("landed %q, %v", landed, err)
	}
	if g("rev-parse", "claude/fix") != tip {
		t.Error("the landed branch is not at the agent's commit")
	}
	if refs := g("for-each-ref", "refs/fenzi/"); refs != "" {
		t.Errorf("refs left under refs/fenzi: %s", refs)
	}
	if g("rev-parse", "HEAD") != head || g("branch", "--show-current") != "main" {
		t.Error("landing moved the checked-out branch")
	}
	if got := g("status", "--porcelain"); !strings.Contains(got, "M a.txt") {
		t.Errorf("landing changed the working tree:\n%s", got)
	}

	// Apply: the folder still holds exactly the edits it had at start.
	if err := FastForward(repo, Landing{Branch: "main", Head: head, Start: start, Tip: tip}); err != nil {
		t.Fatalf("fast-forward: %v", err)
	}
	if g("rev-parse", "HEAD") != tip || g("branch", "--show-current") != "main" {
		t.Error("main is not at the tip")
	}
	if got := g("status", "--porcelain"); got != "" {
		t.Errorf("the folder is not clean after the fast-forward:\n%s", got)
	}
	for rel, want := range map[string]string{"a.txt": "a3\n", "b.txt": "b2\n", "z.txt": "z\n", "left.txt": "left\n", "notes.txt": "n\n", "config.local": "cfg2\n", ".env": "SECRET=1\n"} {
		if b, _ := os.ReadFile(filepath.Join(repo, rel)); string(b) != want {
			t.Errorf("%s = %q, want %q", rel, b, want)
		}
	}
	if !strings.Contains(g("log", "--format=%s", "main"), "Uncommitted changes when fenzi run started") {
		t.Error("the developer's edits are not a commit on main")
	}
	// The same change twice: a second apply finds it there already.
	if err := FastForward(repo, Landing{Branch: "main", Head: head, Start: start, Tip: tip}); !errors.Is(err, ErrMerged) {
		t.Errorf("second apply: %v, want ErrMerged", err)
	}
}

// The clean start, where the developer stashed nothing because there was
// nothing: the fast-forward works the same way.
func TestFastForwardFromACleanStart(t *testing.T) {
	repo, g := gitRepo(t)
	head := g("rev-parse", "HEAD")
	start, _, _ := Start(repo, "sb")
	sb, bundle := agentWorks(t, repo, "sb", start, g)
	tip, _ := git(sb, "rev-parse", "HEAD")
	fetched, err := FetchOut(repo, "sb", bundle, "fenzi/x")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Land(repo, "sb", "main", fetched[0]); err != nil {
		t.Fatal(err)
	}
	if err := FastForward(repo, Landing{Branch: "main", Head: head, Start: start, Tip: tip}); err != nil {
		t.Fatal(err)
	}
	if g("rev-parse", "HEAD") != tip || g("status", "--porcelain") != "" {
		t.Error("main is not at the tip with a clean folder")
	}
}

func TestFastForwardRefusals(t *testing.T) {
	repo, g := gitRepo(t)
	head := g("rev-parse", "HEAD")
	start, _, _ := Start(repo, "sb")
	sb, bundle := agentWorks(t, repo, "sb", start, g)
	tip, _ := git(sb, "rev-parse", "HEAD")
	fetched, _ := FetchOut(repo, "sb", bundle, "fenzi/x")
	if _, err := Land(repo, "sb", "main", fetched[0]); err != nil {
		t.Fatal(err)
	}
	l := Landing{Branch: "main", Head: head, Start: start, Tip: tip}
	refused := func(name, want string) {
		t.Helper()
		before := g("rev-parse", "main")
		err := FastForward(repo, l)
		var r *Refusal
		if !errors.As(err, &r) || !strings.Contains(r.Reason, want) {
			t.Errorf("%s: %v, want a refusal about %q", name, err, want)
		}
		if g("rev-parse", "main") != before {
			t.Fatalf("%s: main moved", name)
		}
	}
	// The wrong branch is checked out.
	g("switch", "-qc", "other")
	refused("other branch", "you are on other now")
	g("switch", "-q", "main")
	// The folder has edits since the start.
	write(t, repo, "a.txt", "mine\n")
	refused("edits", "edits since the sandbox started")
	g("checkout", "-q", "--", "a.txt")
	// The branch moved.
	write(t, repo, "c.txt", "c\n")
	g("add", "c.txt")
	g("commit", "-qm", "mine")
	refused("moved", "moved from")
	g("reset", "-q", "--hard", head)
	// Detached at start.
	l.Branch = ""
	refused("detached", "no branch was checked out")
	l.Branch = "main"
	// The agent rewrote the start.
	l.Start = g("rev-parse", "HEAD~1")
	rewritten, _ := git(sb, "commit-tree", tip+"^{tree}", "-p", l.Start, "-m", "rewritten")
	git(sb, "update-ref", "refs/heads/rewrite", rewritten)
	out := filepath.Join(t.TempDir(), "rewrite.bundle")
	git(sb, "bundle", "create", "-q", out, "refs/heads/rewrite", "--not", l.Start)
	f, err := FetchOut(repo, "sb2", out, "")
	if err != nil {
		t.Fatal(err)
	}
	l.Start, l.Tip = start, f[0].Head
	refused("rewrite", "rewrote commits")
	// Everything in place: it works.
	l.Tip = tip
	if err := FastForward(repo, l); err != nil {
		t.Fatal(err)
	}
}

// Land never moves the branch the sandbox started on or the one checked
// out, and does not replace a branch of the same name with other commits.
func TestLandNames(t *testing.T) {
	repo, g := gitRepo(t)
	head := g("rev-parse", "HEAD")
	start, _, _ := Start(repo, "sb")
	sb, bundle := agentWorks(t, repo, "sb", start, g)
	tip, _ := git(sb, "rev-parse", "HEAD")
	fetched, _ := FetchOut(repo, "sb", bundle, "fenzi/x")
	// An unrelated branch of the agent's name exists.
	g("branch", "claude/fix", head)
	write(t, repo, "x.txt", "x\n")
	g("switch", "-q", "claude/fix")
	g("add", "x.txt")
	g("commit", "-qm", "unrelated")
	unrelated := g("rev-parse", "HEAD")
	g("switch", "-q", "main")
	landed, err := Land(repo, "sb", "main", fetched[0])
	if err != nil || landed != "fenzi/sb/claude/fix" {
		t.Fatalf("landed as %q, %v", landed, err)
	}
	if g("rev-parse", "claude/fix") != unrelated || g("rev-parse", "fenzi/sb/claude/fix") != tip {
		t.Error("the unrelated branch was replaced, or the agent's commits did not land")
	}
	// The agent used the developer's branch name: never that branch.
	landed, err = Land(repo, "sb", "main", Fetched{Name: "main", Head: tip})
	if err != nil || landed != "fenzi/sb/main" || g("rev-parse", "main") != head {
		t.Errorf("landed on %q (%v), main at %s", landed, err, g("rev-parse", "main"))
	}
	// A branch Fenzi landed earlier for the same sandbox is fast-forwarded.
	later, _ := git(sb, "commit-tree", tip+"^{tree}", "-p", tip, "-m", "later")
	git(sb, "update-ref", "refs/heads/claude/fix", later)
	out := filepath.Join(t.TempDir(), "later.bundle")
	git(sb, "bundle", "create", "-q", out, "refs/heads/claude/fix", "--not", start)
	f, err := FetchOut(repo, "sb", out, "")
	if err != nil {
		t.Fatal(err)
	}
	landed, err = Land(repo, "sb", "main", f[0])
	if err != nil || landed != "fenzi/sb/claude/fix" || g("rev-parse", "fenzi/sb/claude/fix") != later {
		t.Errorf("second landing: %q %v at %s", landed, err, g("rev-parse", "fenzi/sb/claude/fix"))
	}
}

// The agent names its branch after one of the developer's: develop here, an
// old branch already merged into main and so an ancestor of everything. It
// is never moved; the commits land under fenzi/<sandbox>/ instead.
func TestLandNeverMovesTheDevelopersBranch(t *testing.T) {
	repo, g := gitRepo(t)
	develop := g("rev-parse", "HEAD~1")
	g("branch", "develop", develop)
	start, _, _ := Start(repo, "sb")
	sb, _ := agentWorks(t, repo, "sb", start, g)
	git(sb, "branch", "-m", "claude/fix", "develop")
	tip, _ := git(sb, "rev-parse", "HEAD")
	bundle := filepath.Join(t.TempDir(), "develop.bundle")
	if _, err := git(sb, "bundle", "create", "-q", bundle, "HEAD", "--branches", "--not", start); err != nil {
		t.Fatal(err)
	}
	f, err := FetchOut(repo, "sb", bundle, "fenzi/x")
	if err != nil || len(f) != 1 || f[0].Name != "develop" {
		t.Fatalf("%+v, %v", f, err)
	}
	if !IsAncestor(repo, develop, tip) {
		t.Fatal("the fixture's develop is not an ancestor of the tip; the test proves nothing")
	}
	landed, err := Land(repo, "sb", "main", f[0])
	if err != nil || landed != "fenzi/sb/develop" {
		t.Fatalf("landed as %q, %v", landed, err)
	}
	if g("rev-parse", "develop") != develop {
		t.Error("the developer's develop was moved")
	}
	if g("rev-parse", "fenzi/sb/develop") != tip {
		t.Error("the agent's commits did not land")
	}
}

// A tree with a .GIT folder, which on this disk would be the repository's
// own .git, is refused by fsck before any ref is written. Git internals as
// files never cross back, through the bundle or through apply.
func TestFetchRefusesDotGitInATree(t *testing.T) {
	repo, g := gitRepo(t)
	start, _, _ := Start(repo, "sb")
	sb, _ := agentWorks(t, repo, "sb", start, g)
	run := func(args ...string) string {
		t.Helper()
		out, err := git(sb, args...)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	cmd := exec.Command("git", "-C", sb, "hash-object", "-w", "--stdin")
	cmd.Stdin = strings.NewReader("#!/bin/sh\necho owned\n")
	blob, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	mktree := func(entries string) string {
		cmd := exec.Command("git", "-C", sb, "mktree")
		cmd.Stdin = strings.NewReader(entries)
		out, err := cmd.Output()
		if err != nil {
			t.Fatal(err)
		}
		return strings.TrimSpace(string(out))
	}
	hooks := mktree("100755 blob " + strings.TrimSpace(string(blob)) + "\tpre-commit\n")
	dotgit := mktree("040000 tree " + hooks + "\thooks\n")
	tree := mktree("040000 tree " + dotgit + "\t.GIT\n100644 blob " + run("rev-parse", "HEAD:a.txt") + "\ta.txt\n")
	evil := run("commit-tree", tree, "-p", "HEAD", "-m", "evil")
	run("update-ref", "refs/heads/evil", evil)
	bundle := filepath.Join(t.TempDir(), "evil.bundle")
	run("bundle", "create", "-q", bundle, "refs/heads/evil", "--not", start)
	_, err = FetchOut(repo, "sb", bundle, "")
	if err == nil || !strings.Contains(err.Error(), "hasDotgit") {
		t.Fatalf("the hostile bundle was not refused: %v", err)
	}
	if refs := g("for-each-ref", "refs/fenzi/sb/heads/"); refs != "" {
		t.Errorf("refs were written: %s", refs)
	}
	if _, err := os.Stat(filepath.Join(repo, ".git", "hooks", "pre-commit")); err == nil {
		t.Error("the hook landed in .git/hooks")
	}
}

// A detached HEAD in the sandbox lands under the agent's branch name.
func TestFetchDetachedHead(t *testing.T) {
	repo, g := gitRepo(t)
	start, _, _ := Start(repo, "sb")
	sb, _ := agentWorks(t, repo, "sb", start, g)
	git(sb, "checkout", "-q", "--detach")
	git(sb, "branch", "-D", "claude/fix")
	tip, _ := git(sb, "rev-parse", "HEAD")
	bundle := filepath.Join(t.TempDir(), "detached.bundle")
	if _, err := git(sb, "bundle", "create", "-q", bundle, "HEAD", "--branches", "--not", start); err != nil {
		t.Fatal(err)
	}
	f, err := FetchOut(repo, "sb", bundle, "fenzi/x")
	if err != nil || len(f) != 1 || f[0].Name != "fenzi/x" || f[0].Head != tip {
		t.Fatalf("%+v, %v", f, err)
	}
	if landed, err := Land(repo, "sb", "main", f[0]); err != nil || landed != "fenzi/x" || g("rev-parse", "fenzi/x") != tip {
		t.Errorf("landed %q, %v", landed, err)
	}
}

func TestBundleInTooLarge(t *testing.T) {
	repo, g := gitRepo(t)
	g("update-ref", StartRef("sb"), "HEAD")
	file := filepath.Join(t.TempDir(), "in.bundle")
	size, err := BundleIn(repo, "sb", file)
	if err != nil || size == 0 {
		t.Fatalf("%d, %v", size, err)
	}
	if _, err := os.Stat(file); err != nil {
		t.Fatal("the bundle was not written")
	}
}
