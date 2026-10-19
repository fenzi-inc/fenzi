package run

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"fenzi/cli/internal/config"
	"fenzi/cli/internal/workspace"
)

// sandboxFS stands in for the sandbox's disk behind the fake gateway: an
// upload copies a folder in, an exec of python3 runs the real script with
// git on it, and a download copies a folder out. /sandbox is root.
type sandboxFS struct {
	t    *testing.T
	root string
	// agent is what the agent does in the project when it is started.
	agent func(project string)
}

func (s *sandboxFS) local(p string) string {
	return filepath.Join(s.root, strings.TrimPrefix(p, "/sandbox"))
}

func (s *sandboxFS) hook(args []string) {
	switch {
	case len(args) >= 4 && args[0] == "sandbox" && args[1] == "upload":
		// A folder lands as <workdir>/<basename>, every file of it.
		src := args[3]
		dst := filepath.Join(s.root, filepath.Base(src))
		if out, err := exec.Command("cp", "-R", src, dst).CombinedOutput(); err != nil {
			s.t.Fatalf("upload: %v %s", err, out)
		}
		// The upload leaves out .git and what .gitignore matches.
		os.RemoveAll(filepath.Join(dst, ".git"))
		os.Remove(filepath.Join(dst, ".env"))
	case len(args) >= 5 && args[0] == "sandbox" && args[1] == "download":
		// Into a path that does not exist, the folder's contents land directly.
		if out, err := exec.Command("cp", "-R", s.local(args[3]), args[4]).CombinedOutput(); err != nil {
			s.t.Fatalf("download: %v %s", err, out)
		}
	case len(args) > 5 && args[0] == "sandbox" && args[1] == "exec" && args[4] == "--tty":
		// The agent runs.
		for i, a := range args {
			if a == "--workdir" {
				s.agent(s.local(args[i+1]))
			}
		}
	}
}

func (s *sandboxFS) answer(args []string) (string, bool) {
	i := 0
	for ; i < len(args); i++ {
		if args[i] == "--" {
			break
		}
	}
	if i+2 >= len(args) || args[i+1] != "python3" || args[i+2] != "-c" {
		return "", false
	}
	cmd := args[i+1:]
	for j := 3; j < len(cmd); j++ {
		if strings.HasPrefix(cmd[j], "/sandbox") {
			cmd[j] = s.local(cmd[j])
		}
	}
	out, err := exec.Command(cmd[0], cmd[1:]...).Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			s.t.Fatalf("sandbox python3: %v\n%s", err, ee.Stderr)
		}
		s.t.Fatalf("sandbox python3: %v", err)
	}
	return string(out), true
}

// hostRepo makes the developer's repository with one commit and an
// uncommitted edit, isolated from the developer's own git configuration.
func hostRepo(t *testing.T) (repo string, g func(...string) string) {
	t.Helper()
	for _, bin := range []string{"git", "python3"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s is not installed", bin)
		}
	}
	cfg := filepath.Join(t.TempDir(), "gitconfig")
	os.WriteFile(cfg, []byte("[user]\n\tname = Michael Host\n\temail = m@host.invalid\n[init]\n\tdefaultBranch = main\n"), 0o600)
	t.Setenv("GIT_CONFIG_GLOBAL", cfg)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
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
	os.WriteFile(filepath.Join(repo, "main.go"), []byte("package main\n"), 0o644)
	os.WriteFile(filepath.Join(repo, "old.go"), []byte("package old\n"), 0o644)
	os.WriteFile(filepath.Join(repo, ".gitignore"), []byte(".env\n"), 0o644)
	os.WriteFile(filepath.Join(repo, ".env"), []byte("SECRET=1\n"), 0o644)
	g("add", "-A")
	g("commit", "-qm", "base")
	os.WriteFile(filepath.Join(repo, "main.go"), []byte("package main\n\n// michael\n"), 0o644)
	return repo, g
}

// The whole round trip through run.Run with the fake gateway: the history
// goes in, the agent commits on its own branch, the commits come back with
// the same ids as a branch on the host, and the developer's branch, index
// and folder are as they were.
func TestRunRoundTripsTheHistory(t *testing.T) {
	repo, g := hostRepo(t)
	h := setup(t)
	h.opts.Repo = repo
	h.deps.Filter = workspace.GitFilter
	var agentTip string
	fs := &sandboxFS{t: t, root: t.TempDir(), agent: func(project string) {
		sg := func(args ...string) string {
			t.Helper()
			out, err := exec.Command("git", append([]string{"-C", project}, args...)...).CombinedOutput()
			if err != nil {
				t.Fatalf("agent git %s: %v\n%s", strings.Join(args, " "), err, out)
			}
			return strings.TrimSpace(string(out))
		}
		if got := sg("branch", "--show-current"); got != "fenzi/test-0001" {
			t.Errorf("the agent is on %q, want fenzi/test-0001", got)
		}
		if got := sg("status", "--porcelain"); got != "" {
			t.Errorf("the agent's folder is not clean at start:\n%s", got)
		}
		if _, err := os.Stat(filepath.Join(project, ".env")); err == nil {
			t.Error(".env was uploaded")
		}
		sg("switch", "-qc", "claude/fix")
		os.WriteFile(filepath.Join(project, "main.go"), []byte("package main\n\n// michael\n// claude\n"), 0o644)
		os.WriteFile(filepath.Join(project, "new.go"), []byte("package new\n"), 0o644)
		os.Remove(filepath.Join(project, "old.go"))
		sg("add", "-A")
		sg("commit", "-qm", "agent: edit main, add new, drop old")
		agentTip = sg("rev-parse", "HEAD")
		os.WriteFile(filepath.Join(project, "left.go"), []byte("package left\n"), 0o644)
	}}
	h.os.Hook = fs.hook
	h.os.Answer = fs.answer
	head := g("rev-parse", "HEAD")

	res, err := Run(context.Background(), h.deps, h.opts)
	if err != nil {
		t.Fatalf("%v\n%s", err, h.out)
	}
	out := h.out.String()
	for _, want := range []string{
		"main at " + head[:7] + "; your uncommitted changes become the first commit on the agent's branch",
		"the agent works on fenzi/test-0001",
		"2 commits by Claude Code on claude/fix, now in your repository",
		"the last one holds what Claude Code left uncommitted",
		"main is unchanged until fenzi apply",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	var uploads []string
	for _, c := range h.os.Calls {
		if strings.HasPrefix(c, "sandbox upload ") {
			uploads = append(uploads, c)
		}
	}
	if len(uploads) != 2 || uploads[0] != "sandbox upload fenzi-test-0001 "+repo || !strings.HasSuffix(uploads[1], "/in/.fenzi") {
		t.Errorf("uploads = %q", uploads)
	}
	if _, err := os.Stat(filepath.Join(fs.root, ".fenzi", "start.bundle")); err != nil {
		t.Error("the bundle did not land at /sandbox/.fenzi/start.bundle")
	}
	if b, _ := os.ReadFile(filepath.Join(fs.root, filepath.Base(repo), ".git")); !strings.HasPrefix(string(b), "gitdir: ") {
		t.Errorf("the project's .git in the sandbox is not a gitfile: %q", b)
	}

	// The host: the agent's branch with the same ids, main untouched.
	s, _ := h.deps.Dirs.LoadState()
	sb, _ := s.Find("fenzi-test-0001")
	gr := sb.Git
	if gr == nil || !gr.History || gr.Branch != "main" || gr.Head != head || !gr.Dirty || gr.Start == head || gr.AgentBranch != "fenzi/test-0001" {
		t.Fatalf("record = %+v", gr)
	}
	if gr.Landed != "claude/fix" || gr.Commits != 2 || !gr.Checkpoint || gr.Tip == "" {
		t.Errorf("landing = %+v", gr)
	}
	if g("rev-parse", "claude/fix^") != agentTip {
		t.Errorf("claude/fix^ = %s, want the agent's commit %s", g("rev-parse", "claude/fix^"), agentTip)
	}
	if g("rev-parse", "claude/fix") != gr.Tip || g("rev-parse", "claude/fix~2") != gr.Start || g("rev-parse", gr.Start+"^") != head {
		t.Error("claude/fix is not start commit, agent commit, checkpoint on top of main")
	}
	if g("rev-parse", "HEAD") != head || g("branch", "--show-current") != "main" {
		t.Error("main moved")
	}
	if got := g("status", "--porcelain"); got != "M main.go" {
		t.Errorf("the folder changed:\n%s", got)
	}
	if refs := g("for-each-ref", "refs/fenzi/"); refs != "" {
		t.Errorf("refs left: %s", refs)
	}
	if b, _ := os.ReadFile(filepath.Join(repo, "main.go")); string(b) != "package main\n\n// michael\n" {
		t.Error("run must not change the folder; apply does")
	}
	// The files came back too, for the diff. The download brings the
	// sandbox's .git as well, but that is the one-line gitfile, not a
	// repository, and it is not a change.
	if len(res.Changes) != 4 {
		t.Errorf("changes = %v, want M main.go, A new.go, D old.go, A left.go", res.Changes)
	}
	if info, err := os.Stat(filepath.Join(res.Staging, StagedFiles, ".git")); err == nil && info.IsDir() {
		t.Error("the staged copy holds a .git folder")
	}
	// The sandbox was deleted, so the start pin is gone with it.
	if !strings.Contains(out, "fenzi-test-0001, deleted") {
		t.Errorf("not deleted:\n%s", out)
	}
}

// With no commit by the agent, nothing lands and the exit says so; the
// files still come back for the diff.
func TestRunWithNoAgentCommit(t *testing.T) {
	repo, g := hostRepo(t)
	g("add", "-A")
	g("commit", "-qm", "clean")
	h := setup(t)
	h.opts.Repo = repo
	h.deps.Filter = workspace.GitFilter
	fs := &sandboxFS{t: t, root: t.TempDir(), agent: func(project string) {}}
	h.os.Hook = fs.hook
	h.os.Answer = fs.answer
	res, err := Run(context.Background(), h.deps, h.opts)
	if err != nil {
		t.Fatalf("%v\n%s", err, h.out)
	}
	if !strings.Contains(h.out.String(), "no commits by Claude Code; main is unchanged") || len(res.Changes) != 0 {
		t.Errorf("%v\n%s", res.Changes, h.out)
	}
	s, _ := h.deps.Dirs.LoadState()
	sb, _ := s.Find("fenzi-test-0001")
	if sb.Git == nil || sb.Git.Landed != "" || sb.Git.Dirty {
		t.Errorf("record = %+v", sb.Git)
	}
}

// The agent replaced the repository: its commits are not brought back, and
// the exit says so. The files still come back.
func TestRunAgentReplacedTheRepository(t *testing.T) {
	repo, _ := hostRepo(t)
	h := setup(t)
	h.opts.Repo = repo
	h.deps.Filter = workspace.GitFilter
	fs := &sandboxFS{t: t, root: t.TempDir(), agent: func(project string) {
		os.Remove(filepath.Join(project, ".git"))
		exec.Command("git", "-C", project, "init", "-q").Run()
		os.WriteFile(filepath.Join(project, "new.go"), []byte("package new\n"), 0o644)
	}}
	h.os.Hook = fs.hook
	h.os.Answer = fs.answer
	res, err := Run(context.Background(), h.deps, h.opts)
	if err != nil {
		t.Fatalf("%v\n%s", err, h.out)
	}
	if !strings.Contains(h.out.String(), "the agent replaced the repository") || len(res.Changes) != 1 {
		t.Errorf("%v\n%s", res.Changes, h.out)
	}
	s, _ := h.deps.Dirs.LoadState()
	sb, _ := s.Find("fenzi-test-0001")
	if sb.Git == nil || sb.Git.History || sb.Git.Landed != "" {
		t.Errorf("record = %+v", sb.Git)
	}
}

// A merge the agent left unfinished keeps the sandbox: nothing is
// collected, and the error names it.
func TestRunKeepsTheSandboxOnAnUnfinishedMerge(t *testing.T) {
	repo, _ := hostRepo(t)
	h := setup(t)
	h.opts.Repo = repo
	h.deps.Filter = workspace.GitFilter
	fs := &sandboxFS{t: t, root: t.TempDir(), agent: func(project string) {
		sg := func(args ...string) {
			exec.Command("git", append([]string{"-C", project}, args...)...).Run()
		}
		sg("switch", "-qc", "side")
		os.WriteFile(filepath.Join(project, "main.go"), []byte("side\n"), 0o644)
		sg("commit", "-qam", "side")
		sg("switch", "-q", "fenzi/test-0001")
		os.WriteFile(filepath.Join(project, "main.go"), []byte("other\n"), 0o644)
		sg("commit", "-qam", "other")
		sg("merge", "side")
	}}
	h.os.Hook = fs.hook
	h.os.Answer = fs.answer
	_, err := Run(context.Background(), h.deps, h.opts)
	if err == nil || !strings.Contains(err.Error(), "left a merge unfinished") || !strings.Contains(err.Error(), "is kept") {
		t.Fatalf("err = %v", err)
	}
	if h.called("sandbox delete") {
		t.Error("the sandbox was deleted with the agent's work in it")
	}
}

// A folder that is a repository but cannot round-trip its history gets
// files only, and the record says why.
func TestRunFilesOnlyReasons(t *testing.T) {
	repo, g := hostRepo(t)
	g("add", "-A")
	g("commit", "-qm", "clean")
	// A shallow clone of it.
	shallow := filepath.Join(t.TempDir(), "shallow")
	if out, err := exec.Command("git", "clone", "-q", "--depth", "1", "file://"+repo, shallow).CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	h := setup(t)
	h.opts.Repo = shallow
	h.deps.Filter = workspace.GitFilter
	if _, err := Run(context.Background(), h.deps, h.opts); err != nil {
		t.Fatalf("%v\n%s", err, h.out)
	}
	if !strings.Contains(h.out.String(), "files only, the repository is a shallow clone") {
		t.Errorf("%s", h.out)
	}
	for _, c := range h.os.Calls {
		if strings.Contains(c, "python3 -c import json, os, shutil") {
			t.Error("the rebuild ran in a files-only sandbox")
		}
	}
	s, _ := h.deps.Dirs.LoadState()
	sb, _ := s.Find("fenzi-test-0001")
	if sb.Git == nil || sb.Git.History || sb.Git.Branch != "main" {
		t.Errorf("record = %+v", sb.Git)
	}
	if !strings.Contains(strings.Join(h.os.Calls, "\n"), "Do not run git init or git clone in this folder: a repository you create here is not brought back") {
		t.Error("the agent was not told the folder has no history")
	}
}

// The agent is told what the folder is.
func TestHistoryNote(t *testing.T) {
	g := &config.Git{History: true, Branch: "michael/bol-293", Start: "d92ffafb6b64", AgentBranch: "fenzi/web-1a2b"}
	note := historyNote(g)
	for _, want := range []string{"fenzi/web-1a2b, at commit d92ffaf", "The developer's own branch is michael/bol-293", "Do not push", "do not amend, rebase or reset"} {
		if !strings.Contains(note, want) {
			t.Errorf("missing %q in %q", want, note)
		}
	}
	for _, g := range []*config.Git{nil, {Branch: "main", FilesOnly: "the repository has submodules"}} {
		if !strings.Contains(historyNote(g), "without git history") {
			t.Errorf("files note for %+v: %q", g, historyNote(g))
		}
	}
	if AgentBranch("fenzi-web-1a2b") != "fenzi/web-1a2b" || AgentBranch("mine") != "fenzi/mine" {
		t.Error("AgentBranch")
	}
}
