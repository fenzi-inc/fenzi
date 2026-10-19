package run

// The git round trip, sandbox side. Before the agent starts, the history
// of the developer's repository goes in as a bundle and the sandbox's copy
// of the project becomes a repository on a branch of its own. When the
// agent exits, its commits come back as a bundle, and workspace lands them
// as a branch on this machine. Both steps run git inside the sandbox
// through one python3 script each, with every argument passed as argv.
// The host side is in workspace/history.go.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	"fenzi/agents"
	"fenzi/cli/internal/config"
	"fenzi/cli/internal/workspace"
	"fenzi/compiler"
)

// Where the round trip keeps its files in the sandbox: all under
// /sandbox/.fenzi, outside the project copy, so none of it is in the diff.
// The project's .git is a one-line file pointing at historyGitDir, so the
// download of the project brings back no repository.
var (
	historyDir    = path.Join(compiler.DefaultWorkdir, ".fenzi")
	historyBundle = path.Join(historyDir, "start.bundle")
	historyGitDir = path.Join(historyDir, "git")
	historyOut    = path.Join(historyDir, "out")
)

// inBundleDir is the folder uploaded beside the project. Its name is what
// it lands as in the sandbox: <workdir>/.fenzi. The folder is not a git
// repository, so the upload copies everything in it (OpenShell 0.1.2
// source, run.rs: when git ls-files fails, the upload is unfiltered; not
// yet recorded on a gateway).
func inBundleDir(runDir string) string { return filepath.Join(runDir, "in", ".fenzi") }

// AgentBranch is the branch the agent works on in the sandbox: fenzi/ and
// the sandbox name without its fenzi- prefix. It lands under the same name,
// so the developer's own branches are never written by the agent.
func AgentBranch(sandbox string) string {
	return "fenzi/" + strings.TrimPrefix(sandbox, "fenzi-")
}

// agentIdentity is who the agent commits as inside the sandbox. The
// developer's identity is not used: a commit the agent made is the agent's.
func agentIdentity(a agents.Entry) (name, email string) {
	return a.Display + " (fenzi sandbox)", a.Name + "@sandbox.fenzi.dev"
}

// gitRecord is the record of the folder's repository for a sandbox, from
// the state read before upload. Nil when the folder is not a repository.
func gitRecord(st workspace.RepoState, noUpload bool) *config.Git {
	if !st.Repo {
		return nil
	}
	g := &config.Git{Branch: st.Branch, Head: st.Head, Dirty: st.Dirty, FilesOnly: st.FilesOnly}
	if noUpload {
		g.FilesOnly = "started with --no-upload"
	}
	g.History = g.FilesOnly == ""
	return g
}

// prepareHistory pins the start in the developer's repository and writes
// the bundle to upload. On any failure the sandbox gets files only, and
// the record says why.
func prepareHistory(repo, sandbox, runDir string, g *config.Git) (size int64) {
	start, dirty, err := workspace.Start(repo, sandbox)
	if err != nil {
		g.History, g.FilesOnly = false, err.Error()
		return 0
	}
	g.Start, g.Dirty, g.AgentBranch = start, dirty, AgentBranch(sandbox)
	dir := inBundleDir(runDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		g.History, g.FilesOnly = false, err.Error()
		return 0
	}
	size, err = workspace.BundleIn(repo, sandbox, filepath.Join(dir, "start.bundle"))
	if errors.Is(err, workspace.ErrTooLarge) {
		g.History, g.FilesOnly = false, fmt.Sprintf("the history is %s, over the %s limit", mib(size), mib(workspace.MaxBundle))
		return size
	}
	if err != nil {
		g.History, g.FilesOnly = false, err.Error()
		return 0
	}
	return size
}

func mib(n int64) string {
	if n < 1<<20 {
		return fmt.Sprintf("%d KiB", (n+1023)/1024)
	}
	return fmt.Sprintf("%d MiB", (n+(1<<20)-1)/(1<<20))
}

// rebuildScript makes the uploaded project a repository: git init with the
// repository outside the project, the start commit fetched from the bundle,
// the agent's branch at it, the index reset to it, and the agent's
// identity. The working tree must then be clean, that is the upload must
// have sent exactly the start commit's tree; otherwise the repository is
// removed and the sandbox keeps files only. argv: project, git dir,
// bundle, the start ref in the bundle, the start commit, the agent's
// branch, user.name, user.email.
const rebuildScript = `import json, os, shutil, subprocess, sys
project, gitdir, bundle, ref, start, branch, name, email = sys.argv[1:9]
# The fetch and the ref updates write reflog entries before user.email is
# set. Without an identity git builds one from the hostname and resolves it,
# and the sandbox's DNS policy refuses that name, a denied call in the log
# that the agent never made.
os.environ.update(GIT_AUTHOR_NAME=name, GIT_AUTHOR_EMAIL=email, GIT_COMMITTER_NAME=name, GIT_COMMITTER_EMAIL=email)
def git(*a):
    return subprocess.run(["git", "-C", project, *a], check=True, capture_output=True, text=True).stdout
def drop():
    shutil.rmtree(gitdir, ignore_errors=True)
    try: os.remove(os.path.join(project, ".git"))
    except OSError: pass
try:
    subprocess.run(["git", "init", "-q", "--separate-git-dir", gitdir, project], check=True, capture_output=True, text=True)
    git("fetch", "-q", "--no-tags", bundle, ref + ":refs/fenzi/start")
    got = git("rev-parse", "--verify", "-q", "refs/fenzi/start").strip()
    if got != start:
        drop(); print(json.dumps({"status": "mismatch", "detail": "the bundle holds %s, not the start commit %s" % (got, start)})); sys.exit()
    git("update-ref", "refs/heads/" + branch, start)
    git("symbolic-ref", "HEAD", "refs/heads/" + branch)
    git("reset", "-q")
    git("config", "user.name", name); git("config", "user.email", email)
    dirty = git("status", "--porcelain").splitlines()
    if dirty:
        drop(); print(json.dumps({"status": "mismatch", "detail": "the copy differs from the start commit: " + ", ".join(l[3:] for l in dirty[:5])})); sys.exit()
    print(json.dumps({"status": "ok", "head": start, "git": git("--version").strip()}))
except subprocess.CalledProcessError as e:
    drop(); print(json.dumps({"status": "error", "detail": (e.stderr or e.stdout or str(e)).strip()[-1000:]}))
`

// collectScript brings the agent's work to a point that can be bundled and
// bundles it. It refuses when the agent replaced the repository or left a
// rebase or merge unfinished; it commits what was left uncommitted as one
// checkpoint on the agent's current branch; then it bundles every commit
// since the start, HEAD named so a detached HEAD is kept. argv: project,
// output folder, the start commit, the agent's display name.
const collectScript = `import json, os, subprocess, sys
project, outdir, start, agent = sys.argv[1:5]
def run(*a):
    return subprocess.run(["git", "-C", project, *a], capture_output=True, text=True)
def git(*a):
    r = run(*a)
    if r.returncode != 0: raise SystemExit(json.dumps({"status": "error", "detail": (r.stderr or r.stdout).strip()[-1000:]}))
    return r.stdout
r = run("rev-parse", "--verify", "-q", "refs/fenzi/start")
if r.returncode != 0 or r.stdout.strip() != start:
    print(json.dumps({"status": "replaced"})); sys.exit()
for what in ("rebase-merge", "rebase-apply", "MERGE_HEAD", "CHERRY_PICK_HEAD", "REVERT_HEAD", "BISECT_LOG"):
    p = git("rev-parse", "--git-path", what).strip()
    if os.path.exists(os.path.join(project, p)):
        print(json.dumps({"status": "in_progress", "what": what})); sys.exit()
branch = run("symbolic-ref", "-q", "--short", "HEAD").stdout.strip()
git("add", "-A")
checkpoint = run("diff", "--cached", "--quiet").returncode == 1
if checkpoint:
    git("commit", "-q", "-m", "Changes left uncommitted when %s exited" % agent)
head = git("rev-parse", "HEAD").strip()
if int(git("rev-list", "--count", "HEAD", "--branches", "--not", start)) == 0:
    print(json.dumps({"status": "nothing", "branch": branch, "head": head})); sys.exit()
os.makedirs(outdir, exist_ok=True)
out = os.path.join(outdir, "out.bundle")
git("bundle", "create", "-q", out, "HEAD", "--branches", "--not", start)
print(json.dumps({"status": "ok", "branch": branch, "head": head, "checkpoint": checkpoint,
    "commits": int(git("rev-list", "--count", start + "..HEAD")),
    "branches": git("for-each-ref", "--format=%(refname:short)", "refs/heads/").split(),
    "tags": git("for-each-ref", "--format=%(refname:short)", "refs/tags/").split(),
    "size": os.path.getsize(out)}))
`

// sandboxReply is what both scripts print, one JSON object.
type sandboxReply struct {
	Status     string   `json:"status"`
	Detail     string   `json:"detail"`
	What       string   `json:"what"`
	Branch     string   `json:"branch"`
	Head       string   `json:"head"`
	Checkpoint bool     `json:"checkpoint"`
	Commits    int      `json:"commits"`
	Branches   []string `json:"branches"`
	Tags       []string `json:"tags"`
	Size       int64    `json:"size"`
}

func sandboxPython(ctx context.Context, d Deps, sandbox, script string, args ...string) (sandboxReply, error) {
	var r sandboxReply
	out, err := d.OpenShell.ExecOutput(ctx, sandbox, append([]string{"python3", "-c", script}, args...)...)
	if err != nil {
		return r, err
	}
	if err := json.Unmarshal(out, &r); err != nil {
		return r, fmt.Errorf("unreadable reply from the sandbox: %q", strings.TrimSpace(string(out)))
	}
	return r, nil
}

// rebuildHistory runs rebuildScript after the project and the bundle were
// uploaded. On any failure the sandbox keeps files only and the record
// says why; the run goes on.
func rebuildHistory(ctx context.Context, d Deps, sandbox, project, repo string, a agents.Entry, g *config.Git) {
	name, email := agentIdentity(a)
	r, err := sandboxPython(ctx, d, sandbox, rebuildScript, project, historyGitDir, historyBundle, workspace.StartRef(sandbox), g.Start, g.AgentBranch, name, email)
	switch {
	case err != nil:
		g.History, g.FilesOnly = false, "rebuilding the repository in the sandbox failed: "+err.Error()
	case r.Status != "ok":
		g.History, g.FilesOnly = false, "rebuilding the repository in the sandbox failed: "+firstOf(r.Detail, r.Status)
	}
	if !g.History {
		workspace.DropRefs(repo, sandbox)
	}
}

func firstOf(s ...string) string {
	for _, v := range s {
		if v != "" {
			return v
		}
	}
	return ""
}

// ErrInProgress means the agent left a rebase, merge, cherry-pick, revert or
// bisect unfinished in the sandbox. Nothing is collected and the sandbox is
// kept, so fenzi connect can finish or abort it.
type ErrInProgress struct{ What string }

func (e *ErrInProgress) Error() string {
	return "the agent left a " + inProgressWord(e.What) + " unfinished in the sandbox"
}

func inProgressWord(what string) string {
	switch what {
	case "rebase-merge", "rebase-apply":
		return "rebase"
	case "MERGE_HEAD":
		return "merge"
	case "CHERRY_PICK_HEAD":
		return "cherry-pick"
	case "REVERT_HEAD":
		return "revert"
	}
	return "bisect"
}

// collectHistory brings the agent's commits back before the project is
// downloaded: collectScript in the sandbox, the bundle downloaded, fetched
// with fsck on, and landed as a branch. It fills in the record's Landed,
// Tip, Commits and Checkpoint. When the agent made no commit, nothing is
// fetched and the record says so. An error keeps the sandbox.
func collectHistory(ctx context.Context, d Deps, sb *config.Sandbox, project, staging string, say func(label, format string, args ...any)) error {
	g := sb.Git
	display := sb.Agent
	if a, err := agents.Get(sb.Agent); err == nil {
		display = a.Display
	}
	r, err := sandboxPython(ctx, d, sb.Name, collectScript, project, historyOut, g.Start, display)
	if err != nil {
		return fmt.Errorf("collecting the agent's commits: %w", err)
	}
	switch r.Status {
	case "replaced":
		g.History, g.FilesOnly = false, "the agent replaced the repository in the sandbox; its commits are not brought back"
		say("git", "%s", g.FilesOnly)
		saveGit(d.Dirs, sb)
		return nil
	case "in_progress":
		return &ErrInProgress{What: r.What}
	case "nothing":
		g.Commits = 0
		say("git", "no commits by %s; %s is unchanged", display, g.Branch)
		saveGit(d.Dirs, sb)
		return nil
	case "ok":
	default:
		return fmt.Errorf("collecting the agent's commits: %s", firstOf(r.Detail, r.Status))
	}
	if r.Size > workspace.MaxBundle*4 {
		return fmt.Errorf("the agent's commits are %s, over the %s limit; the sandbox is kept", mib(r.Size), mib(workspace.MaxBundle*4))
	}
	tmp, err := os.MkdirTemp(staging, ".bundle-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	// The download is given a path that does not exist yet, so the
	// folder's contents land directly in it, as recorded from OpenShell 0.1.2.
	local := filepath.Join(tmp, "out")
	if err := d.OpenShell.Download(ctx, sb.Name, historyOut, local); err != nil {
		return fmt.Errorf("downloading the agent's commits: %w", err)
	}
	bundle := filepath.Join(local, "out.bundle")
	if _, err := os.Stat(bundle); err != nil {
		return fmt.Errorf("the agent's commits did not arrive: %s is missing after the download", bundle)
	}
	fetched, err := workspace.FetchOut(sb.Repo, sb.Name, bundle, g.AgentBranch)
	if err != nil {
		return err
	}
	// The branch the agent was on lands; the others stay fetched under
	// refs/fenzi/<sandbox>/ until Land drops them, and are named.
	at := r.Branch
	if at == "" {
		at = g.AgentBranch
	}
	var head workspace.Fetched
	var others []string
	for _, f := range fetched {
		if f.Name == at {
			head = f
		} else if !workspace.IsAncestor(sb.Repo, f.Head, r.Head) {
			others = append(others, f.Name)
		}
	}
	if head.Name == "" {
		return fmt.Errorf("the agent's branch %s is not in its bundle", at)
	}
	landed, err := workspace.Land(sb.Repo, sb.Name, g.Branch, head)
	if err != nil {
		return fmt.Errorf("landing %s: %w", at, err)
	}
	g.Landed, g.Tip, g.Commits, g.Checkpoint = landed, head.Head, r.Commits, r.Checkpoint
	saveGit(d.Dirs, sb)
	line := fmt.Sprintf("%s by %s on %s, now in your repository", plural(r.Commits, "commit"), display, landed)
	if landed != at {
		line = fmt.Sprintf("%s by %s on %s, now in your repository as %s", plural(r.Commits, "commit"), display, at, landed)
	}
	say("git", "%s", line)
	if r.Checkpoint {
		say("", "the last one holds what %s left uncommitted", display)
	}
	if len(others) > 0 {
		say("", "other branches with commits were not brought back: %s", strings.Join(others, ", "))
	}
	if len(r.Tags) > 0 {
		say("", "tags stay in the sandbox: %s", strings.Join(r.Tags, ", "))
	}
	if g.Branch != "" {
		say("", "%s is unchanged until fenzi apply", g.Branch)
	}
	return nil
}

// saveGit writes the sandbox's git record to the state.
func saveGit(dirs config.Dirs, sb *config.Sandbox) {
	s, err := dirs.LoadState()
	if err != nil {
		return
	}
	if cur, ok := s.Find(sb.Name); ok {
		cur.Git = sb.Git
		s.Put(cur)
		_ = dirs.SaveState(s)
	}
}

// historyNote is what the agent is told about the folder.
func historyNote(g *config.Git) string {
	if g == nil || !g.History {
		return agents.FilesNote
	}
	branch := g.Branch
	if branch == "" {
		branch = "not checked out (detached HEAD at " + shortSHA(g.Head) + ")"
	}
	return fmt.Sprintf(agents.HistoryNote, g.AgentBranch, shortSHA(g.Start), branch)
}

func shortSHA(s string) string {
	if len(s) > 7 {
		return s[:7]
	}
	return s
}

// sayGit prints the start of the round trip.
func sayGit(say func(label, format string, args ...any), g *config.Git, size int64) {
	if g == nil {
		return
	}
	where := g.Branch
	if where == "" {
		where = "detached HEAD"
	}
	where += " at " + shortSHA(g.Head)
	if !g.History {
		say("git", "%s; files only, %s", where, g.FilesOnly)
		return
	}
	if g.Dirty {
		say("git", "%s; your uncommitted changes become the first commit on the agent's branch", where)
	} else {
		say("git", "%s", where)
	}
	say("", "the agent works on %s (history %s); its commits come back with the same ids", g.AgentBranch, mib(size))
}
