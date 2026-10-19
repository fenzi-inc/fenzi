package workspace

// The git round trip, host side. The repository on this machine is the
// only history. A sandbox gets a bundle of it and the agent works on a
// branch of its own; its commits come back in a bundle, are fetched into
// refs/fenzi/<sandbox>/ with fsck on, and land as a branch. The developer's
// checked-out branch, index and folder change only in FastForward, which
// fenzi apply runs. Files are never copied on top of committed work.
//
// Every git call here passes argv, never a shell string, and turns hooks
// and the file monitor off: a branch name or a tracked .husky folder the
// agent wrote must not run anything on this machine.

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// MaxBundle is the largest history Fenzi copies into a sandbox. Over it,
// only files go in. The limit is a guess until upload time is measured.
const MaxBundle = 64 << 20

// RepoState is what git says about a folder before it is uploaded.
type RepoState struct {
	// Repo is whether the folder is the root of a git work tree with at
	// least one commit. The other fields are empty when it is not.
	Repo bool
	// Branch is the checked-out branch, "" when HEAD is detached.
	Branch string
	// Head is the commit checked out.
	Head string
	// Dirty is whether the folder has uncommitted edits or untracked files
	// that are not ignored.
	Dirty bool
	// FilesOnly says why the history cannot go into the sandbox, "" when it
	// can. Only files go in and come back then, as they always did.
	FilesOnly string
}

// ReadRepo reads the state of root without writing anything in it.
func ReadRepo(root string) RepoState {
	var st RepoState
	if _, err := exec.LookPath("git"); err != nil {
		return st
	}
	top, err := git(root, "rev-parse", "--show-toplevel")
	if err != nil {
		return st
	}
	if !samePath(top, root) {
		return RepoState{Repo: true, FilesOnly: "the folder is inside a repository, not at its root"}
	}
	head, err := git(root, "rev-parse", "--verify", "-q", "HEAD")
	if err != nil {
		return RepoState{Repo: true, FilesOnly: "the repository has no commit yet"}
	}
	st.Repo, st.Head = true, head
	if b, err := git(root, "symbolic-ref", "-q", "--short", "HEAD"); err == nil {
		st.Branch = b
	}
	status, err := git(root, "status", "--porcelain", "-z", "--untracked-files=normal")
	if err != nil {
		st.FilesOnly = "git status failed: " + err.Error()
		return st
	}
	st.Dirty = status != ""
	for _, what := range []string{"rebase-merge", "rebase-apply", "MERGE_HEAD", "CHERRY_PICK_HEAD", "REVERT_HEAD", "BISECT_LOG"} {
		if p, err := git(root, "rev-parse", "--git-path", what); err == nil {
			if _, err := os.Stat(filepath.Join(root, p)); err == nil {
				st.FilesOnly = "a " + inProgress(what) + " is in progress; finish or abort it first"
				return st
			}
		}
	}
	if shallow, _ := git(root, "rev-parse", "--is-shallow-repository"); shallow == "true" {
		st.FilesOnly = "the repository is a shallow clone"
		return st
	}
	if sparse, _ := git(root, "config", "--bool", "core.sparseCheckout"); sparse == "true" {
		st.FilesOnly = "the repository uses a sparse checkout"
		return st
	}
	if stage, err := git(root, "ls-files", "-z", "-s"); err == nil && strings.Contains("\x00"+stage, "\x00160000 ") {
		st.FilesOnly = "the repository has submodules"
		return st
	}
	return st
}

func inProgress(what string) string {
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

func samePath(a, b string) bool {
	for _, x := range forms(a) {
		for _, y := range forms(b) {
			if x == y {
				return true
			}
		}
	}
	return false
}

// StartRef is the ref that pins a sandbox's start commit, so a rebase and
// a gc on this machine while the agent works cannot make its commits
// unfetchable. LandedRefs is where its branches are fetched before they land.
func StartRef(sandbox string) string   { return "refs/fenzi/" + sandbox + "/start" }
func landedRefs(sandbox string) string { return "refs/fenzi/" + sandbox + "/heads/" }

// Start pins the start of a sandbox and returns the commit the agent's
// branch begins at: HEAD, or, when the folder has uncommitted edits, a
// start commit on top of HEAD holding the folder as it is. That commit is
// built from a temporary index, so the real index is untouched; it is
// authored by the developer with HEAD's dates, so two sandboxes started
// from the same state get the same commit id. Its tree is what the upload
// sends: every tracked file as it is on disk and every untracked file
// .gitignore does not match.
func Start(root, sandbox string) (start string, dirty bool, err error) {
	head, err := git(root, "rev-parse", "--verify", "-q", "HEAD")
	if err != nil {
		return "", false, errors.New("the repository has no commit yet")
	}
	tree, err := worktreeTree(root)
	if err != nil {
		return "", false, err
	}
	start = head
	if headTree, err := git(root, "rev-parse", head+"^{tree}"); err == nil && headTree != tree {
		date, err := git(root, "log", "-1", "--format=%cI", head)
		if err != nil {
			return "", false, err
		}
		cmd := gitCmd(root, "-c", "commit.gpgsign=false", "commit-tree", tree, "-p", head, "-m", "Uncommitted changes when fenzi run started")
		cmd.Env = append(cmd.Env, "GIT_AUTHOR_DATE="+date, "GIT_COMMITTER_DATE="+date)
		if start, err = run(cmd); err != nil {
			return "", false, fmt.Errorf("building the start commit: %w", err)
		}
		dirty = true
	}
	if _, err := git(root, "update-ref", StartRef(sandbox), start); err != nil {
		return "", false, err
	}
	return start, dirty, nil
}

// worktreeTree is the tree of the folder as it is on disk: HEAD's index
// with every change on disk added, in a temporary index.
func worktreeTree(root string) (string, error) {
	tmp, err := os.CreateTemp("", "fenzi-index-")
	if err != nil {
		return "", err
	}
	tmp.Close()
	os.Remove(tmp.Name())
	defer os.Remove(tmp.Name())
	env := []string{"GIT_INDEX_FILE=" + tmp.Name()}
	for _, args := range [][]string{{"read-tree", "HEAD"}, {"add", "-A", "--"}} {
		cmd := gitCmd(root, args...)
		cmd.Env = append(cmd.Env, env...)
		if _, err := run(cmd); err != nil {
			return "", err
		}
	}
	cmd := gitCmd(root, "write-tree")
	cmd.Env = append(cmd.Env, env...)
	return run(cmd)
}

// BundleIn writes the history up to the sandbox's start commit into file,
// under the start ref's name. ErrTooLarge means the file is over MaxBundle
// and was removed.
func BundleIn(root, sandbox, file string) (size int64, err error) {
	if _, err := git(root, "bundle", "create", "-q", file, StartRef(sandbox)); err != nil {
		return 0, err
	}
	info, err := os.Stat(file)
	if err != nil {
		return 0, err
	}
	if info.Size() > MaxBundle {
		os.Remove(file)
		return info.Size(), ErrTooLarge
	}
	return info.Size(), nil
}

// BundleBranch writes the commits on branch since start into file, under
// the branch's own name, so `git fetch <file> <branch>:<branch>` brings
// them into another clone that has start. An unattended run keeps it as
// the job's artifact.
func BundleBranch(root, branch, start, file string) error {
	if strings.HasPrefix(branch, "-") || strings.HasPrefix(start, "-") {
		return fmt.Errorf("refusing branch %q or start %q", branch, start)
	}
	_, err := git(root, "bundle", "create", "-q", file, "refs/heads/"+branch, "^"+start)
	return err
}

// ErrTooLarge means a bundle is over MaxBundle.
var ErrTooLarge = errors.New("the history is too large to copy into the sandbox")

// Fetched is one branch fetched from the sandbox's bundle.
type Fetched struct {
	Name string
	Head string
}

// FetchOut brings the branches in file, the bundle the sandbox made, into
// refs/fenzi/<sandbox>/heads/. fsck is on, with the check for .git in a
// tree pinned to an error whatever the developer's own config says, so a
// hostile tree refuses the whole pack before any ref is written. Tags are
// left in the sandbox and submodules are not fetched. A detached HEAD in the
// bundle is fetched under detachedAs.
func FetchOut(root, sandbox, file, detachedAs string) ([]Fetched, error) {
	heads, err := git(root, "bundle", "list-heads", file)
	if err != nil {
		return nil, fmt.Errorf("reading the sandbox's bundle: %w", err)
	}
	var refspecs []string
	var out []Fetched
	headSHA := ""
	for _, line := range strings.Split(heads, "\n") {
		f := strings.Fields(line)
		if len(f) != 2 {
			continue
		}
		if strings.HasPrefix(f[1], "refs/heads/") {
			name := strings.TrimPrefix(f[1], "refs/heads/")
			refspecs = append(refspecs, "+"+f[1]+":"+landedRefs(sandbox)+name)
			out = append(out, Fetched{Name: name, Head: f[0]})
		} else if f[1] == "HEAD" {
			headSHA = f[0]
		}
	}
	// HEAD is a branch's tip unless it was detached from every branch.
	detached := headSHA != "" && detachedAs != ""
	for _, b := range out {
		if b.Head == headSHA {
			detached = false
		}
	}
	if detached {
		refspecs = append(refspecs, "+HEAD:"+landedRefs(sandbox)+detachedAs)
		out = append(out, Fetched{Name: detachedAs, Head: headSHA})
	}
	if len(refspecs) == 0 {
		return nil, errors.New("the sandbox's bundle names no branch")
	}
	args := append([]string{"-c", "transfer.fsckObjects=true", "-c", "fetch.fsck.hasDotgit=error",
		"fetch", "-q", "--no-tags", "--no-recurse-submodules", file}, refspecs...)
	if _, err := git(root, args...); err != nil {
		return nil, fmt.Errorf("the sandbox's commits were refused: %w", err)
	}
	// list-heads gave the bundle's own view; read the refs as fetched.
	for i := range out {
		if sha, err := git(root, "rev-parse", "--verify", "-q", landedRefs(sandbox)+out[i].Name); err == nil {
			out[i].Head = sha
		}
	}
	return out, nil
}

// Land makes the agent's branch a branch of the repository and returns its
// name. The agent's own name is used when the repository has no branch of
// that name. An existing branch is written only when it is Fenzi's: its
// name starts with fenzi/, the agent's own branch or one Fenzi landed under
// fenzi/<sandbox>/ earlier, and it is an ancestor of the tip, so the write
// is a fast-forward. Any other existing branch, whatever its relation to
// the tip, is the developer's: the commits land as fenzi/<sandbox>/<name>
// instead. An old branch merged into HEAD long ago is always an ancestor of
// the tip, so being an ancestor alone never allows a write. The branch
// checked out at start and the one checked out now are never written here
// either; those move only in FastForward. Afterwards the sandbox's refs
// under refs/fenzi/ are dropped, so a git push --mirror does not publish
// them; the landed branch keeps the commits reachable.
func Land(root, sandbox, startBranch string, b Fetched) (string, error) {
	own := "fenzi/" + sandbox + "/"
	name := b.Name
	current, _ := git(root, "symbolic-ref", "-q", "--short", "HEAD")
	if name == startBranch || name == current {
		name = own + name
	}
	ref := "refs/heads/" + name
	old, err := git(root, "rev-parse", "--verify", "-q", ref)
	exists := err == nil
	if exists && old != b.Head && !(strings.HasPrefix(name, "fenzi/") && isAncestor(root, old, b.Head)) {
		name = own + b.Name
		ref = "refs/heads/" + name
		old, err = git(root, "rev-parse", "--verify", "-q", ref)
		exists = err == nil
	}
	if !exists {
		old = ""
	}
	if old != b.Head {
		if _, err := git(root, "update-ref", ref, b.Head, old); err != nil {
			return "", err
		}
	}
	DropRefs(root, sandbox)
	return name, nil
}

// DropRefs removes every ref Fenzi kept for the sandbox under refs/fenzi/.
func DropRefs(root, sandbox string) {
	refs, err := git(root, "for-each-ref", "--format=%(refname)", "refs/fenzi/"+sandbox+"/")
	if err != nil {
		return
	}
	for _, r := range strings.Fields(refs) {
		_, _ = git(root, "update-ref", "-d", r)
	}
}

// IsAncestor reports whether commit a is reachable from commit b.
func IsAncestor(root, a, b string) bool {
	_, err := git(root, "merge-base", "--is-ancestor", a, b)
	return err == nil
}

func isAncestor(root, a, b string) bool { return IsAncestor(root, a, b) }

// Landing is what FastForward needs: the branch and commit checked out
// when the sandbox started, the commit the agent's branch began at, the
// commit it reached, and the name that commit landed under, for the hints.
type Landing struct {
	Branch, Head, Start, Tip, Name string
}

func (l Landing) tip() string {
	if l.Name != "" {
		return l.Name
	}
	return l.Tip
}

// Refusal says why FastForward did not move the branch. Nothing changed.
type Refusal struct {
	Reason string
	// Hint is what to do instead, as a git command to run by hand.
	Hint string
}

func (r *Refusal) Error() string { return r.Reason }

// ErrMerged means the agent's commits are already on the branch.
var ErrMerged = errors.New("already merged")

// FastForward moves the branch the sandbox started on to the agent's tip,
// when nothing in between has changed: the same branch is checked out at
// the same commit, the agent did not rewrite the commits that were there,
// and the folder is clean or still holds exactly the edits it had at start,
// which are inside the agent's history. Then the index and the folder are
// moved to the tip's tree with read-tree, no hook runs, and the branch is
// moved with a compare-and-swap. Any other case is a Refusal with the
// merge to run by hand; the branch, index and folder are left as they are.
func FastForward(root string, l Landing) error {
	if l.Branch == "" {
		return &Refusal{Reason: "no branch was checked out when the sandbox started", Hint: "git switch -c <branch> " + l.tip()}
	}
	merge := "git merge " + l.tip()
	current, _ := git(root, "symbolic-ref", "-q", "--short", "HEAD")
	if current != l.Branch {
		on := "detached from any branch"
		if current != "" {
			on = "on " + current
		}
		return &Refusal{Reason: fmt.Sprintf("the sandbox started on %s and you are %s now", l.Branch, on), Hint: "git switch " + l.Branch + ", then fenzi apply again; or " + merge}
	}
	head, err := git(root, "rev-parse", "--verify", "-q", "HEAD")
	if err != nil {
		return err
	}
	if isAncestor(root, l.Tip, head) {
		return ErrMerged
	}
	if head != l.Head {
		return &Refusal{Reason: fmt.Sprintf("%s moved from %s to %s while the agent worked", l.Branch, short(l.Head), short(head)), Hint: merge}
	}
	if !isAncestor(root, l.Start, l.Tip) {
		return &Refusal{Reason: "the agent rewrote commits that were on " + l.Branch + " when it started", Hint: "git log " + l.tip() + ", then merge or cherry-pick by hand"}
	}
	tree, err := worktreeTree(root)
	if err != nil {
		return err
	}
	ok := false
	for _, c := range []string{l.Start, l.Head} {
		if t, err := git(root, "rev-parse", c+"^{tree}"); err == nil && t == tree {
			ok = true
		}
	}
	if !ok {
		return &Refusal{Reason: "your folder has edits since the sandbox started", Hint: "commit or stash them, then fenzi apply again"}
	}
	for _, args := range [][]string{
		{"read-tree", tree},
		{"update-index", "-q", "--refresh"},
		{"read-tree", "-m", "-u", tree, l.Tip},
		{"update-ref", "refs/heads/" + l.Branch, l.Tip, head},
	} {
		if _, err := git(root, args...); err != nil {
			return fmt.Errorf("moving %s: %w", l.Branch, err)
		}
	}
	return nil
}

func short(sha string) string {
	if len(sha) > 7 {
		return sha[:7]
	}
	return sha
}

// gitCmd is a git command in root with hooks and the file monitor off and
// no optional lock files, so a read never blocks an editor.
func gitCmd(root string, args ...string) *exec.Cmd {
	cmd := exec.Command("git", append([]string{"-C", root, "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false"}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_OPTIONAL_LOCKS=0")
	return cmd
}

func git(root string, args ...string) (string, error) {
	return run(gitCmd(root, args...))
}

// run returns trimmed stdout, or stderr's first lines as the error.
func run(cmd *exec.Cmd) (string, error) {
	var out, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		if lines := strings.Split(msg, "\n"); len(lines) > 3 {
			msg = strings.Join(lines[:3], " ") + " (" + strconv.Itoa(len(lines)-3) + " more lines)"
		}
		return "", errors.New(msg)
	}
	return strings.TrimSpace(out.String()), nil
}
