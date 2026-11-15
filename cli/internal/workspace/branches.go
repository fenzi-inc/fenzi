package workspace

import (
	"errors"
	"fmt"
	"os/exec"
	"sort"
	"strings"
)

// Branches is what a folder's repository says about its branches, for the
// choice a person makes before a sandbox starts: the sandbox works from
// whatever the folder has checked out.
type Branches struct {
	// Repo is whether the folder is a git work tree with a commit. The
	// other fields are empty when it is not.
	Repo bool `json:"repo"`
	// Current is the checked-out branch, "" when HEAD is detached.
	Current  string `json:"current"`
	Detached bool   `json:"detached"`
	// Dirty is whether the folder has uncommitted edits or untracked files
	// that are not ignored. A switch carries them along.
	Dirty bool `json:"dirty"`
	// Local lists the local branches, sorted, the current one included.
	Local []string `json:"local"`
}

// ReadBranches reads root's branches without writing anything in it.
func ReadBranches(root string) Branches {
	var b Branches
	if _, err := exec.LookPath("git"); err != nil {
		return b
	}
	if _, err := git(root, "rev-parse", "--verify", "-q", "HEAD"); err != nil {
		return b
	}
	b.Repo = true
	if cur, err := git(root, "symbolic-ref", "-q", "--short", "HEAD"); err == nil {
		b.Current = cur
	} else {
		b.Detached = true
	}
	if status, err := git(root, "status", "--porcelain", "-z", "--untracked-files=normal"); err == nil {
		b.Dirty = status != ""
	}
	if list, err := git(root, "for-each-ref", "--format=%(refname:short)", "refs/heads/"); err == nil && list != "" {
		b.Local = strings.Split(list, "\n")
		sort.Strings(b.Local)
	}
	return b
}

// Switch checks out branch name in root. With create, the branch is made
// first, from `from` (a branch or a commit; the checked-out commit when
// empty). Uncommitted edits come along, as git switch carries them; when
// they would be overwritten, git refuses and nothing changes. Hooks stay
// off, as for every git call here.
func Switch(root, name, from string, create bool) error {
	if strings.TrimSpace(name) == "" {
		return errors.New("a branch name is needed")
	}
	if _, err := git(root, "check-ref-format", "--branch", name); err != nil {
		return fmt.Errorf("%q is not a branch name git accepts", name)
	}
	if create {
		args := []string{"switch", "-q", "-c", name}
		if from != "" {
			if _, err := git(root, "rev-parse", "--verify", "-q", from+"^{commit}"); err != nil {
				return fmt.Errorf("%q is not a branch or commit in this repository", from)
			}
			args = append(args, from)
		}
		if _, err := git(root, args...); err != nil {
			return fmt.Errorf("git could not create %s: %v", name, err)
		}
		return nil
	}
	if _, err := git(root, "rev-parse", "--verify", "-q", "refs/heads/"+name); err != nil {
		return fmt.Errorf("there is no local branch %s; fenzi branch --new %s creates it", name, name)
	}
	if _, err := git(root, "switch", "-q", name); err != nil {
		return fmt.Errorf("git could not switch to %s: %v", name, err)
	}
	return nil
}

// HasBranch reports whether root has a local branch named name.
func HasBranch(root, name string) bool {
	_, err := git(root, "rev-parse", "--verify", "-q", "refs/heads/"+name)
	return err == nil
}
