package main

import (
	"errors"
	"fmt"
	"strings"

	"fenzi/cli/internal/tui"
	"fenzi/cli/internal/workspace"
)

// cmdBranch shows the folder's branch and lets a person switch or create
// one before a sandbox starts: the sandbox works from what the folder has
// checked out, and fenzi apply fast-forwards that branch afterwards.
//
//	fenzi branch                     the checked-out branch and the local ones
//	fenzi branch --json              the same, for a program
//	fenzi branch <name>              switch the folder to a local branch
//	fenzi branch --new <name>        create a branch from the checked-out commit and switch to it
//	fenzi branch --new --from <source> <name>
//	                                 create it from another branch or commit (flags first, as everywhere)
func cmdBranch(e env, args []string) (int, error) {
	fs := newFlags("branch", e.stderr)
	asJSON := jsonFlag(fs)
	create := fs.Bool("new", false, "create the branch, then switch to it")
	from := fs.String("from", "", "with --new: the branch or commit the new branch starts from (default: the checked-out commit)")
	pos, err := parse(fs, args)
	if err != nil {
		return 1, err
	}
	if len(pos) > 1 {
		return 1, errors.New("fenzi branch takes one branch name")
	}
	repo, err := cwd()
	if err != nil {
		return 1, err
	}
	if *from != "" && !*create {
		return 1, errors.New("--from goes with --new")
	}
	if len(pos) == 0 {
		if *create {
			return 1, errors.New("--new needs the branch's name: fenzi branch --new <name>")
		}
		b := workspace.ReadBranches(repo)
		if *asJSON {
			return 0, writeJSON(e.stdout, b)
		}
		u := tui.New(e.stdin, e.stdout)
		if !b.Repo {
			u.Problem("Branch", "this folder is not a git repository with a commit")
			return 3, nil
		}
		switch {
		case b.Detached:
			u.Done("Branch", "none: HEAD is detached")
		case b.Dirty:
			u.Done("Branch", b.Current+" (uncommitted edits)")
		default:
			u.Done("Branch", b.Current)
		}
		if others := without(b.Local, b.Current); len(others) > 0 {
			u.Note("Also here: " + strings.Join(others, ", ") + ". fenzi branch <name> switches; fenzi branch --new <name> creates one.")
		}
		return 0, nil
	}
	name := pos[0]
	if err := workspace.Switch(repo, name, *from, *create); err != nil {
		return 1, err
	}
	if *asJSON {
		return 0, writeJSON(e.stdout, workspace.ReadBranches(repo))
	}
	u := tui.New(e.stdin, e.stdout)
	if *create {
		if *from != "" {
			u.Done("Branch", fmt.Sprintf("%s, created from %s", name, *from))
		} else {
			u.Done("Branch", name+", created")
		}
	} else {
		u.Done("Branch", name)
	}
	return 0, nil
}

func without(list []string, item string) []string {
	var out []string
	for _, s := range list {
		if s != item {
			out = append(out, s)
		}
	}
	return out
}

// switchBranch is fenzi run --branch: the folder switched before the
// start is recorded, so the sandbox works from that branch. A branch that
// does not exist yet is created, from --from or the checked-out commit.
func switchBranch(repo, name, from string) (created bool, err error) {
	if name == "" {
		if from != "" {
			return false, errors.New("--from goes with --branch")
		}
		return false, nil
	}
	if !workspace.ReadBranches(repo).Repo {
		return false, errors.New("--branch needs a git repository with a commit; this folder has none")
	}
	if workspace.HasBranch(repo, name) {
		if from != "" {
			return false, fmt.Errorf("%s exists already; --from only goes with a branch that is created", name)
		}
		return false, workspace.Switch(repo, name, "", false)
	}
	return true, workspace.Switch(repo, name, from, true)
}
