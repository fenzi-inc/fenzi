package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"fenzi/cli/internal/config"
	"fenzi/cli/internal/tui"
	"fenzi/cli/internal/workspace"
)

// review is one set of staged changes and how to name it in a command.
type review struct {
	sb      config.Sandbox
	base    workspace.Manifest
	files   string
	changes []workspace.Change
	// flag is appended to suggested commands: "" when the sandbox is the
	// latest for this folder, otherwise " --sandbox <name>".
	flag string
	home string
}

func newReview(sb config.Sandbox, base workspace.Manifest, files string, changes []workspace.Change, flag string) review {
	return review{sb: sb, base: base, files: files, changes: changes, flag: flag, home: homeDir()}
}

func (r review) folder() string { return tilde(r.sb.Repo, r.home) }

func (r review) diffs() []workspace.FileDiff {
	out := make([]workspace.FileDiff, len(r.changes))
	for i, c := range r.changes {
		d, err := workspace.Diff(r.sb.Repo, r.files, c)
		if err != nil {
			d = workspace.FileDiff{Change: c, Large: true}
		}
		out[i] = d
	}
	return out
}

func plural(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %s", n, many)
}

func counts(u *tui.UI, d workspace.FileDiff) string {
	switch {
	case d.Binary:
		return u.Dim("binary")
	case d.Large && d.Added+d.Removed == 0:
		return u.Dim("too large to compare")
	}
	var parts []string
	if d.Added > 0 || d.Removed == 0 {
		parts = append(parts, u.Accent(fmt.Sprintf("+%d", d.Added)))
	}
	if d.Removed > 0 {
		parts = append(parts, u.Deny(fmt.Sprintf("−%d", d.Removed)))
	}
	return strings.Join(parts, " ")
}

var kindWord = map[workspace.Kind]string{workspace.Added: "new", workspace.Modified: "edited", workspace.Deleted: "deleted"}

// summary lists the files with their line counts.
func (r review) summary(u *tui.UI, diffs []workspace.FileDiff) {
	added, removed := 0, 0
	width := 0
	for _, d := range diffs {
		added += d.Added
		removed += d.Removed
		width = max(width, len([]rune(d.Path)))
	}
	width = min(width, 48)
	title := fmt.Sprintf("%s from the agent", plural(len(diffs), "file changed", "files changed"))
	u.Println(fmt.Sprintf("  %s %s  %s", u.Accent("■"), u.Bold(title), u.Dim("not applied yet")))
	u.Blank()
	for _, d := range diffs {
		kind := fmt.Sprintf("%-7s", kindWord[d.Kind])
		if d.Kind == workspace.Deleted {
			kind = u.Deny(kind)
		} else {
			kind = u.Dim(kind)
		}
		path := d.Path
		if pad := width - len([]rune(path)); pad > 0 {
			path += strings.Repeat(" ", pad)
		}
		u.Println(fmt.Sprintf("    %s %s  %s", kind, u.Bold(path), counts(u, d)))
	}
	if len(diffs) > 1 {
		u.Println(fmt.Sprintf("    %s %s  %s", strings.Repeat(" ", 7), strings.Repeat(" ", width), u.Dim(fmt.Sprintf("+%d −%d in total", added, removed))))
	}
}

// patch writes every file's diff: a header per file, then its hunks with
// line numbers. Removed lines are in the red pen, added lines in the accent.
func (r review) patch(u *tui.UI, w io.Writer, diffs []workspace.FileDiff) {
	p := func(s string) { fmt.Fprintln(w, s) }
	for _, d := range diffs {
		p("")
		head := fmt.Sprintf("%s  %s", d.Path, kindWord[d.Kind])
		p("  " + u.Accent("──") + " " + u.Bold(head) + "  " + counts(u, d))
		switch {
		case d.Binary:
			p("     " + u.Dim("binary file, not shown"))
			continue
		case d.Large:
			p("     " + u.Dim("too large to compare line by line"))
			continue
		}
		for i, h := range d.Hunks {
			if i > 0 {
				p("     " + u.Dim("⋮"))
			}
			old, cur := h.OldStart, h.NewStart
			for _, o := range h.Ops {
				switch o.Kind {
				case ' ':
					p(fmt.Sprintf("  %s   %s", u.Dim(fmt.Sprintf("%5d", cur)), o.Text))
					old++
					cur++
				case '-':
					p(fmt.Sprintf("  %s %s", u.Dim(fmt.Sprintf("%5d", old)), u.Deny("- "+o.Text)))
					old++
				case '+':
					p(fmt.Sprintf("  %s %s", u.Dim(fmt.Sprintf("%5d", cur)), u.Accent("+ "+o.Text)))
					cur++
				}
			}
		}
	}
	p("")
}

// show prints the patch, through a pager when it is taller than the screen.
func (r review) show(e env, u *tui.UI, diffs []workspace.FileDiff) {
	var buf bytes.Buffer
	r.patch(u, &buf, diffs)
	_, height := u.Size()
	if !u.Interactive() || strings.Count(buf.String(), "\n") < height-2 || !page(e, &buf) {
		_, _ = e.stdout.Write(buf.Bytes())
	}
}

// page runs $PAGER, or less, on the patch. It reports false when no pager ran.
func page(e env, buf *bytes.Buffer) bool {
	argv := []string{"less", "-RFX"}
	if p := strings.Fields(os.Getenv("PAGER")); len(p) > 0 {
		argv = p
	}
	if _, err := exec.LookPath(argv[0]); err != nil {
		return false
	}
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Stdin = buf
	cmd.Stdout, cmd.Stderr = e.stdout, e.stderr
	cmd.Env = append(os.Environ(), "LESS=-RFX")
	return cmd.Run() == nil
}

// decide asks what to do with the changes until they are applied or kept.
// applyFirst makes applying the default answer.
func (r review) decide(e env, u *tui.UI, diffs []workspace.FileDiff, applyFirst bool) (int, error) {
	shown := false
	for {
		u.Blank()
		show := "Show the changes"
		if shown {
			show = "Show them again"
		}
		apply := "Apply them to " + r.folder()
		opts := []tui.Option{{Label: apply}, {Label: show}, {Label: "Keep them for later"}}
		if !shown && !applyFirst {
			opts[0], opts[1] = opts[1], opts[0]
		}
		i, err := u.Select("What should happen to these changes?", opts, 0)
		if errors.Is(err, tui.ErrCancelled) {
			r.later(u)
			return 0, nil
		}
		if err != nil {
			return 1, err
		}
		switch opts[i].Label {
		case show:
			r.show(e, u, diffs)
			shown = true
		case apply:
			return r.apply(u)
		default:
			r.later(u)
			return 0, nil
		}
	}
}

func (r review) apply(u *tui.UI) (int, error) {
	conflicts, err := workspace.Conflicts(r.sb.Repo, r.base, r.changes)
	if err != nil {
		return 1, err
	}
	if len(conflicts) > 0 {
		u.Blank()
		u.Problem("Not applied", plural(len(conflicts), "file", "files")+" also changed in "+r.folder()+" while the agent worked")
		for _, c := range conflicts {
			u.Println("      " + c)
		}
		u.Note("Applying would overwrite those edits, so nothing was changed. Save or undo them, then run fenzi apply" + r.flag + " again.")
		return 1, nil
	}
	next, err := workspace.Applied(r.base, r.files, r.changes)
	if err != nil {
		return 1, err
	}
	if err := workspace.Apply(r.sb.Repo, r.files, r.changes); err != nil {
		return 1, err
	}
	// The sandbox may keep running; its next copy is compared with what was
	// just applied, so the snapshot stays and only the staged copy goes.
	if err := next.Save(filepath.Join(filepath.Dir(r.files), "base.json")); err != nil {
		return 1, err
	}
	_ = os.RemoveAll(r.files)
	u.Blank()
	u.Done("Applied", plural(len(r.changes), "file", "files")+" in "+r.folder())
	u.Note("Your version control sees them as ordinary edits. Review or commit them as usual.")
	return 0, nil
}

func (r review) later(u *tui.UI) {
	u.Blank()
	u.Skip("Kept for later", "nothing in "+r.folder()+" changed")
	u.Note("The changes stay staged on this machine. From " + r.folder() + ":")
	u.Commands([2]string{"fenzi diff" + r.flag, "see them again"}, [2]string{"fenzi apply" + r.flag, "apply them"})
}

// offer is shown after an agent exits or a sandbox is stopped.
func (r review) offer(e env) (int, error) {
	u := tui.New(e.stdin, e.stdout)
	diffs := r.diffs()
	u.Blank()
	r.summary(u, diffs)
	if !u.Interactive() {
		r.later(u)
		return 0, nil
	}
	return r.decide(e, u, diffs, false)
}

func sandboxFlag(name string) string {
	if name == "" {
		return ""
	}
	return " --sandbox " + name
}

func cmdDiff(e env, args []string) (int, error) {
	fs := newFlags("diff", e.stderr)
	sandbox := fs.String("sandbox", "", "sandbox name (default: the latest for this folder)")
	stat := fs.Bool("stat", false, "list the files and line counts only")
	if _, err := parse(fs, args); err != nil {
		return 1, err
	}
	sb, base, files, changes, err := staged(e, *sandbox)
	if err != nil {
		return 1, err
	}
	u := tui.New(e.stdin, e.stdout)
	r := newReview(sb, base, files, changes, sandboxFlag(*sandbox))
	if len(changes) == 0 {
		u.Done("No changes", "the agent left "+r.folder()+" as it was")
		return 0, nil
	}
	diffs := r.diffs()
	u.Blank()
	r.summary(u, diffs)
	if !*stat {
		r.show(e, u, diffs)
	} else {
		u.Blank()
	}
	u.Println("  " + u.Dim("Nothing in "+r.folder()+" has changed. ") + u.Bold("fenzi apply"+r.flag) + u.Dim(" copies them in."))
	return 0, nil
}

func cmdApply(e env, args []string) (int, error) {
	fs := newFlags("apply", e.stderr)
	sandbox := fs.String("sandbox", "", "sandbox name (default: the latest for this folder)")
	yes := fs.Bool("yes", false, "apply without asking")
	if _, err := parse(fs, args); err != nil {
		return 1, err
	}
	sb, base, files, changes, err := staged(e, *sandbox)
	if err != nil {
		return 1, err
	}
	u := tui.New(e.stdin, e.stdout)
	r := newReview(sb, base, files, changes, sandboxFlag(*sandbox))
	if len(changes) == 0 {
		u.Done("Nothing to apply", "the agent left "+r.folder()+" as it was")
		return 0, nil
	}
	diffs := r.diffs()
	u.Blank()
	r.summary(u, diffs)
	switch {
	case *yes:
		return r.apply(u)
	case u.Interactive():
		return r.decide(e, u, diffs, true)
	}
	u.Blank()
	answer, err := u.Input("Apply them to "+r.folder()+"? [y/N]", "")
	if a := strings.ToLower(answer); err != nil || (a != "y" && a != "yes") {
		r.later(u)
		return 0, nil
	}
	return r.apply(u)
}
