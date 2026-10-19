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
	"time"

	"fenzi/agents"
	"fenzi/cli/internal/config"
	"fenzi/cli/internal/run"
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

// landed reports whether the agent's commits are a branch in the
// repository. Then apply merges that branch; the files are never copied on
// top of committed work, which is where a second copy of a change comes
// from.
func (r review) landed() bool {
	return r.sb.Git != nil && r.sb.Git.History && r.sb.Git.Landed != ""
}

// agent is the agent's display name.
func (r review) agent() string {
	if a, err := agents.Get(r.sb.Agent); err == nil {
		return a.Display
	}
	return r.sb.Agent
}

// applyLabel is the apply choice: merge the landed branch, or copy the files.
func (r review) applyLabel() string {
	if r.landed() {
		return "Merge " + r.sb.Git.Landed + " into " + r.sb.Git.Branch
	}
	return "Apply them to " + r.folder()
}

// jsonDiff is `fenzi diff --json`: the files the agent changed, each with
// its counts, its hunks and the reason it runs on this machine once applied
// (the "!" label of the text), and what fenzi apply would do with them.
type jsonDiff struct {
	Sandbox string `json:"sandbox"`
	// Folder is the project, absolute. Agent is the agent's display name.
	Folder string `json:"folder"`
	Agent  string `json:"agent"`
	// Files is empty when the agent left the folder as it was.
	Files   []jsonFileDiff `json:"files"`
	Added   int            `json:"added"`
	Removed int            `json:"removed"`
	// HostRun counts the files that run on this machine once applied.
	HostRun int `json:"host_run"`
	// Landed is set when the agent's commits are a branch in the repository;
	// apply then merges instead of copying files.
	Landed *jsonLanded `json:"landed,omitempty"`
	// Apply is what fenzi apply does, as the text names the choice: "Merge
	// claude/fix into main" or "Apply them to ~/web".
	Apply string `json:"apply"`
}

type jsonLanded struct {
	// Branch is the branch the sandbox started on; Name the branch that
	// holds the agent's commits; Commits how many. Merged is the commit
	// Branch was moved to by fenzi apply, absent until then.
	Branch  string `json:"branch"`
	Name    string `json:"name"`
	Commits int    `json:"commits"`
	Merged  string `json:"merged,omitempty"`
}

type jsonFileDiff struct {
	Path string `json:"path"`
	// Kind is new, edited or deleted, the words of the text output.
	Kind    string `json:"kind"`
	Added   int    `json:"added"`
	Removed int    `json:"removed"`
	Binary  bool   `json:"binary,omitempty"`
	// Large means the file was not compared line by line.
	Large bool `json:"large,omitempty"`
	// HostRun says why the file runs on this machine once applied, with no
	// further step; absent when it does not.
	HostRun string `json:"host_run,omitempty"`
	// Hunks is absent with --stat, and for a binary or large file.
	Hunks []jsonHunk `json:"hunks,omitempty"`
}

type jsonHunk struct {
	OldStart int      `json:"old_start"`
	NewStart int      `json:"new_start"`
	Ops      []jsonOp `json:"ops"`
}

// jsonOp is one line of a hunk: kind is " " (kept), "-" (removed) or "+" (added).
type jsonOp struct {
	Kind string `json:"kind"`
	Text string `json:"text"`
}

// document is the review as fenzi diff --json prints it.
func (r review) document(stat bool) jsonDiff {
	doc := jsonDiff{Sandbox: r.sb.Name, Folder: r.sb.Repo, Agent: r.agent(), Files: []jsonFileDiff{}, Apply: r.applyLabel()}
	if r.landed() {
		g := r.sb.Git
		doc.Landed = &jsonLanded{Branch: g.Branch, Name: g.Landed, Commits: g.Commits, Merged: g.Merged}
	}
	if len(r.changes) == 0 {
		return doc
	}
	for _, d := range r.diffs() {
		f := jsonFileDiff{Path: d.Path, Kind: kindWord[d.Kind], Added: d.Added, Removed: d.Removed, Binary: d.Binary, Large: d.Large, HostRun: d.HostRun}
		if !stat {
			for _, h := range d.Hunks {
				j := jsonHunk{OldStart: h.OldStart, NewStart: h.NewStart, Ops: make([]jsonOp, 0, len(h.Ops))}
				for _, o := range h.Ops {
					j.Ops = append(j.Ops, jsonOp{Kind: string(o.Kind), Text: o.Text})
				}
				f.Hunks = append(f.Hunks, j)
			}
		}
		doc.Added += d.Added
		doc.Removed += d.Removed
		if d.HostRun != "" {
			doc.HostRun++
		}
		doc.Files = append(doc.Files, f)
	}
	return doc
}

// afterApply is the footer of fenzi diff: what fenzi apply does.
func (r review) afterApply(u *tui.UI) string {
	if r.landed() {
		g := r.sb.Git
		return "  " + u.Dim(fmt.Sprintf("%s is unchanged; the commits are on %s. ", g.Branch, g.Landed)) + u.Bold("fenzi apply"+r.flag) + u.Dim(" fast-forwards "+g.Branch+" to them.")
	}
	return "  " + u.Dim("Nothing in "+r.folder()+" has changed. ") + u.Bold("fenzi apply"+r.flag) + u.Dim(" copies them in.")
}

func (r review) diffs() []workspace.FileDiff {
	out := make([]workspace.FileDiff, len(r.changes))
	for i, c := range r.changes {
		d, err := workspace.Diff(r.sb.Repo, r.files, c)
		if err != nil {
			d = workspace.FileDiff{Change: c, Large: true, HostRun: workspace.HostRun(c, nil, nil)}
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
	state := "not applied yet"
	if r.landed() {
		g := r.sb.Git
		title = fmt.Sprintf("%s in %s by %s on %s", plural(len(diffs), "file changed", "files changed"), plural(g.Commits, "commit", "commits"), r.agent(), g.Landed)
		state = "not merged yet"
	}
	u.Println(fmt.Sprintf("  %s %s  %s", u.Accent("■"), u.Bold(title), u.Dim(state)))
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
		u.Println(fmt.Sprintf("    %s %s  %s%s", kind, u.Bold(path), counts(u, d), hostRun(u, d)))
	}
	if len(diffs) > 1 {
		u.Println(fmt.Sprintf("    %s %s  %s", strings.Repeat(" ", 7), strings.Repeat(" ", width), u.Dim(fmt.Sprintf("+%d −%d in total", added, removed))))
	}
	if n := runsOnHost(diffs); n > 0 {
		u.Blank()
		u.Note(fmt.Sprintf("%s marked ! %s on this machine once applied, with no further step from you. Read %s before you apply.",
			plural(n, "file", "files"), pick(n, "runs", "run"), pick(n, "it", "them")))
	}
}

// hostRun is the label after a file's counts when it runs on this machine
// once applied. It only warns; apply still writes the file.
func hostRun(u *tui.UI, d workspace.FileDiff) string {
	if d.HostRun == "" {
		return ""
	}
	return "  " + u.Deny("! "+d.HostRun)
}

func runsOnHost(diffs []workspace.FileDiff) int {
	n := 0
	for _, d := range diffs {
		if d.HostRun != "" {
			n++
		}
	}
	return n
}

func pick(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// patch writes every file's diff: a header per file, then its hunks with
// line numbers. Removed lines are in the red pen, added lines in the accent.
func (r review) patch(u *tui.UI, w io.Writer, diffs []workspace.FileDiff) {
	p := func(s string) { fmt.Fprintln(w, s) }
	for _, d := range diffs {
		p("")
		head := fmt.Sprintf("%s  %s", d.Path, kindWord[d.Kind])
		p("  " + u.Accent("──") + " " + u.Bold(head) + "  " + counts(u, d) + hostRun(u, d))
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
		apply := r.applyLabel()
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
	if r.landed() {
		return r.merge(u)
	}
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
	_ = run.MarkApplied(filepath.Dir(r.files), time.Now())
	_ = os.RemoveAll(r.files)
	u.Blank()
	u.Done("Applied", plural(len(r.changes), "file", "files")+" in "+r.folder())
	u.Note("Your version control sees them as ordinary edits. Review or commit them as usual.")
	return 0, nil
}

// merge moves the branch the sandbox started on to the agent's commits,
// when the checkout is still where it was at start. Anything else is a
// refusal with the merge to run by hand; the branch and the folder are left
// as they are. The commits are already in the repository, so nothing is
// copied, and a second apply finds them merged.
func (r review) merge(u *tui.UI) (int, error) {
	g := r.sb.Git
	err := workspace.FastForward(r.sb.Repo, workspace.Landing{Branch: g.Branch, Head: g.Head, Start: g.Start, Tip: g.Tip, Name: g.Landed})
	var refusal *workspace.Refusal
	switch {
	case errors.As(err, &refusal):
		u.Blank()
		u.Problem("Not merged", refusal.Reason)
		u.Note("Nothing was changed. The commits are on " + g.Landed + ". Next: " + refusal.Hint + ".")
		return 1, nil
	case errors.Is(err, workspace.ErrMerged):
		r.clearStaged()
		u.Blank()
		u.Done("Already merged", g.Branch+" has the commits on "+g.Landed)
		u.Note("Nothing was changed. The staged copy of the files is dropped; the commits are the one copy.")
		return 0, nil
	case err != nil:
		return 1, err
	}
	// The branch is at the tip now. A sandbox that keeps running starts its
	// next round from there, so the next apply compares with it.
	g.Merged, g.Head, g.Start, g.Dirty = g.Tip, g.Tip, g.Tip, false
	if s, err := config.Default(); err == nil {
		if st, err := s.LoadState(); err == nil {
			if cur, ok := st.Find(r.sb.Name); ok {
				cur.Git = g
				st.Put(cur)
				_ = s.SaveState(st)
			}
		}
	}
	r.clearStaged()
	u.Blank()
	u.Done("Merged", fmt.Sprintf("%s is at %s, %s by %s", g.Branch, shortSHA(g.Tip), plural(g.Commits, "commit", "commits"), r.agent()))
	note := "Your folder has the files as the agent left them, and the commits have the same ids as in the sandbox. Push when you are ready."
	if g.Dirty {
		note = "Your uncommitted changes from the start are the first of those commits. " + note
	}
	u.Note(note)
	return 0, nil
}

// clearStaged drops the staged copy once the commits are on the branch, and
// keeps the snapshot for a sandbox that keeps running.
func (r review) clearStaged() {
	if next, err := workspace.Applied(r.base, r.files, r.changes); err == nil {
		_ = next.Save(filepath.Join(filepath.Dir(r.files), "base.json"))
	}
	_ = run.MarkApplied(filepath.Dir(r.files), time.Now())
	_ = os.RemoveAll(r.files)
}

func shortSHA(s string) string {
	if len(s) > 7 {
		return s[:7]
	}
	return s
}

func (r review) later(u *tui.UI) {
	u.Blank()
	if r.landed() {
		g := r.sb.Git
		u.Skip("Kept for later", g.Branch+" is unchanged")
		u.Note("The commits are on " + g.Landed + " in your repository. From " + r.folder() + ":")
		u.Commands([2]string{"fenzi diff" + r.flag, "see them again"}, [2]string{"fenzi apply" + r.flag, "fast-forward " + g.Branch + " to them"}, [2]string{"git log " + g.Landed, "see the commits"})
		return
	}
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
	asJSON := jsonFlag(fs)
	if _, err := parse(fs, args); err != nil {
		return 1, err
	}
	sb, base, files, changes, err := staged(e, *sandbox)
	if err != nil {
		return 1, err
	}
	u := tui.New(e.stdin, e.stdout)
	r := newReview(sb, base, files, changes, sandboxFlag(*sandbox))
	if *asJSON {
		return 0, writeJSON(e.stdout, r.document(*stat))
	}
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
	u.Println(r.afterApply(u))
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
	answer, err := u.Input(r.applyLabel()+"? [y/N]", "")
	if a := strings.ToLower(answer); err != nil || (a != "y" && a != "yes") {
		r.later(u)
		return 0, nil
	}
	return r.apply(u)
}
