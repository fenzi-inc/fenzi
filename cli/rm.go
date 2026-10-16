package main

// fenzi rm: forget finished sandboxes. A finished sandbox is already gone
// from the gateway; what is left on this machine is its record in the state,
// the changes staged when it ended, and the log saved then. rm removes those
// three, in that order. A running sandbox is refused: fenzi stop ends it.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"fenzi/cli/internal/config"
	"fenzi/cli/internal/run"
	"fenzi/cli/internal/tui"
)

// jsonRemoved is one sandbox rm removed: its record always, and whether
// staged changes and a saved log went with it.
type jsonRemoved struct {
	Name          string `json:"name"`
	StagedChanges bool   `json:"staged_changes"`
	SavedLog      bool   `json:"saved_log"`
}

// jsonRefused is a sandbox rm left alone, with the reason it printed.
type jsonRefused struct {
	Name   string `json:"name"`
	Reason string `json:"reason"`
}

type jsonRm struct {
	Removed []jsonRemoved `json:"removed"`
	Refused []jsonRefused `json:"refused"`
}

func cmdRm(e env, args []string) (int, error) {
	fs := newFlags("rm", e.stderr)
	finished := fs.Bool("finished", false, "remove every finished sandbox")
	asJSON := jsonFlag(fs)
	pos, err := parse(fs, args)
	if err != nil {
		return 1, err
	}
	switch {
	case len(pos) == 0 && !*finished:
		return 1, errors.New("name a sandbox, or pass --finished for every finished one. fenzi ps --all lists them")
	case len(pos) > 0 && *finished:
		return 1, errors.New("name sandboxes or pass --finished, not both")
	}
	dirs, err := config.Default()
	if err != nil {
		return 1, err
	}
	// The gateway says what is running; the state says what Fenzi started.
	live, err := client().Sandboxes(e.ctx)
	if err != nil {
		return 1, err
	}
	running := map[string]bool{}
	for _, n := range live {
		running[n] = true
	}
	s, err := dirs.LoadState()
	if err != nil {
		return 1, err
	}
	for i := range s.Sandboxes {
		s.Sandboxes[i].Running = running[s.Sandboxes[i].Name]
	}

	var names []string
	if *finished {
		for _, sb := range s.Sandboxes {
			if !sb.Running {
				names = append(names, sb.Name)
			}
		}
	} else {
		seen := map[string]bool{}
		for _, n := range pos {
			if _, ok := s.Find(n); !ok && !running[n] {
				return 1, fmt.Errorf("%s is not a sandbox on this machine; fenzi ps --all lists them", n)
			}
			if !seen[n] {
				seen[n] = true
				names = append(names, n)
			}
		}
	}

	doc := jsonRm{Removed: []jsonRemoved{}, Refused: []jsonRefused{}}
	for _, n := range names {
		if running[n] {
			doc.Refused = append(doc.Refused, jsonRefused{Name: n, Reason: fmt.Sprintf("%s is running; fenzi stop %s ends it first", n, n)})
			continue
		}
		r, err := removeSandbox(dirs, s, n)
		if err != nil {
			return 1, err
		}
		doc.Removed = append(doc.Removed, r)
	}

	if *asJSON {
		if err := writeJSON(e.stdout, doc); err != nil {
			return 1, err
		}
		if len(doc.Refused) > 0 {
			return 0, quietExit(1)
		}
		return 0, nil
	}
	u := tui.New(e.stdin, e.stdout)
	switch {
	case len(doc.Removed) == 0 && len(doc.Refused) == 0:
		u.Blank()
		u.Done("No finished sandboxes", "")
		u.Blank()
		return 0, nil
	case len(doc.Removed) == 0:
		u.Title("Nothing removed", "")
	default:
		u.Title(plural(len(doc.Removed), "sandbox removed", "sandboxes removed"), "")
	}
	for _, r := range doc.Removed {
		what := "record"
		if r.StagedChanges {
			what += ", staged changes"
		}
		if r.SavedLog {
			what += ", saved log"
		}
		u.Done(r.Name, what)
	}
	for _, r := range doc.Refused {
		u.Problem(r.Name, r.Reason[len(r.Name)+1:])
	}
	u.Blank()
	if len(doc.Refused) > 0 {
		return 0, quietExit(1)
	}
	return 0, nil
}

// removeSandbox forgets one finished sandbox: its record in the state, then
// its staging folder, then its run folder with the saved log. The state is
// written before the folders go, so a failure half way leaves no record that
// points at missing files.
func removeSandbox(dirs config.Dirs, s *config.State, name string) (jsonRemoved, error) {
	r := jsonRemoved{Name: name}
	// The folders are built from the name, so a hand-edited record with an
	// empty name or a path in it must not reach RemoveAll.
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, `/\`) {
		return r, fmt.Errorf("%q is not a sandbox name fenzi created; nothing was removed", name)
	}
	kept := s.Sandboxes[:0]
	for _, sb := range s.Sandboxes {
		if sb.Name != name {
			kept = append(kept, sb)
		}
	}
	s.Sandboxes = kept
	if err := dirs.SaveState(s); err != nil {
		return r, err
	}
	staging := dirs.Staging(name)
	if _, err := os.Stat(filepath.Join(staging, "files")); err == nil {
		r.StagedChanges = true
	}
	if err := os.RemoveAll(staging); err != nil {
		return r, err
	}
	runDir := dirs.Run(name)
	if _, err := os.Stat(filepath.Join(runDir, run.LogFile)); err == nil {
		r.SavedLog = true
	}
	if err := os.RemoveAll(runDir); err != nil {
		return r, err
	}
	return r, nil
}
