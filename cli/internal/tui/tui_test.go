package tui

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func session(input string) (*UI, *bytes.Buffer) {
	var out bytes.Buffer
	return New(strings.NewReader(input), &out), &out
}

func TestSelectByNumberSkipsDisabled(t *testing.T) {
	opts := []Option{{Label: "Claude Code"}, {Label: "Codex", Disabled: true, Hint: "not available yet"}, {Label: "Other"}}
	u, out := session("2\n3\n")
	i, err := u.Select("Which agent?", opts, 0)
	if err != nil || i != 2 {
		t.Fatalf("got %d, %v", i, err)
	}
	for _, want := range []string{"1. Claude Code", "2. Codex  (not available yet)", "That is not one of the choices.", "? Which agent? Other"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestBackOnlyWhenOffered(t *testing.T) {
	opts := []Option{{Label: "A"}, {Label: "B"}}
	u, out := session("b\nb\n2\n")
	if _, err := u.Choose("Pick", opts, 0, true); !errors.Is(err, ErrBack) {
		t.Fatalf("choose with back: %v", err)
	}
	if !strings.Contains(out.String(), "b. Back") {
		t.Errorf("back not listed:\n%s", out)
	}
	if i, err := u.Select("Pick", opts, 0); err != nil || i != 1 {
		t.Fatalf("select without back: %d, %v", i, err)
	}
	u, _ = session("b\n<\n")
	if v, err := u.Ask("Folder?", "~/web", true); err != nil || v != "b" {
		t.Fatalf("a folder named b: %q, %v", v, err)
	}
	if _, err := u.Ask("Folder?", "~/web", true); !errors.Is(err, ErrBack) {
		t.Fatalf("ask with back: %v", err)
	}
	u, _ = session("<\n")
	if v, err := u.Input("Folder?", "~/web"); err != nil || v != "<" {
		t.Fatalf("input without back: %q, %v", v, err)
	}
}

func TestSelectDefaultAndDisabledDefault(t *testing.T) {
	opts := []Option{{Label: "A", Disabled: true}, {Label: "B"}}
	u, _ := session("\n")
	if i, err := u.Select("Pick", opts, 0); err != nil || i != 1 {
		t.Fatalf("got %d, %v", i, err)
	}
}

func TestClosedInputCancels(t *testing.T) {
	u, _ := session("")
	if _, err := u.Confirm("Go?", "Yes", "No"); !errors.Is(err, ErrCancelled) {
		t.Fatalf("got %v", err)
	}
	if _, err := u.Input("Folder?", "~/web"); !errors.Is(err, ErrCancelled) {
		t.Fatalf("got %v", err)
	}
}

func TestInputDefault(t *testing.T) {
	u, _ := session("\n  ~/api \n")
	if v, _ := u.Input("Folder?", "~/web"); v != "~/web" {
		t.Fatalf("default: %q", v)
	}
	if v, _ := u.Input("Folder?", "~/web"); v != "~/api" {
		t.Fatalf("typed: %q", v)
	}
}

func TestPlainOutputHasNoEscapes(t *testing.T) {
	u, out := session("")
	u.Box("Ready", []string{"Agent     Claude Code", "", strings.Repeat("word ", 40)})
	u.Step(1, 5, "This machine")
	u.Done("Runtime", "OpenShell 0.1.2")
	u.Problem("Gateway", "not connected")
	u.Spin("Key", "storing", func() (string, error) { return "stored", nil })
	if strings.Contains(out.String(), "\x1b") {
		t.Fatalf("escape codes without a terminal:\n%q", out)
	}
	if !strings.Contains(out.String(), "Agent     Claude Code") {
		t.Errorf("box changed the spacing of a short line:\n%s", out)
	}
}

func TestBoxLinesHaveOneWidth(t *testing.T) {
	u, out := session("")
	u.Box("Fenzi 0.1.0", []string{"short", "", strings.Repeat("a longer sentence that wraps ", 6)})
	lines := strings.Split(strings.TrimRight(out.String(), "\n"), "\n")
	w := visible(lines[0])
	for _, l := range lines {
		if visible(l) != w {
			t.Errorf("width %d, want %d: %q", visible(l), w, l)
		}
	}
	if !strings.HasPrefix(strings.TrimSpace(lines[0]), "┌─ Fenzi 0.1.0 ─") {
		t.Errorf("title not in the border: %q", lines[0])
	}
}

func TestVisibleSkipsColour(t *testing.T) {
	if n := visible(accent + "abc" + reset); n != 3 {
		t.Fatalf("got %d", n)
	}
}
