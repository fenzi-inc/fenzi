package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"fenzi/agents"
	"fenzi/cli/internal/config"
	"fenzi/cli/internal/tui"
)

func TestReadyNamesThePolicyRunWillUse(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	dirs, err := config.Default()
	if err != nil {
		t.Fatal(err)
	}
	claude, err := agents.Get("claude")
	if err != nil {
		t.Fatal(err)
	}
	project := t.TempDir()
	ready := func() string {
		var out bytes.Buffer
		u := tui.New(strings.NewReader("2\n"), &out)
		start, err := setupReady(env{ctx: context.Background(), stdin: strings.NewReader(""), stdout: &out, stderr: &out}, u, dirs, claude, project, false)
		if err != nil || start {
			t.Fatalf("start %v, err %v\n%s", start, err, out.String())
		}
		return out.String()
	}

	out := ready()
	if !strings.Contains(out, "developer-default (built in)") || strings.Contains(out, "fenzi.yaml") || !strings.Contains(out, "api.github.com, read-only") {
		t.Errorf("without a project file:\n%s", out)
	}

	file := "version: 1\nhosts:\n  - host: api.stripe.com\n    access: read-only\n  - host: api.example.com\n    port: 8443\n    access: read-write\n    allow:\n      - POST /v1/things\n"
	if err := os.WriteFile(filepath.Join(project, "fenzi.yaml"), []byte(file), 0o644); err != nil {
		t.Fatal(err)
	}
	out = ready()
	for _, want := range []string{"developer-default (built in) + ./fenzi.yaml", "api.stripe.com, read-only", "api.example.com:8443, read-write: POST /v1/things", "api.github.com, read-only"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}

	if err := os.WriteFile(filepath.Join(project, "fenzi.yaml"), []byte("version: 1\nhosts:\n  - host: x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if out = ready(); !strings.Contains(out, "cannot be used") || !strings.Contains(out, "fenzi run stops until it is fixed") {
		t.Errorf("a broken project file:\n%s", out)
	}
}

func TestTilde(t *testing.T) {
	home := "/Users/ana"
	cases := map[string]string{"/Users/ana/web": "~/web", "/Users/ana": "~", "/Users/anabel": "/Users/anabel", "/tmp": "/tmp"}
	for in, want := range cases {
		if got := tilde(in, home); got != want {
			t.Errorf("tilde(%q) = %q, want %q", in, got, want)
		}
	}
	if got := untilde("~/web", home); got != "/Users/ana/web" {
		t.Errorf("untilde: %q", got)
	}
	if got := shellPath("~/my code"); got != "'~/my code'" {
		t.Errorf("shellPath: %q", got)
	}
}

func TestBareCommandShowsHelpWithoutATerminal(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	var out bytes.Buffer
	if code := cli(nil, strings.NewReader(""), &out, &out); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(out.String(), "setup") || strings.Contains(out.String(), "This machine") {
		t.Fatalf("expected help, got:\n%s", out.String())
	}
}
