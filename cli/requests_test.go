package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeOpenShell puts an openshell on PATH that prints rules for `rule get`
// and nothing for anything else.
func fakeOpenShell(t *testing.T, rules string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "rules.txt"), []byte(rules), 0o600); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\nif [ \"$1\" = rule ]; then cat '" + filepath.Join(dir, "rules.txt") + "'; fi\n"
	if err := os.WriteFile(filepath.Join(dir, "openshell"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
}

// Recorded from OpenShell 0.1.2 in a Claude Code session, the agent's host
// replaced with example.com.
const mixedRules = `  Chunk: ccd96a39-17bd-4710-af49-c88725b0540f
  Status: pending
  Rule: example_home_read
  Binary: /usr/bin/curl
  Confidence: 75%
  Rationale: User asked to see what is on the example.com homepage. Need a single read-only GET of the homepage with curl.
  Endpoints: www.example.com:443 [L7 rest, allow GET /]

  Chunk: 59b83e6d-8a8a-43e4-a597-066a5d16fc36
  Status: pending
  Rule: allow_github_com_443
  Binary: /usr/lib/git-core/git-remote-http
  Confidence: 65%
  Rationale: Allow git-remote-http to connect to github.com:443 (HTTPS).
  Endpoints: github.com:443 [L4]

  Chunk: 7682170e-0b75-4850-9a03-f5c98a3713be
  Status: pending
  Rule: allow_downloads_claude_ai_443
  Binary: /usr/local/lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe
  Confidence: 65%
  Rationale: Allow claude.exe to connect to downloads.claude.ai:443 (HTTPS).
  Endpoints: downloads.claude.ai:443 [L4]
`

func TestRequestsShowsWhatTheAgentAskedFor(t *testing.T) {
	fakeOpenShell(t, mixedRules)
	out, code := runCLI(t, "", "requests", "--sandbox", "fenzi-web-1a2b")
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	for _, want := range []string{"1 request from the agent", "www.example.com:443", "2 more were drafted by the sandbox", "github.com:443, downloads.claude.ai:443", "fenzi requests --all"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "59b83e6d") || strings.Contains(out, "7682170e") {
		t.Errorf("drafts are listed without --all:\n%s", out)
	}

	out, _ = runCLI(t, "", "requests", "--all", "--sandbox", "fenzi-web-1a2b")
	for _, want := range []string{"1 request from the agent", "2 drafts from refused connections", "59b83e6d", "7682170e"} {
		if !strings.Contains(out, want) {
			t.Errorf("--all: missing %q in:\n%s", want, out)
		}
	}
}

func TestRequestsOnlyDrafts(t *testing.T) {
	fakeOpenShell(t, mixedRules[strings.Index(mixedRules, "  Chunk: 59b8"):])
	out, code := runCLI(t, "", "requests", "--sandbox", "fenzi-web-1a2b")
	if code != 0 || !strings.Contains(out, "No requests from the agent") || !strings.Contains(out, "2 more were drafted") {
		t.Errorf("exit %d:\n%s", code, out)
	}
}
