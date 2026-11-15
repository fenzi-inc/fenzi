package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"fenzi/teamapi"
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
	for _, want := range []string{"1 request from the agent", "www.example.com:443", "2 more connections were blocked that the agent did not ask about", "github.com:443, downloads.claude.ai:443", "fenzi requests --all"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "59b83e6d") || strings.Contains(out, "7682170e") {
		t.Errorf("drafts are listed without --all:\n%s", out)
	}

	out, _ = runCLI(t, "", "requests", "--all", "--sandbox", "fenzi-web-1a2b")
	for _, want := range []string{"1 request from the agent", "2 blocked connections the agent did not ask about", "59b83e6d", "7682170e"} {
		if !strings.Contains(out, want) {
			t.Errorf("--all: missing %q in:\n%s", want, out)
		}
	}
}

func TestRequestsOnlyDrafts(t *testing.T) {
	fakeOpenShell(t, mixedRules[strings.Index(mixedRules, "  Chunk: 59b8"):])
	out, code := runCLI(t, "", "requests", "--sandbox", "fenzi-web-1a2b")
	if code != 0 || !strings.Contains(out, "No requests from the agent") || !strings.Contains(out, "2 more connections were blocked") {
		t.Errorf("exit %d:\n%s", code, out)
	}
}

// On the Free plan the first answer offered keeps the approval in
// fenzi.yaml; approving for this sandbox only comes second.
func TestRequestsOffersSaveFirst(t *testing.T) {
	fakeOpenShell(t, mixedRules)
	out, code := runCLI(t, "", "requests", "--sandbox", "fenzi-web-1a2b")
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	save := strings.Index(out, "fenzi approve <id> --save --sandbox fenzi-web-1a2b")
	once := strings.Index(out, "for this sandbox only")
	if save < 0 || once < 0 || save > once || !strings.Contains(out, "keep it in fenzi.yaml") {
		t.Errorf("save is not the first answer:\n%s", out)
	}
}

// A signed-in machine runs the team's policy, which a project file does
// not change, so no save is offered.
func TestRequestsOnATeamOfferNoSave(t *testing.T) {
	fakeRuntime(t, map[string]reply{"rule get": {out: mixedRules}}, "")
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	srv := httptest.NewServer(&refusingConsole{bundle: teamapi.ToWire(signed(key, 2))})
	t.Cleanup(srv.Close)
	enrollCached(t, srv.URL, key)
	out, _ := runCLI(t, "", "requests", "--sandbox", "fenzi-web-1a2b")
	if strings.Contains(out, "--save") || !strings.Contains(out, "fenzi approve <id> --sandbox fenzi-web-1a2b") {
		t.Errorf("a team machine was offered a save:\n%s", out)
	}
}

// A request the agent filed that the sandbox's draft superseded is listed
// as the agent's, with the agent's reason (recorded on OpenShell 0.1.4;
// see absorbed_test.go in the openshell package).
func TestRequestsShowsAMergedDraftAsTheAgents(t *testing.T) {
	dir := t.TempDir()
	write := func(name, text string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	pending := write("pending.txt", mergedPending)
	all := write("all.txt", mergedAll)
	logs := write("logs.txt", mergedLog)
	script := "#!/bin/sh\ncase \"$*\" in\n" +
		"'rule get fenzi-proj-7c2e --status pending') cat '" + pending + "' ;;\n" +
		"'rule get fenzi-proj-7c2e') cat '" + all + "' ;;\n" +
		"logs*) cat '" + logs + "' ;;\nesac\n"
	write("openshell", script)
	os.Chmod(filepath.Join(dir, "openshell"), 0o755)
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("XDG_CACHE_HOME", t.TempDir())

	out, code := runCLI(t, "", "requests", "--sandbox", "fenzi-proj-7c2e")
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	for _, want := range []string{"2 requests from the agent", "a3516572", "Read the example.net home page for a test.", "1 more connection was blocked that the agent did not ask about"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

// Recorded on OpenShell 0.1.4, 25 October 2026; the sandbox name and the
// first word of the agent's reason are changed.
const mergedAll = `Network Rules:  (version 5, 5 chunks)

  Chunk: a3516572-6552-4d50-9719-b2140b7068a7
  Status: pending
  Rule: example_net_read
  Binary: /usr/bin/curl
  Confidence: 65%
  Rationale: Allow curl to connect to example.net:443 (HTTPS).
  Prover: prover: no new findings
  Candidate: 424afa010498
  Endpoints: example.net:443 [L7 rest, allow GET /]
  Binaries: /usr/bin/curl

  Chunk: 01c4511d-de0a-413b-a447-87485c33b275
  Status: rejected
  Rule: example_net_read
  Binary: /usr/bin/curl
  Confidence: 75%
  Rationale: Read the example.net home page for a test.
  Prover: prover: no new findings
  Candidate: 424afa010498
  Endpoints: example.net:443 [L7 rest, allow GET /]
  Binaries: /usr/bin/curl

  Chunk: dcc1390a-30fc-4e98-8551-928a2eae112e
  Status: pending
  Rule: example_org_read
  Binary: /usr/bin/curl
  Confidence: 75%
  Rationale: User asked to fetch the example.org homepage with curl (GET /) and show the first 5 lines.
  Prover: prover: no new findings
  Candidate: 12339297329c
  Endpoints: example.org:443 [L7 rest, allow GET /]
  Binaries: /usr/bin/curl

  Chunk: 9c579f86-3171-4005-bb9f-bd743ff2dfe8
  Status: rejected
  Rule: allow_example_org_443
  Binary: /usr/bin/curl
  Confidence: 65%
  Rationale: Allow curl to connect to example.org:443 (HTTPS).
  Prover: prover: no new findings
  Candidate: 70f67764f8d4
  Endpoints: example.org:443 [L4]
  Binaries: /usr/bin/curl

  Chunk: c016b2e1-6dd0-43ea-8684-674ff85be049
  Status: pending
  Rule: allow_downloads_claude_ai_443
  Binary: /usr/local/lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe
  Confidence: 65%
  Rationale: Allow claude.exe to connect to downloads.claude.ai:443 (HTTPS).
  Prover: prover: no new findings
  Candidate: 559cde4251d9
  Endpoints: downloads.claude.ai:443 [L4]
  Binaries: /usr/local/lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe

`

const mergedPending = `Network Rules:  (version 5, 3 chunks)

  Chunk: a3516572-6552-4d50-9719-b2140b7068a7
  Status: pending
  Rule: example_net_read
  Binary: /usr/bin/curl
  Confidence: 65%
  Rationale: Allow curl to connect to example.net:443 (HTTPS).
  Prover: prover: no new findings
  Candidate: 424afa010498
  Endpoints: example.net:443 [L7 rest, allow GET /]
  Binaries: /usr/bin/curl

  Chunk: dcc1390a-30fc-4e98-8551-928a2eae112e
  Status: pending
  Rule: example_org_read
  Binary: /usr/bin/curl
  Confidence: 75%
  Rationale: User asked to fetch the example.org homepage with curl (GET /) and show the first 5 lines.
  Prover: prover: no new findings
  Candidate: 12339297329c
  Endpoints: example.org:443 [L7 rest, allow GET /]
  Binaries: /usr/bin/curl

  Chunk: c016b2e1-6dd0-43ea-8684-674ff85be049
  Status: pending
  Rule: allow_downloads_claude_ai_443
  Binary: /usr/local/lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe
  Confidence: 65%
  Rationale: Allow claude.exe to connect to downloads.claude.ai:443 (HTTPS).
  Prover: prover: no new findings
  Candidate: 559cde4251d9
  Endpoints: downloads.claude.ai:443 [L4]
  Binaries: /usr/local/lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe

`

const mergedLog = `[1792938196.405] [sandbox] [INFO ] [openshell_supervisor] Flushed denial analysis to gateway proposals=1 sandbox_name=fenzi-proj-7c2e summaries=1
[1792938216.405] [sandbox] [INFO ] [openshell_supervisor] Flushed denial analysis to gateway proposals=1 sandbox_name=fenzi-proj-7c2e summaries=1
[1792938221.934] [sandbox] [OCSF ] [ocsf] CONFIG:PROPOSED [INFO] agent_authored proposal chunk:dcc1390a-30fc-4e98-8551-928a2eae112e on example.org:443 [GET /] by /usr/bin/curl [chunk_id:dcc1390a-30fc-4e98-8551-928a2eae112e]
[1792938297.104] [sandbox] [OCSF ] [ocsf] CONFIG:PROPOSED [INFO] agent_authored proposal chunk:01c4511d-de0a-413b-a447-87485c33b275 on example.net:443 [GET /] by /usr/bin/curl [chunk_id:01c4511d-de0a-413b-a447-87485c33b275]
[1792938306.305] [sandbox] [INFO ] [openshell_supervisor] Flushed denial analysis to gateway proposals=1 sandbox_name=fenzi-proj-7c2e summaries=1
`
