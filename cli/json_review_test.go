package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"fenzi/cli/internal/config"
	"fenzi/cli/internal/forward"
	"fenzi/cli/internal/run"
)

// fenzi diff --json: the files with their counts and hunks, the label of a
// file that runs on this machine once applied, and what apply would do.
func TestJSONDiff(t *testing.T) {
	stagedFixture(t)
	// The agent also added a direnv file, which runs when the folder is entered.
	dirs, _ := config.Default()
	if err := os.WriteFile(filepath.Join(dirs.Staging(sandboxName), "files", ".envrc"), []byte("export X=1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var doc jsonDiff
	if stderr, code := runJSON(t, &doc, "diff", "--sandbox", sandboxName, "--json"); code != 0 || stderr != "" {
		t.Fatalf("exit %d stderr %q", code, stderr)
	}
	if doc.Sandbox != sandboxName || doc.Agent != "Claude Code" || doc.Folder == "" || doc.Landed != nil {
		t.Errorf("document = %+v", doc)
	}
	if len(doc.Files) != 4 || doc.Added != 4 || doc.Removed != 2 || doc.HostRun != 1 {
		t.Fatalf("files = %+v, +%d -%d, host_run %d", doc.Files, doc.Added, doc.Removed, doc.HostRun)
	}
	byPath := map[string]jsonFileDiff{}
	for _, f := range doc.Files {
		byPath[f.Path] = f
	}
	if f := byPath[".envrc"]; f.Kind != "new" || f.Added != 1 || f.HostRun != "direnv runs it when you enter the folder" {
		t.Errorf(".envrc = %+v", f)
	}
	if f := byPath["app.py"]; f.Kind != "edited" || f.Added != 2 || f.Removed != 1 || f.HostRun != "" || len(f.Hunks) != 1 {
		t.Errorf("app.py = %+v", f)
	} else {
		h := f.Hunks[0]
		var kinds strings.Builder
		for _, o := range h.Ops {
			kinds.WriteString(o.Kind)
		}
		if h.OldStart != 1 || h.NewStart != 1 || kinds.String() != " +   -+   " {
			t.Errorf("hunk = %+v, kinds %q", h, kinds.String())
		}
		if h.Ops[1].Text != "import sys" {
			t.Errorf("added line = %q", h.Ops[1].Text)
		}
	}
	if f := byPath["old.txt"]; f.Kind != "deleted" || f.Removed != 1 {
		t.Errorf("old.txt = %+v", f)
	}
	if !strings.HasPrefix(doc.Apply, "Apply them to ") {
		t.Errorf("apply = %q", doc.Apply)
	}
	// --stat leaves the hunks out.
	var stat jsonDiff
	if stderr, code := runJSON(t, &stat, "diff", "--stat", "--sandbox", sandboxName, "--json"); code != 0 || stderr != "" {
		t.Fatalf("--stat: exit %d stderr %q", code, stderr)
	}
	for _, f := range stat.Files {
		if f.Hunks != nil {
			t.Errorf("--stat kept hunks for %s", f.Path)
		}
	}
	if stat.Added != 4 || stat.HostRun != 1 {
		t.Errorf("--stat totals = +%d, host_run %d", stat.Added, stat.HostRun)
	}
}

// With the commits landed as a branch, the document says so and apply is a merge.
func TestJSONDiffLanded(t *testing.T) {
	landedFixture(t)
	var doc jsonDiff
	if stderr, code := runJSON(t, &doc, "diff", "--sandbox", sandboxName, "--json"); code != 0 || stderr != "" {
		t.Fatalf("exit %d stderr %q", code, stderr)
	}
	if doc.Landed == nil || doc.Landed.Branch != "main" || doc.Landed.Name != "claude/fix" || doc.Landed.Commits != 1 || doc.Landed.Merged != "" {
		t.Errorf("landed = %+v", doc.Landed)
	}
	if doc.Apply != "Merge claude/fix into main" {
		t.Errorf("apply = %q", doc.Apply)
	}
	if len(doc.Files) != 3 {
		t.Errorf("files = %+v", doc.Files)
	}
}

// A sandbox whose agent left the folder as it was: an empty list, not an error.
func TestJSONDiffNoChanges(t *testing.T) {
	repo := stagedFixture(t)
	dirs, _ := config.Default()
	staged := filepath.Join(dirs.Staging(sandboxName), "files")
	os.RemoveAll(staged)
	os.MkdirAll(staged, 0o700)
	for _, p := range []string{"app.py", "old.txt", "README.md"} {
		b, _ := os.ReadFile(filepath.Join(repo, p))
		os.WriteFile(filepath.Join(staged, p), b, 0o644)
	}
	var doc jsonDiff
	if stderr, code := runJSON(t, &doc, "diff", "--sandbox", sandboxName, "--json"); code != 0 || stderr != "" {
		t.Fatalf("exit %d stderr %q", code, stderr)
	}
	if doc.Files == nil || len(doc.Files) != 0 || doc.Added != 0 {
		t.Errorf("document = %+v", doc)
	}
	// Nothing staged stays an error on standard error, as without --json.
	os.RemoveAll(dirs.Staging(sandboxName))
	var none json.RawMessage
	if stderr, code := runJSON(t, &none, "diff", "--sandbox", sandboxName, "--json"); code != 1 || none != nil || !strings.Contains(stderr, "nothing staged for "+sandboxName) {
		t.Errorf("exit %d, stdout %q, stderr %q", code, none, stderr)
	}
}

// The log lines of a run in which the agent filed a request through
// policy.local and a person approved it (OpenShell 0.1.2, 16 October 2026,
// the host replaced), around the decisions recorded with them.
const requestLines = `[1791297760.100] [sandbox] [OCSF ] [ocsf] NET:OPEN [MED] DENIED /usr/bin/curl(0) -> example.com:443 [reason:transparent_tcp_policy_denied]
[1791297778.239] [sandbox] [OCSF ] [ocsf] CONFIG:PROPOSED [INFO] agent_authored proposal chunk:fad7c2ed-3aca-4fb7-bb37-495820dd7562 on example.com:443 HEAD / by /usr/bin/curl
[1791297802.289] [sandbox] [OCSF ] [ocsf] CONFIG:APPROVED [INFO] chunk:fad7c2ed-3aca-4fb7-bb37-495820dd7562 approved on example.com:443 HEAD / by /usr/bin/curl
[1791297830.500] [sandbox] [OCSF ] [ocsf] NET:OPEN [INFO] ALLOWED /usr/bin/curl(0) -> example.com:443 [policy:example_com engine:opa]
`

// fenzi log --requests adds the request the agent filed and its approval to
// the decisions, in the table and in JSON; without the flag the log is
// decisions only, as before.
func TestLogRequests(t *testing.T) {
	fakeRuntime(t, nil, "")
	dirs := seedState(t, config.Sandbox{Name: "fenzi-web-1a2b", Agent: "claude", Repo: "/Users/ana/web", Created: time.Now()})
	if err := os.MkdirAll(dirs.Run("fenzi-web-1a2b"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dirs.Run("fenzi-web-1a2b"), run.LogFile), []byte(requestLines), 0o600); err != nil {
		t.Fatal(err)
	}
	var recs []forward.Record
	if stderr, code := runJSON(t, &recs, "log", "--sandbox", "fenzi-web-1a2b", "--json"); code != 0 || stderr != "" || len(recs) != 2 {
		t.Fatalf("without --requests: exit %d stderr %q records %+v", code, stderr, recs)
	}
	if stderr, code := runJSON(t, &recs, "log", "--requests", "--sandbox", "fenzi-web-1a2b", "--json"); code != 0 || stderr != "" {
		t.Fatalf("exit %d stderr %q", code, stderr)
	}
	if len(recs) != 4 {
		t.Fatalf("records = %+v", recs)
	}
	if r := recs[1]; r.Class != "Config" || r.Action != "Requested" || r.Chunk != "fad7c2ed-3aca-4fb7-bb37-495820dd7562" || r.Destination != "example.com:443 HEAD /" || r.Process != "/usr/bin/curl" {
		t.Errorf("request = %+v", r)
	}
	if r := recs[2]; r.Class != "Config" || r.Action != "Approved" || r.Chunk != recs[1].Chunk {
		t.Errorf("approval = %+v", r)
	}
	// --deny keeps denies only; the policy events go with the allows.
	if stderr, code := runJSON(t, &recs, "log", "--requests", "--deny", "--sandbox", "fenzi-web-1a2b", "--json"); code != 0 || stderr != "" || len(recs) != 1 || !recs[0].Denied() {
		t.Errorf("--deny: exit %d stderr %q records %+v", code, stderr, recs)
	}
	// The table: the action words and the chunk's short id in the rule column.
	out, code := runCLI(t, "", "log", "--requests", "--sandbox", "fenzi-web-1a2b")
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	for _, want := range []string{"4 decisions", "requested  curl", "approved   curl", "example.com:443 HEAD /", "fad7c2ed"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	// --raw prints the runtime's lines, which already hold the requests.
	var errOut bytes.Buffer
	if code := cli([]string{"log", "--raw", "--requests", "--sandbox", "fenzi-web-1a2b"}, strings.NewReader(""), &bytes.Buffer{}, &errOut); code != 1 || !strings.Contains(errOut.String(), "--requests") {
		t.Errorf("--raw --requests: exit %d stderr %q", code, errOut.String())
	}
}

// --follow --requests streams the policy events too.
func TestLogRequestsFollow(t *testing.T) {
	fakeRuntime(t, map[string]reply{"logs fenzi-web-1a2b --source sandbox --tail": {out: requestLines}}, "")
	seedState(t, config.Sandbox{Name: "fenzi-web-1a2b", Agent: "claude", Repo: "/Users/ana/web", Created: time.Now(), Running: true})
	var out, errOut bytes.Buffer
	if code := cli([]string{"log", "--follow", "--requests", "--sandbox", "fenzi-web-1a2b", "--json"}, strings.NewReader(""), &out, &errOut); code != 0 || errOut.Len() > 0 {
		t.Fatalf("exit %d stderr %q", code, errOut.String())
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 4 {
		t.Fatalf("got %d lines:\n%s", len(lines), out.String())
	}
	var r forward.Record
	if err := json.Unmarshal([]byte(lines[1]), &r); err != nil || r.Action != "Requested" || r.Chunk == "" {
		t.Errorf("line 1 = %s (%v)", lines[1], err)
	}
	out.Reset()
	if code := cli([]string{"log", "--follow", "--sandbox", "fenzi-web-1a2b", "--json"}, strings.NewReader(""), &out, &errOut); code != 0 {
		t.Fatalf("exit %d stderr %q", code, errOut.String())
	}
	if n := strings.Count(out.String(), "\n"); n != 2 {
		t.Errorf("without --requests, %d lines:\n%s", n, out.String())
	}
}

// ps --json carries when a sandbox ended and the commit the agent's branch
// began at, for the Mac app's timeline and its git log.
func TestJSONPsEndedAndStart(t *testing.T) {
	fakeRuntime(t, nil, "")
	ended := time.Date(2026, 10, 18, 19, 30, 2, 0, time.UTC)
	seedState(t,
		config.Sandbox{Name: "fenzi-web-1a2b", Agent: "claude", Repo: "/Users/ana/web", Created: ended.Add(-time.Hour), Ended: ended,
			Git: &config.Git{Branch: "main", Head: "74615dc1493b4b77c1f380b5381758538a4af6ed", Dirty: true, History: true, Start: "0b1c6d9f6e4a4f0e9d1b4e9b7a3b9d8c7f6e5d4c", AgentBranch: "fenzi/web-1a2b", Landed: "claude/fix", Tip: "8f92089216db6b32da0a714ed948388c1e06d25b", Commits: 2, Checkpoint: true}},
		config.Sandbox{Name: "fenzi-web-0000", Agent: "codex", Repo: "/Users/ana/web", Created: ended, Running: true},
	)
	var docs []jsonSandbox
	if stderr, code := runJSON(t, &docs, "ps", "--all", "--json"); code != 0 || stderr != "" {
		t.Fatalf("exit %d stderr %q", code, stderr)
	}
	if len(docs) != 2 {
		t.Fatalf("docs = %+v", docs)
	}
	byName := map[string]jsonSandbox{}
	for _, d := range docs {
		byName[d.Name] = d
	}
	done := byName["fenzi-web-1a2b"]
	if done.Ended != "2026-10-18T19:30:02Z" || done.Git == nil {
		t.Fatalf("finished = %+v", done)
	}
	if g := done.Git; g.Start != "0b1c6d9f6e4a4f0e9d1b4e9b7a3b9d8c7f6e5d4c" || g.AgentBranch != "fenzi/web-1a2b" || !g.Checkpoint || g.Commits != 2 {
		t.Errorf("git = %+v", g)
	}
	// The fake runtime lists no live sandbox, so ps records the second one as
	// finished; with no end recorded, the field is absent.
	live := byName["fenzi-web-0000"]
	if live.Ended != "" {
		t.Errorf("not stopped by fenzi = %+v", live)
	}
	raw, _ := json.Marshal(live)
	if strings.Contains(string(raw), "ended") {
		t.Errorf("a running sandbox has no ended field: %s", raw)
	}
}
