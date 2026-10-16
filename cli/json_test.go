package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"boundlane/cli/internal/config"
	"boundlane/cli/internal/forward"
	"boundlane/cli/internal/run"
	"boundlane/cli/internal/team"
)

// reply is what the fake runtime prints for a command line that starts with
// the key, and the code it exits with.
type reply struct {
	out  string
	exit int
}

// fakeRuntime puts an openshell on PATH that answers from replies, matched
// by the longest key that prefixes the argument list. Anything else prints
// nothing and exits 0. With prover set, an openshell-prover that prints it
// for every check is added too.
func fakeRuntime(t *testing.T, replies map[string]reply, prover string) {
	t.Helper()
	dir := t.TempDir()
	keys := make([]string, 0, len(replies))
	for k := range replies {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return len(keys[i]) > len(keys[j]) })
	var script strings.Builder
	script.WriteString("#!/bin/sh\ncase \"$*\" in\n")
	for i, k := range keys {
		p := filepath.Join(dir, "reply"+string(rune('a'+i)))
		if err := os.WriteFile(p, []byte(replies[k].out), 0o600); err != nil {
			t.Fatal(err)
		}
		script.WriteString("'" + k + "'*) cat '" + p + "'; exit " + itoa(replies[k].exit) + " ;;\n")
	}
	script.WriteString("esac\n")
	if err := os.WriteFile(filepath.Join(dir, "openshell"), []byte(script.String()), 0o755); err != nil {
		t.Fatal(err)
	}
	if prover != "" {
		p := filepath.Join(dir, "prover.json")
		if err := os.WriteFile(p, []byte(prover), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "openshell-prover"), []byte("#!/bin/sh\ncat '"+p+"'\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
}

func itoa(n int) string { return string(rune('0' + n)) }

// runJSON runs the CLI with standard output and standard error apart, and
// checks that standard output holds exactly one JSON value.
func runJSON(t *testing.T, into any, args ...string) (stderr string, code int) {
	t.Helper()
	var out, errOut bytes.Buffer
	code = cli(args, strings.NewReader(""), &out, &errOut)
	if out.Len() > 0 {
		dec := json.NewDecoder(&out)
		if err := dec.Decode(into); err != nil {
			t.Fatalf("%v: standard output is not JSON: %v\n%s", args, err, out.String())
		}
		if rest, _ := dec.Token(); rest != nil {
			t.Fatalf("%v: standard output has more than the document: %v", args, rest)
		}
	}
	return errOut.String(), code
}

// seedState saves sandboxes as boundlane run would have recorded them.
func seedState(t *testing.T, list ...config.Sandbox) config.Dirs {
	t.Helper()
	dirs, err := config.Default()
	if err != nil {
		t.Fatal(err)
	}
	s := &config.State{}
	for _, sb := range list {
		s.Put(sb)
	}
	if err := dirs.SaveState(s); err != nil {
		t.Fatal(err)
	}
	return dirs
}

func TestJSONVersion(t *testing.T) {
	var doc jsonVersion
	if stderr, code := runJSON(t, &doc, "version", "--json"); code != 0 || stderr != "" {
		t.Fatalf("exit %d stderr %q", code, stderr)
	}
	if doc.Version != Version {
		t.Errorf("version = %q, want %q", doc.Version, Version)
	}
	// Without the flag the display is unchanged.
	var out bytes.Buffer
	cli([]string{"version"}, strings.NewReader(""), &out, &out)
	if !strings.Contains(out.String(), "■ Version") || strings.Contains(out.String(), "{") {
		t.Errorf("text output changed:\n%s", out.String())
	}
}

func TestJSONDoctorWithoutARuntime(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	var doc jsonDoctor
	stderr, code := runJSON(t, &doc, "doctor", "--json")
	if code != 3 || stderr != "" {
		t.Fatalf("exit %d, want 3; stderr %q", code, stderr)
	}
	if doc.Ready {
		t.Error("ready with no runtime")
	}
	status := map[string]string{}
	for _, c := range doc.Checks {
		status[c.Name] = c.Status
	}
	if status["Runtime"] != "fail" || status["Policy check"] != "fail" || status["Image builds"] != "fail" || status["Plan"] != "skip" {
		t.Errorf("checks = %+v", doc.Checks)
	}
	if !strings.Contains(doc.Checks[0].Detail, "is not installed") {
		t.Errorf("runtime detail = %q", doc.Checks[0].Detail)
	}
}

func TestJSONAgents(t *testing.T) {
	var docs []jsonAgent
	if stderr, code := runJSON(t, &docs, "agents", "--json"); code != 0 || stderr != "" {
		t.Fatalf("exit %d stderr %q", code, stderr)
	}
	var names []string
	for _, a := range docs {
		names = append(names, a.Name)
	}
	if strings.Join(names, " ") != "claude codex grok opencode" {
		t.Fatalf("agents = %v", names)
	}
	if docs[0].Display != "Claude Code" || docs[0].KeyEnv != "ANTHROPIC_API_KEY" || docs[0].Version == "" || !docs[0].Available {
		t.Errorf("claude = %+v", docs[0])
	}
}

func TestJSONPs(t *testing.T) {
	fakeRuntime(t, map[string]reply{"sandbox list": {out: "bl-web-1a2b\n"}}, "")
	created := time.Date(2026, 10, 15, 21, 36, 0, 0, time.UTC)
	seedState(t,
		config.Sandbox{Name: "bl-web-1a2b", Agent: "claude", Repo: "/Users/ana/web", Created: created},
		config.Sandbox{Name: "bl-web-0000", Agent: "codex", Repo: "/Users/ana/web", Created: created.Add(-time.Hour)},
	)
	var docs []jsonSandbox
	if stderr, code := runJSON(t, &docs, "ps", "--json"); code != 0 || stderr != "" {
		t.Fatalf("exit %d stderr %q", code, stderr)
	}
	if len(docs) != 1 || docs[0] != (jsonSandbox{Name: "bl-web-1a2b", Agent: "claude", Folder: "/Users/ana/web", Created: "2026-10-15T21:36:00Z", Running: true}) {
		t.Errorf("ps = %+v", docs)
	}
	if stderr, code := runJSON(t, &docs, "ps", "--all", "--json"); code != 0 || stderr != "" {
		t.Fatalf("--all: exit %d stderr %q", code, stderr)
	}
	if len(docs) != 2 || docs[1].Name != "bl-web-0000" || docs[1].Running {
		t.Errorf("ps --all = %+v", docs)
	}
}

func TestJSONPsNone(t *testing.T) {
	fakeRuntime(t, nil, "")
	var docs []jsonSandbox
	if _, code := runJSON(t, &docs, "ps", "--json"); code != 0 || docs == nil || len(docs) != 0 {
		t.Fatalf("exit %d, docs %#v; want an empty list", code, docs)
	}
}

func TestJSONRequests(t *testing.T) {
	fakeOpenShell(t, mixedRules)
	var docs []jsonRequest
	if stderr, code := runJSON(t, &docs, "requests", "--sandbox", "bl-web-1a2b", "--json"); code != 0 || stderr != "" {
		t.Fatalf("exit %d stderr %q", code, stderr)
	}
	want := jsonRequest{
		ID: "ccd96a39-17bd-4710-af49-c88725b0540f", Destination: "www.example.com:443", Binary: "/usr/bin/curl",
		Rationale: "User asked to see what is on the example.com homepage. Need a single read-only GET of the homepage with curl.",
	}
	if len(docs) != 1 || docs[0] != want {
		t.Errorf("requests = %+v", docs)
	}
	if stderr, code := runJSON(t, &docs, "requests", "--all", "--sandbox", "bl-web-1a2b", "--json"); code != 0 || stderr != "" {
		t.Fatalf("--all: exit %d stderr %q", code, stderr)
	}
	if len(docs) != 3 || docs[0].Draft || !docs[1].Draft || !docs[2].Draft || docs[1].Destination != "github.com:443" {
		t.Errorf("requests --all = %+v", docs)
	}
}

func TestJSONRequestsNone(t *testing.T) {
	fakeOpenShell(t, "")
	var docs []jsonRequest
	if _, code := runJSON(t, &docs, "requests", "--sandbox", "bl-web-1a2b", "--json"); code != 0 || docs == nil || len(docs) != 0 {
		t.Fatalf("exit %d, docs %#v; want an empty list", code, docs)
	}
}

func TestJSONApproveAndDeny(t *testing.T) {
	fakeOpenShell(t, mixedRules)
	var doc jsonAnswer
	if stderr, code := runJSON(t, &doc, "approve", "ccd96a39", "--sandbox", "bl-web-1a2b", "--json"); code != 0 || stderr != "" {
		t.Fatalf("exit %d stderr %q", code, stderr)
	}
	if doc.ID != "ccd96a39-17bd-4710-af49-c88725b0540f" || doc.Sandbox != "bl-web-1a2b" || doc.Result != "approved" || doc.Note != approvedNote {
		t.Errorf("approve = %+v", doc)
	}
	doc = jsonAnswer{}
	if stderr, code := runJSON(t, &doc, "deny", "59b83e6d", "--reason", "use the vendored copy", "--sandbox", "bl-web-1a2b", "--json"); code != 0 || stderr != "" {
		t.Fatalf("exit %d stderr %q", code, stderr)
	}
	if doc.Result != "denied" || doc.Note != "The agent sees: use the vendored copy" || !strings.HasPrefix(doc.ID, "59b83e6d-") {
		t.Errorf("deny = %+v", doc)
	}
	// Errors stay on standard error, with nothing on standard output.
	var none json.RawMessage
	stderr, code := runJSON(t, &none, "approve", "zzzz", "--sandbox", "bl-web-1a2b", "--json")
	if code != 1 || none != nil || !strings.Contains(stderr, `no pending request starts with "zzzz"`) {
		t.Errorf("exit %d, stdout %q, stderr %q", code, none, stderr)
	}
}

// Shorthand lines as OpenShell 0.1.2 writes them.
const decisionLines = `[1791059016.500] [sandbox] [OCSF ] [ocsf] CONFIG:LOADED [INFO] Acknowledged initial policy revision as loaded [version:1]
[1791059126.330] [sandbox] [OCSF ] [ocsf] NET:OPEN [INFO] ALLOWED /usr/bin/curl(0) -> api.github.com:443 [policy:allow_api_github_com_443 engine:opa]
[1791059150.996] [sandbox] [OCSF ] [ocsf] HTTP:POST [MED] DENIED POST http://api.github.com:443/markdown?x=1 [policy:allow_api_github_com_443 engine:l7] [reason:L7_REQUEST deny POST api.github.com:443/markdown reason=POST /markdown not permitted by policy]
[1791059085.948] [sandbox] [OCSF ] [ocsf] NET:REFUSE [MED] DENIED paste.example.net [reason:policy_dns_ineligible]
`

func TestJSONLog(t *testing.T) {
	fakeRuntime(t, nil, "")
	dirs := seedState(t, config.Sandbox{Name: "bl-web-1a2b", Agent: "claude", Repo: "/Users/ana/web", Created: time.Now()})
	if err := os.MkdirAll(dirs.Run("bl-web-1a2b"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dirs.Run("bl-web-1a2b"), run.LogFile), []byte(decisionLines), 0o600); err != nil {
		t.Fatal(err)
	}
	var recs []forward.Record
	if stderr, code := runJSON(t, &recs, "log", "--sandbox", "bl-web-1a2b", "--json"); code != 0 || stderr != "" {
		t.Fatalf("exit %d stderr %q", code, stderr)
	}
	if len(recs) != 3 {
		t.Fatalf("records = %+v", recs)
	}
	r := recs[0]
	if r.Sandbox != "bl-web-1a2b" || r.Action != "Allowed" || r.Process != "/usr/bin/curl" || r.Destination != "api.github.com:443" || r.Rule != "allow_api_github_com_443" {
		t.Errorf("record = %+v", r)
	}
	if r.Time.UnixMilli() != 1791059126330 || r.Time.Location() != time.UTC {
		t.Errorf("time = %v", r.Time)
	}
	if recs[1].Destination != "POST api.github.com/markdown" || !recs[1].Denied() {
		t.Errorf("http record = %+v", recs[1])
	}
	if stderr, code := runJSON(t, &recs, "log", "--deny", "--sandbox", "bl-web-1a2b", "--json"); code != 0 || stderr != "" {
		t.Fatalf("--deny: exit %d stderr %q", code, stderr)
	}
	if len(recs) != 2 || recs[0].Rule != "allow_api_github_com_443" || recs[1].Reason != "policy_dns_ineligible" {
		t.Errorf("denies = %+v", recs)
	}
	var none json.RawMessage
	if stderr, code := runJSON(t, &none, "log", "--raw", "--sandbox", "bl-web-1a2b", "--json"); code != 1 || none != nil || !strings.Contains(stderr, "--raw") {
		t.Errorf("--raw --json: exit %d stdout %q stderr %q", code, none, stderr)
	}
}

func TestJSONLogEmpty(t *testing.T) {
	fakeRuntime(t, nil, "")
	dirs := seedState(t, config.Sandbox{Name: "bl-web-1a2b", Repo: "/Users/ana/web", Created: time.Now()})
	if err := os.MkdirAll(dirs.Run("bl-web-1a2b"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dirs.Run("bl-web-1a2b"), run.LogFile), []byte(decisionLines[:strings.Index(decisionLines, "\n")+1]), 0o600); err != nil {
		t.Fatal(err)
	}
	var recs []forward.Record
	if _, code := runJSON(t, &recs, "log", "--sandbox", "bl-web-1a2b", "--json"); code != 0 || recs == nil || len(recs) != 0 {
		t.Fatalf("exit %d, records %#v; want an empty list", code, recs)
	}
}

func TestJSONLogFollow(t *testing.T) {
	fakeRuntime(t, map[string]reply{"logs bl-web-1a2b --source sandbox --tail": {out: decisionLines}}, "")
	seedState(t, config.Sandbox{Name: "bl-web-1a2b", Agent: "claude", Repo: "/Users/ana/web", Created: time.Now(), Running: true})
	var out, errOut bytes.Buffer
	if code := cli([]string{"log", "--follow", "--sandbox", "bl-web-1a2b", "--json"}, strings.NewReader(""), &out, &errOut); code != 0 || errOut.Len() > 0 {
		t.Fatalf("exit %d stderr %q", code, errOut.String())
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("got %d lines:\n%s", len(lines), out.String())
	}
	for i, l := range lines {
		var r forward.Record
		if err := json.Unmarshal([]byte(l), &r); err != nil {
			t.Fatalf("line %d is not one JSON object: %v: %s", i, err, l)
		}
		if r.Sandbox != "bl-web-1a2b" || r.Destination == "" {
			t.Errorf("line %d = %+v", i, r)
		}
	}
	out.Reset()
	if code := cli([]string{"log", "--follow", "--deny", "--sandbox", "bl-web-1a2b", "--json"}, strings.NewReader(""), &out, &errOut); code != 0 {
		t.Fatalf("--deny: exit %d stderr %q", code, errOut.String())
	}
	if n := strings.Count(out.String(), "\n"); n != 2 {
		t.Errorf("--deny printed %d lines:\n%s", n, out.String())
	}
}

func TestJSONKeyList(t *testing.T) {
	fakeRuntime(t, map[string]reply{"provider get bl-codex": {exit: 1}}, "")
	var docs []jsonKey
	if stderr, code := runJSON(t, &docs, "key", "list", "--json"); code != 0 || stderr != "" {
		t.Fatalf("exit %d stderr %q", code, stderr)
	}
	if len(docs) != 4 || docs[0] != (jsonKey{Name: "claude", Display: "Claude Code", KeyEnv: "ANTHROPIC_API_KEY", Stored: true, Available: true}) {
		t.Errorf("keys = %+v", docs)
	}
	if docs[1].Name != "codex" || docs[1].Stored || !docs[1].Available {
		t.Errorf("codex = %+v", docs[1])
	}
}

func TestJSONStatusFree(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	var doc jsonStatus
	if stderr, code := runJSON(t, &doc, "status", "--json"); code != 0 || stderr != "" {
		t.Fatalf("exit %d stderr %q", code, stderr)
	}
	if doc.SignedIn || doc.Email != "" || doc.Notes == nil || len(doc.Notes) != 0 {
		t.Errorf("status = %+v", doc)
	}
}

// Recorded output of openshell-prover 0.1.2 for a policy inside its boundary.
const proverWithin = `{"schema_version":1,"prover_version":"0.1.2","check":"boundary","coverage":{"domains":["filesystem","network_l4","network_rest","process","landlock"]},"result":"within_boundary","exit_code":0,"inputs":{"candidate":"c.yaml","boundary":"b.yaml"},"counterexample":null,"reason_code":null,"reason":null}`

func TestJSONPolicyCheck(t *testing.T) {
	fakeRuntime(t, nil, proverWithin)
	var doc jsonPolicyCheck
	if stderr, code := runJSON(t, &doc, "policy", "check", "--agent", "claude", "--json"); code != 0 || stderr != "" {
		t.Fatalf("exit %d stderr %q", code, stderr)
	}
	want := jsonPolicyCheck{Passed: true, Result: "within_boundary", Checked: "developer-default (built in)", Agent: "Claude Code", NotChecked: []string{}}
	if doc.Passed != want.Passed || doc.Result != want.Result || doc.Checked != want.Checked || doc.Agent != want.Agent || doc.Example != "" || doc.NotChecked == nil || len(doc.NotChecked) != 0 {
		t.Errorf("check = %+v", doc)
	}
	var none json.RawMessage
	if stderr, code := runJSON(t, &none, "policy", "compile", "--json"); code != 1 || none != nil || !strings.Contains(stderr, "--json is for boundlane policy check") {
		t.Errorf("compile --json: exit %d stdout %q stderr %q", code, none, stderr)
	}
}

func TestJSONPolicyCheckFails(t *testing.T) {
	exceeds := strings.Replace(proverWithin, `"result":"within_boundary"`, `"result":"exceeds_boundary"`, 1)
	exceeds = strings.Replace(exceeds, `"counterexample":null`, `"counterexample":{"domain":"network","host":"paste.example.net","port":443,"method":"GET","path":"/"}`, 1)
	fakeRuntime(t, nil, exceeds)
	var doc jsonPolicyCheck
	stderr, code := runJSON(t, &doc, "policy", "check", "--json")
	if code != 2 || !strings.Contains(stderr, "policy check") {
		t.Fatalf("exit %d, want 2; stderr %q", code, stderr)
	}
	if doc.Passed || doc.Result != "exceeds_boundary" || doc.Example != "any program can GET paste.example.net:443/" {
		t.Errorf("check = %+v", doc)
	}
}

func TestJSONUpdateCheck(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/latest.txt" {
			w.Write([]byte("0.9.0\n"))
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	t.Setenv("BOUNDLANE_DOWNLOAD_BASE", srv.URL)
	var doc jsonUpdate
	if stderr, code := runJSON(t, &doc, "update", "--check", "--json"); code != 0 || stderr != "" {
		t.Fatalf("exit %d stderr %q", code, stderr)
	}
	if doc != (jsonUpdate{Current: Version, Latest: "0.9.0", Available: false}) {
		t.Errorf("dev build: %+v", doc)
	}
	was := Version
	Version = "0.1.0"
	t.Cleanup(func() { Version = was })
	if stderr, code := runJSON(t, &doc, "update", "--check", "--json"); code != 0 || stderr != "" {
		t.Fatalf("exit %d stderr %q", code, stderr)
	}
	if doc != (jsonUpdate{Current: "0.1.0", Latest: "0.9.0", Available: true}) {
		t.Errorf("older build: %+v", doc)
	}
	srv.Close()
	var none json.RawMessage
	if stderr, code := runJSON(t, &none, "update", "--check", "--json"); code != 1 || none != nil || !strings.Contains(stderr, "could not reach") {
		t.Errorf("unreachable: exit %d stdout %q stderr %q", code, none, stderr)
	}
}

func TestJSONLogFollowLineTooLong(t *testing.T) {
	// One line longer than the scanner's 4 MiB buffer, as an abnormal runtime
	// could print. The command must end and say why, not wait forever on the
	// runtime's blocked write.
	long := strings.Repeat("x", 5*1024*1024) + "\n" + decisionLines
	fakeRuntime(t, map[string]reply{"logs bl-web-1a2b --source sandbox --tail": {out: long}}, "")
	seedState(t, config.Sandbox{Name: "bl-web-1a2b", Agent: "claude", Repo: "/Users/ana/web", Created: time.Now(), Running: true})
	done := make(chan struct{})
	var code int
	var out, errOut bytes.Buffer
	go func() {
		code = cli([]string{"log", "--follow", "--sandbox", "bl-web-1a2b", "--json"}, strings.NewReader(""), &out, &errOut)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("log --follow --json did not return after an over-long line")
	}
	if code != 1 || !strings.Contains(errOut.String(), "reading the sandbox log") || !strings.Contains(errOut.String(), "too long") {
		t.Fatalf("exit %d stderr %q", code, errOut.String())
	}
}

func TestPsLeavesAnUnchangedStateFileAlone(t *testing.T) {
	fakeRuntime(t, map[string]reply{"sandbox list": {out: "bl-web-1a2b\n"}}, "")
	dirs := seedState(t, config.Sandbox{Name: "bl-web-1a2b", Agent: "claude", Repo: "/Users/ana/web", Created: time.Now(), Running: true})
	path := filepath.Join(dirs.Config, "state.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// Written by hand in a shape SaveState would not produce, so a rewrite shows.
	compact := bytes.Join(bytes.Fields(raw), nil)
	if err := os.WriteFile(path, compact, 0o600); err != nil {
		t.Fatal(err)
	}
	var docs []jsonSandbox
	if stderr, code := runJSON(t, &docs, "ps", "--all", "--json"); code != 0 || stderr != "" || len(docs) != 1 || !docs[0].Running {
		t.Fatalf("exit %d stderr %q docs %+v", code, stderr, docs)
	}
	if after, _ := os.ReadFile(path); !bytes.Equal(after, compact) {
		t.Errorf("ps rewrote a state file it did not change:\n%s", after)
	}
	// A sandbox that stopped is a change, and is written.
	fakeRuntime(t, nil, "")
	t.Setenv("XDG_CONFIG_HOME", filepath.Dir(dirs.Config))
	if _, code := runJSON(t, &docs, "ps", "--all", "--json"); code != 0 || len(docs) != 1 || docs[0].Running {
		t.Fatalf("exit %d docs %+v", code, docs)
	}
	if after, _ := os.ReadFile(path); bytes.Equal(after, compact) {
		t.Error("ps did not record that the sandbox stopped")
	}
}

func TestStatusDoesNotWaitForeverOnTheTeamServer(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	// A server that accepts the connection and never answers.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	t.Cleanup(srv.Close)
	old := teamTimeout
	teamTimeout = 200 * time.Millisecond
	t.Cleanup(func() { teamTimeout = old })
	dirs, err := config.Default()
	if err != nil {
		t.Fatal(err)
	}
	if err := (team.Enrollment{Server: srv.URL, Token: "t", Email: "ana@acme.dev", Tenant: "acme", Machine: "m"}).Save(dirs); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	var doc jsonStatus
	stderr, code := runJSON(t, &doc, "status", "--json")
	if took := time.Since(start); took > 5*time.Second {
		t.Fatalf("status took %s against a server that never answers", took)
	}
	if code != 1 || !strings.Contains(stderr, "control plane unreachable") {
		t.Fatalf("exit %d stderr %q", code, stderr)
	}
}
