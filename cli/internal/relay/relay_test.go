//go:build team

package relay

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"fenzi/cli/internal/config"
	"fenzi/cli/internal/openshell"
	"fenzi/cli/internal/run"
	"fenzi/cli/internal/team"
	"fenzi/controlplane"
)

func TestPassLoadsAHostChangeAndShipsADeny(t *testing.T) {
	s, err := controlplane.Open(filepath.Join(t.TempDir(), "team.db"), allow{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	if _, err := s.Publish(context.Background(), "acme", []byte(baseDoc)); err != nil {
		t.Fatal(err)
	}
	second, err := s.Publish(context.Background(), "acme", []byte(hostDoc))
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(controlplane.Handler(s))
	t.Cleanup(srv.Close)
	tok := signIn(t, srv, "mbp")

	dirs := config.Dirs{Config: t.TempDir()}
	state := &config.State{}
	state.Put(config.Sandbox{Name: "fenzi-1", Agent: "claude", Running: true, TeamRevision: 1, Created: time.Now()})
	if err := dirs.SaveState(state); err != nil {
		t.Fatal(err)
	}
	gw := &fakeGW{
		logs:  []byte("[1791059085.948] [sandbox] [OCSF ] [ocsf] NET:REFUSE [MED] DENIED paste.example.net [reason:policy_dns_ineligible]\n"),
		rules: []byte("Chunk: abcdef\nStatus: pending\nBinary: /usr/bin/curl\nRationale: need the host\nEndpoints: paste.example.net:443 [L7]\n"),
		list:  []byte("r2 Loaded\n"),
	}
	opt := Option{
		Gateway: gw, Client: team.Client{Base: srv.URL}, Token: tok, Machine: "mbp",
		Revision: second.Revision, Document: second.Document, Dirs: dirs, Prover: passing(),
	}
	rep, err := Pass(context.Background(), opt)
	if err != nil {
		t.Fatal(err)
	}
	if !gw.set || rep.Decisions != 1 || rep.Requests != 1 {
		t.Fatalf("set %v report %+v", gw.set, rep)
	}
	if !strings.Contains(strings.Join(rep.Notes, " "), "loaded r2") {
		t.Fatalf("notes %v", rep.Notes)
	}
	got, err := s.Decisions("acme", 10)
	if err != nil || len(got) != 1 || got[0].Destination != "paste.example.net" || got[0].Action != "Denied" {
		t.Fatalf("decisions %+v err %v", got, err)
	}

	pending, err := s.Proposals("acme", "pending")
	if err != nil || len(pending) != 1 {
		t.Fatalf("pending %+v %v", pending, err)
	}
	if pending[0].Draft || pending[0].Revision != 2 {
		t.Fatalf("a request with the agent's own rationale: %+v", pending[0])
	}
	if err := s.Review(pending[0].ID, "dana@acme.dev", "approved", ""); err != nil {
		t.Fatal(err)
	}
	rep, err = Pass(context.Background(), opt)
	if err != nil {
		t.Fatal(err)
	}
	if gw.approved != "abcdef" || rep.Applied != 1 {
		t.Fatalf("approved %q report %+v", gw.approved, rep)
	}
	again, _ := s.Applies("acme", "mbp")
	if len(again) != 0 {
		t.Fatalf("still applying %+v", again)
	}
}

func TestStaleApprovalIsNotRetried(t *testing.T) {
	s, opt, gw := teamFixture(t)
	if _, err := Pass(context.Background(), opt); err != nil {
		t.Fatal(err)
	}
	pending, err := s.Proposals("acme", "pending")
	if err != nil || len(pending) != 1 {
		t.Fatalf("pending %+v %v", pending, err)
	}
	if err := s.Review(pending[0].ID, "dana@acme.dev", "approved", ""); err != nil {
		t.Fatal(err)
	}
	gw.approveErr = errStale
	gw.rules = []byte("Chunk: abcdef\nStatus: pending\nBinary: /usr/bin/curl\nRationale: refreshed reason\nEndpoints: paste.example.net:443 [L7]\n")
	rep, err := Pass(context.Background(), opt)
	if err != nil {
		t.Fatal(err)
	}
	if gw.approveCalls != 1 || rep.Applied != 0 {
		t.Fatalf("calls %d report %+v", gw.approveCalls, rep)
	}
	if !strings.Contains(strings.Join(rep.Notes, " "), "pending again") {
		t.Fatalf("notes %v", rep.Notes)
	}
	again, err := s.Proposals("acme", "pending")
	if err != nil || len(again) != 1 || again[0].Rationale != "refreshed reason" {
		t.Fatalf("pending %+v %v", again, err)
	}
	if _, err := Pass(context.Background(), opt); err != nil {
		t.Fatal(err)
	}
	if gw.approveCalls != 1 {
		t.Fatalf("retried a stale approval, calls %d", gw.approveCalls)
	}

	if err := s.Review(again[0].ID, "dana@acme.dev", "approved", ""); err != nil {
		t.Fatal(err)
	}
	gw.rules = []byte("Chunk: zzzzzz\nStatus: pending\nBinary: /usr/bin/curl\nRationale: replacement\nEndpoints: other.example:443 [L7]\n")
	rep, err = Pass(context.Background(), opt)
	if err != nil {
		t.Fatal(err)
	}
	if gw.approveCalls != 2 || !strings.Contains(strings.Join(rep.Notes, " "), "Review the new request") {
		t.Fatalf("calls %d notes %v", gw.approveCalls, rep.Notes)
	}
	old, err := s.Proposals("acme", "superseded")
	if err != nil || len(old) != 1 || old[0].Chunk != "abcdef" {
		t.Fatalf("superseded %+v %v", old, err)
	}
	fresh, err := s.Proposals("acme", "pending")
	if err != nil || len(fresh) != 1 || fresh[0].Chunk != "zzzzzz" {
		t.Fatalf("replacement %+v %v", fresh, err)
	}
	if _, err := Pass(context.Background(), opt); err != nil {
		t.Fatal(err)
	}
	if gw.approveCalls != 2 {
		t.Fatalf("retried the replaced chunk, calls %d", gw.approveCalls)
	}
}

func teamFixture(t *testing.T) (*controlplane.Service, Option, *fakeGW) {
	t.Helper()
	s, err := controlplane.Open(filepath.Join(t.TempDir(), "team.db"), allow{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	if _, err := s.Publish(context.Background(), "acme", []byte(baseDoc)); err != nil {
		t.Fatal(err)
	}
	second, err := s.Publish(context.Background(), "acme", []byte(hostDoc))
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(controlplane.Handler(s))
	t.Cleanup(srv.Close)
	dirs := config.Dirs{Config: t.TempDir()}
	state := &config.State{}
	state.Put(config.Sandbox{Name: "fenzi-1", Agent: "claude", Running: true, TeamRevision: 1, Created: time.Now()})
	if err := dirs.SaveState(state); err != nil {
		t.Fatal(err)
	}
	gw := &fakeGW{
		logs:  []byte("[1791059085.948] [sandbox] [OCSF ] [ocsf] NET:REFUSE [MED] DENIED paste.example.net [reason:policy_dns_ineligible]\n"),
		rules: []byte("Chunk: abcdef\nStatus: pending\nBinary: /usr/bin/curl\nRationale: need the host\nEndpoints: paste.example.net:443 [L7]\n"),
		list:  []byte("r2 Loaded\n"),
	}
	opt := Option{
		Gateway: gw, Client: team.Client{Base: srv.URL}, Token: signIn(t, srv, "mbp"), Machine: "mbp",
		Revision: second.Revision, Document: second.Document, Dirs: dirs, Prover: passing(),
	}
	return s, opt, gw
}

func TestWallChangeDoesNotTouchTheRunningSandbox(t *testing.T) {
	s, err := controlplane.Open(filepath.Join(t.TempDir(), "team.db"), allow{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	if _, err := s.Publish(context.Background(), "acme", []byte(baseDoc)); err != nil {
		t.Fatal(err)
	}
	second, err := s.Publish(context.Background(), "acme", []byte(wallDoc))
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(controlplane.Handler(s))
	t.Cleanup(srv.Close)
	tok := signIn(t, srv, "mbp")
	dirs := config.Dirs{Config: t.TempDir()}
	state := &config.State{}
	state.Put(config.Sandbox{Name: "fenzi-1", Agent: "claude", Running: true, TeamRevision: 1, Created: time.Now()})
	if err := dirs.SaveState(state); err != nil {
		t.Fatal(err)
	}
	gw := &fakeGW{list: []byte("Loaded\n")}
	rep, err := Pass(context.Background(), Option{
		Gateway: gw, Client: team.Client{Base: srv.URL}, Token: tok, Machine: "mbp",
		Revision: second.Revision, Document: second.Document, Dirs: dirs,
	})
	if err != nil {
		t.Fatal(err)
	}
	if gw.set {
		t.Fatal("a path change must not be pushed onto a running sandbox")
	}
	if !strings.Contains(strings.Join(rep.Notes, " "), "next run") {
		t.Fatalf("notes %v", rep.Notes)
	}
}

func signIn(t *testing.T, srv *httptest.Server, machine string) string {
	t.Helper()
	c := team.Client{Base: srv.URL}
	start, err := c.StartDevice(context.Background(), machine)
	if err != nil {
		t.Fatal(err)
	}
	if err := approve(srv.URL, start.UserCode, "dana@acme.dev"); err != nil {
		t.Fatal(err)
	}
	en, err := c.Exchange(context.Background(), start.DeviceCode)
	if err != nil {
		t.Fatal(err)
	}
	return en.Token
}

func approve(base, code, email string) error {
	res, err := http.PostForm(base+"/device", url.Values{"code": {code}, "email": {email}})
	if err != nil {
		return err
	}
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return errStatus(res.StatusCode)
	}
	return nil
}

func TestApprovalIsShippedWithItsChunk(t *testing.T) {
	s, opt, gw := teamFixture(t)
	// Recorded from a Codex session on OpenShell 0.1.2; the host is replaced.
	gw.logs = append(gw.logs, "[1791297802.289] [sandbox] [OCSF ] [ocsf] CONFIG:APPROVED [INFO] chunk:fad7c2ed-3aca-4fb7-bb37-495820dd7562 approved on example.com:443 HEAD / by /usr/bin/curl\n"...)
	gw.mode = "manual"
	opt.BeatNotes = []string{"the server sent r1, older than r2; still on r2"}
	rep, err := Pass(context.Background(), opt)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Decisions != 2 {
		t.Fatalf("report %+v", rep)
	}
	got, err := s.Decisions("acme", 10)
	if err != nil || len(got) != 2 {
		t.Fatalf("decisions %+v %v", got, err)
	}
	a := got[0]
	if a.Class != "Config" || a.Action != "Approved" || a.Chunk != "fad7c2ed-3aca-4fb7-bb37-495820dd7562" ||
		a.Destination != "example.com:443 HEAD /" || a.Process != "/usr/bin/curl" || a.Machine != "mbp" {
		t.Fatalf("approval %+v", a)
	}
	machines, err := s.Machines("acme")
	if err != nil || len(machines) != 1 || machines[0].ApprovalMode != "manual" || machines[0].Version != "0.1.2" || len(machines[0].Sandboxes) != 1 {
		t.Fatalf("machines %+v %v", machines, err)
	}
	if len(machines[0].Notes) != 1 || machines[0].Notes[0] != opt.BeatNotes[0] {
		t.Fatalf("notes %+v", machines[0].Notes)
	}
	opt.BeatNotes = nil
	if _, err := Pass(context.Background(), opt); err != nil {
		t.Fatal(err)
	}
	if machines, _ := s.Machines("acme"); len(machines[0].Notes) != 0 {
		t.Fatalf("a cleared note stayed: %+v", machines[0].Notes)
	}
}

func TestPushNoteNamesTheTenant(t *testing.T) {
	_, opt, gw := teamFixture(t)
	opt.Tenant = "globex"
	if _, err := Pass(context.Background(), opt); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(gw.policy), "from globex r2 (signed)") {
		t.Fatalf("policy header:\n%s", gw.policy)
	}
}

// A sandbox started without a key holds the model API rule itself, so a
// team revision loaded into it must keep that rule.
func TestPushKeepsTheModelRuleOfASignInSandbox(t *testing.T) {
	_, opt, gw := teamFixture(t)
	state, err := opt.Dirs.LoadState()
	if err != nil {
		t.Fatal(err)
	}
	sb, _ := state.Find("fenzi-1")
	sb.SignIn = true
	state.Put(sb)
	if err := opt.Dirs.SaveState(state); err != nil {
		t.Fatal(err)
	}
	if _, err := Pass(context.Background(), opt); err != nil {
		t.Fatal(err)
	}
	if !gw.set || !strings.Contains(string(gw.policy), "host: api.anthropic.com") {
		t.Fatalf("loaded policy:\n%s", gw.policy)
	}
}

func TestPushIsProvedFirst(t *testing.T) {
	_, opt, gw := teamFixture(t)
	prover, calls := fakeProver(proverExceeds, 1)
	opt.Prover = prover
	rep, err := Pass(context.Background(), opt)
	if err != nil {
		t.Fatal(err)
	}
	if gw.set {
		t.Fatal("a revision the prover refused was loaded")
	}
	if len(calls.Calls) != 1 {
		t.Fatalf("prover calls %v", calls.Calls)
	}
	want := "fenzi-1: r2 not loaded, the policy check on this machine returned exceeds_boundary (any program can GET paste.example.net:443/). It keeps r1."
	if !strings.Contains(strings.Join(rep.Notes, "\n"), want) {
		t.Fatalf("notes %q", rep.Notes)
	}
	state, err := opt.Dirs.LoadState()
	if err != nil {
		t.Fatal(err)
	}
	if sb, _ := state.Find("fenzi-1"); sb.TeamRevision != 1 {
		t.Fatalf("sandbox recorded as r%d", sb.TeamRevision)
	}

	// The next pass checks again and says nothing new.
	rep, err = Pass(context.Background(), opt)
	if err != nil {
		t.Fatal(err)
	}
	if gw.set || len(calls.Calls) != 2 || strings.Contains(strings.Join(rep.Notes, "\n"), "not loaded") {
		t.Fatalf("set %v calls %d notes %q", gw.set, len(calls.Calls), rep.Notes)
	}
}

func TestPushWithoutAProverLoadsNothing(t *testing.T) {
	_, opt, gw := teamFixture(t)
	opt.Prover = nil
	rep, err := Pass(context.Background(), opt)
	if err != nil {
		t.Fatal(err)
	}
	if gw.set {
		t.Fatal("loaded without a prover")
	}
	if !strings.Contains(strings.Join(rep.Notes, "\n"), "fenzi-1: r2 not loaded, the policy prover could not run: no prover on this machine. It keeps r1.") {
		t.Fatalf("notes %q", rep.Notes)
	}

	// A prover that is not installed is the same.
	missing := &openshell.Fake{Replies: map[string]openshell.Reply{}}
	opt.Prover = openshell.Prover{R: missingRunner{missing}}
	if _, err := Pass(context.Background(), opt); err != nil {
		t.Fatal(err)
	}
	if gw.set {
		t.Fatal("loaded when the prover is not installed")
	}
}

// missingRunner fails every command the way Exec does when the binary is
// not on PATH.
type missingRunner struct{ *openshell.Fake }

func (missingRunner) Output(context.Context, ...string) ([]byte, error) {
	return nil, errors.New("openshell-prover is not installed or not on PATH: exec: \"openshell-prover\": executable file not found in $PATH")
}

// An MCP request approved in the console is rejected on the machine, with
// the reason: OpenShell 0.1.2 would store it as every tool on the server.
func TestConsoleApprovalOfAnMCPRequestIsRejected(t *testing.T) {
	s, opt, gw := teamFixture(t)
	gw.rules = []byte("Chunk: abcdef\nStatus: pending\nRule: mcp_proposal\nBinary: /usr/bin/curl\nRationale: read one wiki\nEndpoints: mcp.example.org:443 [mcp, allow initialize *, allow tools/list *, allow tools/call *]\n")
	if _, err := Pass(context.Background(), opt); err != nil {
		t.Fatal(err)
	}
	pending, err := s.Proposals("acme", "pending")
	if err != nil || len(pending) != 1 {
		t.Fatalf("pending %+v %v", pending, err)
	}
	if err := s.Review(pending[0].ID, "dana@acme.dev", "approved", ""); err != nil {
		t.Fatal(err)
	}
	rep, err := Pass(context.Background(), opt)
	if err != nil {
		t.Fatal(err)
	}
	if gw.approveCalls != 0 || gw.rejected != "abcdef" || !strings.Contains(gw.rejectReason, "every tool") {
		t.Fatalf("approve calls %d, rejected %q: %s", gw.approveCalls, gw.rejected, gw.rejectReason)
	}
	if !strings.Contains(strings.Join(rep.Notes, " "), "MCP request") {
		t.Errorf("notes %v", rep.Notes)
	}
}

// A new revision loaded on a running sandbox keeps the rules of this
// machine's own MCP servers, which run gave it beside the team's.
func TestPushKeepsTheMachinesOwnMCPServers(t *testing.T) {
	_, opt, gw := teamFixture(t)
	file := filepath.Join(t.TempDir(), "mcp.yaml")
	if err := os.WriteFile(file, []byte("version: 1\nmcp:\n  deepwiki:\n    url: https://mcp.deepwiki.com/mcp\n    tools:\n      allow: [read_wiki_structure]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := run.MachineMCP
	run.MachineMCP = func() string { return file }
	t.Cleanup(func() { run.MachineMCP = old })
	if _, err := Pass(context.Background(), opt); err != nil {
		t.Fatal(err)
	}
	if !gw.set || !strings.Contains(string(gw.policy), "mcp_deepwiki") || !strings.Contains(string(gw.policy), "read_wiki_structure") {
		t.Fatalf("loaded policy:\n%s", gw.policy)
	}
}
