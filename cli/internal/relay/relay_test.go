//go:build team

package relay

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"boundlane/cli/internal/config"
	"boundlane/cli/internal/team"
	"boundlane/controlplane"
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
	state.Put(config.Sandbox{Name: "bl-1", Agent: "claude", Running: true, TeamRevision: 1, Created: time.Now()})
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
		Revision: second.Revision, Document: second.Document, Dirs: dirs,
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
	state.Put(config.Sandbox{Name: "bl-1", Agent: "claude", Running: true, TeamRevision: 1, Created: time.Now()})
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
		Revision: second.Revision, Document: second.Document, Dirs: dirs,
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
	state.Put(config.Sandbox{Name: "bl-1", Agent: "claude", Running: true, TeamRevision: 1, Created: time.Now()})
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

var errStale = staleError("proposal inputs changed; evaluation refreshed, refetch and review again")

type staleError string

func (e staleError) Error() string { return string(e) }

type errStatus int

func (e errStatus) Error() string { return http.StatusText(int(e)) }

type allow struct{}

func (allow) Check(context.Context, []byte, []byte) (bool, string, error) { return true, "", nil }

type fakeGW struct {
	logs         []byte
	logErr       error
	rules        []byte
	list         []byte
	set          bool
	policy       []byte
	approved     string
	approveCalls int
	approveErr   error
	pendingCalls int
	mode         string
	modeErr      error
}

// Version and ComputeDrivers return what OpenShell 0.1.2 gave on the test machine.
func (g *fakeGW) Version(context.Context) (string, error) { return "openshell 0.1.2\n", nil }
func (g *fakeGW) ComputeDrivers(context.Context) ([]string, error) {
	return []string{"docker"}, nil
}
func (g *fakeGW) GlobalSetting(context.Context, string) (string, error) {
	if g.mode == "" {
		return "<unset>", g.modeErr
	}
	return g.mode, g.modeErr
}
func (g *fakeGW) Sandboxes(context.Context) ([]string, error) { return []string{"bl-1"}, nil }
func (g *fakeGW) LogLines(context.Context, string, int) ([]byte, error) {
	return g.logs, g.logErr
}
func (g *fakeGW) PendingRules(context.Context, string) ([]byte, error) {
	g.pendingCalls++
	return g.rules, nil
}
func (g *fakeGW) RuleApprove(_ context.Context, _, chunk string) error {
	g.approveCalls++
	g.approved = chunk
	return g.approveErr
}
func (g *fakeGW) RuleReject(context.Context, string, string, string) error { return nil }
func (g *fakeGW) PolicySet(_ context.Context, _, file string) error {
	g.set = true
	b, err := os.ReadFile(file)
	g.policy = b
	return err
}
func (g *fakeGW) PolicyList(context.Context, string) ([]byte, error) { return g.list, nil }

const baseDoc = `version: 1
name: acme
agents: [claude]
workspace: read-write
hosts:
  - host: example.com
    access: read-only
approvals: person
`

const hostDoc = `version: 1
name: acme
agents: [claude]
workspace: read-write
hosts:
  - host: example.com
    access: read-only
  - host: pypi.org
    access: read-only
approvals: person
`

const wallDoc = `version: 1
name: acme
agents: [claude]
workspace: read-write
paths:
  read_only: [/etc]
hosts:
  - host: example.com
    access: read-only
approvals: person
`
