package relay

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"fenzi/cli/internal/config"
	"fenzi/cli/internal/run"
)

// saveLog writes a sandbox's log the way run and stop save it before the
// sandbox is deleted.
func saveLog(t *testing.T, dirs config.Dirs, name, log string) {
	t.Helper()
	if err := os.MkdirAll(dirs.Run(name), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dirs.Run(name), run.LogFile), []byte(log), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestAFinishedSandboxIsShippedOnce(t *testing.T) {
	gw := &fakeGW{listed: []string{}}
	f, opt := fakeFixture(t, gw)
	opt.Dirs.Cache = t.TempDir()
	// fenzi-1 was started from r1 and ended between two passes: the gateway no
	// longer lists it, and only its saved log is left.
	saveLog(t, opt.Dirs, "fenzi-1", denyLine(1791059085.948, "paste.example.net")+denyLine(1791059086.100, "other.example.net"))

	rep, err := Pass(context.Background(), opt)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Decisions != 2 || len(f.records) != 2 {
		t.Fatalf("report %+v records %+v", rep, f.records)
	}
	if r := f.records[0]; r.Sandbox != "fenzi-1" || r.Machine != "mbp" || r.PolicyRevision != "1" || r.Destination != "paste.example.net" {
		t.Fatalf("record %+v", r)
	}

	rep, err = Pass(context.Background(), opt)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Decisions != 0 || len(f.records) != 2 {
		t.Fatalf("second pass sent again: report %+v records %d", rep, len(f.records))
	}
}

func TestAFinishedSandboxSendsOnlyWhatTheStreamDidNot(t *testing.T) {
	first := denyLine(1791059085.948, "paste.example.net")
	gw := &fakeGW{logs: []byte(first)}
	f, opt := fakeFixture(t, gw)
	opt.Dirs.Cache = t.TempDir()
	if _, err := Pass(context.Background(), opt); err != nil {
		t.Fatal(err)
	}
	if len(f.records) != 1 {
		t.Fatalf("records %+v", f.records)
	}

	// The agent made one more call, then the run saved the log and deleted
	// the sandbox before the next pass.
	gw.listed = []string{}
	saveLog(t, opt.Dirs, "fenzi-1", first+denyLine(1791059090.5, "late.example.net"))
	if _, err := Pass(context.Background(), opt); err != nil {
		t.Fatal(err)
	}
	if len(f.records) != 2 || f.records[1].Destination != "late.example.net" {
		t.Fatalf("records %+v", f.records)
	}
	if _, err := Pass(context.Background(), opt); err != nil {
		t.Fatal(err)
	}
	if len(f.records) != 2 {
		t.Fatalf("sent again: %+v", f.records)
	}
}

func TestAFreeSessionFromBeforeSignInIsNotSent(t *testing.T) {
	gw := &fakeGW{listed: []string{}}
	f, opt := fakeFixture(t, gw)
	opt.Dirs.Cache = t.TempDir()
	state := &config.State{}
	state.Put(config.Sandbox{Name: "fenzi-free", Agent: "claude", Created: time.Now()})
	if err := opt.Dirs.SaveState(state); err != nil {
		t.Fatal(err)
	}
	saveLog(t, opt.Dirs, "fenzi-free", denyLine(1791059085.948, "paste.example.net"))
	if _, err := Pass(context.Background(), opt); err != nil {
		t.Fatal(err)
	}
	if len(f.records) != 0 {
		t.Fatalf("a Free session that this forwarder never read was sent: %+v", f.records)
	}
}

func TestRequestsCarryTheDraftFlagAndTheRevision(t *testing.T) {
	// The first two blocks are recorded from OpenShell 0.1.2: a request a
	// Claude Code session filed through policy.local, then a draft the
	// supervisor made from a refusal. The host the agent asked for is
	// replaced with example.com. The third block is not a recording: it is
	// the same format with the chunk id from the recorded log below and a
	// generated rationale, to check that the log wins over the rationale.
	rules := `  Chunk: ccd96a39-17bd-4710-af49-c88725b0540f
  Status: pending
  Rule: example_home_read
  Binary: /usr/bin/curl
  Confidence: 75%
  Rationale: User asked to see what is on the example.com homepage. Need a single read-only GET of the homepage with curl.
  Prover: prover: no new findings
  Candidate: 4dea2e771f03
  Endpoints: www.example.com:443 [L7 rest, allow GET /]
  Binaries: /usr/bin/curl

  Chunk: 59b83e6d-8a8a-43e4-a597-066a5d16fc36
  Status: pending
  Rule: allow_github_com_443
  Binary: /usr/lib/git-core/git-remote-http
  Confidence: 65%
  Rationale: Allow git-remote-http to connect to github.com:443 (HTTPS).
  Prover: prover: no new findings
  Candidate: 1fd6084bd0f7
  Endpoints: github.com:443 [L4]
  Binaries: /usr/lib/git-core/git-remote-http

  Chunk: fad7c2ed-3aca-4fb7-bb37-495820dd7562
  Status: pending
  Rule: allow_example_com_443
  Binary: /usr/bin/curl
  Rationale: Allow curl to connect to example.com:443 (HTTPS).
  Prover: prover: no new findings
  Endpoints: example.com:443 [L4]
`
	// Recorded from a Codex session on OpenShell 0.1.2; the host is replaced.
	// The log shows the agent filed the third chunk, though its rationale
	// reads like a generated one.
	log := `[1791297763.974] [sandbox] [INFO ] [openshell_supervisor] Flushed denial analysis to gateway proposals=1 sandbox_name=fenzi-mouse-keepe-a3a6 summaries=1
[1791297778.239] [sandbox] [OCSF ] [ocsf] CONFIG:PROPOSED [INFO] agent_authored proposal chunk:fad7c2ed-3aca-4fb7-bb37-495820dd7562 on example.com:443 HEAD / by /usr/bin/curl
`
	gw := &fakeGW{rules: []byte(rules), logs: []byte(log)}
	f, opt := fakeFixture(t, gw)
	opt.Revision = 4
	rep, err := Pass(context.Background(), opt)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Requests != 3 || len(f.proposals) != 3 {
		t.Fatalf("report %+v proposals %+v", rep, f.proposals)
	}
	want := map[string]bool{
		"ccd96a39-17bd-4710-af49-c88725b0540f": false,
		"59b83e6d-8a8a-43e4-a597-066a5d16fc36": true,
		"fad7c2ed-3aca-4fb7-bb37-495820dd7562": false,
	}
	for _, p := range f.proposals {
		if p.Draft != want[p.Chunk] || p.Revision != 4 {
			t.Errorf("%s: draft %v revision %d", p.Destination, p.Draft, p.Revision)
		}
	}
}
