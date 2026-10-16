package relay

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"fenzi/cli/internal/config"
	"fenzi/cli/internal/forward"
	"fenzi/cli/internal/openshell"
	"fenzi/cli/internal/team"
	"fenzi/teamapi"
)

// fakeTeam is a team server that records what the forwarder sends.
type fakeTeam struct {
	mu      sync.Mutex
	beats   []string
	batches []int
	records []forward.Record
	refuse  int
	// proposals are the requests the forwarder reported.
	proposals []teamapi.Proposal
	// lists is the last full pending list per sandbox (PUT), and puts how
	// many were sent. old makes the server one that predates the call.
	lists map[string][]teamapi.Proposal
	puts  int
	old   bool
}

func (f *fakeTeam) start(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/heartbeat", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.beats = append(f.beats, string(b))
		f.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /v1/decisions", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Records []forward.Record `json:"records"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.refuse > 0 {
			f.refuse--
			http.Error(w, "a decision needs a sandbox and an action", http.StatusBadRequest)
			return
		}
		if len(req.Records) > batchLimit {
			http.Error(w, "too many decisions in one batch", http.StatusBadRequest)
			return
		}
		f.batches = append(f.batches, len(req.Records))
		f.records = append(f.records, req.Records...)
		json.NewEncoder(w).Encode(map[string]int{"stored": len(req.Records)})
	})
	mux.HandleFunc("POST /v1/proposals", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Proposals []teamapi.Proposal `json:"proposals"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		f.mu.Lock()
		f.proposals = append(f.proposals, req.Proposals...)
		f.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("PUT /v1/proposals", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.puts++
		if f.old {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Sandbox   string             `json:"sandbox"`
			Proposals []teamapi.Proposal `json:"proposals"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if f.lists == nil {
			f.lists = map[string][]teamapi.Proposal{}
		}
		f.lists[req.Sandbox] = append([]teamapi.Proposal{}, req.Proposals...)
		f.proposals = append(f.proposals, req.Proposals...)
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /v1/applies", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"applies":[]}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// deadServer is an address nothing listens on.
func deadServer(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.NotFoundHandler())
	srv.Close()
	return srv.URL
}

func fakeFixture(t *testing.T, gw *fakeGW) (*fakeTeam, Option) {
	t.Helper()
	f := &fakeTeam{}
	srv := f.start(t)
	dirs := config.Dirs{Config: t.TempDir()}
	state := &config.State{}
	state.Put(config.Sandbox{Name: "bl-1", Agent: "claude", Running: true, TeamRevision: 1, Created: time.Now()})
	if err := dirs.SaveState(state); err != nil {
		t.Fatal(err)
	}
	return f, Option{Gateway: gw, Client: team.Client{Base: srv.URL}, Token: "t", Tenant: "acme", Machine: "mbp", Dirs: dirs}
}

// denyLine is a recorded OpenShell 0.1.2 deny with its time and host changed.
func denyLine(at float64, host string) string {
	return fmt.Sprintf("[%.3f] [sandbox] [OCSF ] [ocsf] NET:REFUSE [MED] DENIED %s [reason:policy_dns_ineligible]\n", at, host)
}

func TestHeartbeatOnEveryPass(t *testing.T) {
	gw := &fakeGW{}
	f, opt := fakeFixture(t, gw)
	for range 2 {
		if _, err := Pass(context.Background(), opt); err != nil {
			t.Fatal(err)
		}
	}
	want := `{"openshell_version":"0.1.2","driver":"docker","policy_revision":0,"approval_mode":"","sandboxes":[{"name":"bl-1","agent":"claude","revision":1,"running":true}],"notes":[]}`
	if len(f.beats) != 2 || f.beats[0] != want {
		t.Fatalf("beats %q", f.beats)
	}

	opt.BeatNotes = []string{"the server sent r3, which failed the signature check; still on r2"}
	if _, err := Pass(context.Background(), opt); err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(f.beats[2], `"notes":["the server sent r3, which failed the signature check; still on r2"]}`) {
		t.Fatalf("beat without the note: %s", f.beats[2])
	}

	gw.mode = "auto"
	beat := Beat(context.Background(), gw, opt.Dirs, 3)
	if beat.ApprovalMode != "auto" || beat.PolicyRevision != 3 {
		t.Errorf("beat %+v", beat)
	}
	gw.modeErr = errors.New("openshell settings get: unreadable output")
	if beat := Beat(context.Background(), gw, opt.Dirs, 3); beat.ApprovalMode != "" {
		t.Errorf("an unreadable setting must be sent empty: %+v", beat)
	}
}

func TestHeartbeatFailureDoesNotStopThePass(t *testing.T) {
	gw := &fakeGW{logs: []byte(denyLine(1791059085.948, "paste.example.net"))}
	f, opt := fakeFixture(t, gw)
	inner := f.start(t).Config.Handler
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/heartbeat" {
			http.Error(w, "heartbeat is broken", http.StatusInternalServerError)
			return
		}
		inner.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	opt.Client.Base = srv.URL
	rep, err := Pass(context.Background(), opt)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Decisions != 1 || !strings.Contains(strings.Join(rep.Notes, " "), "heartbeat: heartbeat is broken") {
		t.Fatalf("report %+v", rep)
	}
}

func TestSpoolKeepsRecordsWhileTheServerIsAway(t *testing.T) {
	gw := &fakeGW{
		logs:  []byte(denyLine(1791059085.948, "paste.example.net")),
		rules: []byte("Chunk: abcdef\nStatus: pending\nBinary: /usr/bin/curl\nRationale: need the host\nEndpoints: paste.example.net:443 [L7]\n"),
	}
	f, opt := fakeFixture(t, gw)
	live := opt.Client.Base
	opt.Client.Base = deadServer(t)

	rep, err := Pass(context.Background(), opt)
	if err != nil {
		t.Fatalf("an unreachable server must not fail the pass: %v", err)
	}
	if !rep.Unreachable || rep.Spooled != 1 || rep.Decisions != 0 {
		t.Fatalf("report %+v", rep)
	}
	if !strings.Contains(strings.Join(rep.Notes, " "), "control plane unreachable, 1 record spooled") {
		t.Fatalf("notes %v", rep.Notes)
	}
	if gw.pendingCalls != 1 {
		t.Fatalf("pending requests must still be read, calls %d", gw.pendingCalls)
	}
	info, err := os.Stat(spoolPath(opt.Dirs))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("spool %v %v", info, err)
	}

	gw.logs = append(gw.logs, denyLine(1791059086, "other.example.net")...)
	rep, err = Pass(context.Background(), opt)
	if err != nil || rep.Spooled != 2 {
		t.Fatalf("second pass %+v %v", rep, err)
	}

	opt.Client.Base = live
	rep, err = Pass(context.Background(), opt)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Unreachable || rep.Spooled != 0 || rep.Decisions != 2 || len(f.records) != 2 {
		t.Fatalf("report %+v records %+v", rep, f.records)
	}
	if f.records[0].Destination != "paste.example.net" || f.records[1].Destination != "other.example.net" {
		t.Fatalf("the spool must be sent oldest first: %+v", f.records)
	}
	if _, err := os.Stat(spoolPath(opt.Dirs)); !os.IsNotExist(err) {
		t.Fatalf("an empty spool leaves no file: %v", err)
	}
}

func TestUploadSplitsBatches(t *testing.T) {
	f, opt := fakeFixture(t, &fakeGW{})
	sp, err := openSpool(opt.Dirs, 0)
	if err != nil {
		t.Fatal(err)
	}
	base := time.Unix(1791059085, 0).UTC()
	var recs []forward.Record
	for i := range 1201 {
		recs = append(recs, forward.Record{Time: base.Add(time.Duration(i) * time.Millisecond), Sandbox: "bl-1", Class: "Network Activity", Action: "Denied", Destination: "paste.example.net"})
	}
	sp.add(recs)
	if err := sp.save(); err != nil {
		t.Fatal(err)
	}
	rep, err := Pass(context.Background(), opt)
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(f.batches) != "[500 500 201]" || rep.Decisions != 1201 || rep.Spooled != 0 {
		t.Fatalf("batches %v report %+v", f.batches, rep)
	}
}

func TestRefusedBatchDoesNotBlockTheSpool(t *testing.T) {
	gw := &fakeGW{logs: []byte(denyLine(1791059085.948, "paste.example.net"))}
	f, opt := fakeFixture(t, gw)
	f.refuse = 1
	rep, err := Pass(context.Background(), opt)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Spooled != 0 || !strings.Contains(strings.Join(rep.Notes, " "), "refused 1 record:") {
		t.Fatalf("report %+v", rep)
	}
}

func TestFullSpoolDropsTheOldestAndRecordsAGap(t *testing.T) {
	sp := &spool{limit: 5}
	at := func(s int) time.Time { return time.Unix(1791059000+int64(s), 0).UTC() }
	rec := func(sandbox string, s int) forward.Record {
		return forward.Record{Time: at(s), Sandbox: sandbox, Machine: "mbp", Class: "Network Activity", Action: "Denied", Destination: "h"}
	}
	if n := sp.add([]forward.Record{rec("a", 0), rec("a", 1), rec("a", 2), rec("a", 3)}); n != 0 {
		t.Fatalf("dropped %d", n)
	}
	if n := sp.add([]forward.Record{rec("b", 4), rec("b", 5), rec("b", 6)}); n != 3 {
		t.Fatalf("dropped %d", n)
	}
	if len(sp.recs) != 5 {
		t.Fatalf("spool holds %d", len(sp.recs))
	}
	g := sp.recs[0]
	want := "spool full: 3 records dropped between " + at(0).Format(time.RFC3339Nano) + " and " + at(2).Format(time.RFC3339Nano)
	if !g.Gap || g.Sandbox != "a" || g.Action != "Gap" || g.Destination != "log stream" || g.Reason != want || !g.Time.Equal(at(0)) {
		t.Fatalf("gap %+v", g)
	}

	// A second overflow merges the earlier gap instead of counting it.
	if n := sp.add([]forward.Record{rec("b", 7), rec("b", 8)}); n != 3 {
		t.Fatalf("dropped %d", n)
	}
	if len(sp.recs) != 5 {
		t.Fatalf("spool holds %d", len(sp.recs))
	}
	a, b := sp.recs[0], sp.recs[1]
	if a.Reason != "spool full: 4 records dropped between "+at(0).Format(time.RFC3339Nano)+" and "+at(3).Format(time.RFC3339Nano) {
		t.Fatalf("merged gap %+v", a)
	}
	if b.Sandbox != "b" || b.Reason != "spool full: 2 records dropped between "+at(4).Format(time.RFC3339Nano)+" and "+at(5).Format(time.RFC3339Nano) {
		t.Fatalf("second gap %+v", b)
	}
}

func TestFullSpoolIsReported(t *testing.T) {
	var log strings.Builder
	for i := range 4 {
		log.WriteString(denyLine(1791059085+float64(i), fmt.Sprintf("h%d.example", i)))
	}
	_, opt := fakeFixture(t, &fakeGW{logs: []byte(log.String())})
	opt.Client.Base = deadServer(t)
	opt.SpoolLimit = 3
	rep, err := Pass(context.Background(), opt)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Dropped != 2 || rep.Spooled != 3 || !strings.Contains(strings.Join(rep.Notes, " "), "spool full: 2 records dropped") {
		t.Fatalf("report %+v", rep)
	}
}

func TestLogWindowGap(t *testing.T) {
	gw := &fakeGW{logs: []byte(denyLine(1791059000, "first.example"))}
	f, opt := fakeFixture(t, gw)
	if _, err := Pass(context.Background(), opt); err != nil {
		t.Fatal(err)
	}

	// A cursor at a whole second must not hide a later record in the same second.
	gw.logs = []byte(denyLine(1791059000, "first.example") + denyLine(1791059000.5, "half.example"))
	if _, err := Pass(context.Background(), opt); err != nil {
		t.Fatal(err)
	}
	if len(f.records) != 2 || f.records[1].Destination != "half.example" {
		t.Fatalf("records %+v", f.records)
	}

	// A full window that starts after the last line read skipped lines.
	var full strings.Builder
	for i := range logWindow {
		full.WriteString(denyLine(1791059100+float64(i), fmt.Sprintf("h%d.example", i)))
	}
	gw.logs = []byte(full.String())
	f.records = nil
	if _, err := Pass(context.Background(), opt); err != nil {
		t.Fatal(err)
	}
	if len(f.records) != logWindow+1 {
		t.Fatalf("got %d records", len(f.records))
	}
	g := f.records[0]
	if !g.Gap || g.Destination != "log stream" || !g.Time.Equal(time.Unix(1791059000, 5e8)) || !strings.Contains(g.Reason, "were not read") {
		t.Fatalf("gap %+v", g)
	}

	// A full window that reaches back to the last line read skipped nothing.
	full.Reset()
	for i := range logWindow {
		full.WriteString(denyLine(1791059200+float64(i), fmt.Sprintf("n%d.example", i)))
	}
	gw.logs = []byte(full.String())
	f.records = nil
	if _, err := Pass(context.Background(), opt); err != nil {
		t.Fatal(err)
	}
	for _, r := range f.records {
		if r.Gap {
			t.Fatalf("overlapping window reported a gap: %+v", r)
		}
	}

	// A window that is not full is the whole log; it skipped nothing.
	gw.logs = []byte(denyLine(1791060000, "late.example"))
	f.records = nil
	if _, err := Pass(context.Background(), opt); err != nil {
		t.Fatal(err)
	}
	if len(f.records) != 1 || f.records[0].Gap {
		t.Fatalf("records %+v", f.records)
	}
}

func TestLogFailureRecordsAGap(t *testing.T) {
	gw := &fakeGW{logErr: errors.New("openshell logs bl-1: sandbox not found")}
	f, opt := fakeFixture(t, gw)
	rep, err := Pass(context.Background(), opt)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.records) != 1 || !f.records[0].Gap || !strings.Contains(strings.Join(rep.Notes, " "), "a gap was recorded") {
		t.Fatalf("records %+v notes %v", f.records, rep.Notes)
	}
}

type fakeStream struct {
	reads  []openshell.StreamRead
	err    error
	afters []string
}

func (f *fakeStream) ReadStream(_ context.Context, _, after string, _ int) (openshell.StreamRead, error) {
	f.afters = append(f.afters, after)
	if f.err != nil {
		return openshell.StreamRead{Cursor: after}, f.err
	}
	r := f.reads[0]
	f.reads = f.reads[1:]
	return r, nil
}

// Messages recorded from the gateway's watch stream and the shorthand log,
// OpenShell 0.1.2; the approval's host is replaced.
const (
	streamAllow    = "NET:OPEN [INFO] ALLOWED /usr/local/lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe(0) -> api.anthropic.com:443 [policy:_provider_bl_claude engine:opa]"
	streamApproval = "CONFIG:APPROVED [INFO] chunk:fad7c2ed-3aca-4fb7-bb37-495820dd7562 approved on example.com:443 HEAD / by /usr/bin/curl"
)

func TestStreamIsReadAfterItsCursor(t *testing.T) {
	gw := &fakeGW{logErr: errors.New("the log window must not be read")}
	f, opt := fakeFixture(t, gw)
	at := time.Date(2026, 10, 3, 21, 46, 19, 337e6, time.UTC)
	st := &fakeStream{reads: []openshell.StreamRead{
		{Cursor: "v1:s1:2", Lines: []openshell.StreamLine{
			{Cursor: "v1:s1:1", Time: at, Level: "OCSF", Message: streamAllow},
			{Cursor: "v1:s1:2", Time: at.Add(time.Second), Level: "OCSF", Message: streamApproval},
		}},
		{Cursor: "v1:s1:3", Lines: []openshell.StreamLine{
			{Cursor: "v1:s1:3", Time: at.Add(2 * time.Second), Level: "WARN", Message: "Failed to install sandbox agent skill on toggle-on"},
		}},
	}}
	opt.Stream = st
	rep, err := Pass(context.Background(), opt)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Decisions != 2 || len(f.records) != 2 || f.records[1].Chunk != "fad7c2ed-3aca-4fb7-bb37-495820dd7562" {
		t.Fatalf("report %+v records %+v", rep, f.records)
	}
	if _, err := Pass(context.Background(), opt); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(st.afters) != "[ v1:s1:2]" || len(f.records) != 2 {
		t.Fatalf("afters %q records %+v", st.afters, f.records)
	}
	cur, err := loadCursors(opt.Dirs)
	if err != nil || cur.Stream["bl-1"] != "v1:s1:3" {
		t.Fatalf("cursor %+v %v", cur, err)
	}
}

func TestStreamGaps(t *testing.T) {
	f, opt := fakeFixture(t, &fakeGW{})
	at := time.Date(2026, 10, 3, 21, 46, 19, 0, time.UTC)
	cur, _ := loadCursors(opt.Dirs)
	cur.Stream["bl-1"] = "v1:old:7"
	cur.Last["bl-1"] = at.Format(time.RFC3339Nano)
	if err := saveCursors(opt.Dirs, cur); err != nil {
		t.Fatal(err)
	}
	opt.Stream = &fakeStream{reads: []openshell.StreamRead{{
		Cursor: "v1:s2:1", Reset: "Restart the watch with an empty resume_after_cursor",
		Warnings: []string{"log buffer overflowed"},
		Lines:    []openshell.StreamLine{{Cursor: "v1:s2:1", Time: at.Add(time.Minute), Level: "OCSF", Message: streamAllow}},
	}}}
	if _, err := Pass(context.Background(), opt); err != nil {
		t.Fatal(err)
	}
	if len(f.records) != 3 {
		t.Fatalf("records %+v", f.records)
	}
	reset, warn := f.records[0], f.records[1]
	if !reset.Gap || !reset.Time.Equal(at) || !strings.Contains(reset.Reason, "refused the stream cursor (Restart the watch") {
		t.Errorf("reset gap %+v", reset)
	}
	if !warn.Gap || warn.Reason != "log stream warning: log buffer overflowed" {
		t.Errorf("warning gap %+v", warn)
	}
}

func TestStreamFallsBackToTheLogWindow(t *testing.T) {
	gw := &fakeGW{logs: []byte(denyLine(1791059085.948, "paste.example.net"))}
	f, opt := fakeFixture(t, gw)
	opt.Stream = &fakeStream{err: fmt.Errorf("no client files: %w", openshell.ErrNoStream)}
	rep, err := Pass(context.Background(), opt)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.records) != 1 || len(rep.Notes) != 0 {
		t.Fatalf("a machine without the certificate reads the log quietly: %+v %v", f.records, rep.Notes)
	}
	gw.logs = append(gw.logs, denyLine(1791059086, "other.example.net")...)
	opt.Stream = &fakeStream{err: errors.New("rpc error: code = Unavailable desc = connection refused")}
	rep, err = Pass(context.Background(), opt)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.records) != 2 || !strings.Contains(strings.Join(rep.Notes, " "), "log stream watch failed") {
		t.Fatalf("records %+v notes %v", f.records, rep.Notes)
	}
}
