// Package relay pushes a signed policy onto running sandboxes and ships
// decisions and requests to the team server. It runs on the machine with the
// gateway. The server never connects in.
package relay

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"boundlane/agents"
	"boundlane/cli/internal/config"
	"boundlane/cli/internal/forward"
	"boundlane/cli/internal/openshell"
	"boundlane/cli/internal/run"
	"boundlane/cli/internal/team"
	"boundlane/compiler"
	"boundlane/teamapi"
)

// Gateway is the local OpenShell gateway. openshell.Client implements it.
type Gateway interface {
	Runtime
	Sandboxes(ctx context.Context) ([]string, error)
	LogLines(ctx context.Context, name string, n int) ([]byte, error)
	PendingRules(ctx context.Context, name string) ([]byte, error)
	RuleApprove(ctx context.Context, name, chunk string) error
	RuleReject(ctx context.Context, name, chunk, reason string) error
	PolicySet(ctx context.Context, name, file string) error
	PolicyList(ctx context.Context, name string) ([]byte, error)
}

// Runtime is what a heartbeat reads from the gateway.
type Runtime interface {
	Version(ctx context.Context) (string, error)
	ComputeDrivers(ctx context.Context) ([]string, error)
	GlobalSetting(ctx context.Context, key string) (string, error)
}

// Streamer reads a sandbox's log stream after a cursor. *openshell.Watch
// implements it.
type Streamer interface {
	ReadStream(ctx context.Context, sandbox, after string, tail int) (openshell.StreamRead, error)
}

// Option is one pass of sync and forward.
type Option struct {
	Gateway Gateway
	// Stream, when set, is read instead of the last log lines. A machine
	// without the gateway's client certificate falls back to the log lines.
	Stream   Streamer
	Client   team.Client
	Token    string
	Tenant   string
	Machine  string
	Revision int
	Document []byte
	Dirs     config.Dirs
	// SpoolLimit bounds the records kept while the control plane is away.
	// Zero means spoolLimit.
	SpoolLimit int
}

// Report is what one pass did.
type Report struct {
	// Decisions is how many records the server stored.
	Decisions int
	Requests  int
	Applied   int
	// Spooled is how many records still wait on disk for the server.
	Spooled int
	// Dropped is how many records a full spool lost on this pass.
	Dropped int
	// Unreachable means a call to the control plane got no answer.
	Unreachable bool
	Notes       []string
}

const (
	// logWindow is how many log lines one pass reads per sandbox.
	logWindow = 200
	// batchLimit is the most records one upload carries. The server refuses more.
	batchLimit = 500
)

// Pass sends a heartbeat, loads a network change onto running sandboxes,
// spools and uploads new decisions and approvals, reports pending requests,
// and applies reviews. A control plane that cannot be reached does not stop
// the work on the gateway: records wait in the spool and the report says so.
// A gateway error still ends the pass.
func Pass(ctx context.Context, opt Option) (Report, error) {
	p := &pass{Option: opt}
	if err := p.sync(ctx); err != nil {
		return p.rep, err
	}
	// After sync, so the report carries the revision each sandbox now holds.
	p.heartbeat(ctx)
	if err := p.ship(ctx); err != nil {
		return p.rep, err
	}
	if err := p.apply(ctx); err != nil {
		return p.rep, err
	}
	switch {
	case p.rep.Unreachable:
		p.note(fmt.Sprintf("control plane unreachable, %s spooled", records(p.rep.Spooled)))
	case p.rep.Spooled > 0:
		p.note(fmt.Sprintf("%s spooled for the next pass", records(p.rep.Spooled)))
	}
	return p.rep, nil
}

func records(n int) string {
	if n == 1 {
		return "1 record"
	}
	return strconv.Itoa(n) + " records"
}

type pass struct {
	Option
	rep Report
}

func (p *pass) note(n string) {
	for _, have := range p.rep.Notes {
		if have == n {
			return
		}
	}
	p.rep.Notes = append(p.rep.Notes, n)
}

// up reports whether the control plane is still worth calling on this pass.
func (p *pass) up() bool { return !p.rep.Unreachable }

// failed records a control plane error. One that got no answer stops the
// other server calls of this pass.
func (p *pass) failed(what string, err error) {
	if team.Unreachable(err) {
		p.rep.Unreachable = true
		return
	}
	p.note(what + ": " + err.Error())
}

func (p *pass) heartbeat(ctx context.Context) {
	if err := p.Client.Heartbeat(ctx, p.Token, Beat(ctx, p.Gateway, p.Dirs, p.Revision)); err != nil {
		p.failed("heartbeat", err)
	}
}

// Beat gathers what a heartbeat reports, read the way doctor and status read
// it. A value the gateway does not give is left empty.
func Beat(ctx context.Context, rt Runtime, dirs config.Dirs, revision int) team.Beat {
	b := team.Beat{PolicyRevision: revision, Sandboxes: []team.BeatSandbox{}}
	if out, err := rt.Version(ctx); err == nil {
		b.OpenShellVersion = strings.TrimSpace(out)
		if v, _ := openshell.Pinned.Contains(out); v != "" {
			b.OpenShellVersion = v
		}
	}
	if drivers, err := rt.ComputeDrivers(ctx); err == nil {
		b.Driver = strings.Join(drivers, ", ")
	}
	if mode, err := rt.GlobalSetting(ctx, "proposal_approval_mode"); err == nil && mode != openshell.Unset {
		b.ApprovalMode = mode
	}
	if state, err := dirs.LoadState(); err == nil {
		for _, sb := range state.Sandboxes {
			b.Sandboxes = append(b.Sandboxes, team.BeatSandbox{Name: sb.Name, Agent: sb.Agent, Revision: sb.TeamRevision, Running: sb.Running})
		}
	}
	return b
}

func (p *pass) sync(ctx context.Context) error {
	opt := p.Option
	rep := &p.rep
	if opt.Revision == 0 || len(opt.Document) == 0 {
		return nil
	}
	next, err := compiler.Parse(opt.Document)
	if err != nil {
		return err
	}
	state, err := opt.Dirs.LoadState()
	if err != nil {
		return err
	}
	changed := false
	for i := range state.Sandboxes {
		sb := &state.Sandboxes[i]
		if !sb.Running || sb.TeamRevision == opt.Revision {
			continue
		}
		if sb.TeamRevision == 0 {
			if sb.Notified != opt.Revision {
				rep.Notes = append(rep.Notes, sb.Name+" was not started from a team revision. The next run uses r"+strconv.Itoa(opt.Revision)+".")
				sb.Notified = opt.Revision
				changed = true
			}
			continue
		}
		// The sandbox's own revision comes from the server. Without it the
		// change cannot be classified, so the sandbox waits for the next pass.
		if !p.up() {
			continue
		}
		old, err := opt.Client.Revision(ctx, opt.Token, sb.TeamRevision)
		if err != nil {
			p.failed(fmt.Sprintf("%s: revision %d", sb.Name, sb.TeamRevision), err)
			continue
		}
		prev, err := compiler.Parse(old.Document)
		if err != nil {
			return err
		}
		switch compiler.Effect(prev, next) {
		case compiler.EffectNetwork:
			note, err := push(ctx, opt, sb.Name, sb.Agent, next)
			if err != nil {
				return err
			}
			rep.Notes = append(rep.Notes, note)
			sb.TeamRevision = opt.Revision
			changed = true
		case compiler.EffectWall:
			if sb.Notified != opt.Revision {
				rep.Notes = append(rep.Notes, sb.Name+": "+compiler.EffectNote(compiler.EffectWall))
				sb.Notified = opt.Revision
				changed = true
			}
		default:
			sb.TeamRevision = opt.Revision
			changed = true
		}
	}
	if changed {
		return opt.Dirs.SaveState(state)
	}
	return nil
}

func push(ctx context.Context, opt Option, name, agent string, doc *compiler.Document) (string, error) {
	entry, err := agents.Get(agent)
	if err != nil {
		return "", err
	}
	dir, err := os.MkdirTemp("", "boundlane-sync-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(dir)
	compiled, err := run.WriteCompiled(doc, entry, dir, fmt.Sprintf("%s r%d (signed)", opt.Tenant, opt.Revision))
	if err != nil {
		return "", err
	}
	if err := opt.Gateway.PolicySet(ctx, name, compiled.Policy); err != nil {
		return "", err
	}
	list, err := opt.Gateway.PolicyList(ctx, name)
	if err != nil {
		return "", err
	}
	switch {
	case bytes.Contains(list, []byte("Loaded")):
		return fmt.Sprintf("%s loaded r%d. %s", name, opt.Revision, compiler.EffectNote(compiler.EffectNetwork)), nil
	case bytes.Contains(list, []byte("Pending")):
		return fmt.Sprintf("%s has r%d pending. The supervisor loads it on its next poll.", name, opt.Revision), nil
	default:
		return fmt.Sprintf("%s accepted r%d. policy list did not say Loaded.", name, opt.Revision), nil
	}
}

// ship reads each sandbox's new decisions and approvals into the spool,
// reports pending requests, and uploads the spool. Records reach the spool
// before the cursors move, so a crash sends some twice, which the server
// ignores, and loses none.
func (p *pass) ship(ctx context.Context) error {
	names, err := p.Gateway.Sandboxes(ctx)
	if err != nil {
		return err
	}
	cur, err := loadCursors(p.Dirs)
	if err != nil {
		return err
	}
	sp, err := openSpool(p.Dirs, p.SpoolLimit)
	if err != nil {
		return err
	}
	var fresh []forward.Record
	for _, name := range names {
		recs, ok, err := p.read(ctx, name, &cur)
		if err != nil {
			return err
		}
		fresh = append(fresh, recs...)
		if !ok {
			continue
		}
		pending, err := p.Gateway.PendingRules(ctx, name)
		if err != nil {
			return err
		}
		var props []teamapi.Proposal
		for _, r := range openshell.ParseRules(pending) {
			if r.Chunk == "" {
				continue
			}
			props = append(props, teamapi.Proposal{
				Chunk: r.Chunk, Sandbox: name, Destination: r.Destination(),
				Binary: r.Binary, Rationale: r.Rationale, Prover: r.Prover,
			})
		}
		// Pending requests are read again on every pass, so one the server
		// did not take is reported next time.
		if len(props) > 0 && p.up() {
			if err := p.Client.PutProposals(ctx, p.Token, name, props); err != nil {
				p.failed(name+": requests", err)
			} else {
				p.rep.Requests += len(props)
			}
		}
	}
	if dropped := sp.add(fresh); dropped > 0 {
		p.rep.Dropped += dropped
		p.note(fmt.Sprintf("spool full: %s dropped. The console shows the gap.", records(dropped)))
	}
	if err := sp.save(); err != nil {
		return err
	}
	if err := saveCursors(p.Dirs, cur); err != nil {
		return err
	}
	return p.upload(ctx, sp)
}

// read gets a sandbox's new records from the gateway's log stream when this
// machine can watch it, and from the last logWindow log lines otherwise. ok is
// false when neither could be read; the records then hold a gap.
func (p *pass) read(ctx context.Context, name string, cur *cursorFile) (recs []forward.Record, ok bool, err error) {
	if p.Stream != nil {
		after := cur.Stream[name]
		read, err := p.Stream.ReadStream(ctx, name, after, logWindow)
		if err == nil {
			return p.streamed(read, name, after, cur), true, nil
		}
		if ctx.Err() != nil {
			return nil, false, ctx.Err()
		}
		if !errors.Is(err, openshell.ErrNoStream) {
			p.note(fmt.Sprintf("%s: log stream watch failed, read the last %d log lines instead (%v)", name, logWindow, err))
		}
	}
	raw, err := p.Gateway.LogLines(ctx, name, logWindow)
	if err != nil {
		p.note(name + ": log stream failed, a gap was recorded")
		return []forward.Record{p.gap(name, time.Now().UTC(), err.Error())}, false, nil
	}
	recs, err = p.window(raw, name, cur)
	return recs, err == nil, err
}

// window picks the records of one read of the last logWindow log lines.
func (p *pass) window(raw []byte, name string, cur *cursorFile) ([]forward.Record, error) {
	recs, err := forward.ReadAudit(bytes.NewReader(raw), name)
	if err != nil {
		return nil, err
	}
	lines, oldest, newest := forward.Span(raw)
	out := p.skipped(name, lines, oldest, cur)
	if !newest.IsZero() {
		cur.Last[name] = newest.Format(time.RFC3339Nano)
	}
	return append(out, p.unsent(recs, name, cur)...), nil
}

// streamed picks the records of one stream read. A read that resumed after
// the saved cursor misses nothing unless the gateway says so: a refused cursor
// and a stream warning each leave a gap record. A read without a cursor
// replays the last logWindow lines and is checked like a log window.
func (p *pass) streamed(read openshell.StreamRead, name, after string, cur *cursorFile) []forward.Record {
	var recs []forward.Record
	var oldest, newest time.Time
	for _, l := range read.Lines {
		t := l.Time.UTC()
		if oldest.IsZero() || t.Before(oldest) {
			oldest = t
		}
		if t.After(newest) {
			newest = t
		}
		if r, ok := forward.AuditFromStream(l.Time, l.Level, l.Message, name); ok {
			recs = append(recs, r)
		}
	}
	var out []forward.Record
	switch {
	case read.Reset != "":
		from, ok := stamp(cur.Last[name])
		if !ok {
			from = time.Now().UTC()
		}
		to := "now"
		if !oldest.IsZero() {
			to = oldest.Format(time.RFC3339Nano)
		}
		out = append(out, p.gap(name, from, fmt.Sprintf("the gateway refused the stream cursor (%s); events between %s and %s may be missing",
			read.Reset, from.Format(time.RFC3339Nano), to)))
	case after == "":
		out = append(out, p.skipped(name, len(read.Lines), oldest, cur)...)
	}
	if len(read.Warnings) > 0 {
		out = append(out, p.gap(name, time.Now().UTC(), "log stream warning: "+strings.Join(read.Warnings, "; ")))
	}
	if !newest.IsZero() {
		cur.Last[name] = newest.Format(time.RFC3339Nano)
	}
	if read.Cursor != "" {
		cur.Stream[name] = read.Cursor
	}
	return append(out, p.unsent(recs, name, cur)...)
}

// skipped returns a gap record when a read of the last logWindow lines did
// not reach back to the newest line the last pass read.
//
// When the read is full and its oldest line is newer than that line, the
// lines in between were never read. Exactly logWindow new lines give the same
// picture, so that case is reported as a possible gap too. A read that is not
// full holds the whole log the gateway kept, so it skipped nothing this pass
// could have read.
func (p *pass) skipped(name string, lines int, oldest time.Time, cur *cursorFile) []forward.Record {
	last, ok := stamp(cur.Last[name])
	if !ok || lines < logWindow || !oldest.After(last) {
		return nil
	}
	return []forward.Record{p.gap(name, last, fmt.Sprintf("the last %d log lines start at %s; lines after %s were not read",
		logWindow, oldest.Format(time.RFC3339Nano), last.Format(time.RFC3339Nano)))}
}

// unsent drops records at or before the newest one already sent, labels the
// rest with this machine and revision, and moves the cursor.
func (p *pass) unsent(recs []forward.Record, name string, cur *cursorFile) []forward.Record {
	seen, hasSeen := stamp(cur.Seen[name])
	newest := seen
	var out []forward.Record
	for _, rec := range recs {
		if hasSeen && !rec.Time.After(seen) {
			continue
		}
		rec.Machine = p.Machine
		rec.PolicyRevision = strconv.Itoa(p.Revision)
		out = append(out, rec)
		if rec.Time.After(newest) {
			newest = rec.Time
		}
	}
	if !newest.IsZero() {
		cur.Seen[name] = newest.UTC().Format(time.RFC3339Nano)
	}
	return out
}

func (p *pass) gap(sandbox string, at time.Time, reason string) forward.Record {
	return forward.Record{
		Time: at, Sandbox: sandbox, Machine: p.Machine,
		PolicyRevision: strconv.Itoa(p.Revision), Class: "gap", Action: "Gap",
		Destination: "log stream", Reason: reason, Gap: true,
	}
}

// upload sends the spool oldest first, at most batchLimit records a call. A
// batch leaves the spool only when the server has answered 2xx. A batch the
// server refuses as malformed is dropped so it cannot block the rest.
func (p *pass) upload(ctx context.Context, sp *spool) error {
	for len(sp.recs) > 0 && p.up() {
		n := min(len(sp.recs), batchLimit)
		stored, err := p.Client.Ingest(ctx, p.Token, sp.recs[:n])
		if err != nil {
			switch team.Status(err) {
			case http.StatusBadRequest, http.StatusRequestEntityTooLarge, http.StatusUnprocessableEntity:
				p.note(fmt.Sprintf("the control plane refused %s: %v", records(n), err))
			default:
				p.failed("decisions", err)
				p.rep.Spooled = len(sp.recs)
				return nil
			}
		} else {
			p.rep.Decisions += stored
		}
		sp.recs = sp.recs[n:]
		if err := sp.save(); err != nil {
			return err
		}
	}
	p.rep.Spooled = len(sp.recs)
	return nil
}

func (p *pass) apply(ctx context.Context) error {
	if !p.up() {
		return nil
	}
	opt := p.Option
	rep := &p.rep
	list, err := opt.Client.Applies(ctx, opt.Token)
	if err != nil {
		p.failed("reviews", err)
		return nil
	}
	for _, r := range list {
		var err error
		switch r.Status {
		case "approved":
			err = opt.Gateway.RuleApprove(ctx, r.Sandbox, r.Chunk)
		case "denied":
			reason := r.Reason
			if reason == "" {
				reason = "denied in the console"
			}
			err = opt.Gateway.RuleReject(ctx, r.Sandbox, r.Chunk, reason)
		default:
			continue
		}
		if err != nil {
			if staleProposal(err) {
				if rerr := p.releaseStale(ctx, r); rerr != nil {
					return rerr
				}
				if !p.up() {
					return nil
				}
				continue
			}
			rep.Notes = append(rep.Notes, fmt.Sprintf("%s %s: %v", r.Sandbox, r.Chunk, err))
			continue
		}
		// OpenShell has the review. If the server does not hear that now, it
		// lists the review again and the next pass sends it again.
		if err := opt.Client.MarkApplied(ctx, opt.Token, r.ID); err != nil {
			p.failed(fmt.Sprintf("%s %s", r.Sandbox, r.Chunk), err)
			if !p.up() {
				return nil
			}
			continue
		}
		rep.Applied++
		rep.Notes = append(rep.Notes, fmt.Sprintf("%s %s %s", r.Sandbox, r.Status, r.Destination))
	}
	return nil
}

// staleProposal is OpenShell refusing a chunk because the evaluation was refreshed.
// The recorded message is "proposal inputs changed; evaluation refreshed, refetch and review again".
func staleProposal(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "proposal inputs changed") || strings.Contains(msg, "refetch and review again")
}

// releaseStale puts the request back on the console when the same chunk is still pending,
// and drops it when OpenShell has already replaced the chunk.
func (p *pass) releaseStale(ctx context.Context, r teamapi.Proposal) error {
	opt := p.Option
	fresh, still, err := currentProposal(ctx, opt, r.Sandbox, r.Chunk)
	if err != nil {
		return err
	}
	if err := opt.Client.ReleaseReview(ctx, opt.Token, r.ID, still); err != nil {
		p.failed(fmt.Sprintf("%s %s", r.Sandbox, r.Chunk), err)
		return nil
	}
	if still {
		if err := opt.Client.PutProposals(ctx, opt.Token, r.Sandbox, []teamapi.Proposal{fresh}); err != nil {
			p.failed(r.Sandbox+": requests", err)
			return nil
		}
		p.rep.Notes = append(p.rep.Notes, fmt.Sprintf("%s %s changed since it was reviewed. It is pending again.", r.Sandbox, fresh.Destination))
		return nil
	}
	p.rep.Notes = append(p.rep.Notes, fmt.Sprintf("%s %s changed since it was reviewed. Review the new request.", r.Sandbox, r.Destination))
	return nil
}

func currentProposal(ctx context.Context, opt Option, sandbox, chunk string) (teamapi.Proposal, bool, error) {
	raw, err := opt.Gateway.PendingRules(ctx, sandbox)
	if err != nil {
		return teamapi.Proposal{}, false, err
	}
	for _, p := range openshell.ParseRules(raw) {
		if p.Chunk != chunk {
			continue
		}
		return teamapi.Proposal{
			Chunk: p.Chunk, Sandbox: sandbox, Destination: p.Destination(),
			Binary: p.Binary, Rationale: p.Rationale, Prover: p.Prover,
		}, true, nil
	}
	return teamapi.Proposal{}, false, nil
}

// cursorFile is where each sandbox's log was read up to. Seen is the newest
// record sent, Last the newest line read of any kind; both are RFC 3339
// times. Stream is the gateway's cursor for the log stream.
type cursorFile struct {
	Seen   map[string]string `json:"seen"`
	Last   map[string]string `json:"last,omitempty"`
	Stream map[string]string `json:"stream,omitempty"`
}

// stamp parses a cursor time. Cursors are compared as times: RFC 3339 strings
// with trimmed fractions do not sort.
func stamp(s string) (time.Time, bool) {
	t, err := time.Parse(time.RFC3339Nano, s)
	return t, err == nil
}

func cursorPath(dirs config.Dirs) string { return filepath.Join(dirs.Config, "forward.json") }

func loadCursors(dirs config.Dirs) (cursorFile, error) {
	b, err := os.ReadFile(cursorPath(dirs))
	if os.IsNotExist(err) {
		return cursorFile{Seen: map[string]string{}, Last: map[string]string{}, Stream: map[string]string{}}, nil
	}
	if err != nil {
		return cursorFile{}, err
	}
	var c cursorFile
	err = json.Unmarshal(b, &c)
	if c.Seen == nil {
		c.Seen = map[string]string{}
	}
	if c.Last == nil {
		c.Last = map[string]string{}
	}
	if c.Stream == nil {
		c.Stream = map[string]string{}
	}
	return c, err
}

func saveCursors(dirs config.Dirs, c cursorFile) error {
	if err := os.MkdirAll(dirs.Config, 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(cursorPath(dirs), b, 0o600)
}
