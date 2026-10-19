package run

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"fenzi/cli/internal/config"
	"fenzi/cli/internal/forward"
	"fenzi/cli/internal/openshell"
	"fenzi/cli/internal/workspace"
)

// Headless is an unattended run, fenzi run --headless: the agent's own
// non-interactive mode on one task, with nobody at the terminal, ended at
// a time limit. Its commits come back as a branch through the history
// round trip; nothing is applied to the checkout.
type Headless struct {
	Task string
	// Timeout bounds the whole run, from the start of Run. Zero: none.
	Timeout time.Duration
	// RequestTimeout is how long a request the agent files waits for an
	// answer before Fenzi refuses it, so the agent stops waiting and goes
	// on without the access. Zero: until the run ends. Nothing is ever
	// approved without a person.
	RequestTimeout time.Duration
	// PollEvery is how often pending requests are read; requestPoll when
	// zero.
	PollEvery time.Duration
}

// requestPoll is how often an unattended run reads the pending requests,
// the same as fenzi forward's pass.
const requestPoll = 5 * time.Second

// Outcomes of an unattended run, first match wins: the time limit, then a
// request nobody answered, then the agent's exit status.
const (
	OutcomeFinished   = "finished"
	OutcomeFailed     = "agent failed"
	OutcomeTimedOut   = "timed out"
	OutcomeUnanswered = "request unanswered"
)

// Exit statuses of fenzi run --headless. 1 to 3 are fenzi's own: an
// error, a refused policy, a gateway that is not ready.
const (
	ExitAgentFailed = 4
	ExitTimedOut    = 5
	ExitUnanswered  = 6
)

// Answers to a request the agent filed during an unattended run.
const (
	AnswerApproved = "approved"
	AnswerRejected = "rejected"
	// AnswerExpired: no answer within RequestTimeout; Fenzi refused it.
	AnswerExpired = "no answer, refused"
	// AnswerPending: still waiting when the run ended.
	AnswerPending = "no answer when the run ended"
)

// Summary is what an unattended run did, for its exit status, the job
// summary and the artifact.
type Summary struct {
	Agent        string    `json:"agent"`
	Sandbox      string    `json:"sandbox"`
	Policy       string    `json:"policy"`
	Revision     string    `json:"revision"`
	TeamRevision int       `json:"team_revision,omitempty"`
	Outcome      string    `json:"outcome"`
	ExitStatus   int       `json:"exit_status"`
	AgentExit    *int      `json:"agent_exit,omitempty"`
	Started      time.Time `json:"started"`
	Ended        time.Time `json:"ended"`
	Timeout      string    `json:"timeout,omitempty"`
	// Refused are the calls the policy denied, one entry per program and
	// destination.
	Refused  []RefusedCall `json:"refused"`
	Requests []Request     `json:"requests"`
	// Branch is set when the agent's commits came back.
	Branch *Branch `json:"branch,omitempty"`
	// FilesOnly says why there is no branch, for a folder whose history
	// did not go in or come back.
	FilesOnly string `json:"files_only,omitempty"`
	// Changes is how many files differ in the staged copy.
	Changes int `json:"changes"`
	// Bundle is the file in the output folder that holds Branch's
	// commits, written by WriteOut.
	Bundle string `json:"bundle,omitempty"`
	// Kept is set when the sandbox was kept at the end (--keep).
	Kept bool `json:"kept,omitempty"`
}

type RefusedCall struct {
	Process     string    `json:"process,omitempty"`
	Destination string    `json:"destination"`
	Reason      string    `json:"reason,omitempty"`
	Count       int       `json:"count"`
	First       time.Time `json:"first"`
}

type Request struct {
	Chunk       string    `json:"chunk"`
	Destination string    `json:"destination,omitempty"`
	Process     string    `json:"process,omitempty"`
	Answer      string    `json:"answer"`
	Seen        time.Time `json:"seen"`
}

type Branch struct {
	Name       string `json:"name"`
	Start      string `json:"start"`
	Tip        string `json:"tip"`
	Commits    int    `json:"commits"`
	Checkpoint bool   `json:"checkpoint,omitempty"`
}

// TimeoutError means the time limit came before the agent started, so
// nothing ran.
type TimeoutError struct {
	Limit time.Duration
	Err   error
}

func (e *TimeoutError) Error() string {
	return fmt.Sprintf("the %s time limit passed before the agent started: %v", e.Limit, e.Err)
}
func (e *TimeoutError) Unwrap() error { return e.Err }

// The notes to the agent for an unattended run, added after the guide.
const (
	unattendedTeam = "This run is unattended: nobody is at the terminal. A person on the team reviews requests in the team console. %s If a request is refused, finish what you can without the access, and say in your last message which host you needed and why. Commit your work on the current branch before you finish."
	unattendedFree = "This run is unattended and nobody reviews requests, so a request you file is never approved. Do not file one. Finish what you can without the access, and say in your last message which host you needed and why. Commit your work on the current branch before you finish."
)

func requestWait(h *Headless) string {
	if h.RequestTimeout > 0 {
		return fmt.Sprintf("Each request waits at most %s for an answer; with none it is refused.", h.RequestTimeout)
	}
	return "A request waits for an answer until the run's time limit."
}

// sayRequests tells the person reading the job log who answers requests.
func sayRequests(say func(label, format string, args ...any), team bool, h *Headless) {
	switch {
	case !team:
		say("requests", "nobody answers them on Free; a request the agent files stays refused and fails the run")
	case h.RequestTimeout > 0:
		say("requests", "sent to the team console; each waits %s for a reviewer, then stays refused", h.RequestTimeout)
	default:
		say("requests", "sent to the team console; each waits for a reviewer until the time limit")
	}
}

// requestWatch reads the sandbox's pending requests while the agent runs.
// It refuses a request the agent filed once it has waited RequestTimeout,
// with a reason the agent reads, and never approves one. Drafts the
// supervisor made from refused connections are not requests and are left
// alone; the refused calls are in the log.
type requestWatch struct {
	d       Deps
	sandbox string
	wait    time.Duration
	mu      sync.Mutex
	seen    map[string]*Request
	order   []string
	pending map[string]bool
}

func newRequestWatch(d Deps, sandbox string, wait time.Duration) *requestWatch {
	return &requestWatch{d: d, sandbox: sandbox, wait: wait, seen: map[string]*Request{}, pending: map[string]bool{}}
}

// expiredReason is what the agent reads when its request waited too long.
func expiredReason(wait time.Duration) string {
	return fmt.Sprintf("No answer within %s. This run is unattended, so the call stays refused. Continue without this access.", wait)
}

// pass reads the pending requests once. With refuse, a request that has
// waited too long is refused.
func (w *requestWatch) pass(ctx context.Context, refuse bool) {
	out, err := w.d.OpenShell.PendingRules(ctx, w.sandbox)
	if err != nil {
		return
	}
	var list []openshell.Proposal
	if !openshell.NoRules(out) {
		list = openshell.ParseRules(out)
	}
	var filed map[string]bool
	if len(list) > 0 {
		if log, err := w.d.OpenShell.LogLines(ctx, w.sandbox, openshell.RequestLogWindow); err == nil {
			filed = openshell.AgentFiled(log)
		}
	}
	now := w.d.Now()
	w.mu.Lock()
	defer w.mu.Unlock()
	w.pending = map[string]bool{}
	for _, p := range list {
		if p.IsDraft(filed) {
			continue
		}
		r, ok := w.seen[p.Chunk]
		if !ok {
			r = &Request{Chunk: p.Chunk, Destination: p.Destination(), Process: p.Binary, Seen: now}
			w.seen[p.Chunk] = r
			w.order = append(w.order, p.Chunk)
		}
		if r.Answer != "" {
			continue
		}
		w.pending[p.Chunk] = true
		if refuse && w.wait > 0 && now.Sub(r.Seen) >= w.wait {
			if err := w.d.OpenShell.RuleReject(ctx, w.sandbox, p.Chunk, expiredReason(w.wait)); err == nil {
				r.Answer = AnswerExpired
				delete(w.pending, p.Chunk)
			}
		}
	}
}

// loop runs passes until ctx ends.
func (w *requestWatch) loop(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		w.pass(ctx, true)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// requests answers each request: refused by Fenzi, still pending, or, from
// the log, approved; one that left the pending list with no approval in
// the log was rejected by a reviewer. Requests the log shows the agent
// filed that no pass saw are added too.
func (w *requestWatch) requests(log []forward.Record) []Request {
	w.mu.Lock()
	defer w.mu.Unlock()
	approved := map[string]bool{}
	for _, r := range log {
		if !r.Config() {
			continue
		}
		switch r.Action {
		case "Approved":
			approved[r.Chunk] = true
		case "Requested":
			if _, ok := w.seen[r.Chunk]; !ok && r.Chunk != "" {
				w.seen[r.Chunk] = &Request{Chunk: r.Chunk, Destination: r.Destination, Process: r.Process, Seen: r.Time}
				w.order = append(w.order, r.Chunk)
			}
		}
	}
	out := []Request{}
	for _, id := range w.order {
		r := *w.seen[id]
		switch {
		case r.Answer != "":
		case approved[id]:
			r.Answer = AnswerApproved
		case w.pending[id]:
			r.Answer = AnswerPending
		default:
			r.Answer = AnswerRejected
		}
		out = append(out, r)
	}
	return out
}

// refusedCalls groups the log's denies by program, destination and
// reason, in the order they first happened. A reset after a policy change
// is not a refusal.
func refusedCalls(log []forward.Record) []RefusedCall {
	out := []RefusedCall{}
	at := map[string]int{}
	for _, r := range log {
		if r.Config() || !r.Denied() || r.Reset() {
			continue
		}
		key := r.Process + "\x00" + r.What() + "\x00" + r.Reason
		if i, ok := at[key]; ok {
			out[i].Count++
			continue
		}
		at[key] = len(out)
		out = append(out, RefusedCall{Process: r.Process, Destination: r.What(), Reason: r.Reason, Count: 1, First: r.Time})
	}
	return out
}

// outcome picks the run's outcome and exit status.
func (s *Summary) settle(timedOut bool) {
	unanswered := false
	for _, r := range s.Requests {
		if r.Answer == AnswerExpired || r.Answer == AnswerPending {
			unanswered = true
		}
	}
	switch {
	case timedOut:
		s.Outcome, s.ExitStatus = OutcomeTimedOut, ExitTimedOut
	case unanswered:
		s.Outcome, s.ExitStatus = OutcomeUnanswered, ExitUnanswered
	case s.AgentExit != nil && *s.AgentExit != 0:
		s.Outcome, s.ExitStatus = OutcomeFailed, ExitAgentFailed
	default:
		s.Outcome, s.ExitStatus = OutcomeFinished, 0
	}
}

// summarize builds the summary once the log is saved and the commits are
// back.
func summarize(s *Summary, logRaw []byte, w *requestWatch, g *config.Git, changes []workspace.Change, timedOut bool) {
	events, _ := forward.ReadEvents(strings.NewReader(string(logRaw)), s.Sandbox)
	s.Refused = refusedCalls(events)
	s.Requests = w.requests(events)
	s.Changes = len(changes)
	switch {
	case g == nil:
		s.FilesOnly = "the folder is not a git repository"
	case !g.History:
		s.FilesOnly = g.FilesOnly
	case g.Landed != "":
		s.Branch = &Branch{Name: g.Landed, Start: g.Start, Tip: g.Tip, Commits: g.Commits, Checkpoint: g.Checkpoint}
	}
	s.settle(timedOut)
}

// sayHeadless prints the summary at the end of the run's output.
func sayHeadless(say func(label, format string, args ...any), s *Summary) {
	switch s.Outcome {
	case OutcomeTimedOut:
		say("result", "%s after %s, exit %d", s.Outcome, s.Timeout, s.ExitStatus)
	case OutcomeFailed:
		say("result", "%s with status %d, exit %d", s.Outcome, *s.AgentExit, s.ExitStatus)
	default:
		say("result", "%s, exit %d", s.Outcome, s.ExitStatus)
	}
	if len(s.Refused) == 0 {
		say("refused", "none")
	} else {
		say("refused", "%s", plural(len(s.Refused), "call"))
		for i, r := range s.Refused {
			if i == shownSecrets {
				say("", "  and %d more, fenzi log --deny", len(s.Refused)-shownSecrets)
				break
			}
			say("", "  %s", r.line())
		}
	}
	for _, r := range s.Requests {
		say("request", "%s by %s: %s", dash(r.Destination), dash(filepath.Base(r.Process)), r.Answer)
	}
	if s.Branch == nil && s.FilesOnly != "" {
		say("branch", "none: %s", s.FilesOnly)
	}
}

func (r RefusedCall) line() string {
	l := r.Destination
	if r.Process != "" {
		l = filepath.Base(r.Process) + " to " + l
	}
	if r.Reason != "" {
		l += ": " + r.Reason
	}
	if r.Count > 1 {
		l += fmt.Sprintf(" (%d times)", r.Count)
	}
	return l
}

func dash(s string) string {
	if s == "" || s == "." {
		return "-"
	}
	return s
}

// Files WriteOut puts in the output folder.
const (
	SummaryJSON   = "summary.json"
	SummaryMD     = "summary.md"
	BranchBundle  = "branch.bundle"
	refusedInJobs = 20
)

// WriteOut writes the summary as JSON and Markdown into dir, and the
// branch's commits as a git bundle, for a CI job to keep. repo is the
// checkout the branch landed in.
func WriteOut(dir, repo string, s *Summary) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if s.Branch != nil {
		if err := workspace.BundleBranch(repo, s.Branch.Name, s.Branch.Start, filepath.Join(dir, BranchBundle)); err != nil {
			return fmt.Errorf("writing the branch's bundle: %w", err)
		}
		s.Bundle = BranchBundle
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, SummaryJSON), append(b, '\n'), 0o644); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, SummaryMD), []byte(s.Markdown()), 0o644)
}

// Markdown is the summary for a CI job's summary page.
func (s *Summary) Markdown() string {
	var b strings.Builder
	fmt.Fprintf(&b, "### fenzi run: %s %s\n\n", s.Agent, s.Outcome)
	b.WriteString("| | |\n| --- | --- |\n")
	row := func(k, v string) { fmt.Fprintf(&b, "| %s | %s |\n", k, md(v)) }
	switch {
	case s.AgentExit != nil:
		row("Result", fmt.Sprintf("%s, agent status %d, exit %d", s.Outcome, *s.AgentExit, s.ExitStatus))
	default:
		row("Result", fmt.Sprintf("%s, exit %d", s.Outcome, s.ExitStatus))
	}
	row("Policy", s.Policy+", "+s.Revision)
	took := s.Ended.Sub(s.Started).Round(time.Second).String()
	if s.Timeout != "" {
		took += " of " + s.Timeout
	}
	row("Time", took)
	if s.Kept {
		row("Sandbox", s.Sandbox+", kept")
	} else {
		row("Sandbox", s.Sandbox+", deleted at the end")
	}
	switch {
	case s.Branch != nil:
		v := fmt.Sprintf("`%s`, %s since %s, tip %s", s.Branch.Name, plural(s.Branch.Commits, "commit"), shortSHA(s.Branch.Start), shortSHA(s.Branch.Tip))
		if s.Bundle != "" {
			v += ", in " + s.Bundle
		}
		fmt.Fprintf(&b, "| Branch | %s |\n", v)
	case s.FilesOnly != "":
		row("Branch", "none: "+s.FilesOnly)
	}
	row("Changed files", fmt.Sprint(s.Changes))

	fmt.Fprintf(&b, "\n#### Refused calls: %d\n\n", len(s.Refused))
	if len(s.Refused) > 0 {
		b.WriteString("| Program | Destination | Reason | Times |\n| --- | --- | --- | --- |\n")
		for i, r := range s.Refused {
			if i == refusedInJobs {
				fmt.Fprintf(&b, "\nAnd %d more in %s.\n", len(s.Refused)-refusedInJobs, SummaryJSON)
				break
			}
			fmt.Fprintf(&b, "| %s | %s | %s | %d |\n", md(dash(r.Process)), md(r.Destination), md(dash(r.Reason)), r.Count)
		}
	}
	fmt.Fprintf(&b, "\n#### Requests: %d\n\n", len(s.Requests))
	if len(s.Requests) > 0 {
		b.WriteString("| Destination | Program | Answer |\n| --- | --- | --- |\n")
		for _, r := range s.Requests {
			fmt.Fprintf(&b, "| %s | %s | %s |\n", md(dash(r.Destination)), md(dash(r.Process)), md(r.Answer))
		}
	}
	if s.Branch != nil && s.Bundle != "" {
		fmt.Fprintf(&b, "\nTo fetch the branch from the artifact:\n\n```\ngit fetch %s %s:%s\n```\n", s.Bundle, s.Branch.Name, s.Branch.Name)
	}
	return b.String()
}

// md keeps a value inside one Markdown table cell.
func md(s string) string {
	s = strings.ReplaceAll(s, "|", `\|`)
	return strings.Join(strings.Fields(s), " ")
}

// errHeadlessKey is why an unattended run needs a key: signing in takes
// a person at a browser.
func errHeadlessKey(name, env string) error {
	return fmt.Errorf("an unattended run needs a key for %s: export %s for this run (in CI, from a secret), or run fenzi key set %s. Signing in takes a person at a browser", name, env, name)
}

// timedOut reports whether ctx ended at its deadline.
func timedOut(ctx context.Context) bool {
	return errors.Is(ctx.Err(), context.DeadlineExceeded)
}
