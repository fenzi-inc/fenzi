package main

// The --json flag. With it a command writes one JSON document to standard
// output and nothing else there; errors still go to standard error with the
// same exit codes. The text output does not change.

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"time"

	"fenzi/cli/internal/config"
	"fenzi/cli/internal/forward"
	"fenzi/cli/internal/openshell"
)

// jsonFlag adds --json to a command.
func jsonFlag(fs *flag.FlagSet) *bool {
	return fs.Bool("json", false, "print the result as JSON, for scripts and other programs")
}

// writeJSON prints one document, indented, with a newline after it.
func writeJSON(w io.Writer, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	_, err = w.Write(append(b, '\n'))
	return err
}

// jsonCheck is one line of doctor: status is ok, fail, or skip.
type jsonCheck struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

type jsonDoctor struct {
	Checks []jsonCheck `json:"checks"`
	Ready  bool        `json:"ready"`
}

type jsonVersion struct {
	Version string `json:"version"`
}

type jsonAgent struct {
	Name    string `json:"name"`
	Display string `json:"display"`
	Version string `json:"version"`
	KeyEnv  string `json:"key_env"`
	Status  string `json:"status"`
	// Available is whether the agent can run: its provider profile is reviewed.
	Available bool `json:"available"`
	// SignIn is whether the agent can start with no key stored and sign in
	// itself, as Claude Code does with a Claude subscription.
	SignIn bool `json:"sign_in"`
}

type jsonSandbox struct {
	Name  string `json:"name"`
	Agent string `json:"agent"`
	// Folder is the absolute path the sandbox was started for.
	Folder string `json:"folder"`
	// Created is RFC 3339, or empty for a sandbox the runtime reports that
	// Fenzi did not start.
	Created string `json:"created"`
	Running bool   `json:"running"`
	// Ended is RFC 3339 too: when fenzi saw the agent exit or stopped the
	// sandbox. Absent while it runs, and for a sandbox that ended some
	// other way.
	Ended string `json:"ended,omitempty"`
	// Lost is a sandbox whose container stopped (phase Error), as when the
	// container runtime restarts. It is not running; fenzi stop starts it
	// again when OpenShell can, or deletes it.
	Lost bool `json:"lost,omitempty"`
	// Applied is a finished sandbox whose changes fenzi apply wrote into
	// the folder: nothing is staged for it any more. fenzi diff says the
	// same as an error, "its changes were applied".
	Applied bool `json:"applied,omitempty"`
	// Git is the folder's repository as recorded when the sandbox started,
	// and where the agent's commits landed; absent when the folder is not a
	// repository.
	Git *jsonGit `json:"git,omitempty"`
}

// jsonGit is config.Git for the Mac app: the branch and commit checked out
// at start, whether the history went into the sandbox, the branch the
// agent's commits landed on, and the commit fenzi apply moved the branch to.
type jsonGit struct {
	Branch    string `json:"branch"`
	Head      string `json:"head"`
	Dirty     bool   `json:"dirty"`
	History   bool   `json:"history"`
	FilesOnly string `json:"files_only,omitempty"`
	// Start is the commit the agent's branch began at: Head, or the start
	// commit built from the uncommitted edits when the folder was dirty.
	// AgentBranch is the branch the agent worked on in the sandbox. The
	// agent's commits are start..landed in the repository.
	Start       string `json:"start,omitempty"`
	AgentBranch string `json:"agent_branch,omitempty"`
	Landed      string `json:"landed,omitempty"`
	Tip         string `json:"tip,omitempty"`
	Commits     int    `json:"commits,omitempty"`
	// Checkpoint is whether the last commit holds what the agent left
	// uncommitted.
	Checkpoint bool   `json:"checkpoint,omitempty"`
	Merged     string `json:"merged,omitempty"`
}

func sandboxJSON(sb config.Sandbox) jsonSandbox {
	created := ""
	if !sb.Created.IsZero() {
		created = sb.Created.UTC().Format(time.RFC3339)
	}
	ended := ""
	if !sb.Ended.IsZero() {
		ended = sb.Ended.UTC().Format(time.RFC3339)
	}
	j := jsonSandbox{Name: sb.Name, Agent: sb.Agent, Folder: sb.Repo, Created: created, Ended: ended, Running: sb.Running}
	if g := sb.Git; g != nil {
		j.Git = &jsonGit{Branch: g.Branch, Head: g.Head, Dirty: g.Dirty, History: g.History, FilesOnly: g.FilesOnly, Start: g.Start, AgentBranch: g.AgentBranch, Landed: g.Landed, Tip: g.Tip, Commits: g.Commits, Checkpoint: g.Checkpoint, Merged: g.Merged}
	}
	return j
}

type jsonRequest struct {
	// ID is the full chunk id; the text output shows its first 8 characters.
	ID          string `json:"id"`
	Destination string `json:"destination"`
	Binary      string `json:"binary"`
	Rationale   string `json:"rationale"`
	// Draft is a proposal the sandbox wrote from a refused connection, not
	// one the agent asked for.
	Draft bool `json:"draft"`
	// Rule is the name the runtime gave the rule an approval adds.
	Rule string `json:"rule,omitempty"`
	// Endpoints is the runtime's own endpoints line, as `rule get` prints
	// it: "github.com:443 [L4]" or "www.example.com:443 [L7 rest, allow GET /]".
	Endpoints string `json:"endpoints,omitempty"`
	// Access is what approving opens, in the org document's terms:
	// read-only or read-write. Empty for a shape that has not been
	// recorded, and for an MCP request.
	Access string `json:"access,omitempty"`
	// Allow is the rule's "METHOD /path" line when it names one, for any
	// method: what approving lets through.
	Allow []string `json:"allow,omitempty"`
	// L4 means the rule names no method or path: approving lets any
	// traffic through to the host and port.
	L4 bool `json:"l4,omitempty"`
	// MCP means the request is for an MCP server, which fenzi approve
	// refuses: OpenShell would approve it as every tool on that server.
	MCP bool `json:"mcp,omitempty"`
}

// requestJSON is one pending request with what approving it opens.
func requestJSON(p openshell.Proposal, draft bool) jsonRequest {
	a := p.RequestedAccess()
	var allow []string
	if line := p.AllowLine(); line != "" {
		allow = []string{line}
	}
	return jsonRequest{
		ID: p.Chunk, Destination: p.Destination(), Binary: p.Binary, Rationale: p.Rationale, Draft: draft,
		Rule: p.Rule, Endpoints: p.Endpoints, Access: a.Access, Allow: allow, L4: a.L4, MCP: p.MCP(),
	}
}

// jsonDecision is one record of `log --json`: the forwarder's record, and
// for a deny the reason in plain words when it is one the CLI knows.
type jsonDecision struct {
	forward.Record
	Explained string `json:"explained,omitempty"`
}

func decisionJSON(r forward.Record) jsonDecision {
	return jsonDecision{Record: r, Explained: r.Explained()}
}

// jsonAnswer is what approve and deny print: result is approved or denied.
type jsonAnswer struct {
	ID      string `json:"id"`
	Sandbox string `json:"sandbox"`
	Result  string `json:"result"`
	Note    string `json:"note"`
	// SameKind is the host rule an approval added to the running sandbox,
	// so calls of the same kind pass without another request.
	SameKind     string   `json:"same_kind,omitempty"`
	AlsoApproved []string `json:"also_approved,omitempty"`
	Skipped      string   `json:"same_kind_skipped,omitempty"`
}

type jsonKey struct {
	Name    string `json:"name"`
	Display string `json:"display"`
	KeyEnv  string `json:"key_env"`
	Stored  bool   `json:"stored"`
	// Available is false while the agent's provider profile is not reviewed.
	Available bool `json:"available"`
	// SignIn: with no key stored, the agent signs in itself when it starts.
	SignIn bool `json:"sign_in"`
}

type jsonStatus struct {
	SignedIn       bool   `json:"signed_in"`
	Email          string `json:"email"`
	Role           string `json:"role"`
	Team           string `json:"team"`
	Machine        string `json:"machine"`
	Server         string `json:"server"`
	ConsoleURL     string `json:"console_url"`
	PolicyRevision int    `json:"policy_revision"`
	// PolicyPublished is when the revision this machine holds was published,
	// RFC 3339, from the signed bundle. Empty with no revision. The bundle
	// does not carry who published it; the console shows that.
	PolicyPublished string   `json:"policy_published,omitempty"`
	Notes           []string `json:"notes"`
	// Forwarder is the background forwarder. Only on a signed-in machine.
	Forwarder *jsonForwarder `json:"forwarder,omitempty"`
}

type jsonForwarder struct {
	// Installed means the background forwarder is installed: a launchd agent
	// or a systemd user unit. Running means it has a live process.
	Installed bool `json:"installed"`
	Running   bool `json:"running"`
	// Manager is "launchd agent" or "systemd user unit", empty elsewhere.
	Manager string `json:"manager"`
	// Detail is the service manager's word when it is not running.
	Detail string `json:"detail"`
	// ForwardingNow names the forwarder that runs now ("the background
	// forwarder", "fenzi forward", "fenzi run"), empty when none does.
	ForwardingNow string `json:"forwarding_now"`
}

type jsonPolicyCheck struct {
	Passed bool `json:"passed"`
	// Result is the prover's word: within_boundary, exceeds_boundary,
	// error, unsupported, or inconclusive.
	Result string `json:"result"`
	// Checked names the policy sources, and Agent the agent it was compiled for.
	Checked string `json:"checked"`
	// Boundary names the team boundary the policy was proved against. It is
	// absent when the boundary was derived from the same policy.
	Boundary   string   `json:"boundary,omitempty"`
	Agent      string   `json:"agent"`
	Example    string   `json:"example"`
	Reason     string   `json:"reason"`
	NotChecked []string `json:"not_checked"`
	// Policy is the compiled policy as a person reads it: the workspace,
	// the paths, the hosts, the model API and the MCP servers the agent
	// gets. Absent only when the compile itself failed.
	Policy *jsonPolicyView `json:"policy,omitempty"`
}

type jsonUpdate struct {
	Current   string `json:"current"`
	Latest    string `json:"latest"`
	Available bool   `json:"available"`
	// Installed is the path the new release was written to, after an install.
	Installed string `json:"installed,omitempty"`
}

// followJSON is log --follow with --json: the running sandbox's decisions,
// one JSON object per line. Other log lines are not printed.
func followJSON(e env, sandbox, since string, denyOnly, requests bool) error {
	return followRecords(e, sandbox, since, requests, func(r forward.Record) error {
		if denyOnly && !(r.Denied() && !r.Reset()) {
			return nil
		}
		b, err := json.Marshal(decisionJSON(r))
		if err != nil {
			return err
		}
		_, err = e.stdout.Write(append(b, '\n'))
		return err
	})
}

// followRecords reads `openshell logs --tail` for a running sandbox and
// passes each network or HTTP decision, mapped to the forwarder's record,
// to emit; with requests, the requests the agent filed and the approvals
// too. Other log lines are skipped. An error from emit, such as a closed
// reader, ends the runtime's command too.
func followRecords(e env, sandbox, since string, requests bool, emit func(forward.Record) error) error {
	from := forward.FromShorthand
	if requests {
		from = forward.EventFromShorthand
	}
	ctx, cancel := context.WithCancel(e.ctx)
	defer cancel()
	pr, pw := io.Pipe()
	c := openshell.Client{R: openshell.Exec{Bin: "openshell", Stdout: pw, Stderr: e.stderr}}
	done := make(chan error, 1)
	go func() {
		err := c.Logs(ctx, sandbox, since, true)
		pw.Close()
		done <- err
	}()
	sc := bufio.NewScanner(pr)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		r, ok := from(sc.Text(), sandbox)
		if !ok {
			continue
		}
		if err := emit(r); err != nil {
			// The reader is gone; stop the runtime's command too.
			cancel()
			pr.Close()
			<-done
			return err
		}
	}
	if err := sc.Err(); err != nil {
		// A line longer than the buffer stops the scanner while the runtime
		// is still writing; unblock its write and end it, then say why.
		cancel()
		pr.Close()
		<-done
		return fmt.Errorf("reading the sandbox log: %w", err)
	}
	return <-done
}
