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

	"boundlane/cli/internal/config"
	"boundlane/cli/internal/forward"
	"boundlane/cli/internal/openshell"
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
}

type jsonSandbox struct {
	Name  string `json:"name"`
	Agent string `json:"agent"`
	// Folder is the absolute path the sandbox was started for.
	Folder string `json:"folder"`
	// Created is RFC 3339, or empty for a sandbox the runtime reports that
	// Boundlane did not start.
	Created string `json:"created"`
	Running bool   `json:"running"`
}

func sandboxJSON(sb config.Sandbox) jsonSandbox {
	created := ""
	if !sb.Created.IsZero() {
		created = sb.Created.UTC().Format(time.RFC3339)
	}
	return jsonSandbox{Name: sb.Name, Agent: sb.Agent, Folder: sb.Repo, Created: created, Running: sb.Running}
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
}

// jsonAnswer is what approve and deny print: result is approved or denied.
type jsonAnswer struct {
	ID      string `json:"id"`
	Sandbox string `json:"sandbox"`
	Result  string `json:"result"`
	Note    string `json:"note"`
}

type jsonKey struct {
	Name    string `json:"name"`
	Display string `json:"display"`
	KeyEnv  string `json:"key_env"`
	Stored  bool   `json:"stored"`
	// Available is false while the agent's provider profile is not reviewed.
	Available bool `json:"available"`
}

type jsonStatus struct {
	SignedIn       bool     `json:"signed_in"`
	Email          string   `json:"email"`
	Role           string   `json:"role"`
	Team           string   `json:"team"`
	Machine        string   `json:"machine"`
	Server         string   `json:"server"`
	ConsoleURL     string   `json:"console_url"`
	PolicyRevision int      `json:"policy_revision"`
	Notes          []string `json:"notes"`
}

type jsonPolicyCheck struct {
	Passed bool `json:"passed"`
	// Result is the prover's word: within_boundary, exceeds_boundary,
	// error, unsupported, or inconclusive.
	Result string `json:"result"`
	// Checked names the policy sources, and Agent the agent it was compiled for.
	Checked    string   `json:"checked"`
	Agent      string   `json:"agent"`
	Example    string   `json:"example"`
	Reason     string   `json:"reason"`
	NotChecked []string `json:"not_checked"`
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
func followJSON(e env, sandbox, since string, denyOnly bool) error {
	return followRecords(e, sandbox, since, func(r forward.Record) error {
		if denyOnly && !(r.Denied() && !r.Reset()) {
			return nil
		}
		b, err := json.Marshal(r)
		if err != nil {
			return err
		}
		_, err = e.stdout.Write(append(b, '\n'))
		return err
	})
}

// followRecords reads `openshell logs --tail` for a running sandbox and
// passes each network or HTTP decision, mapped to the forwarder's record,
// to emit. Other log lines are skipped. An error from emit, such as a
// closed reader, ends the runtime's command too.
func followRecords(e env, sandbox, since string, emit func(forward.Record) error) error {
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
		r, ok := forward.FromShorthand(sc.Text(), sandbox)
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
