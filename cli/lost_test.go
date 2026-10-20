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
	"fenzi/cli/internal/run"
	"fenzi/cli/internal/tui"
)

// Recorded from OpenShell 0.1.2 on 17 October 2026: the container runtime
// restarted under a running sandbox, which stayed listed in phase Error, and
// `sandbox start` refused it.
const (
	lostList    = "NAME                 CREATED              PHASE\nfenzi-rs-brain-8a52  2026-10-17 19:20:02  Error\n"
	lostStart   = "Error:   × code: 'The system is not in a state required for the operation's\n  │ execution', message: \"sandbox must be Stopped, Completed, or a failed\n  │ main-process Error to start (current phase: Error)\"\n"
	lostSandbox = "fenzi-rs-brain-8a52"
)

func lostFixture(t *testing.T, extra map[string]reply) config.Dirs {
	t.Helper()
	replies := map[string]reply{
		"sandbox list --selector fenzi=1": {out: lostList},
		"sandbox start":                   {out: lostStart, exit: 1},
	}
	for k, v := range extra {
		replies[k] = v
	}
	fakeRuntime(t, replies, "")
	return seedState(t, config.Sandbox{Name: lostSandbox, Agent: "claude", Repo: "/Users/ana/rs-brain", Created: time.Now(), Running: true})
}

func TestPsShowsALostSandbox(t *testing.T) {
	lostFixture(t, nil)
	var list []jsonSandbox
	if stderr, code := runJSON(t, &list, "ps", "--json"); code != 0 {
		t.Fatalf("exit %d %s", code, stderr)
	}
	if len(list) != 1 || list[0].Running || !list[0].Lost {
		t.Fatalf("%+v", list)
	}
	out, _ := runCLI(t, "", "ps")
	if !strings.Contains(out, "stopped") || !strings.Contains(out, "fenzi stop <sandbox>") {
		t.Errorf("ps:\n%s", out)
	}
}

// Stop asks OpenShell to start the sandbox again; when it refuses, the
// sandbox is deleted only on a yes, with its log saved first.
func TestStopALostSandbox(t *testing.T) {
	startPoll = 0
	lostFixture(t, nil)
	out, code := runCLI(t, "n\n", "stop", lostSandbox)
	if code != 0 || !strings.Contains(out, "Not started") || !strings.Contains(out, "Kept") {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	for _, c := range runtimeCalls(t) {
		if strings.HasPrefix(c, "sandbox delete") || strings.HasPrefix(c, "sandbox download") {
			t.Fatalf("kept means untouched: %s", c)
		}
	}
	out, code = runCLI(t, "", "stop", lostSandbox, "--yes")
	if code != 0 || !strings.Contains(out, "deleted") || !strings.Contains(out, "not copied") {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	deleted := false
	for _, c := range runtimeCalls(t) {
		deleted = deleted || c == "sandbox delete "+lostSandbox
		if strings.HasPrefix(c, "sandbox download") {
			t.Errorf("no download from a lost sandbox: %s", c)
		}
	}
	if !deleted {
		t.Errorf("not deleted: %v", runtimeCalls(t))
	}
}

func TestRmALostSandbox(t *testing.T) {
	dirs := lostFixture(t, nil)
	var doc jsonRm
	if stderr, code := runJSON(t, &doc, "rm", lostSandbox, "--json"); code != 0 {
		t.Fatalf("exit %d %s", code, stderr)
	}
	if len(doc.Removed) != 1 || !doc.Removed[0].Lost || len(doc.Refused) != 0 {
		b, _ := json.Marshal(doc)
		t.Fatalf("%s", b)
	}
	deleted := false
	for _, c := range runtimeCalls(t) {
		deleted = deleted || c == "sandbox delete "+lostSandbox
	}
	if !deleted || len(names(t, dirs)) != 0 {
		t.Errorf("deleted %v, records %v", deleted, names(t, dirs))
	}
}

func TestConnectExplainsALostSandbox(t *testing.T) {
	lostFixture(t, nil)
	out, code := runCLI(t, "", "connect", lostSandbox)
	if code != 1 || !strings.Contains(out, "its container stopped") || !strings.Contains(out, "fenzi rm "+lostSandbox) || strings.Contains(out, "Still running") {
		t.Fatalf("exit %d\n%s", code, out)
	}
	for _, c := range runtimeCalls(t) {
		if strings.HasPrefix(c, "sandbox exec") {
			t.Errorf("connect ran %q on a stopped sandbox", c)
		}
	}
}

// The sandbox stops between the list and the exec, or during the session.
// The exec's refusal is what OpenShell 0.1.4 printed on 19 October 2026 for
// a sandbox the gateway could not start again after it restarted.
func TestConnectSaysWhenTheSandboxStoppedDuringTheSession(t *testing.T) {
	lostFixture(t, map[string]reply{
		"sandbox exec": {out: "Error:   × sandbox '" + lostSandbox + "' is not ready (phase: Error); wait for it to reach Ready state\n", exit: 1},
	})
	var out bytes.Buffer
	e := env{ctx: t.Context(), stdin: strings.NewReader(""), stdout: &out, stderr: &out}
	sb := config.Sandbox{Name: lostSandbox, Agent: "claude", Repo: t.TempDir(), Created: time.Now(), Running: true}
	code, err := connectTo(e, tui.New(strings.NewReader(""), &out), sb, nil, false, true)
	if err != nil || code != 1 || !strings.Contains(out.String(), "its container stopped") || strings.Contains(out.String(), "Still running") {
		t.Fatalf("exit %d, err %v\n%s", code, err, out.String())
	}
}

// ps --json marks a finished sandbox whose changes were applied, from the
// same record fenzi diff reads.
func TestPsMarksAnAppliedSandbox(t *testing.T) {
	dirs := lostFixture(t, map[string]reply{"sandbox list --selector fenzi=1": {out: "No sandboxes found.\n"}})
	staging := dirs.Staging(lostSandbox)
	if err := os.MkdirAll(staging, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(staging, run.AppliedMark), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	var list []jsonSandbox
	if stderr, code := runJSON(t, &list, "ps", "--all", "--json"); code != 0 {
		t.Fatalf("exit %d %s", code, stderr)
	}
	if len(list) != 1 || !list[0].Applied || list[0].Running {
		t.Fatalf("list = %+v", list)
	}
	// A copy staged again (a later stop) is not applied.
	if err := os.MkdirAll(filepath.Join(staging, "files"), 0o755); err != nil {
		t.Fatal(err)
	}
	if appliedFor(dirs, lostSandbox) {
		t.Error("a staged copy counts as applied")
	}
}
