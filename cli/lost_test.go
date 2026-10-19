package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"fenzi/cli/internal/config"
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
