package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"fenzi/cli/internal/config"
	"fenzi/cli/internal/run"
	"fenzi/cli/internal/team"
)

// sameHostRules is mixedRules with a second request for www.example.com: the
// supervisor's draft for another program, in the shape recorded from
// OpenShell 0.1.2 for drafts.
const sameHostRules = mixedRules + `
  Chunk: 4f1c2d3e-5a6b-4c7d-8e9f-0a1b2c3d4e5f
  Status: pending
  Rule: allow_www_example_com_443
  Binary: /usr/bin/wget
  Confidence: 65%
  Rationale: Allow wget to connect to www.example.com:443 (HTTPS).
  Endpoints: www.example.com:443 [L4]
`

// agentSameHostRules is sameHostRules with both www.example.com requests
// made by the agent's own program, which a host rule covers.
var agentSameHostRules = strings.NewReplacer(
	"Binary: /usr/bin/curl", "Binary: /usr/local/lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe",
	"Binary: /usr/bin/wget", "Binary: /usr/local/lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe",
).Replace(sameHostRules)

// sameKindFixture is applyFixture with the requests above pending.
func sameKindFixture(t *testing.T) config.Dirs { return sameKindFixtureWith(t, agentSameHostRules) }

func sameKindFixtureWith(t *testing.T, rules string) config.Dirs {
	t.Helper()
	fakeRuntime(t, map[string]reply{
		"sandbox list": {out: "fenzi-web-1a2b\n"},
		"policy list":  {out: policyList},
		"rule get":     {out: rules},
	}, proverWithin)
	repo := t.TempDir()
	t.Chdir(repo)
	dirs := seedState(t, config.Sandbox{Name: "fenzi-web-1a2b", Agent: "claude", Repo: repo, Revision: "local-00000000", Created: time.Now(), Running: true})
	started, err := run.ResolveFree(repo, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := run.SaveResolved(dirs.Run("fenzi-web-1a2b"), started.Doc); err != nil {
		t.Fatal(err)
	}
	return dirs
}

func TestApproveLoadsTheHostForTheRestOfTheSandbox(t *testing.T) {
	dirs := sameKindFixture(t)
	out, code := runCLI(t, "", "approve", "ccd96a39", "--sandbox", "fenzi-web-1a2b")
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	flat := strings.Join(strings.Fields(out), " ")
	if !strings.Contains(flat, "Calls of the same kind to www.example.com:443 pass for the rest of this sandbox: read-only.") ||
		!strings.Contains(flat, "Also approved 1 other pending request(s)") {
		t.Fatalf("output:\n%s", out)
	}
	if !called(t, "rule approve fenzi-web-1a2b --chunk-id ccd96a39-17bd-4710-af49-c88725b0540f") ||
		!called(t, "policy set fenzi-web-1a2b --policy ") ||
		!called(t, "rule approve fenzi-web-1a2b --chunk-id 4f1c2d3e-5a6b-4c7d-8e9f-0a1b2c3d4e5f") {
		t.Fatalf("calls %q", runtimeCalls(t))
	}
	if called(t, "rule approve fenzi-web-1a2b --chunk-id 59b83e6d") {
		t.Fatal("a request for another host was approved")
	}
	hosts, err := run.LoadApproved(dirs.Run("fenzi-web-1a2b"))
	if err != nil || len(hosts) != 1 || hosts[0].Host != "www.example.com" || hosts[0].Access != "read-only" {
		t.Fatalf("approved %+v err %v", hosts, err)
	}
	saved, _ := run.LoadResolved(dirs.Run("fenzi-web-1a2b"))
	if saved.Hosts[len(saved.Hosts)-1].Host != "www.example.com" {
		t.Fatalf("running policy %+v", saved.Hosts)
	}

	// policy apply loads fenzi.yaml and keeps what was approved here.
	out, code = runCLI(t, "", "policy", "apply")
	if code != 0 {
		t.Fatalf("apply exit %d\n%s", code, out)
	}
	saved, _ = run.LoadResolved(dirs.Run("fenzi-web-1a2b"))
	found := false
	for _, h := range saved.Hosts {
		found = found || h.Host == "www.example.com"
	}
	if !found {
		t.Fatalf("policy apply dropped the approval: %+v", saved.Hosts)
	}
}

func TestApproveJSONSaysWhatItLoaded(t *testing.T) {
	_ = sameKindFixture(t)
	var doc jsonAnswer
	stdout, code := runCLI(t, "", "approve", "ccd96a39", "--sandbox", "fenzi-web-1a2b", "--json")
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, stdout)
	}
	if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
		t.Fatalf("%v\n%s", err, stdout)
	}
	if doc.SameKind != "read-only" || len(doc.AlsoApproved) != 1 || !strings.Contains(doc.Note, "Calls of the same kind") {
		t.Fatalf("%+v", doc)
	}
}

func TestApproveOnATeamMachineStaysAsAsked(t *testing.T) {
	dirs := sameKindFixture(t)
	if err := (team.Enrollment{Server: "http://127.0.0.1:1", Token: "tok", Tenant: "acme"}).Save(dirs); err != nil {
		t.Fatal(err)
	}
	out, code := runCLI(t, "", "approve", "ccd96a39", "--sandbox", "fenzi-web-1a2b")
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	if called(t, "policy set") || strings.Contains(out, "same kind") {
		t.Fatalf("widened on a team machine:\n%s\n%q", out, runtimeCalls(t))
	}
}

// A request from another program than the agent's stays as asked: a host
// rule for the agent's program would replace it and refuse that program.
func TestApproveForAnotherProgramStaysAsAsked(t *testing.T) {
	_ = sameKindFixtureWith(t, sameHostRules)
	out, code := runCLI(t, "", "approve", "ccd96a39", "--sandbox", "fenzi-web-1a2b")
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	flat := strings.Join(strings.Fields(out), " ")
	if called(t, "policy set") || strings.Contains(flat, "Calls of the same kind") || !strings.Contains(flat, "it is for curl") {
		t.Fatalf("widened a curl request:\n%s\n%q", out, runtimeCalls(t))
	}
}
