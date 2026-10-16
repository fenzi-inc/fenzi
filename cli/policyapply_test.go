package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"fenzi/cli/internal/config"
	"fenzi/cli/internal/run"
	"fenzi/cli/internal/team"
)

// policyList is what the fake runtime answers to policy list. OpenShell 0.1.2
// showed a new revision Pending and then Loaded there; the full text was not
// recorded, and Fenzi reads only those two words, as sync does.
const policyList = "Loaded\n"

// applyFixture is a Free-plan machine with one sandbox running from a
// project folder, started with the folder's policy as it was then.
func applyFixture(t *testing.T, prover string) (repo string, dirs config.Dirs) {
	t.Helper()
	fakeRuntime(t, map[string]reply{
		"sandbox list": {out: "bl-web-1a2b\n"},
		"policy list":  {out: policyList},
	}, prover)
	repo = t.TempDir()
	t.Chdir(repo)
	dirs = seedState(t, config.Sandbox{Name: "bl-web-1a2b", Agent: "claude", Repo: repo, Revision: "local-00000000", Created: time.Now(), Running: true})
	started, err := run.ResolveFree(repo, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := run.SaveResolved(dirs.Run("bl-web-1a2b"), started.Doc); err != nil {
		t.Fatal(err)
	}
	return repo, dirs
}

func writeProject(t *testing.T, repo, doc string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(repo, run.ProjectFile), []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
}

func called(t *testing.T, prefix string) bool {
	t.Helper()
	for _, c := range runtimeCalls(t) {
		if strings.HasPrefix(c, prefix) {
			return true
		}
	}
	return false
}

func TestPolicyApplyLoadsAHostChange(t *testing.T) {
	repo, dirs := applyFixture(t, proverWithin)
	writeProject(t, repo, "version: 1\nhosts:\n  - host: api.example.org\n    access: read-only\n")
	out, code := runCLI(t, "", "policy", "apply")
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	if !called(t, "policy set bl-web-1a2b --policy ") || !called(t, "policy list bl-web-1a2b") {
		t.Fatalf("calls %q", runtimeCalls(t))
	}
	for _, c := range runtimeCalls(t) {
		if strings.HasPrefix(c, "policy set") && !strings.HasSuffix(c, " --wait") {
			t.Errorf("policy set without --wait: %s", c)
		}
	}
	if !strings.Contains(out, "bl-web-1a2b") || !strings.Contains(out, "hosts loaded") || !strings.Contains(out, "Applies to running agents.") {
		t.Fatalf("output:\n%s", out)
	}
	saved, err := run.LoadResolved(dirs.Run("bl-web-1a2b"))
	if err != nil || len(saved.Hosts) == 0 || saved.Hosts[len(saved.Hosts)-1].Host != "api.example.org" {
		t.Fatalf("saved %+v err %v", saved, err)
	}
	pol, err := os.ReadFile(filepath.Join(dirs.Run("bl-web-1a2b"), "policy.yaml"))
	if err != nil || !strings.Contains(string(pol), "api.example.org") {
		t.Fatalf("run folder policy: %v\n%s", err, pol)
	}
	s, _ := dirs.LoadState()
	if sb, _ := s.Find("bl-web-1a2b"); sb.Revision == "local-00000000" || !strings.HasPrefix(sb.Revision, "local-") {
		t.Fatalf("state revision %q", sb.Revision)
	}

	// The same file again changes nothing.
	before := len(runtimeCalls(t))
	out, code = runCLI(t, "", "policy", "apply")
	if code != 0 || !strings.Contains(out, "already runs this policy") {
		t.Fatalf("exit %d\n%s", code, out)
	}
	for _, c := range runtimeCalls(t)[before:] {
		if strings.HasPrefix(c, "policy set") {
			t.Fatalf("loaded again: %s", c)
		}
	}
}

func TestPolicyApplyLeavesAPathChangeForTheNextRun(t *testing.T) {
	repo, dirs := applyFixture(t, proverWithin)
	writeProject(t, repo, "version: 1\npaths:\n  read_only: [/opt/data]\nhosts:\n  - host: api.example.org\n    access: read-only\n")
	out, code := runCLI(t, "", "policy", "apply")
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	if called(t, "policy set") {
		t.Fatalf("a path change was loaded onto a running sandbox: %q", runtimeCalls(t))
	}
	if !strings.Contains(out, "Takes effect on the next run. Running agents keep the old paths.") || !strings.Contains(strings.Join(strings.Fields(out), " "), "fenzi stop bl-web-1a2b") {
		t.Fatalf("output:\n%s", out)
	}
	saved, err := run.LoadResolved(dirs.Run("bl-web-1a2b"))
	if err != nil || len(saved.Paths.ReadOnly) > 0 && saved.Paths.ReadOnly[len(saved.Paths.ReadOnly)-1] == "/opt/data" {
		t.Fatalf("the saved policy changed: %+v %v", saved, err)
	}
}

func TestPolicyApplyIsProvedFirst(t *testing.T) {
	exceeds := strings.Replace(proverWithin, `"result":"within_boundary"`, `"result":"exceeds_boundary"`, 1)
	repo, _ := applyFixture(t, exceeds)
	writeProject(t, repo, "version: 1\nhosts:\n  - host: api.example.org\n    access: read-only\n")
	out, code := runCLI(t, "", "policy", "apply")
	if code != 2 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	if called(t, "policy set") {
		t.Fatal("a change the prover refused was loaded")
	}
	if !strings.Contains(out, "not changed, the policy check returned exceeds_boundary") {
		t.Fatalf("output:\n%s", out)
	}
}

func TestPolicyApplyWithoutASavedPolicy(t *testing.T) {
	repo, dirs := applyFixture(t, proverWithin)
	os.Remove(filepath.Join(dirs.Run("bl-web-1a2b"), run.ResolvedFile))
	writeProject(t, repo, "version: 1\nhosts:\n  - host: api.example.org\n    access: read-only\n")
	out, code := runCLI(t, "", "policy", "apply")
	if code != 0 || called(t, "policy set") || !strings.Contains(out, "started before Fenzi saved the policy it runs") {
		t.Fatalf("exit %d\n%s", code, out)
	}
}

func TestPolicyApplyOnASignedInMachine(t *testing.T) {
	_, dirs := applyFixture(t, proverWithin)
	if err := (team.Enrollment{Server: "http://127.0.0.1:1", Token: "tok", Tenant: "acme"}).Save(dirs); err != nil {
		t.Fatal(err)
	}
	out, code := runCLI(t, "", "policy", "apply")
	if code != 1 || !strings.Contains(out, "its policy comes from the console") {
		t.Fatalf("exit %d\n%s", code, out)
	}
	if called(t, "policy set") {
		t.Fatal("loaded on a signed-in machine")
	}
}
