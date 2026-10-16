package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"fenzi/cli/internal/config"
	"fenzi/cli/internal/team"
	"fenzi/teamapi"
)

// acmeBoundary is the team's boundary. It lists api.stripe.com, which the
// team policy does not, and not github.com.
const acmeBoundary = `version: 1
name: acme-boundary
agents: [claude]
workspace: read-write
hosts:
  - host: api.stripe.com
    access: read-only
`

func signedWithBoundary(key ed25519.PrivateKey, rev int, boundary string) teamapi.Bundle {
	b := teamapi.Bundle{
		Tenant: "acme", Revision: rev, Format: teamapi.FormatBoundary,
		Document: []byte(teamDoc), Boundary: []byte(boundary),
		Published: time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC),
	}
	b.Signature = ed25519.Sign(key, teamapi.Message(b))
	return b
}

// enrollWithBoundary signs this test's config folder in to a console that
// serves r3 with the team boundary, and caches r3.
func enrollWithBoundary(t *testing.T, boundary string) {
	t.Helper()
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	b := signedWithBoundary(key, 3, boundary)
	srv := httptest.NewServer(&refusingConsole{bundle: teamapi.ToWire(b)})
	t.Cleanup(srv.Close)
	dirs, err := config.Default()
	if err != nil {
		t.Fatal(err)
	}
	en := team.Enrollment{
		Server: srv.URL, Token: "tok", Email: "dana@acme.dev", Tenant: "acme", Machine: "mbp",
		PublicKey: base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey)),
	}
	if err := en.Take(b); err != nil {
		t.Fatal(err)
	}
	if err := en.Save(dirs); err != nil {
		t.Fatal(err)
	}
}

// boundaryProver puts an openshell-prover on PATH that passes and keeps a
// copy of the boundary file it was given. It returns that copy's path.
func boundaryProver(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	seen := filepath.Join(dir, "boundary-seen.yaml")
	reply := filepath.Join(dir, "prover.json")
	if err := os.WriteFile(reply, []byte(proverWithin), 0o600); err != nil {
		t.Fatal(err)
	}
	// check <candidate> --boundary <boundary> --output json
	script := "#!/bin/sh\ncat \"$4\" > '" + seen + "'\ncat '" + reply + "'\n"
	if err := os.WriteFile(filepath.Join(dir, "openshell-prover"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return seen
}

func readSeen(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("the prover was not run: %v", err)
	}
	return string(b)
}

// The policy fenzi run uses on a signed-in machine is proved against the
// boundary in the same signed bundle, and so is an org file checked there.
func TestPolicyCheckUsesTheTeamBoundary(t *testing.T) {
	fakeRuntime(t, nil, "")
	enrollWithBoundary(t, acmeBoundary)
	seen := boundaryProver(t)
	t.Chdir(t.TempDir())

	var doc jsonPolicyCheck
	if stderr, code := runJSON(t, &doc, "policy", "check", "--json"); code != 0 {
		t.Fatalf("exit %d stderr %q", code, stderr)
	}
	if doc.Checked != "acme r3 (signed)" || doc.Boundary != "the acme boundary in r3 (signed)" {
		t.Errorf("check = %+v", doc)
	}
	if b := readSeen(t, seen); !strings.Contains(b, "host: api.stripe.com") || !strings.Contains(b, "host: api.anthropic.com") {
		t.Errorf("not proved against the team boundary:\n%s", b)
	}

	org := filepath.Join(t.TempDir(), "draft.yaml")
	draft := teamDoc + "hosts:\n  - host: paste.example.net\n    access: read-only\n"
	if err := os.WriteFile(org, []byte(draft), 0o600); err != nil {
		t.Fatal(err)
	}
	out, code := runCLI(t, "", "policy", "check", "--org", org)
	if code != 0 || !strings.Contains(out, "Proved against the acme boundary in r3 (signed).") {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	if b := readSeen(t, seen); strings.Contains(b, "paste.example.net") || !strings.Contains(b, "api.stripe.com") {
		t.Errorf("a draft was proved against a boundary derived from itself:\n%s", b)
	}

	out, code = runCLI(t, "", "policy", "compile", "--org", org, "--emit", "boundary")
	if code != 0 || !strings.Contains(out, "from the acme boundary in r3 (signed)") || strings.Contains(out, "paste.example.net") {
		t.Fatalf("compile --emit boundary: exit %d:\n%s", code, out)
	}

	// A boundary file given on the command line replaces the team's.
	mine := filepath.Join(t.TempDir(), "mine.yaml")
	if err := os.WriteFile(mine, []byte("# mine\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var given jsonPolicyCheck
	if stderr, code := runJSON(t, &given, "policy", "check", "--org", org, "--boundary", mine, "--json"); code != 0 || given.Boundary != "" {
		t.Fatalf("exit %d stderr %q check %+v", code, stderr, given)
	}
	if b := readSeen(t, seen); b != "# mine\n" {
		t.Errorf("--boundary was not used:\n%s", b)
	}
}

// resolvePolicy is what fenzi run uses to pick its policy: on a
// signed-in machine it carries the boundary from the signed bundle, which run
// then proves both the compiled and the effective policy against.
func TestRunResolvesTheBundleBoundary(t *testing.T) {
	fakeRuntime(t, nil, "")
	enrollWithBoundary(t, acmeBoundary)
	dirs, err := config.Default()
	if err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	res, err := resolvePolicy(env{ctx: t.Context(), stdin: strings.NewReader(""), stdout: &out, stderr: &out}, dirs, t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	if res.TeamRevision != 3 || res.Boundary == nil || res.BoundarySource != "the acme boundary in r3 (signed)" || res.Boundary.Hosts[0].Host != "api.stripe.com" {
		t.Fatalf("resolved %+v", res)
	}
}

// On a machine that is not signed in, nothing changes: the boundary is
// derived from the policy, and the check names none.
func TestPolicyCheckOnFreeHasNoTeamBoundary(t *testing.T) {
	fakeRuntime(t, nil, "")
	seen := boundaryProver(t)
	t.Chdir(t.TempDir())
	var doc jsonPolicyCheck
	if stderr, code := runJSON(t, &doc, "policy", "check", "--json"); code != 0 || doc.Boundary != "" {
		t.Fatalf("exit %d stderr %q check %+v", code, stderr, doc)
	}
	if b := readSeen(t, seen); !strings.Contains(b, "from developer-default (built in)") {
		t.Errorf("boundary:\n%s", b)
	}
}

// Approving a request for a host the team boundary does not list is refused
// before OpenShell is asked. A listed host is approved as before.
func TestApproveChecksTheTeamBoundary(t *testing.T) {
	fakeRuntime(t, map[string]reply{"rule get": {out: mixedRules}}, proverWithin)
	seedState(t, config.Sandbox{Name: "bl-web-1a2b", Agent: "claude", Repo: t.TempDir(), Created: time.Now(), Running: true})
	enrollWithBoundary(t, acmeBoundary)

	out, code := runCLI(t, "", "approve", "59b83e6d", "--sandbox", "bl-web-1a2b")
	if code != 1 || !strings.Contains(out, "github.com:443 is outside the acme boundary in r3 (signed)") {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	for _, c := range runtimeCalls(t) {
		if strings.HasPrefix(c, "rule approve") {
			t.Fatalf("approved outside the boundary: %s", c)
		}
	}

	enrollWithBoundary(t, acmeBoundary+"  - host: github.com\n    access: read-only\n")
	if out, code := runCLI(t, "", "approve", "59b83e6d", "--sandbox", "bl-web-1a2b"); code != 0 {
		t.Fatalf("a listed host: exit %d:\n%s", code, out)
	}
	approved := false
	for _, c := range runtimeCalls(t) {
		approved = approved || strings.HasPrefix(c, "rule approve bl-web-1a2b --chunk-id 59b83e6d")
	}
	if !approved {
		t.Fatalf("not approved: %v", runtimeCalls(t))
	}
}
