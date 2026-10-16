//go:build team

package relay

import (
	"context"
	"os"
	"strings"
	"testing"

	"fenzi/cli/internal/openshell"
)

// acmeBoundary is wider than hostDoc by api.stripe.com and lists no
// paste.example.net.
const acmeBoundary = `version: 1
name: acme-boundary
agents: [claude]
workspace: read-write
hosts:
  - host: example.com
    access: read-only
  - host: pypi.org
    access: read-only
  - host: api.stripe.com
    access: read-only
`

func TestPushIsProvedAgainstTheBundleBoundary(t *testing.T) {
	_, opt, gw := teamFixture(t)
	opt.Tenant = "acme"
	opt.Boundary = []byte(acmeBoundary)
	var given string
	f := &openshell.Fake{Replies: map[string]openshell.Reply{"check": {Out: proverPass}}}
	f.Hook = func(args []string) {
		// check <candidate> --boundary <boundary> --output json
		b, err := os.ReadFile(args[3])
		if err != nil {
			t.Error(err)
		}
		given = string(b)
	}
	opt.Prover = openshell.Prover{R: f}
	if _, err := Pass(context.Background(), opt); err != nil {
		t.Fatal(err)
	}
	if !gw.set {
		t.Fatal("not loaded")
	}
	if !strings.Contains(given, "host: api.stripe.com") || !strings.Contains(given, "from the acme boundary in r2 (signed)") {
		t.Fatalf("proved against:\n%s", given)
	}
}

func TestPushForAnAgentOutsideTheBoundaryLoadsNothing(t *testing.T) {
	_, opt, gw := teamFixture(t)
	opt.Boundary = []byte(strings.Replace(acmeBoundary, "[claude]", "[codex]", 1))
	rep, err := Pass(context.Background(), opt)
	if err != nil {
		t.Fatal(err)
	}
	if gw.set {
		t.Fatal("loaded for an agent the boundary does not name")
	}
	if !strings.Contains(strings.Join(rep.Notes, "\n"), "bl-1: r2 not loaded, the team boundary does not name this agent: claude. It keeps r1.") {
		t.Fatalf("notes %q", rep.Notes)
	}
}

// A console approval for a host the team boundary does not list is not
// applied on this machine; one the boundary lists is.
func TestConsoleApprovalOutsideTheBoundaryIsNotApplied(t *testing.T) {
	s, opt, gw := teamFixture(t)
	opt.Tenant = "acme"
	opt.Boundary = []byte(acmeBoundary)
	if _, err := Pass(context.Background(), opt); err != nil {
		t.Fatal(err)
	}
	pending, err := s.Proposals("acme", "pending")
	if err != nil || len(pending) != 1 {
		t.Fatalf("pending %+v %v", pending, err)
	}
	if err := s.Review(pending[0].ID, "dana@acme.dev", "approved", ""); err != nil {
		t.Fatal(err)
	}
	rep, err := Pass(context.Background(), opt)
	if err != nil {
		t.Fatal(err)
	}
	if gw.approveCalls != 0 || rep.Applied != 0 {
		t.Fatalf("applied outside the boundary: calls %d report %+v", gw.approveCalls, rep)
	}
	if !strings.Contains(strings.Join(rep.Notes, "\n"), "bl-1 abcdef not approved here: paste.example.net:443 is outside the acme boundary in r2 (signed)") {
		t.Fatalf("notes %q", rep.Notes)
	}

	opt.Boundary = []byte(acmeBoundary + "  - host: paste.example.net\n    access: read-only\n")
	rep, err = Pass(context.Background(), opt)
	if err != nil {
		t.Fatal(err)
	}
	if gw.approveCalls != 1 || gw.approved != "abcdef" || rep.Applied != 1 {
		t.Fatalf("calls %d report %+v", gw.approveCalls, rep)
	}
}
