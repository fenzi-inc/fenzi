package run

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"fenzi/agents"
	"fenzi/compiler"
)

// acmeBoundary is a team boundary: wider than developer-default by
// api.stripe.com, which only the boundary lists.
const acmeBoundary = `version: 1
name: acme-boundary
agents: [claude]
workspace: read-write
hosts:
  - host: api.github.com
    access: read-only
  - host: registry.npmjs.org
    access: read-only
  - host: pypi.org
    access: read-only
  - host: files.pythonhosted.org
    access: read-only
  - host: api.stripe.com
    access: read-only
`

// Both proofs a run makes, the compiled policy and the effective one, are
// against the team boundary when the signed bundle carries one.
func TestRunProvesAgainstTheTeamBoundary(t *testing.T) {
	h := setup(t)
	var err error
	h.opts.Policy, err = h.opts.Policy.WithTeamBoundary([]byte(acmeBoundary), "acme", 3)
	if err != nil {
		t.Fatal(err)
	}
	var given []string
	h.prover.Hook = func(args []string) {
		// check <candidate> --boundary <boundary> --output json
		b, err := os.ReadFile(args[3])
		if err != nil {
			t.Errorf("boundary file: %v", err)
		}
		given = append(given, string(b))
	}
	if _, err := Run(context.Background(), h.deps, h.opts); err != nil {
		t.Fatalf("%v\n%s", err, h.out)
	}
	if len(given) != 2 {
		t.Fatalf("prover ran %d times, want 2", len(given))
	}
	for i, b := range given {
		if !strings.Contains(b, "host: api.stripe.com") || !strings.Contains(b, "from the acme boundary in r3 (signed)") {
			t.Errorf("proof %d was not against the team boundary:\n%s", i, b)
		}
	}
	if !strings.Contains(h.out.String(), "the acme boundary in r3 (signed)") {
		t.Errorf("run did not say which boundary it used:\n%s", h.out)
	}
}

func TestRunRefusesAnAgentTheTeamBoundaryDoesNotName(t *testing.T) {
	h := setup(t)
	var err error
	h.opts.Policy, err = h.opts.Policy.WithTeamBoundary([]byte(strings.Replace(acmeBoundary, "[claude]", "[codex]", 1)), "acme", 3)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Run(context.Background(), h.deps, h.opts)
	if !errors.Is(err, compiler.ErrNotInBoundary) {
		t.Fatalf("err %v", err)
	}
	if h.called("sandbox create") || len(h.prover.Calls) != 0 {
		t.Fatal("a sandbox was created, or the prover ran, outside the team boundary")
	}
}

func TestWithTeamBoundary(t *testing.T) {
	base := Resolved{Doc: &compiler.Document{Version: 1}, Sources: "acme r3 (signed)"}
	same, err := base.WithTeamBoundary(nil, "acme", 3)
	if err != nil || same.Boundary != nil || same.BoundarySource != "" {
		t.Fatalf("no boundary: %+v %v", same, err)
	}
	if _, err := base.WithTeamBoundary([]byte("version: 1\nnope: 1\n"), "acme", 3); err == nil || !strings.HasPrefix(err.Error(), "team boundary: ") {
		t.Fatalf("a boundary that does not parse: %v", err)
	}
	if _, err := base.WithTeamBoundary([]byte("version: 1\n"), "acme", 3); err == nil || !strings.Contains(err.Error(), "name the agents") {
		t.Fatalf("a boundary without agents: %v", err)
	}
}

func TestHostInBoundary(t *testing.T) {
	claude, err := agents.Get("claude")
	if err != nil {
		t.Fatal(err)
	}
	free := Resolved{Doc: &compiler.Document{Version: 1}}
	if ok, err := free.HostInBoundary(claude, "paste.example.net:443"); !ok || err != nil {
		t.Fatal("without a team boundary every destination passes")
	}
	team, err := free.WithTeamBoundary([]byte(acmeBoundary), "acme", 3)
	if err != nil {
		t.Fatal(err)
	}
	for dest, want := range map[string]bool{
		"api.stripe.com:443":       true,
		"api.anthropic.com:443":    true, // the model endpoint the provider adds
		"platform.claude.com:443":  true, // a host the agent needs to start
		"paste.example.net:443":    false,
		"api.stripe.com:8443":      false,
		"":                         false,
		"api.stripe.com":           false,
		"files.pythonhosted.org:1": false,
	} {
		if ok, err := team.HostInBoundary(claude, dest); ok != want || err != nil {
			t.Errorf("%q: %v %v, want %v", dest, ok, err, want)
		}
	}
	codex, err := agents.Get("codex")
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := team.HostInBoundary(codex, "api.stripe.com:443"); ok || err != nil {
		t.Errorf("an agent the boundary does not name: %v %v", ok, err)
	}
}
