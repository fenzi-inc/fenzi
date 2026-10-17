//go:build team

package relay

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"fenzi/agents"
	"fenzi/cli/internal/config"
	"fenzi/compiler"
	"fenzi/controlplane"
	"fenzi/teamapi"
)

// effectiveFor is what the runtime prints for a sandbox running doc, in the
// shape effectiveDefault reproduces: the compiled policy for the claude
// catalog entry without its comment line or trailing newline, plus the
// provider rule.
func effectiveFor(t *testing.T, doc string) []byte {
	t.Helper()
	d, err := compiler.Parse([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	entry, err := agents.Get("claude")
	if err != nil {
		t.Fatal(err)
	}
	p, err := compiler.Compile(d, compiler.Target{Agent: entry.CompilerAgent()})
	if err != nil {
		t.Fatal(err)
	}
	b, err := p.YAML("")
	if err != nil {
		t.Fatal(err)
	}
	return []byte(strings.TrimSuffix(string(b), "\n") + providerClaude)
}

// reported is the fenzi-1 entry of the last heartbeat the server stored.
func reported(t *testing.T, s *controlplane.Service) controlplane.MachineSandbox {
	t.Helper()
	machines, err := s.Machines("acme")
	if err != nil || len(machines) != 1 || len(machines[0].Sandboxes) != 1 {
		t.Fatalf("machines %+v %v", machines, err)
	}
	return machines[0].Sandboxes[0]
}

func TestComparedPolicyMatchesWithTheProviderRule(t *testing.T) {
	s, opt, gw := teamFixture(t)
	gw.effective = effectiveFor(t, hostDoc)
	rep, err := Pass(context.Background(), opt)
	if err != nil {
		t.Fatal(err)
	}
	if gw.effectiveCalls != 1 {
		t.Fatalf("effective policy read %d times", gw.effectiveCalls)
	}
	sb := reported(t, s)
	if sb.Revision != 2 || sb.PolicyCheck != teamapi.PolicyMatch || len(sb.PolicyDiffers) != 0 {
		t.Fatalf("reported %+v", sb)
	}
	for _, n := range rep.Notes {
		if strings.Contains(n, "differs") {
			t.Fatalf("note %q", n)
		}
	}
}

func TestComparedPolicyMismatchIsReported(t *testing.T) {
	s, opt, gw := teamFixture(t)
	// The runtime still holds r1's hosts while the sandbox is recorded on r2.
	gw.effective = effectiveFor(t, baseDoc)
	rep, err := Pass(context.Background(), opt)
	if err != nil {
		t.Fatal(err)
	}
	sb := reported(t, s)
	if sb.Revision != 2 || sb.PolicyCheck != teamapi.PolicyMismatch || !reflect.DeepEqual(sb.PolicyDiffers, []string{"network_policies"}) {
		t.Fatalf("reported %+v", sb)
	}
	notes := strings.Join(rep.Notes, "\n")
	if !strings.Contains(notes, "fenzi-1: the policy the runtime holds differs from r2 in network_policies") {
		t.Fatalf("notes %v", rep.Notes)
	}
	if strings.Contains(notes, "pypi.org") || strings.Contains(notes, "example.com") {
		t.Fatalf("a note printed policy content: %v", rep.Notes)
	}
}

func TestComparePendingLoadIsSkipped(t *testing.T) {
	s, opt, gw := teamFixture(t)
	gw.effective = effectiveFor(t, hostDoc)
	gw.list = []byte("r2 Pending\n")
	if _, err := Pass(context.Background(), opt); err != nil {
		t.Fatal(err)
	}
	if gw.effectiveCalls != 0 {
		t.Fatal("a sandbox whose load is not confirmed Loaded was compared")
	}
	state, err := opt.Dirs.LoadState()
	if err != nil || state.Sandboxes[0].TeamRevision != 2 || state.Sandboxes[0].PendingLoad != 2 {
		t.Fatalf("state %+v %v", state, err)
	}
	if sb := reported(t, s); sb.PolicyCheck != teamapi.PolicyPending || len(sb.PolicyDiffers) != 0 {
		t.Fatalf("reported %+v", sb)
	}

	// policy list still says Pending: nothing is read.
	if _, err := Pass(context.Background(), opt); err != nil {
		t.Fatal(err)
	}
	if gw.effectiveCalls != 0 {
		t.Fatal("compared while the load is still pending")
	}

	// Once policy list says Loaded, the sandbox is compared and the record cleared.
	gw.list = []byte("r2 Loaded\n")
	if _, err := Pass(context.Background(), opt); err != nil {
		t.Fatal(err)
	}
	if gw.effectiveCalls != 1 {
		t.Fatalf("effective policy read %d times", gw.effectiveCalls)
	}
	state, _ = opt.Dirs.LoadState()
	if state.Sandboxes[0].PendingLoad != 0 {
		t.Fatalf("state %+v", state.Sandboxes[0])
	}
	if sb := reported(t, s); sb.PolicyCheck != teamapi.PolicyMatch {
		t.Fatalf("reported %+v", sb)
	}
}

func TestCompareSkipsSandboxesOffTheTeamPolicy(t *testing.T) {
	s, opt, gw := teamFixture(t)
	gw.effective = effectiveFor(t, hostDoc)
	state := &config.State{}
	state.Put(config.Sandbox{Name: "fenzi-1", Agent: "claude", Running: true, Created: time.Now()})
	if err := opt.Dirs.SaveState(state); err != nil {
		t.Fatal(err)
	}
	if _, err := Pass(context.Background(), opt); err != nil {
		t.Fatal(err)
	}
	if gw.effectiveCalls != 0 {
		t.Fatal("a sandbox not started from a team revision was compared")
	}
	if sb := reported(t, s); sb.PolicyCheck != "" {
		t.Fatalf("reported %+v", sb)
	}
}
