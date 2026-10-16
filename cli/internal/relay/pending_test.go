package relay

import (
	"context"
	"testing"
)

// Output of `rule get <name> --status pending`, OpenShell 0.1.2, recorded 16
// October 2026 on a Claude Code sandbox after its requests were approved on
// the machine. The sandbox name is replaced with bl-1.
const noPending = "No network rules for sandbox 'bl-1'\n"

// A block recorded from `rule get` on the same sandbox, 16 October 2026: the
// request the agent filed through policy.local. It was listed as approved
// by then; Status is set back to pending, as it read before the approval.
const onePending = `Network Rules:  (version 2, 1 chunks)

  Chunk: aea27fd2-2745-484c-8470-de07913e70d9
  Status: pending
  Rule: fenzi_dev
  Binary: /usr/bin/curl
  Confidence: 75%
  Rationale: Curl to fenzi.dev to fetch content
  Prover: prover: no new findings
  Candidate: 62770fa70661
  Endpoints: fenzi.dev:443 [L7 rest, allow GET /**]
  Binaries: /usr/bin/curl
`

func TestTheFullPendingListIsSentWithItsRuleNames(t *testing.T) {
	gw := &fakeGW{rules: []byte(onePending)}
	f, opt := fakeFixture(t, gw)
	rep, err := Pass(context.Background(), opt)
	if err != nil {
		t.Fatal(err)
	}
	got := f.lists["bl-1"]
	if f.puts != 1 || len(got) != 1 || rep.Requests != 1 {
		t.Fatalf("puts %d lists %+v report %+v", f.puts, f.lists, rep)
	}
	if got[0].Chunk != "aea27fd2-2745-484c-8470-de07913e70d9" || got[0].Rule != "fenzi_dev" || got[0].Destination != "fenzi.dev:443" {
		t.Fatalf("request %+v", got[0])
	}
}

func TestAnEmptyPendingListIsSent(t *testing.T) {
	gw := &fakeGW{rules: []byte(noPending), listed: []string{"bl-1", "bl-2"}}
	f, opt := fakeFixture(t, gw)
	if _, err := Pass(context.Background(), opt); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"bl-1", "bl-2"} {
		list, ok := f.lists[name]
		if !ok || len(list) != 0 {
			t.Errorf("%s: an empty list must be sent, got %+v (sent %v)", name, list, ok)
		}
	}
}

func TestUnreadablePendingOutputIsNotSentAsAFullList(t *testing.T) {
	// Not a recording: output in a shape no 0.1.2 run printed.
	gw := &fakeGW{rules: []byte(`{"chunks":[]}`)}
	f, opt := fakeFixture(t, gw)
	if _, err := Pass(context.Background(), opt); err != nil {
		t.Fatal(err)
	}
	if f.puts != 0 || len(f.proposals) != 0 {
		t.Fatalf("puts %d proposals %+v", f.puts, f.proposals)
	}
}

func TestAnOlderConsoleGetsTheOlderReport(t *testing.T) {
	gw := &fakeGW{rules: []byte(onePending), listed: []string{"bl-1", "bl-2"}}
	f, opt := fakeFixture(t, gw)
	f.old = true
	rep, err := Pass(context.Background(), opt)
	if err != nil {
		t.Fatal(err)
	}
	if f.puts != 1 {
		t.Fatalf("the full list is tried once a pass, got %d", f.puts)
	}
	if len(f.proposals) != 2 || rep.Requests != 2 || len(rep.Notes) != 0 {
		t.Fatalf("proposals %+v report %+v", f.proposals, rep)
	}
	for _, p := range f.proposals {
		if p.Rule != "" {
			t.Fatalf("the older report must leave out the rule name: %+v", p)
		}
	}

	f.proposals = nil
	gw.rules = []byte(noPending)
	if _, err := Pass(context.Background(), opt); err != nil {
		t.Fatal(err)
	}
	if len(f.proposals) != 0 {
		t.Fatalf("an empty list has no older report: %+v", f.proposals)
	}
}
