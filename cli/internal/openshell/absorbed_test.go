package openshell

import (
	"context"
	"strings"
	"testing"
)

// Recorded on OpenShell 0.1.4, 25 October 2026, with the sandbox name and
// the first word of the agent's reason changed. Claude Code filed
// example_net_read within a second of the refusal, and the sandbox's draft
// flushed after it took the rule and superseded the agent's chunk
// (policy.local: "superseded by chunk a3516572-..."). The agent's earlier
// example_org_read came after its draft, so the draft was superseded
// instead; c016b2e1 was then refused by a person with fenzi deny.
const absorbedAll = `Network Rules:  (version 5, 5 chunks)

  Chunk: a3516572-6552-4d50-9719-b2140b7068a7
  Status: pending
  Rule: example_net_read
  Binary: /usr/bin/curl
  Confidence: 65%
  Rationale: Allow curl to connect to example.net:443 (HTTPS).
  Prover: prover: no new findings
  Candidate: 424afa010498
  Endpoints: example.net:443 [L7 rest, allow GET /]
  Binaries: /usr/bin/curl

  Chunk: 01c4511d-de0a-413b-a447-87485c33b275
  Status: rejected
  Rule: example_net_read
  Binary: /usr/bin/curl
  Confidence: 75%
  Rationale: Read the example.net home page for a test.
  Prover: prover: no new findings
  Candidate: 424afa010498
  Endpoints: example.net:443 [L7 rest, allow GET /]
  Binaries: /usr/bin/curl

  Chunk: dcc1390a-30fc-4e98-8551-928a2eae112e
  Status: pending
  Rule: example_org_read
  Binary: /usr/bin/curl
  Confidence: 75%
  Rationale: User asked to fetch the example.org homepage with curl (GET /) and show the first 5 lines.
  Prover: prover: no new findings
  Candidate: 12339297329c
  Endpoints: example.org:443 [L7 rest, allow GET /]
  Binaries: /usr/bin/curl

  Chunk: 9c579f86-3171-4005-bb9f-bd743ff2dfe8
  Status: rejected
  Rule: allow_example_org_443
  Binary: /usr/bin/curl
  Confidence: 65%
  Rationale: Allow curl to connect to example.org:443 (HTTPS).
  Prover: prover: no new findings
  Candidate: 70f67764f8d4
  Endpoints: example.org:443 [L4]
  Binaries: /usr/bin/curl

  Chunk: c016b2e1-6dd0-43ea-8684-674ff85be049
  Status: pending
  Rule: allow_downloads_claude_ai_443
  Binary: /usr/local/lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe
  Confidence: 65%
  Rationale: Allow claude.exe to connect to downloads.claude.ai:443 (HTTPS).
  Prover: prover: no new findings
  Candidate: 559cde4251d9
  Endpoints: downloads.claude.ai:443 [L4]
  Binaries: /usr/local/lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe

`

const absorbedPending = `Network Rules:  (version 5, 3 chunks)

  Chunk: a3516572-6552-4d50-9719-b2140b7068a7
  Status: pending
  Rule: example_net_read
  Binary: /usr/bin/curl
  Confidence: 65%
  Rationale: Allow curl to connect to example.net:443 (HTTPS).
  Prover: prover: no new findings
  Candidate: 424afa010498
  Endpoints: example.net:443 [L7 rest, allow GET /]
  Binaries: /usr/bin/curl

  Chunk: dcc1390a-30fc-4e98-8551-928a2eae112e
  Status: pending
  Rule: example_org_read
  Binary: /usr/bin/curl
  Confidence: 75%
  Rationale: User asked to fetch the example.org homepage with curl (GET /) and show the first 5 lines.
  Prover: prover: no new findings
  Candidate: 12339297329c
  Endpoints: example.org:443 [L7 rest, allow GET /]
  Binaries: /usr/bin/curl

  Chunk: c016b2e1-6dd0-43ea-8684-674ff85be049
  Status: pending
  Rule: allow_downloads_claude_ai_443
  Binary: /usr/local/lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe
  Confidence: 65%
  Rationale: Allow claude.exe to connect to downloads.claude.ai:443 (HTTPS).
  Prover: prover: no new findings
  Candidate: 559cde4251d9
  Endpoints: downloads.claude.ai:443 [L4]
  Binaries: /usr/local/lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe

`

const absorbedLog = `[1792938221.934] [sandbox] [OCSF ] [ocsf] CONFIG:PROPOSED [INFO] agent_authored proposal chunk:dcc1390a-30fc-4e98-8551-928a2eae112e on example.org:443 [GET /] by /usr/bin/curl [chunk_id:dcc1390a-30fc-4e98-8551-928a2eae112e]
[1792938297.104] [sandbox] [OCSF ] [ocsf] CONFIG:PROPOSED [INFO] agent_authored proposal chunk:01c4511d-de0a-413b-a447-87485c33b275 on example.net:443 [GET /] by /usr/bin/curl [chunk_id:01c4511d-de0a-413b-a447-87485c33b275]
`

type fakeRules struct {
	out   []byte
	calls int
}

func (f *fakeRules) Rules(context.Context, string) ([]byte, error) {
	f.calls++
	return f.out, nil
}

func TestADraftThatSupersededTheAgentsRequestIsTheAgents(t *testing.T) {
	filed := AgentFiled([]byte(absorbedLog))
	pending := ParseRules([]byte(absorbedPending))
	if len(pending) != 3 || pending[0].Candidate != "424afa010498" {
		t.Fatalf("pending %+v", pending)
	}
	if !pending[0].IsDraft(filed) {
		t.Fatal("before: the merged draft should read as a draft, which is the bug")
	}
	r := &fakeRules{out: []byte(absorbedAll)}
	got := WithAbsorbed(context.Background(), r, "fenzi-proj-7c2e", pending, filed)
	if r.calls != 1 {
		t.Errorf("rule get read %d times", r.calls)
	}
	m := got[0]
	if m.IsDraft(filed) || m.Absorbed != "01c4511d-de0a-413b-a447-87485c33b275" || m.Rationale != "Read the example.net home page for a test." {
		t.Errorf("merged draft %+v", m)
	}
	// The agent's own pending request is unchanged, and the person-refused
	// draft for downloads.claude.ai stays a draft: no agent chunk matches it.
	if got[1].Absorbed != "" || got[1].IsDraft(filed) {
		t.Errorf("agent's request %+v", got[1])
	}
	if got[2].Absorbed != "" || !got[2].IsDraft(filed) {
		t.Errorf("draft %+v", got[2])
	}
	if pending[0].Absorbed != "" {
		t.Error("WithAbsorbed changed its input")
	}
}

// With no agent chunk missing from the pending list, nothing more is read.
func TestWithAbsorbedReadsOnlyWhenItCanMatter(t *testing.T) {
	pending := ParseRules([]byte(absorbedPending))
	r := &fakeRules{out: []byte(absorbedAll)}
	WithAbsorbed(context.Background(), r, "s", pending, nil)
	// Only the agent's pending example_org_read in the log.
	onlyPending := AgentFiled([]byte(strings.SplitN(absorbedLog, "\n", 2)[0]))
	if len(onlyPending) != 1 {
		t.Fatalf("filed %v", onlyPending)
	}
	WithAbsorbed(context.Background(), r, "s", pending, onlyPending)
	if r.calls != 0 {
		t.Errorf("read %d times", r.calls)
	}
}
