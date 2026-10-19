package openshell

import "testing"

// Recorded from OpenShell 0.1.2.
const recordedRules = `Network Rules:  (version 1, 3 chunks)

  Chunk: df10f171-e5d2-41f0-b4f5-b58fa89ca326
  Status: pending
  Rule: allow_registry_npmjs_org_443
  Binary: /usr/bin/curl
  Confidence: 65%
  Rationale: Allow curl to connect to registry.npmjs.org:443 (HTTPS).
  Prover: prover: no new findings
  Candidate: e2a7b62f4862
  Endpoints: registry.npmjs.org:443 [L7 rest, access=read-only]
  Binaries: /usr/bin/curl

  Chunk: 2e2d858b-ea43-497e-929e-8de6af591ebf
  Status: pending
  Rule: allow_paste_example_net_443
  Binary: /usr/bin/curl
  Confidence: 65%
  Rationale: Allow curl to connect to paste.example.net:443 (HTTPS).
  Prover: prover: no new findings
  Candidate: 417f842edd56
  Endpoints: paste.example.net:443 [L4]
  Binaries: /usr/bin/curl

  Chunk: 2e9a1375-7b44-41f2-aaa7-76f322324db7
  Status: pending
  Rule: allow_api_github_com_443
  Binary: /usr/bin/curl
  Endpoints: api.github.com:443 [L7 rest, access=read-only]
  Hits: 2 (first seen 2026-10-03 20:24:45, last seen 2026-10-03 20:24:45)
`

func TestParseRules(t *testing.T) {
	list := ParseRules([]byte(recordedRules))
	if len(list) != 3 {
		t.Fatalf("got %d proposals", len(list))
	}
	p := list[1]
	if p.Chunk != "2e2d858b-ea43-497e-929e-8de6af591ebf" || p.Status != "pending" || p.Binary != "/usr/bin/curl" ||
		p.Destination() != "paste.example.net:443" || p.Prover != "no new findings" || p.Rule != "allow_paste_example_net_443" {
		t.Errorf("proposal = %+v", p)
	}
	if list[2].Hits == "" {
		t.Error("hits not read")
	}
	if ParseRules([]byte("No network rules for sandbox 'x'\n")) != nil {
		t.Error("empty output must give no proposals")
	}
}

// Recorded from OpenShell 0.1.2: a request a Claude Code session filed
// through policy.local, then drafts the supervisor made from refusals. The
// host the agent asked for is replaced with example.com.
const recordedMixed = `  Chunk: ccd96a39-17bd-4710-af49-c88725b0540f
  Status: pending
  Rule: example_home_read
  Binary: /usr/bin/curl
  Confidence: 75%
  Rationale: User asked to see what is on the example.com homepage. Need a single read-only GET of the homepage with curl.
  Prover: prover: no new findings
  Candidate: 4dea2e771f03
  Endpoints: www.example.com:443 [L7 rest, allow GET /]
  Binaries: /usr/bin/curl

  Chunk: 59b83e6d-8a8a-43e4-a597-066a5d16fc36
  Status: pending
  Rule: allow_github_com_443
  Binary: /usr/lib/git-core/git-remote-http
  Confidence: 65%
  Rationale: Allow git-remote-http to connect to github.com:443 (HTTPS).
  Prover: prover: no new findings
  Candidate: 1fd6084bd0f7
  Endpoints: github.com:443 [L4]
  Binaries: /usr/lib/git-core/git-remote-http

  Chunk: 7682170e-0b75-4850-9a03-f5c98a3713be
  Status: pending
  Rule: allow_downloads_claude_ai_443
  Binary: /usr/local/lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe
  Confidence: 65%
  Rationale: Allow claude.exe to connect to downloads.claude.ai:443 (HTTPS).
  Prover: prover: no new findings
  Candidate: a6239bd33512
  Endpoints: downloads.claude.ai:443 [L4]
  Binaries: /usr/local/lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe
`

func TestDrafted(t *testing.T) {
	list := ParseRules([]byte(recordedMixed))
	if len(list) != 3 {
		t.Fatalf("got %d proposals", len(list))
	}
	if list[0].Drafted() {
		t.Error("the agent's own request was taken for a draft")
	}
	for _, p := range list[1:] {
		if !p.Drafted() {
			t.Errorf("%s: a supervisor draft was taken for the agent's request", p.Rule)
		}
	}
	for _, p := range ParseRules([]byte(recordedRules)) {
		if !p.Drafted() {
			t.Errorf("%s: the first recording's drafts must read as drafts", p.Rule)
		}
	}
}

func TestAgentFiled(t *testing.T) {
	// Recorded from a Codex session on OpenShell 0.1.2; the host is replaced.
	log := []byte(`[1791297763.974] [sandbox] [INFO ] [openshell_supervisor] Flushed denial analysis to gateway proposals=1 sandbox_name=fenzi-mouse-keepe-a3a6 summaries=1
[1791297778.239] [sandbox] [OCSF ] [ocsf] CONFIG:PROPOSED [INFO] agent_authored proposal chunk:fad7c2ed-3aca-4fb7-bb37-495820dd7562 on example.com:443 HEAD / by /usr/bin/curl
[1791297802.289] [sandbox] [OCSF ] [ocsf] CONFIG:APPROVED [INFO] chunk:fad7c2ed-3aca-4fb7-bb37-495820dd7562 approved on example.com:443 HEAD / by /usr/bin/curl
`)
	ids := AgentFiled(log)
	if len(ids) != 1 || !ids["fad7c2ed-3aca-4fb7-bb37-495820dd7562"] {
		t.Errorf("ids = %v", ids)
	}
}

func TestResolveChunk(t *testing.T) {
	list := ParseRules([]byte(recordedRules))
	if id, err := ResolveChunk(list, "df10"); err != nil || id != "df10f171-e5d2-41f0-b4f5-b58fa89ca326" {
		t.Errorf("df10 -> %q, %v", id, err)
	}
	if _, err := ResolveChunk(list, "2e"); err == nil {
		t.Error("an ambiguous prefix must fail")
	}
	if _, err := ResolveChunk(list, "ffff"); err == nil {
		t.Error("an unknown prefix must fail")
	}
}

func TestRequestedAccess(t *testing.T) {
	byHost := map[string]RequestAccess{}
	for _, p := range append(ParseRules([]byte(recordedRules)), ParseRules([]byte(recordedMixed))...) {
		byHost[p.Destination()] = p.RequestedAccess()
	}
	for host, want := range map[string]RequestAccess{
		"registry.npmjs.org:443":  {Access: AccessReadOnly},
		"api.github.com:443":      {Access: AccessReadOnly},
		"paste.example.net:443":   {Access: AccessReadOnly, L4: true},
		"github.com:443":          {Access: AccessReadOnly, L4: true},
		"downloads.claude.ai:443": {Access: AccessReadOnly, L4: true},
		"www.example.com:443":     {Access: AccessReadOnly},
	} {
		got, ok := byHost[host]
		if !ok || got.Access != want.Access || got.L4 != want.L4 || got.Allow != nil {
			t.Errorf("%s: %+v, want %+v", host, got, want)
		}
	}
	// The recorded allow shape with HEAD, then with a write method.
	if got := (Proposal{Endpoints: "example.com:443 [L7 rest, allow HEAD /]"}).RequestedAccess(); got.Access != AccessReadOnly || got.L4 || got.Allow != nil {
		t.Errorf("allow HEAD: %+v", got)
	}
	post := Proposal{Endpoints: "api.example.com:8443 [L7 rest, allow POST /v1/things]"}.RequestedAccess()
	if post.Access != AccessReadWrite || post.L4 || len(post.Allow) != 1 || post.Allow[0] != "POST /v1/things" {
		t.Errorf("allow POST: %+v", post)
	}
	for _, unknown := range []string{
		"api.example.com:443 [L7 rest, access=full]",
		"api.example.com:443 [L7 rest, allow GET /, allow POST /x]",
		"api.example.com:443, api.example.org:443 [L4]",
		"paste.example.net:443 [L7]",
		"",
	} {
		if got := (Proposal{Endpoints: unknown}).RequestedAccess(); got.Access != "" || got.L4 || got.Allow != nil {
			t.Errorf("%q: %+v", unknown, got)
		}
	}
}

func TestAllowLine(t *testing.T) {
	cases := map[string]string{
		"www.example.com:443 [L7 rest, allow GET /]":         "GET /",
		"api.github.com:443 [L7 rest, allow POST /markdown]": "POST /markdown",
		"registry.npmjs.org:443 [L7 rest, access=read-only]": "",
		"paste.example.net:443 [L4]":                         "",
		"mcp.deepwiki.com:443 [mcp, allow initialize *]":     "",
		"": "",
	}
	for endpoints, want := range cases {
		if got := (Proposal{Endpoints: endpoints}).AllowLine(); got != want {
			t.Errorf("AllowLine(%q) = %q, want %q", endpoints, got, want)
		}
	}
}

// Recorded from OpenShell 0.1.4 on 19 October 2026 in sandbox
// fenzi-pin-run-0213: a request filed through policy.local and two drafts
// from refused connections, then, after more requests, a read-only preset and
// a rule with two endpoints.
const (
	recordedRules014 = `Network Rules:  (version 2, 3 chunks)

  Chunk: 4bf8dec4-5775-4de3-b130-59679dfa715c
  Status: pending
  Rule: pin_iana_read
  Binary: /usr/bin/curl
  Confidence: 75%
  Rationale: Pin re-recording: read the www.iana.org homepage once with curl.
  Prover: prover: no new findings
  Candidate: 1581293d868b
  Endpoints: www.iana.org:443 [L7 rest, allow GET /]
  Binaries: /usr/bin/curl

  Chunk: 9b1f3967-19de-44dd-9de7-e359f9ff90fc
  Status: pending
  Rule: allow_www_wikipedia_org_443
  Binary: /usr/bin/curl
  Confidence: 65%
  Rationale: Allow curl to connect to www.wikipedia.org:443 (HTTPS).
  Prover: prover: no new findings
  Candidate: a8c66c649810
  Endpoints: www.wikipedia.org:443 [L4]
  Binaries: /usr/bin/curl

  Chunk: 310b3bd1-e022-4f2d-9fd6-c73c5195b514
  Status: pending
  Rule: allow_paste_example_net_443
  Binary: /usr/bin/curl
  Confidence: 65%
  Rationale: Allow curl to connect to paste.example.net:443 (HTTPS).
  Prover: prover: no new findings
  Candidate: 9fc1c67ed22c
  Endpoints: paste.example.net:443 [L4]
  Binaries: /usr/bin/curl
`
	recordedShapes014 = `Network Rules:  (version 5, 3 chunks)

  Chunk: 483aa435-6248-4d58-8b66-8e1dda9e83c9
  Status: pending
  Rule: pin_two
  Binary: /usr/bin/curl
  Confidence: 75%
  Rationale: Pin re-recording: two endpoints in one rule.
  Prover: prover: no new findings
  Candidate: 208e8eb942ad
  Endpoints: www.kernel.org:443 [L7 rest, allow GET /], cdn.kernel.org:443 [L7 rest, allow POST /pub]
  Binaries: /usr/bin/curl

  Chunk: f8014d08-27fa-45e6-a854-badceae780e9
  Status: pending
  Rule: pin_gnu_ro
  Binary: /usr/bin/curl
  Confidence: 75%
  Rationale: Pin re-recording: read-only access to www.gnu.org.
  Prover: prover: no new findings
  Candidate: d02339ec92bd
  Endpoints: www.gnu.org:443 [L7 rest, access=read-only]
  Binaries: /usr/bin/curl

  Chunk: 9b1f3967-19de-44dd-9de7-e359f9ff90fc
  Status: pending
  Rule: allow_www_wikipedia_org_443
  Binary: /usr/bin/curl
  Confidence: 65%
  Rationale: Allow curl to connect to www.wikipedia.org:443 (HTTPS).
  Prover: prover: no new findings
  Candidate: 970f1fd01d91
  Endpoints: www.wikipedia.org:443 [L4]
  Binaries: /usr/bin/curl
`
)

func TestParseRules014(t *testing.T) {
	list := ParseRules([]byte(recordedRules014))
	if len(list) != 3 {
		t.Fatalf("got %d proposals", len(list))
	}
	agent, draft := list[0], list[1]
	shapes := ParseRules([]byte(recordedShapes014))
	if len(shapes) != 3 {
		t.Fatalf("got %d proposals", len(shapes))
	}
	two, ro := shapes[0], shapes[1]
	if two.Destination() != "www.kernel.org:443" || two.RequestedAccess().Access != "" || two.AllowLine() != "" {
		t.Errorf("two endpoints map to no single hosts entry: %+v %+v", two, two.RequestedAccess())
	}
	if got := ro.RequestedAccess(); got.Access != AccessReadOnly || got.L4 {
		t.Errorf("read-only preset: %+v", got)
	}
	if agent.Drafted() || agent.AllowLine() != "GET /" || agent.Prover != "no new findings" {
		t.Errorf("agent request: %+v", agent)
	}
	if !draft.Drafted() || !draft.RequestedAccess().L4 {
		t.Errorf("draft: %+v", draft)
	}
	if !NoRules([]byte("No network rules for sandbox 'fenzi-pin-run-0213'\n")) {
		t.Error("the 0.1.4 answer for nothing pending")
	}
}

func TestAgentFiled014(t *testing.T) {
	log := []byte(`[1792367365.432] [sandbox] [INFO ] [openshell_supervisor] Flushed denial analysis to gateway proposals=2 sandbox_name=fenzi-pin-run-0213 summaries=2
[1792367362.813] [sandbox] [OCSF ] [ocsf] CONFIG:PROPOSED [INFO] agent_authored proposal chunk:4bf8dec4-5775-4de3-b130-59679dfa715c on www.iana.org:443 [GET /] by /usr/bin/curl [chunk_id:4bf8dec4-5775-4de3-b130-59679dfa715c]
[1792367470.833] [sandbox] [OCSF ] [ocsf] CONFIG:PROPOSED [INFO] agent_authored proposal chunk:f8014d08-27fa-45e6-a854-badceae780e9 on www.gnu.org:443 by /usr/bin/curl [chunk_id:f8014d08-27fa-45e6-a854-badceae780e9]
`)
	ids := AgentFiled(log)
	if len(ids) != 2 || !ids["4bf8dec4-5775-4de3-b130-59679dfa715c"] || !ids["f8014d08-27fa-45e6-a854-badceae780e9"] {
		t.Errorf("ids = %v", ids)
	}
}
