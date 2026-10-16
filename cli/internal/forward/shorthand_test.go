package forward

import (
	"strings"
	"testing"
	"time"
)

// Lines recorded from OpenShell 0.1.2.
const recordedLog = `[1791059016.500] [sandbox] [OCSF ] [ocsf] CONFIG:LOADED [INFO] Acknowledged initial policy revision as loaded [version:1] [hash:478a7ecf5859]
[1791059085.939] [sandbox] [WARN ] [openshell_supervisor_network::proxy] Denied staged transparent connection destination=198.18.0.2:443 reason=binary '/usr/bin/curl' not allowed in policy 'api_github_com'
[1791059085.939] [sandbox] [OCSF ] [ocsf] NET:OPEN [MED] DENIED /usr/bin/curl(0) -> api.github.com:443 [reason:transparent_tcp_policy_denied]
[1791059085.948] [sandbox] [OCSF ] [ocsf] NET:REFUSE [MED] DENIED paste.example.net [reason:policy_dns_ineligible]
[1791059126.330] [sandbox] [OCSF ] [ocsf] NET:OPEN [INFO] ALLOWED /usr/bin/curl(0) -> api.github.com:443 [policy:allow_api_github_com_443 engine:opa]
[1791059126.365] [sandbox] [OCSF ] [ocsf] HTTP:GET [INFO] ALLOWED GET http://api.github.com:443/zen?token=abc [policy:allow_api_github_com_443 engine:l7]
[1791059150.996] [sandbox] [OCSF ] [ocsf] HTTP:POST [MED] DENIED POST http://api.github.com:443/markdown [policy:allow_api_github_com_443 engine:l7] [reason:L7_REQUEST deny POST api.github.com:443/markdown reason=POST /markdown not permitted by policy]
[1791059076.543] [sandbox] [OCSF ] [ocsf] SSH:OPEN [INFO] ALLOWED
`

func TestReadShorthand(t *testing.T) {
	recs, err := ReadShorthand(strings.NewReader(recordedLog), "demo")
	if err != nil {
		t.Fatal(err)
	}
	want := []struct{ action, dest, process, rule string }{
		{"Denied", "api.github.com:443", "/usr/bin/curl", ""},
		{"Denied", "paste.example.net", "", ""},
		{"Allowed", "api.github.com:443", "/usr/bin/curl", "allow_api_github_com_443"},
		{"Allowed", "GET api.github.com/zen", "", "allow_api_github_com_443"},
		{"Denied", "POST api.github.com/markdown", "", "allow_api_github_com_443"},
	}
	if len(recs) != len(want) {
		t.Fatalf("got %d records, want %d: %+v", len(recs), len(want), recs)
	}
	for i, w := range want {
		r := recs[i]
		if r.Action != w.action || r.Destination != w.dest || r.Process != w.process || r.Rule != w.rule || r.Sandbox != "demo" {
			t.Errorf("record %d = %+v, want %+v", i, r, w)
		}
	}
	if got := recs[0].Time.Unix(); got != 1791059085 {
		t.Errorf("time = %d", got)
	}
	for _, r := range recs {
		if strings.Contains(r.Destination, "token") {
			t.Errorf("query string leaked: %s", r.Destination)
		}
	}
	if recs[1].Reason != "policy_dns_ineligible" || recs[2].Reason != "" {
		t.Errorf("reasons: %q, %q", recs[1].Reason, recs[2].Reason)
	}
}

func TestFromStream(t *testing.T) {
	// Recorded from the gateway's watch stream, OpenShell 0.1.2. The same event in the shorthand log carried the prefix
	// "[1791063979.337] [sandbox] [OCSF ] [ocsf] ".
	msg := "NET:OPEN [INFO] ALLOWED /usr/local/lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe(0) -> api.anthropic.com:443 [policy:_provider_bl_claude engine:opa]"
	at := time.Date(2026, 10, 3, 21, 46, 19, 337e6, time.UTC)
	r, ok := FromStream(at, "OCSF", msg, "s")
	want := Record{Time: at, Sandbox: "s", Class: "Network Activity", Action: "Allowed",
		Process: "/usr/local/lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe", Destination: "api.anthropic.com:443", Rule: "_provider_bl_claude"}
	if !ok || r != want {
		t.Errorf("FromStream = %+v, want %+v", r, want)
	}
	short, _ := FromShorthand("[1791063979.337] [sandbox] [OCSF ] [ocsf] "+msg, "s")
	if short != want {
		t.Errorf("the shorthand line and the stream message must give the same record: %+v", short)
	}
	for _, other := range [][2]string{
		{"OCSF", "NET:OPEN [INFO] host.docker.internal:17670"},
		{"OCSF", "CONFIG:UPDATED [INFO] Setting changed [key:ocsf_json_enabled old:<unset> new:true]"},
		{"WARN", "Failed to install sandbox agent skill on toggle-on"},
	} {
		if _, ok := FromStream(at, other[0], other[1], "s"); ok {
			t.Errorf("not a decision: %v", other)
		}
	}
}

func TestShorthandReason(t *testing.T) {
	// Recorded from OpenShell 0.1.2.
	stale := "[1791061242.945] [sandbox] [OCSF ] [ocsf] NET:OPEN [MED] DENIED platform.claude.com:443 [reason:L7 tunnel closed before inspection because policy changed: policy generation is stale [captured_generation:1 current_generation:2]]"
	r, ok := FromShorthand(stale, "s")
	if !ok || r.Destination != "platform.claude.com:443" ||
		r.Reason != "L7 tunnel closed before inspection because policy changed: policy generation is stale [captured_generation:1 current_generation:2]" {
		t.Errorf("record = %+v", r)
	}
	if !r.Reset() {
		t.Error("a connection closed on a policy change is a reset, not a refusal")
	}
	refused := "[1791062448.468] [sandbox] [OCSF ] [ocsf] NET:OPEN [MED] DENIED /usr/bin/python3.11(0) -> 1.1.1.1:443 [reason:transparent_tcp_policy_denied]"
	if r, _ := FromShorthand(refused, "s"); r.Reset() || !r.Denied() {
		t.Errorf("a policy refusal must stay a deny: %+v", r)
	}
	q := "[1] [sandbox] [OCSF ] [ocsf] HTTP:POST [MED] DENIED POST http://api.github.com:443/markdown?token=abc [policy:x engine:l7] [reason:L7_REQUEST deny POST api.github.com:443/markdown?token=abc reason=POST /markdown?token=abc not permitted by policy]"
	if r, _ := FromShorthand(q, "s"); strings.Contains(r.Reason, "token") {
		t.Errorf("query string leaked into the reason: %s", r.Reason)
	}
}

// Recorded from a Codex session on OpenShell 0.1.2; the host is replaced.
const approvedLine = `[1791297802.289] [sandbox] [OCSF ] [ocsf] CONFIG:APPROVED [INFO] chunk:fad7c2ed-3aca-4fb7-bb37-495820dd7562 approved on example.com:443 HEAD / by /usr/bin/curl`

func TestAuditMapsAnApproval(t *testing.T) {
	r, ok := AuditFromShorthand(approvedLine, "bl-mouse-keepe-a3a6")
	want := Record{
		Time: time.Unix(1791297802, 289e6).UTC(), Sandbox: "bl-mouse-keepe-a3a6", Class: "Config", Action: "Approved",
		Destination: "example.com:443 HEAD /", Process: "/usr/bin/curl", Chunk: "fad7c2ed-3aca-4fb7-bb37-495820dd7562",
	}
	if !ok || r != want {
		t.Errorf("AuditFromShorthand = %+v, want %+v", r, want)
	}
	if _, ok := FromShorthand(approvedLine, "s"); ok {
		t.Error("an approval is not a decision; fenzi log must not show it")
	}
	for _, other := range []string{
		`[1791297778.239] [sandbox] [OCSF ] [ocsf] CONFIG:PROPOSED [INFO] agent_authored proposal chunk:fad7c2ed-3aca-4fb7-bb37-495820dd7562 on example.com:443 HEAD / by /usr/bin/curl`,
		`[1791059016.500] [sandbox] [OCSF ] [ocsf] CONFIG:LOADED [INFO] Acknowledged initial policy revision as loaded [version:1] [hash:478a7ecf5859]`,
	} {
		if r, ok := AuditFromShorthand(other, "s"); ok {
			t.Errorf("only CONFIG:APPROVED is recorded well enough to map: %+v", r)
		}
	}
}

func TestReadAuditKeepsDecisionsAndAddsApprovals(t *testing.T) {
	log := recordedLog + approvedLine + "\n"
	decisions, err := ReadShorthand(strings.NewReader(log), "demo")
	if err != nil {
		t.Fatal(err)
	}
	audit, err := ReadAudit(strings.NewReader(log), "demo")
	if err != nil {
		t.Fatal(err)
	}
	if len(decisions) != 5 || len(audit) != 6 {
		t.Fatalf("%d decisions, %d audit records", len(decisions), len(audit))
	}
	for i := range decisions {
		if audit[i] != decisions[i] {
			t.Errorf("record %d: %+v != %+v", i, audit[i], decisions[i])
		}
	}
	if last := audit[5]; last.Class != "Config" || last.Chunk == "" {
		t.Errorf("approval = %+v", last)
	}
}

func TestSpan(t *testing.T) {
	n, oldest, newest := Span([]byte(recordedLog + "\n"))
	if n != 8 {
		t.Errorf("lines = %d", n)
	}
	if oldest != time.Unix(1791059016, 500e6).UTC() || newest != time.Unix(1791059150, 996e6).UTC() {
		t.Errorf("oldest %v newest %v", oldest, newest)
	}
}
