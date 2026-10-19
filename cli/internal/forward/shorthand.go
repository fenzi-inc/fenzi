package forward

import (
	"bufio"
	"bytes"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Shorthand lines from `openshell logs --source sandbox`, as recorded from
// OpenShell 0.1.2:
//
//	[1791059126.330] [sandbox] [OCSF ] [ocsf] NET:OPEN [INFO] ALLOWED /usr/bin/curl(0) -> api.github.com:443 [policy:allow_api_github_com_443 engine:opa]
//	[1791059150.996] [sandbox] [OCSF ] [ocsf] HTTP:POST [MED] DENIED POST http://api.github.com:443/markdown [policy:allow_api_github_com_443 engine:l7] [reason:...]
//	[1791059085.948] [sandbox] [OCSF ] [ocsf] NET:REFUSE [MED] DENIED paste.example.net [reason:policy_dns_ineligible]
var (
	shortLine = regexp.MustCompile(`^\[(\d+(?:\.\d+)?)\] \[sandbox\] \[OCSF\s*\] \[ocsf\] (.*)$`)
	decision  = regexp.MustCompile(`^(NET|HTTP):(\S+) \[\w+\] (ALLOWED|DENIED) (.*)$`)
	shortNet  = regexp.MustCompile(`^(\S+?)\(\d+\) -> (\S+)`)
	shortHTTP = regexp.MustCompile(`^([A-Z]+) (\S+)`)
	shortRule = regexp.MustCompile(`\[policy:(\S+)`)
	// The reason runs to the line's last bracket; it can hold nested ones:
	// [reason:L7 tunnel closed before inspection because policy changed: policy generation is stale [captured_generation:1 current_generation:2]]
	shortReason = regexp.MustCompile(`\[reason:(.*)\]\s*$`)
	// HTTP reasons repeat the request path; records never keep a query string.
	query = regexp.MustCompile(`\?[^\s\]]*`)
	// The approval event the sandbox log carries when the agent waits on a
	// request it filed. OpenShell 0.1.2 wrote:
	//
	//	CONFIG:APPROVED [INFO] chunk:fad7c2ed-3aca-4fb7-bb37-495820dd7562 approved on example.com:443 HEAD / by /usr/bin/curl
	//
	// and 0.1.4 brackets the method and path and adds the chunk again
	// (recorded 19 October 2026):
	//
	//	CONFIG:APPROVED [INFO] chunk:f42110d7-6838-4088-a1b1-5482aeb88792 approved on www.ietf.org:443 [HEAD /] by /usr/bin/curl [chunk_id:f42110d7-6838-4088-a1b1-5482aeb88792]
	//
	// Both are read. 0.1.4 logs CONFIG:APPROVED and CONFIG:REJECTED for every
	// review in the gateway's log, which `--source sandbox` leaves out; the
	// other CONFIG events are not mapped.
	approval = regexp.MustCompile(`^CONFIG:APPROVED \[\w+\] chunk:(\S+) approved on (.+?) by (\S+)(?: \[chunk_id:[^\]]*\])?$`)
	// The line written when the agent files a request through policy.local.
	// OpenShell 0.1.2 (recorded 16 October 2026, the same session):
	//
	//	CONFIG:PROPOSED [INFO] agent_authored proposal chunk:fad7c2ed-3aca-4fb7-bb37-495820dd7562 on example.com:443 HEAD / by /usr/bin/curl
	//
	// OpenShell 0.1.4 (recorded 19 October 2026), for one endpoint with an
	// allow rule, a read-only preset, and two endpoints:
	//
	//	CONFIG:PROPOSED [INFO] agent_authored proposal chunk:4bf8dec4-5775-4de3-b130-59679dfa715c on www.iana.org:443 [GET /] by /usr/bin/curl [chunk_id:4bf8dec4-5775-4de3-b130-59679dfa715c]
	//	CONFIG:PROPOSED [INFO] agent_authored proposal chunk:f8014d08-27fa-45e6-a854-badceae780e9 on www.gnu.org:443 by /usr/bin/curl [chunk_id:f8014d08-27fa-45e6-a854-badceae780e9]
	//	CONFIG:PROPOSED [INFO] agent_authored proposal chunk:483aa435-6248-4d58-8b66-8e1dda9e83c9 on www.kernel.org:443 [GET /], cdn.kernel.org:443 [POST /pub] by /usr/bin/curl [chunk_id:483aa435-6248-4d58-8b66-8e1dda9e83c9]
	//
	// Drafts the supervisor makes from refusals are logged without a chunk
	// id ("Flushed denial analysis") and are not mapped.
	proposed = regexp.MustCompile(`^CONFIG:PROPOSED \[\w+\] agent_authored proposal chunk:(\S+) on (.+?) by (\S+)(?: \[chunk_id:[^\]]*\])?$`)
	// bracketed is one 0.1.4 endpoint with its method and path in brackets.
	bracketed = regexp.MustCompile(`^(\S+) \[([A-Z]+ /\S*)\]$`)
	// MCP requests, recorded from OpenShell 0.1.2 (engine:l7-mcp):
	//
	//	HTTP:POST [MED] DENIED POST http://mcp.deepwiki.com:443/mcp [policy:mcp_deepwiki_com engine:l7-mcp] [reason:JSONRPC_L7_REQUEST decision=deny rule_methods=tools/call tools=read_wiki_contents http_method=POST endpoint=mcp.deepwiki.com:443/mcp policy_version=2 reason=POST /mcp not permitted by policy]
	//	HTTP:POST [INFO] ALLOWED POST http://mcp.deepwiki.com:443/mcp [policy:mcp_deepwiki_com engine:l7-mcp] [msg:JSONRPC_L7_REQUEST decision=allow rule_methods=tools/call tools=read_wiki_structure http_method=POST endpoint=mcp.deepwi...]
	//
	// An allowed line's message is cut short, so a long tool name can be cut
	// too; a name that ends in ... is dropped.
	mcpMethod = regexp.MustCompile(`rule_methods=(\S+)`)
	mcpTool   = regexp.MustCompile(`tools=([^\s\]]+)`)
	mcpReason = regexp.MustCompile(` reason=(.*)$`)
	// lineTime is the time prefix every line of `openshell logs` carries.
	lineTime = regexp.MustCompile(`^\[(\d+(?:\.\d+)?)\] `)
)

// FromShorthand maps one shorthand log line. ok is false for lines that are
// not network or HTTP decisions.
func FromShorthand(line, sandbox string) (Record, bool) {
	m := shortLine.FindStringSubmatch(strings.TrimSpace(line))
	if m == nil {
		return Record{}, false
	}
	return FromStream(epoch(m[1]), "OCSF", m[2], sandbox)
}

// epoch parses "1791063979.337" without going through a float, which would
// turn .337 into .336999.
func epoch(s string) time.Time {
	whole, frac, _ := strings.Cut(s, ".")
	secs, err := strconv.ParseInt(whole, 10, 64)
	if err != nil {
		return time.Time{}
	}
	frac = (frac + "000000000")[:9]
	nanos, _ := strconv.ParseInt(frac, 10, 64)
	return time.Unix(secs, nanos)
}

// FromStream maps one log line from the gateway's watch stream, the gRPC
// stream behind `openshell logs`. OCSF lines arrive with level "OCSF", no
// structured fields, and the shorthand text without its time and source
// prefix:
//
//	NET:OPEN [INFO] ALLOWED /usr/local/lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe(0) -> api.anthropic.com:443 [policy:_provider_fenzi_claude engine:opa]
func FromStream(t time.Time, level, message, sandbox string) (Record, bool) {
	if level != "OCSF" {
		return Record{}, false
	}
	m := decision.FindStringSubmatch(strings.TrimSpace(message))
	if m == nil {
		return Record{}, false
	}
	r := Record{Sandbox: sandbox, Action: titleCase(m[3]), Time: t.UTC().Truncate(time.Millisecond)}
	rest := m[4]
	if rm := shortRule.FindStringSubmatch(rest); rm != nil && rm[1] != "-" {
		r.Rule = rm[1]
	}
	if rm := shortReason.FindStringSubmatch(rest); rm != nil {
		r.Reason = query.ReplaceAllString(rm[1], "")
	}
	switch m[1] {
	case "NET":
		r.Class = "Network Activity"
		if nm := shortNet.FindStringSubmatch(rest); nm != nil {
			r.Process, r.Destination = nm[1], nm[2]
		} else if f := strings.Fields(rest); len(f) > 0 {
			r.Destination = f[0]
		}
	case "HTTP":
		r.Class = "HTTP Activity"
		if hm := shortHTTP.FindStringSubmatch(rest); hm != nil {
			r.Destination = hm[1] + " " + hostPath(hm[2])
		}
		if strings.Contains(rest, "engine:l7-mcp") {
			mcpFields(&r, rest)
		}
	}
	return r, r.Destination != ""
}

// mcpFields adds the MCP method and tool, and keeps only OpenShell's own
// reason from the JSON-RPC summary.
func mcpFields(r *Record, rest string) {
	if m := mcpMethod.FindStringSubmatch(rest); m != nil && m[1] != "-" && !strings.HasSuffix(m[1], "...") {
		r.MCPMethod = m[1]
	}
	if m := mcpTool.FindStringSubmatch(rest); m != nil && m[1] != "-" && !strings.HasSuffix(m[1], "...") {
		r.MCPTool = m[1]
	}
	if m := mcpReason.FindStringSubmatch(r.Reason); m != nil {
		r.Reason = strings.TrimSpace(m[1])
	}
}

// ReadShorthand maps every decision line in a shorthand log.
func ReadShorthand(rd io.Reader, sandbox string) ([]Record, error) {
	return read(rd, sandbox, FromShorthand)
}

// AuditFromStream maps a decision or an approval. The forwarder ships both so
// the control plane can match OpenShell's approvals to console reviews.
// `fenzi log` reads decisions only.
func AuditFromStream(t time.Time, level, message, sandbox string) (Record, bool) {
	if r, ok := FromStream(t, level, message, sandbox); ok {
		return r, true
	}
	if level != "OCSF" {
		return Record{}, false
	}
	m := approval.FindStringSubmatch(strings.TrimSpace(message))
	if m == nil {
		return Record{}, false
	}
	return Record{
		Time: t.UTC().Truncate(time.Millisecond), Sandbox: sandbox, Class: "Config", Action: "Approved",
		Destination: configDestination(m[2]), Process: m[3], Chunk: m[1],
	}, true
}

// EventFromStream maps a decision, an approval, or a request the agent
// filed. `fenzi log --requests` shows all three; the forwarder ships only
// the first two (AuditFromStream), so the control plane's contract does not
// change. A request is Class "Config", Action "Requested", with the chunk
// id, the destination (configDestination), and the program.
func EventFromStream(t time.Time, level, message, sandbox string) (Record, bool) {
	if r, ok := AuditFromStream(t, level, message, sandbox); ok {
		return r, true
	}
	if level != "OCSF" {
		return Record{}, false
	}
	m := proposed.FindStringSubmatch(strings.TrimSpace(message))
	if m == nil {
		return Record{}, false
	}
	return Record{
		Time: t.UTC().Truncate(time.Millisecond), Sandbox: sandbox, Class: "Config", Action: "Requested",
		Destination: configDestination(m[2]), Process: m[3], Chunk: m[1],
	}, true
}

// configDestination writes one endpoint the way 0.1.2 did, "host:443 HEAD /",
// so records do not change with the runtime version. More than one endpoint
// is kept as the runtime wrote it.
func configDestination(d string) string {
	if m := bracketed.FindStringSubmatch(d); m != nil {
		return m[1] + " " + m[2]
	}
	return d
}

// EventFromShorthand is EventFromStream for one shorthand log line.
func EventFromShorthand(line, sandbox string) (Record, bool) {
	m := shortLine.FindStringSubmatch(strings.TrimSpace(line))
	if m == nil {
		return Record{}, false
	}
	return EventFromStream(epoch(m[1]), "OCSF", m[2], sandbox)
}

// ReadEvents maps every decision, approval and filed request in a
// shorthand log.
func ReadEvents(rd io.Reader, sandbox string) ([]Record, error) {
	return read(rd, sandbox, EventFromShorthand)
}

// Config reports a policy event (a request or an approval), not a decision.
func (r Record) Config() bool { return r.Class == "Config" }

// AuditFromShorthand is AuditFromStream for one shorthand log line.
func AuditFromShorthand(line, sandbox string) (Record, bool) {
	m := shortLine.FindStringSubmatch(strings.TrimSpace(line))
	if m == nil {
		return Record{}, false
	}
	return AuditFromStream(epoch(m[1]), "OCSF", m[2], sandbox)
}

// ReadAudit maps every decision and approval line in a shorthand log.
func ReadAudit(rd io.Reader, sandbox string) ([]Record, error) {
	return read(rd, sandbox, AuditFromShorthand)
}

func read(rd io.Reader, sandbox string, from func(string, string) (Record, bool)) ([]Record, error) {
	var out []Record
	sc := bufio.NewScanner(rd)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		if r, ok := from(sc.Text(), sandbox); ok {
			out = append(out, r)
		}
	}
	return out, sc.Err()
}

// Span counts the lines of a shorthand log and returns the times of the
// oldest and newest ones, whatever their kind. Lines without a time prefix
// are counted and have no time.
func Span(raw []byte) (lines int, oldest, newest time.Time) {
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		lines++
		m := lineTime.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		t := epoch(m[1]).UTC()
		if oldest.IsZero() || t.Before(oldest) {
			oldest = t
		}
		if t.After(newest) {
			newest = t
		}
	}
	return lines, oldest, newest
}

// hostPath turns http://host:443/path?q into host/path. The query is dropped.
func hostPath(u string) string {
	u = strings.TrimPrefix(strings.TrimPrefix(u, "http://"), "https://")
	if i := strings.IndexByte(u, '?'); i >= 0 {
		u = u[:i]
	}
	host, path, _ := strings.Cut(u, "/")
	host = strings.TrimSuffix(host, ":443")
	return host + "/" + path
}

func titleCase(s string) string {
	if s == "" {
		return s
	}
	return s[:1] + strings.ToLower(s[1:])
}
