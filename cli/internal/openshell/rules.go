package openshell

import (
	"bufio"
	"bytes"
	"fmt"
	"regexp"
	"strings"
)

// Proposal is one chunk from `openshell rule get`. 0.1.2 prints text only,
// in blocks like:
//
//	Chunk: df10f171-e5d2-41f0-b4f5-b58fa89ca326
//	Status: pending
//	Rule: allow_registry_npmjs_org_443
//	Binary: /usr/bin/curl
//	Rationale: Allow curl to connect to registry.npmjs.org:443 (HTTPS).
//	Prover: prover: no new findings
//	Endpoints: registry.npmjs.org:443 [L7 rest, access=read-only]
type Proposal struct {
	Chunk     string
	Status    string
	Rule      string
	Binary    string
	Rationale string
	Prover    string
	Endpoints string
	Hits      string
}

// MCP reports whether the request is for an MCP server. `rule get` prints
// such an endpoint as [mcp, allow initialize *, ...] (0.1.2).
func (p Proposal) MCP() bool { return strings.Contains(p.Endpoints, "[mcp") }

// MCPApprovalRefused is why Fenzi does not pass an MCP request to `rule
// approve`: OpenShell 0.1.2 stores it without the tool it named, which
// allows every tool on that server (NVIDIA/OpenShell#4679).
const MCPApprovalRefused = "This request is for an MCP server. OpenShell would approve it as every tool on that server (NVIDIA/OpenShell#4679), so Fenzi does not approve it"

// ParseRules reads the text of `openshell rule get`. Unknown lines are ignored.
func ParseRules(out []byte) []Proposal {
	var list []Proposal
	var cur *Proposal
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		key, val, ok := strings.Cut(strings.TrimSpace(sc.Text()), ":")
		if !ok {
			continue
		}
		val = strings.TrimSpace(val)
		if key == "Chunk" {
			list = append(list, Proposal{Chunk: val})
			cur = &list[len(list)-1]
			continue
		}
		if cur == nil {
			continue
		}
		switch key {
		case "Status":
			cur.Status = val
		case "Rule":
			cur.Rule = val
		case "Binary":
			cur.Binary = val
		case "Rationale":
			cur.Rationale = val
		case "Prover":
			cur.Prover = strings.TrimSpace(strings.TrimPrefix(val, "prover:"))
		case "Endpoints":
			cur.Endpoints = val
		case "Hits":
			cur.Hits = val
		}
	}
	return list
}

// noRules is what `rule get <name> --status pending` printed in 0.1.2, with
// exit 0, for a sandbox with nothing pending (recorded 16 October 2026):
//
//	No network rules for sandbox 'fenzi-mouse-keepe-5561'
var noRules = regexp.MustCompile(`^No network rules for sandbox '[^']*'$`)

// NoRules reports whether out is the recorded answer for no chunks. Output
// that neither lists a chunk nor says this is not read as an empty list.
func NoRules(out []byte) bool {
	return noRules.Match(bytes.TrimSpace(out))
}

// agentFiled matches the sandbox log line OpenShell 0.1.2 writes when the
// agent submits a proposal through policy.local:
//
//	CONFIG:PROPOSED [INFO] agent_authored proposal chunk:fad7c2ed-… on host:443 HEAD / by /usr/bin/curl
//
// Drafts the supervisor makes from refusals are logged only as "Flushed
// denial analysis", without a chunk id.
var agentFiled = regexp.MustCompile(`CONFIG:PROPOSED .*agent_authored proposal chunk:([0-9a-f-]+)`)

// AgentFiled returns the chunk ids the sandbox log shows the agent filed.
func AgentFiled(log []byte) map[string]bool {
	ids := map[string]bool{}
	for _, m := range agentFiled.FindAllSubmatch(log, -1) {
		ids[string(m[1])] = true
	}
	return ids
}

// drafted is the rationale 0.1.2 writes on a draft made from a refusal:
// "Allow curl to connect to github.com:443 (HTTPS)."
var drafted = regexp.MustCompile(`^Allow \S+ to connect to \S+:\d+( \([^)]*\))?\.$`)

// Drafted reports whether p reads like a draft the supervisor made from a
// refused connection: no rationale, or the generated one. A request the
// agent files carries its own intent_summary. The log is the surer sign,
// but a long-running sandbox's log no longer has the early lines.
func (p Proposal) Drafted() bool {
	return p.Rationale == "" || drafted.MatchString(p.Rationale)
}

// IsDraft is the rule fenzi requests uses to split requests: a chunk the
// log shows the agent filed is the agent's, and so is one whose rationale is
// not a generated one. Everything else was drafted from a refused connection.
// filed comes from AgentFiled and may be nil when the log could not be read.
func (p Proposal) IsDraft(filed map[string]bool) bool {
	return !filed[p.Chunk] && p.Drafted()
}

// RequestLogWindow is how many log lines are read to find the requests the
// agent filed.
const RequestLogWindow = 2000

// Destination is the first host:port in Endpoints.
func (p Proposal) Destination() string {
	if f := strings.Fields(p.Endpoints); len(f) > 0 {
		return f[0]
	}
	return ""
}

// ResolveChunk expands a unique prefix of a chunk id.
func ResolveChunk(list []Proposal, prefix string) (string, error) {
	var match []string
	for _, p := range list {
		if strings.HasPrefix(p.Chunk, prefix) {
			match = append(match, p.Chunk)
		}
	}
	switch len(match) {
	case 1:
		return match[0], nil
	case 0:
		return "", fmt.Errorf("no pending request starts with %q; run fenzi requests", prefix)
	}
	return "", fmt.Errorf("%q matches %d requests; use more characters", prefix, len(match))
}

// Access levels of a hosts entry in the org document.
const (
	AccessReadOnly  = "read-only"
	AccessReadWrite = "read-write"
)

// RequestAccess is what a request's rule asks for, in the org document's
// terms: the access level of a hosts entry and, for read-write, the allow
// line the entry needs.
type RequestAccess struct {
	// Access is read-only or read-write, or empty when the rule is in a
	// shape that has not been recorded.
	Access string
	// Allow is the rule's "METHOD /path" for a read-write request.
	Allow []string
	// L4 means the rule names no method or path, so the approved rule lets
	// any traffic through to the host and port. It maps to read-only, the
	// narrowest entry the org document has.
	L4 bool
}

// endpointShape is the Endpoints line of `openshell rule get`. The shapes
// recorded from OpenShell 0.1.2 are:
//
//	paste.example.net:443 [L4]
//	registry.npmjs.org:443 [L7 rest, access=read-only]
//	www.example.com:443 [L7 rest, allow GET /]
//
// A line with more than one endpoint, more than one allow rule, or another
// access level has not been recorded, so its access is left empty.
var (
	endpointShape = regexp.MustCompile(`^([a-z0-9][a-z0-9.-]*):(\d+) \[([^\]]+)\]$`)
	l7ReadOnly    = regexp.MustCompile(`^L7 rest, access=read-only$`)
	l7AllowOne    = regexp.MustCompile(`^L7 rest, allow ([A-Z]+) (/\S*)$`)
)

// RequestedAccess maps the rule's endpoints to an access level: GET or HEAD
// is read-only, any other method is read-write with the rule's allow line,
// and a rule with no L7 detail is read-only and flagged L4.
func (p Proposal) RequestedAccess() RequestAccess {
	m := endpointShape.FindStringSubmatch(strings.TrimSpace(p.Endpoints))
	if m == nil {
		return RequestAccess{}
	}
	switch rule := m[3]; {
	case rule == "L4":
		return RequestAccess{Access: AccessReadOnly, L4: true}
	case l7ReadOnly.MatchString(rule):
		return RequestAccess{Access: AccessReadOnly}
	case l7AllowOne.MatchString(rule):
		a := l7AllowOne.FindStringSubmatch(rule)
		if a[1] == "GET" || a[1] == "HEAD" {
			return RequestAccess{Access: AccessReadOnly}
		}
		return RequestAccess{Access: AccessReadWrite, Allow: []string{a[1] + " " + a[2]}}
	}
	return RequestAccess{}
}
