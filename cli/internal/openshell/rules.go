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

// IsDraft is the rule boundlane requests uses to split requests: a chunk the
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
		return "", fmt.Errorf("no pending request starts with %q; run boundlane requests", prefix)
	}
	return "", fmt.Errorf("%q matches %d requests; use more characters", prefix, len(match))
}
