package compiler

import (
	"errors"
	"strings"
	"testing"
)

const mcpDoc = `version: 1
mcp:
  linear:
    url: https://mcp.linear.app/mcp
    token: true
    tools:
      allow: [list_issues, get_issue]
      deny: [delete_issue]
  deepwiki:
    url: https://mcp.deepwiki.com/mcp
    tools:
      allow: ["*"]
      deny: [ask_question]
  files:
    command: [npx, -y, "@modelcontextprotocol/server-filesystem", /sandbox]
    env:
      LOG_LEVEL: warn
`

func mcpDocument(t *testing.T, src string) *Document {
	t.Helper()
	d, err := Parse([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	return d.WithDefaults()
}

// The rule takes the shape OpenShell 0.1.2 accepted and enforced in the
// MCP experiments: protocol mcp with discovery methods, one tools/call per
// tool or one without a tool for all of them, deny rules, the revisions the
// agents send, and the token bound by credential_binding.
func TestMCPRules(t *testing.T) {
	p, err := Compile(mcpDocument(t, mcpDoc), Target{Agent: claude})
	if err != nil {
		t.Fatal(err)
	}
	out, err := p.YAML("")
	if err != nil {
		t.Fatal(err)
	}
	y := string(out)
	for _, want := range []string{
		"  mcp_linear:\n    name: mcp.linear.app\n",
		"        path: /mcp\n        protocol: mcp\n",
		"              method: tools/call\n              tool: list_issues\n",
		"        deny_rules:\n          - method: tools/call\n            tool: delete_issue\n",
		"        mcp:\n          versions:\n            - \"2025-06-18\"\n            - \"2025-11-25\"\n",
		"        credential_binding:\n          provider: fenzi-mcp-linear\n",
		"              method: notifications/initialized\n",
	} {
		if !strings.Contains(y, want) {
			t.Errorf("missing %q in:\n%s", want, y)
		}
	}
	dw := p.NetworkPolicies["mcp_deepwiki"].Endpoints[0]
	var calls []Match
	for _, r := range dw.Rules {
		if r.Allow.Method == "tools/call" {
			calls = append(calls, r.Allow)
		}
	}
	if len(calls) != 1 || calls[0].Tool != "" || dw.CredentialBinding != nil {
		t.Errorf("all tools: one tools/call without a tool and no token, got %+v", dw)
	}
	if _, ok := p.NetworkPolicies["mcp_files"]; ok {
		t.Error("a local server gets no network rule")
	}
	if strings.Contains(y, "path: \"\"") {
		t.Error("an MCP rule must not carry an empty REST path")
	}
	for _, r := range p.NetworkPolicies {
		for _, e := range r.Endpoints {
			if e.Protocol == "mcp" && (len(r.Binaries) != 1 || r.Binaries[0].Path != claude.Binaries[0]) {
				t.Errorf("only the agent's program reaches an MCP server: %+v", r.Binaries)
			}
		}
	}
}

func TestMCPValidation(t *testing.T) {
	cases := map[string]string{
		"no tools":            "mcp:\n  x:\n    url: https://mcp.example.com/mcp\n",
		"http":                "mcp:\n  x:\n    url: http://mcp.example.com/mcp\n    tools: {allow: [a]}\n",
		"query":               "mcp:\n  x:\n    url: https://mcp.example.com/mcp?key=1\n    tools: {allow: [a]}\n",
		"both":                "mcp:\n  x:\n    url: https://mcp.example.com/mcp\n    command: [a]\n    tools: {allow: [a]}\n",
		"neither":             "mcp:\n  x:\n    tools: {allow: [a]}\n",
		"local with tools":    "mcp:\n  x:\n    command: [a]\n    tools: {allow: [a]}\n",
		"local with token":    "mcp:\n  x:\n    command: [a]\n    token: true\n",
		"remote with env":     "mcp:\n  x:\n    url: https://mcp.example.com/mcp\n    env: {A: b}\n    tools: {allow: [a]}\n",
		"bad name":            "mcp:\n  X_1:\n    command: [a]\n",
		"bad tool":            "mcp:\n  x:\n    url: https://mcp.example.com/mcp\n    tools: {allow: [\"a b\"]}\n",
		"ip":                  "mcp:\n  x:\n    url: https://10.0.0.1/mcp\n    tools: {allow: [a]}\n",
		"same host twice":     "mcp:\n  x:\n    url: https://mcp.example.com/a\n    tools: {allow: [a]}\n  y:\n    url: https://mcp.example.com/b\n    tools: {allow: [a]}\n",
		"host rule too":       "hosts:\n  - host: mcp.example.com\n    access: read-only\nmcp:\n  x:\n    url: https://mcp.example.com/mcp\n    tools: {allow: [a]}\n",
		"lowercase env names": "mcp:\n  x:\n    command: [a]\n    env: {lower: b}\n",
	}
	for name, body := range cases {
		d := mcpDocument(t, "version: 1\n"+body)
		if err := d.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := mcpDocument(t, mcpDoc).Validate(); err != nil {
		t.Errorf("the example is valid: %v", err)
	}
}

func TestMCPOnTheModelHost(t *testing.T) {
	d := mcpDocument(t, "version: 1\nmcp:\n  x:\n    url: https://api.anthropic.com/mcp\n    tools: {allow: [a]}\n")
	if _, err := Compile(d, Target{Agent: claude}); err == nil || !strings.Contains(err.Error(), "model API") {
		t.Errorf("got %v", err)
	}
}

func TestMCPMerge(t *testing.T) {
	base := mcpDocument(t, mcpDoc)
	narrow := mcpDocument(t, "version: 1\nmcp:\n  linear:\n    url: https://mcp.linear.app/mcp\n    tools:\n      allow: [list_issues]\n      deny: [delete_issue]\n  extra:\n    url: https://mcp.extra.example/mcp\n    tools: {allow: [a]}\n")
	m, err := Merge(base, narrow)
	if err != nil {
		t.Fatal(err)
	}
	if got := m.MCP["linear"]; len(got.Tools.Allow) != 1 || !got.Token {
		t.Errorf("narrowed linear keeps the base token: %+v", got)
	}
	if _, ok := m.MCP["extra"]; !ok || len(m.MCP) != 4 {
		t.Errorf("a new server is added: %v", m.MCPNames())
	}
	if _, ok := base.MCP["extra"]; ok {
		t.Error("Merge changed the base")
	}

	wide := mcpDocument(t, "version: 1\nmcp:\n  linear:\n    url: https://mcp.linear.app/mcp\n    tools: {allow: [\"*\"]}\n")
	if _, err := Merge(base, wide); err == nil || !strings.Contains(err.Error(), "only narrow") {
		t.Errorf("widening a base server: %v", err)
	}
	moved := mcpDocument(t, "version: 1\nmcp:\n  linear:\n    url: https://evil.example/mcp\n    tools: {allow: [list_issues]}\n")
	if _, err := Merge(base, moved); err == nil {
		t.Error("a project may not move a base server to another URL")
	}
}

func TestCheckMCP(t *testing.T) {
	team := mcpDocument(t, mcpDoc)
	ok := mcpDocument(t, "version: 1\nmcp:\n  deepwiki:\n    url: https://mcp.deepwiki.com/mcp\n    tools:\n      allow: [read_wiki_structure]\n")
	if err := CheckMCP(ok, team); err != nil {
		t.Errorf("a narrower server: %v", err)
	}
	for name, body := range map[string]string{
		"unknown server": "mcp:\n  other:\n    url: https://mcp.other.example/mcp\n    tools: {allow: [a]}\n",
		"other url":      "mcp:\n  linear:\n    url: https://mcp.linear.app/v2\n    tools: {allow: [list_issues]}\n",
		"extra tool":     "mcp:\n  linear:\n    url: https://mcp.linear.app/mcp\n    tools: {allow: [list_issues, create_issue], deny: [delete_issue]}\n",
		"all tools":      "mcp:\n  linear:\n    url: https://mcp.linear.app/mcp\n    tools: {allow: [\"*\"], deny: [delete_issue]}\n",
		"drops a deny":   "mcp:\n  deepwiki:\n    url: https://mcp.deepwiki.com/mcp\n    tools: {allow: [\"*\"]}\n",
		"other command":  "mcp:\n  files:\n    command: [npx, other]\n",
	} {
		var ve *ValidationError
		if err := CheckMCP(mcpDocument(t, "version: 1\n"+body), team); !errors.As(err, &ve) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// openshell-prover 0.1.2 returns unsupported for any policy with an MCP
// rule, so the prover gets the policy without them.
func TestWithoutMCPAndStripMCP(t *testing.T) {
	p, err := Compile(mcpDocument(t, mcpDoc+"hosts:\n  - host: pypi.org\n    access: read-only\n"), Target{Agent: claude})
	if err != nil {
		t.Fatal(err)
	}
	if !p.HasMCP() || p.WithoutMCP().HasMCP() {
		t.Fatal("WithoutMCP must remove every MCP rule")
	}
	if len(p.WithoutMCP().NetworkPolicies) != len(p.NetworkPolicies)-2 {
		t.Errorf("only the two MCP rules go")
	}
	full, _ := p.YAML("")
	stripped, err := StripMCP(full)
	if err != nil {
		t.Fatal(err)
	}
	s := string(stripped)
	if strings.Contains(s, "protocol: mcp") || !strings.Contains(s, "pypi_org:") || !strings.Contains(s, "filesystem_policy:") {
		t.Errorf("stripped:\n%s", s)
	}
}

func TestEffectOfAnMCPChange(t *testing.T) {
	a := mcpDocument(t, mcpDoc)
	b := mcpDocument(t, strings.Replace(mcpDoc, "get_issue]", "get_issue, create_comment]", 1))
	if got := Effect(a, b); got != EffectWall {
		t.Errorf("an MCP change takes a new sandbox, since the agent reads its servers at start: %s", got)
	}
	if got := Effect(a, mcpDocument(t, mcpDoc)); got != EffectSame {
		t.Errorf("same servers: %s", got)
	}
}

func TestMCPNaming(t *testing.T) {
	if MCPTokenEnv("my-server") != "FENZI_MCP_MY_SERVER_TOKEN" || MCPProvider("x") != "fenzi-mcp-x" || MCPRuleKey("a-b") != "mcp_a_b" {
		t.Error("names changed; they are stored on machines and in agent configs")
	}
}
