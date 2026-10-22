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
func TestForProverWithoutMCP(t *testing.T) {
	p, err := Compile(mcpDocument(t, mcpDoc+"hosts:\n  - host: pypi.org\n    access: read-only\n"), Target{Agent: claude})
	if err != nil {
		t.Fatal(err)
	}
	if !p.HasMCP() || p.ForProver().HasMCP() || !p.Unprovable() || p.ForProver().Unprovable() {
		t.Fatal("ForProver must remove every MCP rule")
	}
	if len(p.ForProver().NetworkPolicies) != len(p.NetworkPolicies)-2 {
		t.Errorf("only the two MCP rules go")
	}
	full, _ := p.YAML("")
	if !UnprovableYAML(full) {
		t.Error("UnprovableYAML missed the MCP rules")
	}
	stripped, err := ForProverYAML(full)
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

const secretDoc = `version: 1
hosts:
  - host: api.github.com
    access: read-only
mcp:
  droplets:
    command: [npx, -y, "@digitalocean/mcp", --services, droplets]
    secrets: [DIGITALOCEAN_API_TOKEN]
    hosts: [api.digitalocean.com]
  apps:
    command: [npx, -y, "@digitalocean/mcp", --services, apps]
    secrets: [DIGITALOCEAN_API_TOKEN]
    hosts: [api.digitalocean.com]
  github:
    command: [github-mcp-server, stdio]
    secrets: [GITHUB_PERSONAL_ACCESS_TOKEN]
    hosts: [api.github.com]
  fetch:
    command: [uvx, mcp-server-fetch]
    hosts: [example.org]
`

// A local server's secret is a provider named for the variable, bound with
// credential_binding on a REST rule for each host it lists, for the agent's
// programs. Recorded on OpenShell 0.1.2: a stdio server started by Claude Code
// matched a rule naming only claude.exe, and the proxy put the value on
// that host only.
func TestLocalServerSecretRules(t *testing.T) {
	p, err := Compile(mcpDocument(t, secretDoc), Target{Agent: claude})
	if err != nil {
		t.Fatal(err)
	}
	do, ok := p.NetworkPolicies["api_digitalocean_com"]
	if !ok || len(do.Endpoints) != 1 {
		t.Fatalf("one rule for the host both servers call: %+v", p.NetworkPolicies)
	}
	e := do.Endpoints[0]
	if e.Protocol != "rest" || e.Access != AccessReadWrite || e.Port != 443 || e.CredentialBinding == nil || e.CredentialBinding.Provider != "fenzi-secret-digitalocean-api-token" {
		t.Errorf("endpoint %+v", e)
	}
	if len(do.Binaries) != len(claude.Binaries) || do.Binaries[0].Path != claude.Binaries[0] {
		t.Errorf("the agent's programs, which the server runs under: %+v", do.Binaries)
	}
	gh := p.NetworkPolicies["api_github_com"].Endpoints[0]
	if gh.Access != AccessReadOnly || gh.CredentialBinding == nil || gh.CredentialBinding.Provider != "fenzi-secret-github-personal-access-token" {
		t.Errorf("a host in hosts keeps its access and gets the binding: %+v", gh)
	}
	fetch := p.NetworkPolicies["example_org"].Endpoints[0]
	if fetch.CredentialBinding != nil || fetch.Access != AccessReadWrite {
		t.Errorf("a host with no secret: %+v", fetch)
	}
	if got := strings.Join(mcpDocument(t, secretDoc).Secrets(), ","); got != "DIGITALOCEAN_API_TOKEN,GITHUB_PERSONAL_ACCESS_TOKEN" {
		t.Errorf("secrets %s", got)
	}
	y, _ := p.YAML("")
	if !strings.Contains(string(y), "        credential_binding:\n          provider: fenzi-secret-digitalocean-api-token\n") {
		t.Errorf("yaml:\n%s", y)
	}
}

// openshell-prover 0.1.2 returns unsupported for a REST rule with
// credential_binding, so the prover gets the rule without it.
func TestForProverDropsSecretBindings(t *testing.T) {
	p, err := Compile(mcpDocument(t, secretDoc), Target{Agent: claude})
	if err != nil {
		t.Fatal(err)
	}
	if !p.Unprovable() || p.HasMCP() {
		t.Fatal("bound REST rules are unprovable, and they are not MCP rules")
	}
	fp := p.ForProver()
	if fp.Unprovable() || len(fp.NetworkPolicies) != len(p.NetworkPolicies) {
		t.Fatalf("every rule stays, without its binding: %+v", fp.NetworkPolicies)
	}
	if p.NetworkPolicies["api_digitalocean_com"].Endpoints[0].CredentialBinding == nil {
		t.Error("ForProver changed the policy it was given")
	}
	full, _ := p.YAML("")
	if !UnprovableYAML(full) {
		t.Error("UnprovableYAML missed the binding")
	}
	stripped, err := ForProverYAML(full)
	if err != nil {
		t.Fatal(err)
	}
	if s := string(stripped); strings.Contains(s, "credential_binding") || !strings.Contains(s, "api_digitalocean_com:") || !strings.Contains(s, "access: read-write") {
		t.Errorf("stripped:\n%s", s)
	}
}

func TestLocalServerSecretRefusals(t *testing.T) {
	for _, c := range []struct{ name, mcp, want string }{
		{"no hosts", "  x:\n    command: [x]\n    secrets: [API_TOKEN]\n", "list the hosts the server sends its secrets to"},
		{"bad name", "  x:\n    command: [x]\n    secrets: [api-token]\n    hosts: [api.example.com]\n", "is not a variable name"},
		{"reserved", "  x:\n    command: [x]\n    secrets: [FENZI_MCP_X_TOKEN]\n    hosts: [api.example.com]\n", "prefix the sandbox keeps"},
		{"revision prefix", "  x:\n    command: [x]\n    secrets: [v1_TOKEN]\n    hosts: [api.example.com]\n", "is not a variable name"},
		{"twice", "  x:\n    command: [x]\n    secrets: [API_TOKEN, API_TOKEN]\n    hosts: [api.example.com]\n", "listed twice"},
		{"also in env", "  x:\n    command: [x]\n    env: {API_TOKEN: \"\"}\n    secrets: [API_TOKEN]\n    hosts: [api.example.com]\n", "also in env"},
		{"bad host", "  x:\n    command: [x]\n    hosts: [\"https://api.example.com\"]\n", "bare host name"},
		{"remote", "  x:\n    url: https://mcp.example.com/mcp\n    tools: {allow: [\"*\"]}\n    secrets: [API_TOKEN]\n", "only for a server with a command"},
		{"two secrets on a host", "  x:\n    command: [x]\n    secrets: [A_TOKEN, B_TOKEN]\n    hosts: [api.example.com]\n", "the sandbox puts one secret on a host"},
		{"two servers, two secrets", "  x:\n    command: [x]\n    secrets: [A_TOKEN]\n    hosts: [api.example.com]\n  y:\n    command: [y]\n    secrets: [B_TOKEN]\n    hosts: [api.example.com]\n", "would carry A_TOKEN (mcp.x) and B_TOKEN"},
		{"token header without token", "  x:\n    url: https://mcp.example.com/mcp\n    tools: {allow: [\"*\"]}\n    token_header: X-API-Key\n", "only with token: true"},
		{"token header authorization", "  x:\n    url: https://mcp.example.com/mcp\n    tools: {allow: [\"*\"]}\n    token: true\n    token_header: Authorization\n", "the default"},
		{"token header reserved", "  x:\n    url: https://mcp.example.com/mcp\n    tools: {allow: [\"*\"]}\n    token: true\n    token_header: Mcp-Session-Id\n", "set by the agent's MCP client"},
		{"token header bad", "  x:\n    url: https://mcp.example.com/mcp\n    tools: {allow: [\"*\"]}\n    token: true\n    token_header: \"X API\"\n", "is not a header name"},
		{"an MCP server's host", "  x:\n    command: [x]\n    hosts: [mcp.example.com]\n  y:\n    url: https://mcp.example.com/mcp\n    tools: {allow: [\"*\"]}\n", "is the MCP server mcp.y"},
	} {
		err := mcpDocument(t, "version: 1\nmcp:\n"+c.mcp).Validate()
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: want %q, got %v", c.name, c.want, err)
		}
	}
	_, err := Compile(mcpDocument(t, "version: 1\nmcp:\n  x:\n    command: [x]\n    secrets: [A_TOKEN]\n    hosts: [api.anthropic.com]\n"), Target{Agent: claude})
	if err == nil || !strings.Contains(err.Error(), "the claude model API") {
		t.Errorf("a secret on the model API: %v", err)
	}
	err = mcpDocument(t, "version: 1\nmcp:\n  do:\n    command: [npx, x]\n    env: {DIGITALOCEAN_API_TOKEN: dop_v1_abc}\n").Validate()
	if err == nil || !strings.Contains(err.Error(), "list DIGITALOCEAN_API_TOKEN under secrets") || !strings.Contains(err.Error(), "fenzi mcp token do --env DIGITALOCEAN_API_TOKEN") {
		t.Errorf("a secret value in env says what to do instead: %v", err)
	}
}

// A project or a team machine may list fewer secrets and hosts than the
// layer below, never more. The prover still sees the hosts, without the
// binding; the secrets are Fenzi's check.
func TestLocalServerSecretsNarrowOnly(t *testing.T) {
	base := mcpDocument(t, "version: 1\nmcp:\n  do:\n    command: [npx, do]\n    secrets: [DIGITALOCEAN_API_TOKEN]\n    hosts: [api.digitalocean.com]\n")
	for _, c := range []struct{ name, project, want string }{
		{"another host", "version: 1\nmcp:\n  do:\n    command: [npx, do]\n    secrets: [DIGITALOCEAN_API_TOKEN]\n    hosts: [api.digitalocean.com, paste.example.net]\n", "paste.example.net is not a host"},
		{"another secret", "version: 1\nmcp:\n  do:\n    command: [npx, do]\n    secrets: [DIGITALOCEAN_API_TOKEN, OTHER_TOKEN]\n    hosts: [api.digitalocean.com]\n", "OTHER_TOKEN is not a secret"},
	} {
		proj, err := Parse([]byte(c.project))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Merge(base, proj); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s merge: want %q, got %v", c.name, c.want, err)
		}
		if err := CheckMCP(proj, base); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s team: want %q, got %v", c.name, c.want, err)
		}
	}
	same := mcpDocument(t, "version: 1\nmcp:\n  do:\n    command: [npx, do]\n    secrets: [DIGITALOCEAN_API_TOKEN]\n    hosts: [api.digitalocean.com]\n")
	if err := CheckMCP(same, base); err != nil {
		t.Errorf("the same entry: %v", err)
	}
	if got := Effect(base, mcpDocument(t, "version: 1\nmcp:\n  do:\n    command: [npx, do]\n")); got != EffectWall {
		t.Errorf("dropping a secret changes the sandbox: %s", got)
	}
}

func TestSecretNaming(t *testing.T) {
	if SecretProvider("DIGITALOCEAN_API_TOKEN") != "fenzi-secret-digitalocean-api-token" {
		t.Error("the name changed; it is stored on machines")
	}
}

const connectorsDoc = `version: 1
mcp:
  claude-ai:
    account: claude
    tools:
      allow: [list_teams, list_issues]
      deny: [delete_issue]
  deepwiki:
    url: https://mcp.deepwiki.com/mcp
    tools: {allow: ["*"]}
`

// Claude's account connectors are one MCP rule on the host Claude Code
// reaches them all through, every path, for Claude's programs, with no token
// binding: Claude Code sends its own sign-in. This is the rule that passed
// initialize, tools/list and tools/call for three connectors on OpenShell
// 0.1.2, narrowed to the listed tools.
func TestAccountConnectorsRule(t *testing.T) {
	p, err := Compile(mcpDocument(t, connectorsDoc), Target{Agent: claude})
	if err != nil {
		t.Fatal(err)
	}
	r, ok := p.NetworkPolicies["mcp_claude_ai"]
	if !ok {
		t.Fatalf("no connectors rule: %v", p.NetworkPolicies)
	}
	e := r.Endpoints[0]
	if r.Name != ClaudeConnectorsHost || e.Host != ClaudeConnectorsHost || e.Port != 443 || e.Path != "" || e.Protocol != "mcp" || e.CredentialBinding != nil {
		t.Errorf("endpoint %+v", e)
	}
	if len(r.Binaries) != len(claude.Binaries) || r.Binaries[0].Path != claude.Binaries[0] {
		t.Errorf("binaries %+v", r.Binaries)
	}
	var tools []string
	for _, rule := range e.Rules {
		if rule.Allow.Method == "tools/call" {
			tools = append(tools, rule.Allow.Tool)
		}
	}
	if strings.Join(tools, ",") != "list_teams,list_issues" || len(e.DenyRules) != 1 || e.DenyRules[0].Tool != "delete_issue" {
		t.Errorf("tools %v, deny %+v", tools, e.DenyRules)
	}
	if _, ok := p.NetworkPolicies["mcp_deepwiki"]; !ok {
		t.Error("the other server keeps its rule")
	}

	codex := Agent{Name: "codex", Binaries: []string{"/usr/local/bin/codex"}}
	p, err = Compile(mcpDocument(t, connectorsDoc), Target{Agent: codex})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := p.NetworkPolicies["mcp_claude_ai"]; ok {
		t.Error("another agent gets no rule for Claude's connectors")
	}
	if _, ok := p.NetworkPolicies["mcp_deepwiki"]; !ok {
		t.Error("another agent keeps the other servers")
	}
}

func TestAccountConnectorsValidation(t *testing.T) {
	for name, body := range map[string]string{
		"no tools":      "mcp:\n  c:\n    account: claude\n",
		"other account": "mcp:\n  c:\n    account: openai\n    tools: {allow: [a]}\n",
		"with url":      "mcp:\n  c:\n    account: claude\n    url: https://mcp.example.com/mcp\n    tools: {allow: [a]}\n",
		"with command":  "mcp:\n  c:\n    account: claude\n    command: [a]\n    tools: {allow: [a]}\n",
		"with token":    "mcp:\n  c:\n    account: claude\n    token: true\n    tools: {allow: [a]}\n",
		"twice":         "mcp:\n  c:\n    account: claude\n    tools: {allow: [a]}\n  d:\n    account: claude\n    tools: {allow: [b]}\n",
		"url on host":   "mcp:\n  c:\n    account: claude\n    tools: {allow: [a]}\n  d:\n    url: https://mcp-proxy.anthropic.com/v1/mcp/x\n    tools: {allow: [b]}\n",
		"host rule":     "hosts:\n  - host: mcp-proxy.anthropic.com\n    access: read-only\nmcp:\n  c:\n    account: claude\n    tools: {allow: [a]}\n",
	} {
		if err := mcpDocument(t, "version: 1\n"+body).Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := mcpDocument(t, connectorsDoc).Validate(); err != nil {
		t.Errorf("the example is valid: %v", err)
	}
}

// A team boundary holds account connectors like any server: the same entry,
// and only the tools it allows. A project narrows them and cannot widen them.
func TestAccountConnectorsBoundary(t *testing.T) {
	team := mcpDocument(t, connectorsDoc)
	narrow := mcpDocument(t, "version: 1\nmcp:\n  claude-ai:\n    account: claude\n    tools: {allow: [list_teams], deny: [delete_issue]}\n")
	if err := CheckMCP(narrow, team); err != nil {
		t.Errorf("narrower: %v", err)
	}
	for name, body := range map[string]string{
		"extra tool": "mcp:\n  claude-ai:\n    account: claude\n    tools: {allow: [save_issue], deny: [delete_issue]}\n",
		"as a url":   "mcp:\n  claude-ai:\n    url: https://mcp-proxy.anthropic.com/\n    tools: {allow: [list_teams]}\n",
		"from local": "mcp:\n  claude-ai:\n    command: [x]\n",
	} {
		if err := CheckMCP(mcpDocument(t, "version: 1\n"+body), team); err == nil {
			t.Errorf("%s: passed the boundary", name)
		}
	}
	local := mcpDocument(t, "version: 1\nmcp:\n  claude-ai:\n    command: [x]\n")
	if err := CheckMCP(mcpDocument(t, "version: 1\nmcp:\n  claude-ai:\n    account: claude\n    tools: {allow: [a]}\n"), local); err == nil {
		t.Error("an account entry where the boundary has a local server")
	}
	wide := mcpDocument(t, "version: 1\nmcp:\n  claude-ai:\n    account: claude\n    tools: {allow: [\"*\"]}\n")
	if _, err := Merge(team, wide); err == nil || !strings.Contains(err.Error(), "only narrow") {
		t.Errorf("widening the connectors: %v", err)
	}
}

// A team member's own servers join the team's within its limits: a team
// server can only be narrowed, a new one must be inside the boundary when
// there is one, and team-only keeps them all out. A server outside is left
// out with its reason; the rest still join.
func TestMergeMemberMCP(t *testing.T) {
	team := mcpDocument(t, `version: 1
agents: [claude]
mcp:
  linear:
    url: https://mcp.linear.app/mcp
    tools:
      allow: [list_issues, get_issue]
`)
	member, err := Parse([]byte(`version: 1
mcp:
  linear:
    url: https://mcp.linear.app/mcp
    tools:
      allow: [list_issues]
  deepwiki:
    url: https://mcp.deepwiki.com/mcp
    tools:
      allow: [read_wiki_structure]
  wide:
    url: https://mcp.example.com/mcp
    tools:
      allow: [a]
`))
	if err != nil {
		t.Fatal(err)
	}
	out, refused := MergeMemberMCP(team, member, nil)
	if len(refused) != 0 || len(out.MCP) != 3 || !sameStrings(out.MCP["linear"].Tools.Allow, []string{"list_issues"}) {
		t.Fatalf("refused %v servers %v", refused, out.MCP)
	}
	if len(team.MCP) != 1 {
		t.Fatal("the team's document must not change")
	}

	// Widening a team server is refused, the others still join.
	member.MCP["linear"] = MCPServer{URL: "https://mcp.linear.app/mcp", Tools: MCPTools{Allow: []string{"delete_issue"}}}
	out, refused = MergeMemberMCP(team, member, nil)
	if !strings.Contains(refused["linear"], "delete_issue is not a tool the team allows") || !strings.Contains(refused["linear"], "can only narrow") {
		t.Fatalf("refused %v", refused)
	}
	if !sameStrings(out.MCP["linear"].Tools.Allow, []string{"list_issues", "get_issue"}) || len(out.MCP) != 3 {
		t.Fatalf("the team's linear stays as it is: %v", out.MCP)
	}

	// With a boundary, a new server must be one it allows.
	boundary := mcpDocument(t, `version: 1
agents: [claude]
mcp:
  linear:
    url: https://mcp.linear.app/mcp
    tools:
      allow: [list_issues, get_issue]
  deepwiki:
    url: https://mcp.deepwiki.com/mcp
    tools:
      allow: ["*"]
`)
	delete(member.MCP, "linear")
	out, refused = MergeMemberMCP(team, member, boundary)
	if _, ok := out.MCP["deepwiki"]; !ok || !strings.Contains(refused["wide"], "not an MCP server the team allows") {
		t.Fatalf("refused %v servers %v", refused, out.MCP)
	}

	// A server that makes the policy invalid is left out.
	member.MCP = map[string]MCPServer{"bad": {URL: "http://plain.example.com/mcp", Tools: MCPTools{Allow: []string{"a"}}}}
	if _, refused = MergeMemberMCP(team, member, nil); refused["bad"] == "" {
		t.Fatal("an invalid server must be refused")
	}

	// team-only: the team's servers and nothing else.
	team.MemberMCP = MemberMCPTeamOnly
	out, refused = MergeMemberMCP(team, member, nil)
	if len(out.MCP) != 1 || !strings.Contains(refused["bad"], "team's MCP servers only") {
		t.Fatalf("refused %v servers %v", refused, out.MCP)
	}
}

func TestMemberMCPSetting(t *testing.T) {
	d := mcpDocument(t, "version: 1\nmember_mcp: maybe\n")
	if err := d.Validate(); err == nil || !strings.Contains(err.Error(), "member_mcp: must be") {
		t.Fatalf("err %v", err)
	}
	allow := mcpDocument(t, "version: 1\nmember_mcp: allow\n")
	if err := allow.Validate(); err != nil || !allow.MembersMayAddMCP() || !(&Document{}).MembersMayAddMCP() {
		t.Fatal("allow and empty let members add servers")
	}
	only := mcpDocument(t, "version: 1\nmember_mcp: team-only\n")
	if Effect(allow, only) != EffectWall || Effect(&Document{Version: 1}, allow) != EffectSame {
		t.Fatal("team-only is a wall change; allow is the default")
	}
	if _, err := Merge(allow, only); err == nil || !strings.Contains(err.Error(), "member_mcp: set in a team's policy") {
		t.Fatalf("a project cannot set member_mcp: %v", err)
	}
}
