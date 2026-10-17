package agents

import (
	"encoding/json"
	"strings"
	"testing"

	"fenzi/compiler"
)

func mcpDoc(t *testing.T) *compiler.Document {
	t.Helper()
	d, err := compiler.Parse([]byte(`version: 1
mcp:
  linear:
    url: https://mcp.linear.app/mcp
    token: true
    tools: {allow: [list_issues]}
  files:
    command: [npx, -y, "@modelcontextprotocol/server-filesystem", /sandbox]
    env: {LOG_LEVEL: warn}
`))
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// Each format is what the agent read in the MCP experiments, with the token
// as the placeholder variable in the Authorization header.
func TestWithMCP(t *testing.T) {
	d := mcpDoc(t)
	tokenVar := compiler.MCPTokenEnv("linear")

	claude, err := Get("claude")
	if err != nil {
		t.Fatal(err)
	}
	c, files, err := claude.WithMCP(d)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 || files[0].Path != "/sandbox/.fenzi/mcp.json" {
		t.Fatalf("files %+v", files)
	}
	var cfg struct {
		MCPServers map[string]map[string]any `json:"mcpServers"`
	}
	if err := json.Unmarshal([]byte(files[0].Content), &cfg); err != nil {
		t.Fatal(err)
	}
	if h := cfg.MCPServers["linear"]["headers"].(map[string]any)["Authorization"]; h != "Bearer ${"+tokenVar+"}" || cfg.MCPServers["linear"]["type"] != "http" {
		t.Errorf("linear %v", cfg.MCPServers["linear"])
	}
	if cfg.MCPServers["files"]["command"] != "npx" || cfg.MCPServers["files"]["type"] != "stdio" {
		t.Errorf("files %v", cfg.MCPServers["files"])
	}
	line := strings.Join(c.CommandLine(nil), " ")
	if !strings.Contains(line, "--mcp-config /sandbox/.fenzi/mcp.json --strict-mcp-config") {
		t.Errorf("claude line %q", line)
	}
	if strings.Contains(strings.Join(claude.CommandLine(nil), " "), "mcp") {
		t.Error("WithMCP changed the catalog entry")
	}

	codex, _ := Get("codex")
	cx, files, err := codex.WithMCP(d)
	if err != nil || len(files) != 0 {
		t.Fatalf("%v %v", err, files)
	}
	argv := strings.Join(cx.Argv(nil), "\n")
	for _, want := range []string{
		`mcp_servers.linear.url="https://mcp.linear.app/mcp"`,
		`mcp_servers.linear.bearer_token_env_var="` + tokenVar + `"`,
		`mcp_servers.files.command="npx"`,
		`mcp_servers.files.args=["-y", "@modelcontextprotocol/server-filesystem", "/sandbox"]`,
		`mcp_servers.files.env={LOG_LEVEL = "warn"}`,
	} {
		if !strings.Contains(argv, want) {
			t.Errorf("codex argv missing %s:\n%s", want, argv)
		}
	}

	opencode, _ := Get("opencode")
	oc, _, err := opencode.WithMCP(d)
	if err != nil {
		t.Fatal(err)
	}
	var ocfg map[string]any
	if err := json.Unmarshal([]byte(oc.Env["OPENCODE_CONFIG_CONTENT"]), &ocfg); err != nil {
		t.Fatal(err)
	}
	if ocfg["enabled_providers"] == nil {
		t.Error("the catalog's own settings must stay")
	}
	lin := ocfg["mcp"].(map[string]any)["linear"].(map[string]any)
	if lin["type"] != "remote" || lin["headers"].(map[string]any)["Authorization"] != "Bearer {env:"+tokenVar+"}" {
		t.Errorf("opencode linear %v", lin)
	}
	if strings.Contains(opencode.Env["OPENCODE_CONFIG_CONTENT"], "mcp") {
		t.Error("WithMCP changed the catalog's env")
	}

	grok, _ := Get("grok")
	_, files, err = grok.WithMCP(d)
	if err != nil || len(files) != 1 || files[0].Path != "/sandbox/.grok/config.toml" {
		t.Fatalf("%v %+v", err, files)
	}
	for _, want := range []string{
		"[mcp_servers.linear]\nurl = \"https://mcp.linear.app/mcp\"\nenabled = true\n",
		"[mcp_servers.linear.headers]\nAuthorization = \"Bearer ${" + tokenVar + "}\"\n",
		"[mcp_servers.files]\ncommand = \"npx\"\n",
		"[mcp_servers.files.env]\nLOG_LEVEL = \"warn\"\n",
	} {
		if !strings.Contains(files[0].Content, want) {
			t.Errorf("grok config missing %q:\n%s", want, files[0].Content)
		}
	}
}

func TestWithMCPWithoutServers(t *testing.T) {
	claude, _ := Get("claude")
	got, files, err := claude.WithMCP(&compiler.Document{Version: 1})
	if err != nil || len(files) != 0 || strings.Join(got.Argv(nil), " ") != strings.Join(claude.Argv(nil), " ") {
		t.Errorf("no servers, no change: %v %v", err, files)
	}
	none := Entry{Name: "x", Display: "X"}
	if _, _, err := none.WithMCP(mcpDoc(t)); err == nil {
		t.Error("an agent with no MCP format must refuse servers")
	}
}

func TestEveryAgentTakesMCP(t *testing.T) {
	all, err := All()
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range all {
		if e.MCPFormat == "" {
			t.Errorf("%s has no mcp_format", e.Name)
		}
	}
}

func secretDoc(t *testing.T) *compiler.Document {
	t.Helper()
	d, err := compiler.Parse([]byte(`version: 1
mcp:
  droplets:
    command: [npx, -y, "@digitalocean/mcp", --services, droplets]
    env: {LOG_LEVEL: warn}
    secrets: [DIGITALOCEAN_API_TOKEN]
    hosts: [api.digitalocean.com]
`))
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// A secret reaches a local server under its own name, as a reference the
// agent fills from its environment, where the sandbox put the placeholder.
// Claude Code expands ${VAR} in env (seen in a sandbox); Codex passes only
// the variables env_vars names; OpenCode fills {env:VAR} and Grok ${VAR}
// (seen in plain Docker).
func TestWithMCPSecrets(t *testing.T) {
	d := secretDoc(t)
	claude, _ := Get("claude")
	_, files, err := claude.WithMCP(d)
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		MCPServers map[string]struct {
			Env map[string]string `json:"env"`
		} `json:"mcpServers"`
	}
	if err := json.Unmarshal([]byte(files[0].Content), &cfg); err != nil {
		t.Fatal(err)
	}
	if env := cfg.MCPServers["droplets"].Env; env["DIGITALOCEAN_API_TOKEN"] != "${DIGITALOCEAN_API_TOKEN}" || env["LOG_LEVEL"] != "warn" {
		t.Errorf("claude env %v", env)
	}
	if d.MCP["droplets"].Env["DIGITALOCEAN_API_TOKEN"] != "" {
		t.Error("WithMCP changed the document")
	}

	codex, _ := Get("codex")
	cx, _, err := codex.WithMCP(d)
	if err != nil {
		t.Fatal(err)
	}
	if argv := strings.Join(cx.Argv(nil), "\n"); !strings.Contains(argv, `mcp_servers.droplets.env_vars=["DIGITALOCEAN_API_TOKEN"]`) || strings.Contains(argv, "${DIGITALOCEAN_API_TOKEN}") {
		t.Errorf("codex argv:\n%s", argv)
	}

	opencode, _ := Get("opencode")
	oc, _, err := opencode.WithMCP(d)
	if err != nil {
		t.Fatal(err)
	}
	if cfg := oc.Env["OPENCODE_CONFIG_CONTENT"]; !strings.Contains(cfg, `"DIGITALOCEAN_API_TOKEN":"{env:DIGITALOCEAN_API_TOKEN}"`) || !strings.Contains(cfg, `"LOG_LEVEL":"warn"`) {
		t.Errorf("opencode config %s", cfg)
	}
	grok, _ := Get("grok")
	_, files, err = grok.WithMCP(d)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(files[0].Content, "[mcp_servers.droplets.env]\nDIGITALOCEAN_API_TOKEN = \"${DIGITALOCEAN_API_TOKEN}\"\nLOG_LEVEL = \"warn\"\n") {
		t.Errorf("grok config:\n%s", files[0].Content)
	}
	if _, _, err := (Entry{Name: "x", Display: "X", MCPFormat: "other"}).WithMCP(d); err == nil || !strings.Contains(err.Error(), "not checked yet") {
		t.Errorf("a format not checked with secrets must refuse: %v", err)
	}
	if _, _, err := (Entry{Name: "x", Display: "X", MCPFormat: MCPClaudeJSON, Key: Key{Env: "DIGITALOCEAN_API_TOKEN"}}).WithMCP(d); err == nil || !strings.Contains(err.Error(), "is the X key") {
		t.Errorf("a secret named like the agent's key: %v", err)
	}
}

// A remote server that reads its token from another header gets the
// placeholder there, as it is.
func TestWithMCPTokenHeader(t *testing.T) {
	d, err := compiler.Parse([]byte("version: 1\nmcp:\n  ctx:\n    url: https://mcp.example.com/mcp\n    token: true\n    token_header: X-API-Key\n    tools: {allow: [\"*\"]}\n"))
	if err != nil {
		t.Fatal(err)
	}
	v := compiler.MCPTokenEnv("ctx")
	claude, _ := Get("claude")
	_, files, err := claude.WithMCP(d)
	if err != nil || !strings.Contains(files[0].Content, `"X-API-Key": "${`+v+`}"`) || strings.Contains(files[0].Content, "Bearer") {
		t.Errorf("claude %v\n%s", err, files[0].Content)
	}
	codex, _ := Get("codex")
	cx, _, _ := codex.WithMCP(d)
	if argv := strings.Join(cx.Argv(nil), "\n"); !strings.Contains(argv, `mcp_servers.ctx.env_http_headers={"X-API-Key" = "`+v+`"}`) || strings.Contains(argv, "bearer_token_env_var") {
		t.Errorf("codex argv:\n%s", argv)
	}
	opencode, _ := Get("opencode")
	oc, _, _ := opencode.WithMCP(d)
	if !strings.Contains(oc.Env["OPENCODE_CONFIG_CONTENT"], `"X-API-Key":"{env:`+v+`}"`) {
		t.Errorf("opencode %s", oc.Env["OPENCODE_CONFIG_CONTENT"])
	}
	grok, _ := Get("grok")
	_, files, _ = grok.WithMCP(d)
	if !strings.Contains(files[0].Content, "[mcp_servers.ctx.headers]\nX-API-Key = \"${"+v+"}\"\n") {
		t.Errorf("grok:\n%s", files[0].Content)
	}
}

// Account connectors are not in any agent's config: Claude Code finds them
// itself. With them, Claude Code starts without --strict-mcp-config, under
// which 2.1.288 loads no account connectors; the other servers stay in the
// file it is given.
func TestWithMCPAccountConnectors(t *testing.T) {
	only, err := compiler.Parse([]byte("version: 1\nmcp:\n  claude-ai:\n    account: claude\n    tools: {allow: [list_teams]}\n"))
	if err != nil {
		t.Fatal(err)
	}
	claude, _ := Get("claude")
	c, files, err := claude.WithMCP(only)
	if err != nil || len(files) != 0 || strings.Join(c.Argv(nil), " ") != strings.Join(claude.Argv(nil), " ") {
		t.Errorf("connectors alone change nothing in Claude's config: %v %v %v", err, files, c.Argv(nil))
	}

	both, err := compiler.Parse([]byte("version: 1\nmcp:\n  claude-ai:\n    account: claude\n    tools: {allow: [list_teams]}\n  deepwiki:\n    url: https://mcp.deepwiki.com/mcp\n    tools: {allow: [\"*\"]}\n"))
	if err != nil {
		t.Fatal(err)
	}
	c, files, err = claude.WithMCP(both)
	if err != nil || len(files) != 1 {
		t.Fatalf("%v %v", err, files)
	}
	line := strings.Join(c.CommandLine(nil), " ")
	if !strings.Contains(line, "--mcp-config /sandbox/.fenzi/mcp.json") || strings.Contains(line, "--strict-mcp-config") {
		t.Errorf("claude line %q", line)
	}
	if strings.Contains(files[0].Content, "claude-ai") || !strings.Contains(files[0].Content, "deepwiki") {
		t.Errorf("config:\n%s", files[0].Content)
	}

	for _, name := range []string{"codex", "opencode", "grok"} {
		a, _ := Get(name)
		_, _, err := a.WithMCP(only)
		if err != nil {
			t.Errorf("%s with Claude's connectors only: %v", name, err)
		}
		got, files, err := a.WithMCP(both)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		all := strings.Join(got.Argv(nil), " ") + got.Env["OPENCODE_CONFIG_CONTENT"]
		for _, f := range files {
			all += f.Content
		}
		if strings.Contains(all, "claude-ai") || !strings.Contains(all, "deepwiki") {
			t.Errorf("%s config: %s", name, all)
		}
	}
}
