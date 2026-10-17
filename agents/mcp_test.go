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
