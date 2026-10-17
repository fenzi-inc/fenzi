package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"fenzi/cli/internal/config"
	"fenzi/cli/internal/run"
	"fenzi/compiler"
)

// TestMain keeps every test in this package away from the machine's own
// config, which now includes ~/.config/fenzi/mcp.yaml.
func TestMain(m *testing.M) {
	cfg, _ := os.MkdirTemp("", "fenzi-test-config-")
	cache, _ := os.MkdirTemp("", "fenzi-test-cache-")
	os.Setenv("XDG_CONFIG_HOME", cfg)
	os.Setenv("XDG_CACHE_HOME", cache)
	code := m.Run()
	os.RemoveAll(cfg)
	os.RemoveAll(cache)
	os.Exit(code)
}

func mcpFixture(t *testing.T) string {
	t.Helper()
	fakeRuntime(t, map[string]reply{
		"provider get fenzi-mcp-linear": {},
		"provider get":                  {exit: 1},
	}, proverWithin)
	repo := t.TempDir()
	t.Chdir(repo)
	return repo
}

func TestMCPAddListRemove(t *testing.T) {
	repo := mcpFixture(t)
	out, code := runCLI(t, "", "mcp", "add", "linear", "https://mcp.linear.app/mcp", "--tool", "list_issues", "--tool", "get_issue", "--deny", "delete_issue", "--token")
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	if out, code := runCLI(t, "", "mcp", "add", "files", "--", "npx", "-y", "server-filesystem", "/sandbox"); code != 0 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	raw, err := os.ReadFile(filepath.Join(repo, "fenzi.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := compiler.Parse(raw)
	if err != nil {
		t.Fatalf("%v\n%s", err, raw)
	}
	lin := doc.MCP["linear"]
	if lin.URL != "https://mcp.linear.app/mcp" || !lin.Token || strings.Join(lin.Tools.Allow, ",") != "list_issues,get_issue" || strings.Join(lin.Tools.Deny, ",") != "delete_issue" {
		t.Errorf("linear %+v", lin)
	}
	if strings.Join(doc.MCP["files"].Command, " ") != "npx -y server-filesystem /sandbox" {
		t.Errorf("files %+v", doc.MCP["files"])
	}

	var list []jsonMCP
	if stderr, code := runJSON(t, &list, "mcp", "list", "--json"); code != 0 || stderr != "" {
		t.Fatalf("exit %d %s", code, stderr)
	}
	if len(list) != 2 || list[1].Name != "linear" || list[1].Source != "project" || list[1].TokenStored == nil || !*list[1].TokenStored {
		t.Errorf("list %+v", list)
	}

	if out, code := runCLI(t, "", "mcp", "remove", "files"); code != 0 || !strings.Contains(out, "Removed") {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	raw, _ = os.ReadFile(filepath.Join(repo, "fenzi.yaml"))
	if strings.Contains(string(raw), "files") {
		t.Errorf("not removed:\n%s", raw)
	}
}

func TestMCPAddRefuses(t *testing.T) {
	mcpFixture(t)
	for name, args := range map[string][]string{
		"no tools":         {"mcp", "add", "x", "https://mcp.example.com/mcp"},
		"http":             {"mcp", "add", "x", "http://mcp.example.com/mcp", "--tool", "a"},
		"local with tools": {"mcp", "add", "x", "--tool", "a", "--", "npx", "s"},
		"model host":       {"mcp", "add", "x", "https://api.github.com/mcp", "--tool", "a"},
	} {
		if out, code := runCLI(t, "", args...); code == 0 {
			t.Errorf("%s: accepted:\n%s", name, out)
		}
	}
	if _, err := os.Stat("fenzi.yaml"); err == nil {
		raw, _ := os.ReadFile("fenzi.yaml")
		if strings.Contains(string(raw), "mcp.example.com") {
			t.Errorf("a refused server was written:\n%s", raw)
		}
	}
}

// The machine file is a layer under the project: a project adds servers and
// narrows the machine's, and cannot widen them.
func TestMCPMachineLayer(t *testing.T) {
	repo := mcpFixture(t)
	if out, code := runCLI(t, "", "mcp", "add", "deepwiki", "https://mcp.deepwiki.com/mcp", "--tool", "read_wiki_structure", "--machine"); code != 0 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	if _, err := os.Stat(machineMCPFile()); err != nil {
		t.Fatalf("machine file: %v", err)
	}
	out, code := runCLI(t, "", "mcp", "add", "deepwiki", "https://mcp.deepwiki.com/mcp", "--all-tools")
	if code == 0 || !strings.Contains(out, "can only narrow") {
		t.Fatalf("widening the machine's server: exit %d\n%s", code, out)
	}
	resolved, err := run.ResolveFree(repo, "")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(resolved.Sources, run.MachineMCPSource) || len(resolved.Doc.MCP["deepwiki"].Tools.Allow) != 1 {
		t.Errorf("resolved %s %+v", resolved.Sources, resolved.Doc.MCP)
	}
}

func TestMCPImport(t *testing.T) {
	repo := mcpFixture(t)
	if err := os.WriteFile(filepath.Join(repo, ".mcp.json"), []byte(`{"mcpServers":{
  "Linear_App": {"type":"http","url":"https://mcp.linear.app/mcp","headers":{"Authorization":"Bearer lin_api_secret"}},
  "files": {"command":"npx","args":["-y","server-filesystem"],"env":{"LOG_LEVEL":"warn"}}
}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	out, code := runCLI(t, "", "mcp", "import")
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	raw, _ := os.ReadFile(filepath.Join(repo, "fenzi.yaml"))
	s := string(raw)
	if strings.Contains(s, "lin_api_secret") {
		t.Fatal("a token was copied into fenzi.yaml")
	}
	doc, err := compiler.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if l := doc.MCP["linear-app"]; !l.Token || !l.Tools.AllowsAll() {
		t.Errorf("linear-app %+v", l)
	}
	if !strings.Contains(out, "fenzi mcp token linear-app") || !strings.Contains(out, "every tool allowed") {
		t.Errorf("output:\n%s", out)
	}
}

// Recorded from OpenShell 0.1.2: a proposal for an MCP server, which `rule
// approve` would store as every tool (NVIDIA/OpenShell#4679).
const mcpPending = `Network Rules:  (version 1, 1 chunk)

  Chunk: 3c58ba8c-54ab-410e-be35-d00e3f79dec4
  Status: pending
  Rule: mcp_proposal
  Binary: /usr/bin/curl
  Confidence: 75%
  Rationale: Read the structure of the wiki of one repository.
  Prover: prover: no new findings
  Candidate: 059f6b0c8744
  Endpoints: mcp.example.org:443 [mcp, allow initialize *, allow tools/list *, allow tools/call *]
  Binaries: /usr/bin/curl
`

func TestApproveRefusesAnMCPRequest(t *testing.T) {
	fakeRuntime(t, map[string]reply{
		"sandbox list": {out: "bl-web-1a2b\n"},
		"rule get":     {out: mcpPending},
	}, proverWithin)
	repo := t.TempDir()
	t.Chdir(repo)
	seedState(t, config.Sandbox{Name: "bl-web-1a2b", Agent: "claude", Repo: repo, Created: time.Now(), Running: true})
	out, code := runCLI(t, "", "approve", "3c58ba8c", "--sandbox", "bl-web-1a2b")
	if code == 0 || !strings.Contains(out, "OpenShell#4679") || !strings.Contains(out, "fenzi mcp add") {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	for _, c := range runtimeCalls(t) {
		if strings.HasPrefix(c, "rule approve") {
			t.Fatalf("the MCP request was approved: %s", c)
		}
	}
}
