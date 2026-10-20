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

// fenzi mcp allow adds tools to the entry in the file it comes from.
func TestMCPAllow(t *testing.T) {
	repo := mcpFixture(t)
	if out, code := runCLI(t, "", "mcp", "add", "linear", "https://mcp.linear.app/mcp", "--tool", "list_issues", "--deny", "delete_issue"); code != 0 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	out, code := runCLI(t, "", "mcp", "allow", "linear", "get_issue", "list_issues", "create_comment")
	if code != 0 || !strings.Contains(out, "Allowed") || !strings.Contains(out, "get_issue, create_comment on linear in ./fenzi.yaml") {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	raw, _ := os.ReadFile(filepath.Join(repo, "fenzi.yaml"))
	doc, err := compiler.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(doc.MCP["linear"].Tools.Allow, ","); got != "list_issues,get_issue,create_comment" {
		t.Errorf("allow = %s", got)
	}
	if strings.Join(doc.MCP["linear"].Tools.Deny, ",") != "delete_issue" || doc.MCP["linear"].URL != "https://mcp.linear.app/mcp" {
		t.Errorf("the rest of the entry changed: %+v", doc.MCP["linear"])
	}

	if out, code := runCLI(t, "", "mcp", "allow", "linear", "get_issue"); code != 0 || !strings.Contains(out, "Nothing to change") {
		t.Errorf("again: exit %d:\n%s", code, out)
	}
	if out, code := runCLI(t, "", "mcp", "allow", "linear", "delete_issue"); code != 1 || !strings.Contains(out, "denies delete_issue") {
		t.Errorf("a denied tool: exit %d:\n%s", code, out)
	}
	if out, code := runCLI(t, "", "mcp", "add", "files", "--", "npx", "-y", "server-filesystem", "/sandbox"); code != 0 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	if out, code := runCLI(t, "", "mcp", "allow", "files", "read"); code != 1 || !strings.Contains(out, "local server") {
		t.Errorf("a local server: exit %d:\n%s", code, out)
	}
	if out, code := runCLI(t, "", "mcp", "allow", "nowhere", "x"); code != 1 || !strings.Contains(out, "fenzi mcp list") {
		t.Errorf("an unknown server: exit %d:\n%s", code, out)
	}
	if out, code := runCLI(t, "", "mcp", "add", "wiki", "https://mcp.deepwiki.com/mcp", "--all-tools"); code != 0 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	if out, code := runCLI(t, "", "mcp", "allow", "wiki", "ask_question"); code != 0 || !strings.Contains(out, "already allows every tool") {
		t.Errorf("every tool: exit %d:\n%s", code, out)
	}
}

// An entry only in the machine file is edited there.
func TestMCPAllowMachineEntry(t *testing.T) {
	mcpFixture(t)
	if out, code := runCLI(t, "", "mcp", "add", "conn-allow", "--claude-account", "--tool", "list_teams", "--machine"); code != 0 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	t.Cleanup(func() { runCLI(t, "", "mcp", "remove", "conn-allow", "--machine") })
	out, code := runCLI(t, "", "mcp", "allow", "conn-allow", "api_request")
	if code != 0 || !strings.Contains(out, run.MachineMCPSource) {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	m, err := run.LoadMachineMCP()
	if err != nil || m == nil {
		t.Fatalf("machine file: %v", err)
	}
	if got := strings.Join(m.MCP["conn-allow"].Tools.Allow, ","); got != "list_teams,api_request" {
		t.Errorf("allow = %s", got)
	}
	if _, err := os.Stat("fenzi.yaml"); err == nil {
		raw, _ := os.ReadFile("fenzi.yaml")
		if strings.Contains(string(raw), "conn-allow") {
			t.Errorf("written to the project too:\n%s", raw)
		}
	}
}

// fenzi requests lists the MCP tools the policy refused, with the command
// that allows each. The deny line is what OpenShell 0.1.4 printed on
// 19 October 2026; the empty rule list is the 0.1.4 recording.
func TestRequestsListsRefusedMCPTools(t *testing.T) {
	deny := "[1792410634.010] [sandbox] [OCSF ] [ocsf] HTTP:POST [MED] DENIED POST http://mcp-proxy.anthropic.com:443/v1/mcp/mcpsrv_01NXbt6n5Hhyz7zFREQtXmcQ [policy:mcp_claude_ai engine:l7-mcp] [reason:JSONRPC_L7_REQUEST decision=deny rule_methods=tools/call tools=api_request http_method=POST endpoint=mcp-proxy.anthropic.com:443/v1/mcp/mcpsrv_01NXbt6n5Hhyz7zFREQtXmcQ policy_version=1 reason=MCP tool call has no matching allow rule; ask the policy owner t...]\n"
	fakeRuntime(t, map[string]reply{
		"sandbox list": {out: "fenzi-hello-5eff\n"},
		"rule get":     {out: "No network rules for sandbox 'fenzi-hello-5eff'\n"},
		"logs":         {out: deny + deny + deny},
	}, "")
	dirs := seedState(t, config.Sandbox{Name: "fenzi-hello-5eff", Agent: "claude", Repo: t.TempDir(), Created: time.Now(), Running: true})
	runDir := dirs.Run("fenzi-hello-5eff")
	if err := os.MkdirAll(runDir, 0o755); err != nil {
		t.Fatal(err)
	}
	resolved := "version: 1\nmcp:\n  claude-ai:\n    account: claude\n    tools:\n      allow: [list_issues]\n"
	if err := os.WriteFile(filepath.Join(runDir, run.ResolvedFile), []byte(resolved), 0o600); err != nil {
		t.Fatal(err)
	}
	out, code := runCLI(t, "", "requests", "--sandbox", "fenzi-hello-5eff")
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	for _, want := range []string{"No requests", "1 MCP tool the policy refused", "api_request", "on claude-ai, 3 times", "fenzi mcp allow claude-ai api_request"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	// The JSON is the requests alone, as before.
	var docs []jsonRequest
	if stderr, code := runJSON(t, &docs, "requests", "--sandbox", "fenzi-hello-5eff", "--json"); code != 0 || len(docs) != 0 {
		t.Errorf("json: exit %d %s %+v", code, stderr, docs)
	}
}
