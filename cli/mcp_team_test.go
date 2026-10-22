package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"fenzi/cli/internal/config"
	"fenzi/cli/internal/team"
	"fenzi/teamapi"
)

const teamMCPDoc = `version: 1
name: acme
agents: [claude]
workspace: read-write
approvals: person
mcp:
  linear:
    url: https://mcp.linear.app/mcp
    tools:
      allow: [list_issues, get_issue]
`

// enrollTeamDoc signs this test's config folder in to a console that serves
// r4 with document as the team's policy, and caches r4.
func enrollTeamDoc(t *testing.T, document string) config.Dirs {
	t.Helper()
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	b := teamapi.Bundle{Tenant: "acme", Revision: 4, Document: []byte(document), Published: time.Date(2026, 10, 22, 9, 0, 0, 0, time.UTC)}
	b.Signature = ed25519.Sign(key, teamapi.Message(b))
	srv := httptest.NewServer(&refusingConsole{bundle: teamapi.ToWire(b)})
	t.Cleanup(srv.Close)
	dirs, err := config.Default()
	if err != nil {
		t.Fatal(err)
	}
	en := team.Enrollment{
		Server: srv.URL, Token: "tok", Email: "dana@acme.dev", Tenant: "acme", Machine: "mbp",
		PublicKey: base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey)),
	}
	if err := en.Take(b); err != nil {
		t.Fatal(err)
	}
	if err := en.Save(dirs); err != nil {
		t.Fatal(err)
	}
	return dirs
}

// On a team, a member adds servers of their own to this machine's file, and
// agents get them beside the team's. A team server can only be narrowed,
// this folder's fenzi.yaml is not used, and team-only keeps the machine's
// servers out.
func TestMemberMCPOnTeam(t *testing.T) {
	fakeRuntime(t, nil, proverWithin)
	enrollTeamDoc(t, teamMCPDoc)
	repo := t.TempDir()
	t.Chdir(repo)

	if out, code := runCLI(t, "", "mcp", "add", "deepwiki", "https://mcp.deepwiki.com/mcp", "--tool", "read_wiki_structure"); code == 0 || !strings.Contains(out, "--machine") {
		t.Fatalf("this folder's fenzi.yaml is not used on a team: exit %d\n%s", code, out)
	}
	if out, code := runCLI(t, "", "mcp", "add", "deepwiki", "https://mcp.deepwiki.com/mcp", "--tool", "read_wiki_structure", "--machine"); code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	if out, code := runCLI(t, "", "mcp", "add", "linear", "https://mcp.linear.app/mcp", "--tool", "delete_issue", "--machine"); code == 0 || !strings.Contains(out, "can only narrow") {
		t.Fatalf("widening the team's server must be refused before it is written: exit %d\n%s", code, out)
	}
	if out, code := runCLI(t, "", "mcp", "allow", "linear", "delete_issue"); code == 0 || !strings.Contains(out, "team console") {
		t.Fatalf("a team server's tools are the admin's: exit %d\n%s", code, out)
	}

	var servers []jsonMCP
	if stderr, code := runJSON(t, &servers, "mcp", "list", "--json"); code != 0 {
		t.Fatalf("exit %d %s", code, stderr)
	}
	sources := map[string]string{}
	for _, s := range servers {
		sources[s.Name] = s.Source + s.Refused
	}
	if sources["linear"] != "team" || sources["deepwiki"] != "machine" || len(servers) != 2 {
		t.Fatalf("servers %+v", servers)
	}

	// A server written by hand that widens the team's is listed as not used.
	machineFile := machineMCPFile()
	raw, _ := os.ReadFile(machineFile)
	wide := string(raw) + "  linear:\n    url: https://mcp.linear.app/mcp\n    tools:\n      allow: [delete_issue]\n"
	if err := os.WriteFile(machineFile, []byte(wide), 0o600); err != nil {
		t.Fatal(err)
	}
	servers = nil
	runJSON(t, &servers, "mcp", "list", "--json")
	var refused string
	for _, s := range servers {
		if s.Name == "linear" && s.Source == "machine" {
			refused = s.Refused
		}
	}
	if !strings.Contains(refused, "delete_issue") || len(servers) != 3 {
		t.Fatalf("servers %+v", servers)
	}
}

func TestTeamOnlyKeepsMachineServersOut(t *testing.T) {
	fakeRuntime(t, nil, proverWithin)
	enrollTeamDoc(t, teamMCPDoc+"member_mcp: team-only\n")
	t.Chdir(t.TempDir())
	if out, code := runCLI(t, "", "mcp", "add", "deepwiki", "https://mcp.deepwiki.com/mcp", "--tool", "read_wiki_structure", "--machine"); code == 0 || !strings.Contains(out, "team's MCP servers only") {
		t.Fatalf("exit %d\n%s", code, out)
	}
	if err := os.MkdirAll(filepath.Dir(machineMCPFile()), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(machineMCPFile(), []byte("version: 1\nmcp:\n  deepwiki:\n    url: https://mcp.deepwiki.com/mcp\n    tools:\n      allow: [read_wiki_structure]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, code := runCLI(t, "", "mcp", "list")
	if code != 0 || !strings.Contains(out, "not used: the team's policy gives agents the team's MCP servers only") || !strings.Contains(out, "is not used") {
		t.Fatalf("exit %d\n%s", code, out)
	}
	var st jsonStatus
	if _, code := runJSON(t, &st, "status", "--json"); code != 0 || st.MemberMCP != "team-only" {
		t.Fatalf("status %+v", st)
	}
}
