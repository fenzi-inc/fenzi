package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// viewProject is a project file with every kind of entry the readable policy
// lists: a path, a read-write host with its methods, a remote MCP server with
// a token and a denied tool, one that allows every tool, a local server with
// a secret, and Claude's account connectors.
const viewProject = `version: 1
paths:
  read_only: [/opt/data]
hosts:
  - host: api.example.com
    access: read-write
    allow:
      - GET /v1/**
      - POST /v1/items
mcp:
  linear:
    url: https://mcp.linear.app/mcp
    token: true
    tools:
      allow: [list_issues, create_issue]
      deny: [delete_issue]
  everything:
    url: https://mcp.example.net/
    tools:
      allow: ["*"]
  do:
    command: [npx, digitalocean-mcp]
    secrets: [DIGITALOCEAN_API_TOKEN]
    hosts: [api.digitalocean.com]
  claude-ai:
    account: claude
    tools:
      allow: [list_teams]
`

func TestPolicyViewReadsTheCompiledPolicy(t *testing.T) {
	fakeRuntime(t, nil, proverWithin)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "fenzi.yaml"), []byte(viewProject), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	var doc jsonPolicyCheck
	if stderr, code := runJSON(t, &doc, "policy", "check", "--agent", "claude", "--json"); code != 0 || stderr != "" {
		t.Fatalf("exit %d stderr %q", code, stderr)
	}
	v := doc.Policy
	if v == nil {
		t.Fatal("no policy object")
	}
	if v.Sources != "developer-default (built in) + ./fenzi.yaml" || v.Revision != 0 || v.Approvals != "person" {
		t.Errorf("sources %q revision %d approvals %q", v.Sources, v.Revision, v.Approvals)
	}
	if !reflect.DeepEqual(v.Agents, []string{"claude", "codex", "grok", "opencode"}) {
		t.Errorf("agents = %v", v.Agents)
	}
	if v.Workspace != (jsonPolicyPath{Path: "/sandbox", Access: "read-write"}) {
		t.Errorf("workspace = %+v", v.Workspace)
	}
	// The listed path is the person's; the rest are OpenShell's baseline.
	var mine, baseline int
	for _, p := range v.Paths {
		if p.Path == "/sandbox" {
			t.Errorf("the workspace is listed again under paths")
		}
		if p.Baseline {
			baseline++
		} else {
			mine++
			// The project file lists it, so the screen may change it.
			if p != (jsonPolicyPath{Path: "/opt/data", Access: "read-only", Project: true}) {
				t.Errorf("path = %+v", p)
			}
		}
	}
	if mine != 1 || baseline < 8 {
		t.Errorf("%d listed paths, %d baseline paths: %+v", mine, baseline, v.Paths)
	}

	hosts := map[string]jsonPolicyHost{}
	for _, h := range v.Hosts {
		hosts[h.Host] = h
	}
	if h := hosts["api.example.com"]; h.Port != 443 || h.Access != "read-write" || h.From != "policy" || !reflect.DeepEqual(h.Allow, []string{"GET /v1/**", "POST /v1/items"}) {
		t.Errorf("api.example.com = %+v", h)
	}
	if h := hosts["api.github.com"]; h.Access != "read-only" || h.From != "policy" || len(h.Allow) != 0 || h.Allow == nil {
		t.Errorf("api.github.com = %+v", h)
	}
	// The project's own host is marked; developer-default's is not.
	if !hosts["api.example.com"].Project || hosts["api.github.com"].Project {
		t.Errorf("project marks: api.example.com %v, api.github.com %v", hosts["api.example.com"].Project, hosts["api.github.com"].Project)
	}
	// The agent's own host, with the one write its sign-in needs.
	if h := hosts["platform.claude.com"]; h.From != "agent" || h.Access != "read-write" || !reflect.DeepEqual(h.Allow, []string{"GET /**", "HEAD /**", "OPTIONS /**", "POST /v1/oauth/token"}) {
		t.Errorf("platform.claude.com = %+v", h)
	}
	// The local server's host, with the secret the sandbox puts on it.
	if h := hosts["api.digitalocean.com"]; h.From != "mcp" || h.Server != "do" || h.Secret != "DIGITALOCEAN_API_TOKEN" || h.Access != "read-write" || len(h.Allow) != 0 {
		t.Errorf("api.digitalocean.com = %+v", h)
	}
	// Remote MCP servers are not hosts; the model API is not a host.
	for _, name := range []string{"mcp.linear.app", "mcp.example.net", "mcp-proxy.anthropic.com", "api.anthropic.com"} {
		if _, ok := hosts[name]; ok {
			t.Errorf("%s is listed under hosts", name)
		}
	}

	if !reflect.DeepEqual(v.Model, []jsonPolicyModel{{Host: "api.anthropic.com", Port: 443, Access: "read-write", KeyEnv: "ANTHROPIC_API_KEY"}}) {
		t.Errorf("model = %+v", v.Model)
	}

	mcp := map[string]jsonPolicyMCP{}
	for _, m := range v.MCP {
		mcp[m.Name] = m
	}
	if len(mcp) != 4 {
		t.Fatalf("mcp = %+v", v.MCP)
	}
	if m := mcp["linear"]; m.Kind != "remote" || m.Host != "mcp.linear.app" || m.Port != 443 || m.Path != "/mcp" || !m.Token || m.AllTools ||
		!reflect.DeepEqual(m.Tools, []string{"list_issues", "create_issue"}) || !reflect.DeepEqual(m.Deny, []string{"delete_issue"}) {
		t.Errorf("linear = %+v", m)
	}
	if m := mcp["everything"]; m.Kind != "remote" || !m.AllTools || len(m.Tools) != 0 || m.Tools == nil || m.Deny == nil {
		t.Errorf("everything = %+v", m)
	}
	if m := mcp["do"]; m.Kind != "local" || !reflect.DeepEqual(m.Command, []string{"npx", "digitalocean-mcp"}) || !reflect.DeepEqual(m.Secrets, []string{"DIGITALOCEAN_API_TOKEN"}) || !reflect.DeepEqual(m.Hosts, []string{"api.digitalocean.com"}) || m.Host != "" {
		t.Errorf("do = %+v", m)
	}
	if m := mcp["claude-ai"]; m.Kind != "connectors" || m.Host != "mcp-proxy.anthropic.com" || !reflect.DeepEqual(m.Tools, []string{"list_teams"}) {
		t.Errorf("claude-ai = %+v", m)
	}

	// Another agent does not get Claude's connectors, and has its own model host.
	if stderr, code := runJSON(t, &doc, "policy", "check", "--agent", "codex", "--json"); code != 0 || stderr != "" {
		t.Fatalf("codex: exit %d stderr %q", code, stderr)
	}
	for _, m := range doc.Policy.MCP {
		if m.Name == "claude-ai" {
			t.Errorf("codex gets claude-ai: %+v", m)
		}
	}
	if len(doc.Policy.MCP) != 3 || len(doc.Policy.Model) != 1 || doc.Policy.Model[0].Host == "api.anthropic.com" {
		t.Errorf("codex: mcp %+v model %+v", doc.Policy.MCP, doc.Policy.Model)
	}
}

func TestPolicyViewWithTheBuiltInPolicyAlone(t *testing.T) {
	fakeRuntime(t, nil, proverWithin)
	t.Chdir(t.TempDir())
	var doc jsonPolicyCheck
	if stderr, code := runJSON(t, &doc, "policy", "check", "--json"); code != 0 || stderr != "" {
		t.Fatalf("exit %d stderr %q", code, stderr)
	}
	v := doc.Policy
	if v == nil || v.Sources != "developer-default (built in)" || len(v.MCP) != 0 || v.MCP == nil || v.Paths == nil {
		t.Fatalf("policy = %+v", v)
	}
	var names []string
	for _, h := range v.Hosts {
		names = append(names, h.Host+":"+h.From)
	}
	want := "api.github.com:policy codeload.github.com:policy files.pythonhosted.org:policy github.com:policy objects.githubusercontent.com:policy platform.claude.com:agent pypi.org:policy raw.githubusercontent.com:policy registry.npmjs.org:policy release-assets.githubusercontent.com:policy"
	if got := strings.Join(names, " "); got != want {
		t.Errorf("hosts = %s", got)
	}
}

func TestJSONStatusCarriesThePublishedTime(t *testing.T) {
	_, _ = signedInMachine(t)
	var doc jsonStatus
	if stderr, code := runJSON(t, &doc, "status", "--json"); code != 0 || stderr != "" {
		t.Fatalf("exit %d stderr %q", code, stderr)
	}
	// signed() publishes r2 at noon on 15 October 2026.
	if doc.PolicyRevision != 2 || doc.PolicyPublished != "2026-10-15T12:00:00Z" {
		t.Errorf("status = %+v", doc)
	}
}
