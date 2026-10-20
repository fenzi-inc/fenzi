package main

// The policy as a person reads it: what the agent can touch once the
// compiler has done its work. fenzi policy check --json carries it as the
// "policy" object, so the Mac app can answer "what can this agent touch"
// without reading the OpenShell YAML and without a second compiler. It is
// built from the same compiled policy the prover checks, plus the parts the
// compiled policy does not carry by name: which host came from the document,
// from the agent's catalog entry, or from a local MCP server; the model host
// the provider adds with the key; and the MCP servers and their tools.

import (
	"fmt"
	"sort"
	"strings"

	"fenzi/agents"
	"fenzi/cli/internal/run"
	"fenzi/compiler"
)

// jsonPolicyView is the "policy" object of fenzi policy check --json.
type jsonPolicyView struct {
	// Sources is where the policy came from, as the text output names it:
	// "developer-default (built in) + ./fenzi.yaml" or "acme r14 (signed)".
	Sources string `json:"sources"`
	// Revision is the team revision on a signed-in machine, 0 on Free.
	Revision int `json:"revision"`
	// Agents is the document's agents list; empty means every agent.
	Agents []string `json:"agents"`
	// Approvals is who answers a request: "person".
	Approvals string            `json:"approvals"`
	Workspace jsonPolicyPath    `json:"workspace"`
	Paths     []jsonPolicyPath  `json:"paths"`
	Hosts     []jsonPolicyHost  `json:"hosts"`
	Model     []jsonPolicyModel `json:"model"`
	MCP       []jsonPolicyMCP   `json:"mcp"`
}

// jsonPolicyPath is one path the sandbox may read or write.
type jsonPolicyPath struct {
	Path string `json:"path"`
	// Access is read-only or read-write.
	Access string `json:"access"`
	// Baseline marks a path OpenShell needs for any program to run (/usr,
	// /etc, /tmp and the like), listed by the compiler, not by the policy.
	Baseline bool `json:"baseline,omitempty"`
	// Project marks a path this folder's fenzi.yaml lists, which
	// fenzi policy path can change.
	Project bool `json:"project,omitempty"`
}

// jsonPolicyHost is one host the agent's programs may reach.
type jsonPolicyHost struct {
	Host string `json:"host"`
	Port int    `json:"port"`
	// Access is read-only (every GET, HEAD and OPTIONS) or read-write.
	// Allow lists the "METHOD /path" lines of a read-write host; empty on
	// a read-write host means every method, as a local MCP server's host
	// gets.
	Access string   `json:"access"`
	Allow  []string `json:"allow"`
	// From says who asked for the host: "policy" for the document, "agent"
	// for a host the agent cannot start without (from its catalog entry),
	// "mcp" for a host a local MCP server calls.
	From string `json:"from"`
	// Project marks a host this folder's fenzi.yaml lists, which
	// fenzi policy host can change or remove.
	Project bool `json:"project,omitempty"`
	// Server names the local MCP server for a host From "mcp".
	Server string `json:"server,omitempty"`
	// Secret is the variable whose stored value the sandbox puts on requests
	// to this host, for a local MCP server's host.
	Secret string `json:"secret,omitempty"`
}

// jsonPolicyModel is the model API the agent's provider adds to the
// effective policy, with the key the sandbox injects there.
type jsonPolicyModel struct {
	Host   string `json:"host"`
	Port   int    `json:"port"`
	Access string `json:"access"`
	// KeyEnv is the variable the key is stored under (fenzi key set).
	KeyEnv string `json:"key_env"`
}

// jsonPolicyMCP is one MCP server the agent gets.
type jsonPolicyMCP struct {
	Name string `json:"name"`
	// Kind is remote (a URL the sandbox checks per tool), connectors (the
	// agent's account connectors, checked the same way), or local (a
	// command that runs inside the sandbox).
	Kind string `json:"kind"`
	URL  string `json:"url,omitempty"`
	// Host, Port and Path are where a remote or connectors server is reached.
	Host    string   `json:"host,omitempty"`
	Port    int      `json:"port,omitempty"`
	Path    string   `json:"path,omitempty"`
	Command []string `json:"command,omitempty"`
	// AllTools means every tool not in Deny may be called.
	AllTools bool     `json:"all_tools"`
	Tools    []string `json:"tools"`
	Deny     []string `json:"deny"`
	// Token says a token for the server is stored on this machine.
	Token bool `json:"token"`
	// Secrets and Hosts are a local server's.
	Secrets []string `json:"secrets,omitempty"`
	Hosts   []string `json:"hosts,omitempty"`
}

// policyView builds the readable policy for an agent from a resolved policy.
// It compiles the document the way fenzi run does and reads the result, so
// what it says is what the sandbox gets.
func policyView(resolved run.Resolved, entry agents.Entry) (*jsonPolicyView, error) {
	d := resolved.Doc.WithDefaults()
	target := compiler.Target{Agent: entry.CompilerAgent(), Workdir: compiler.DefaultWorkdir}
	p, err := compiler.Compile(resolved.Doc, target)
	if err != nil {
		return nil, err
	}
	v := &jsonPolicyView{
		Sources:   resolved.Sources,
		Revision:  resolved.TeamRevision,
		Agents:    append([]string{}, d.Agents...),
		Approvals: d.Approvals,
		Workspace: jsonPolicyPath{Path: target.Workdir, Access: d.Workspace},
		Paths:     []jsonPolicyPath{},
		Hosts:     []jsonPolicyHost{},
		Model:     []jsonPolicyModel{},
		MCP:       []jsonPolicyMCP{},
	}
	if p.FilesystemPolicy != nil {
		listed := map[string]bool{}
		for _, path := range append(append([]string{}, d.Paths.ReadOnly...), d.Paths.ReadWrite...) {
			listed[path] = true
		}
		for _, path := range p.FilesystemPolicy.ReadOnly {
			if path != target.Workdir {
				v.Paths = append(v.Paths, jsonPolicyPath{Path: path, Access: compiler.AccessReadOnly, Baseline: !listed[path]})
			}
		}
		for _, path := range p.FilesystemPolicy.ReadWrite {
			if path != target.Workdir {
				v.Paths = append(v.Paths, jsonPolicyPath{Path: path, Access: compiler.AccessReadWrite, Baseline: !listed[path]})
			}
		}
	}

	// Who asked for each host: the document first, then the agent's own
	// needs, then the hosts local MCP servers call.
	from := map[string]jsonPolicyHost{}
	for _, h := range d.Hosts {
		from[hostKey(h.Host, h.Port)] = jsonPolicyHost{From: "policy"}
	}
	for _, h := range entry.Hosts {
		port := h.Port
		if port == 0 {
			port = 443
		}
		if _, ok := from[hostKey(h.Host, port)]; !ok {
			from[hostKey(h.Host, port)] = jsonPolicyHost{From: "agent"}
		}
	}
	for _, name := range d.MCPNames() {
		s := d.MCP[name]
		if s.Remote() {
			continue
		}
		for _, h := range s.Hosts {
			k := hostKey(h, 443)
			if _, ok := from[k]; !ok {
				from[k] = jsonPolicyHost{From: "mcp", Server: name}
			}
		}
	}
	mcpKeys := map[string]string{}
	for _, name := range d.MCPNames() {
		if s := d.MCP[name]; s.Remote() && s.For(entry.Name) {
			mcpKeys[compiler.MCPRuleKey(name)] = name
		}
	}
	keys := make([]string, 0, len(p.NetworkPolicies))
	for k := range p.NetworkPolicies {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		rule := p.NetworkPolicies[k]
		if _, isMCP := mcpKeys[k]; isMCP || strings.HasPrefix(k, "model_") {
			// MCP servers are listed from the document below; a model rule
			// compiled in for a sign-in sandbox is the model entry below.
			continue
		}
		for _, ep := range rule.Endpoints {
			h := from[hostKey(ep.Host, ep.Port)]
			h.Host, h.Port = ep.Host, ep.Port
			h.Allow = []string{}
			if ep.Access != "" {
				// A preset: read-only, or read-write with every method, as a
				// local MCP server's host gets.
				h.Access = ep.Access
			} else {
				h.Access = compiler.AccessReadWrite
				for _, r := range ep.Rules {
					h.Allow = append(h.Allow, strings.TrimSpace(r.Allow.Method+" "+r.Allow.Path))
				}
			}
			if h.From == "" {
				h.From = "policy"
			}
			if ep.CredentialBinding != nil && h.From == "mcp" {
				h.Secret = secretFor(d, h.Server, ep.CredentialBinding.Provider)
			}
			v.Hosts = append(v.Hosts, h)
		}
	}

	for _, m := range entry.Model {
		port := m.Port
		if port == 0 {
			port = 443
		}
		access := m.Access
		if access == "" {
			access = compiler.AccessReadWrite
		}
		v.Model = append(v.Model, jsonPolicyModel{Host: m.Host, Port: port, Access: access, KeyEnv: entry.Key.Env})
	}

	for _, name := range d.MCPNames() {
		s := d.MCP[name]
		if !s.For(entry.Name) {
			continue
		}
		j := jsonPolicyMCP{
			Name: name, URL: s.URL, Command: s.Command, AllTools: s.Tools.AllowsAll(),
			Tools: []string{}, Deny: append([]string{}, s.Tools.Deny...), Token: s.Token,
			Secrets: s.Secrets, Hosts: s.Hosts,
		}
		if !j.AllTools {
			j.Tools = append(j.Tools, s.Tools.Allow...)
		}
		switch {
		case s.Connectors():
			j.Kind = "connectors"
		case s.Remote():
			j.Kind = "remote"
		default:
			j.Kind = "local"
		}
		if s.Remote() {
			ep, err := s.Endpoint()
			if err != nil {
				return nil, fmt.Errorf("mcp.%s: %v", name, err)
			}
			j.Host, j.Port, j.Path = ep.Host, ep.Port, ep.Path
		}
		v.MCP = append(v.MCP, j)
	}
	return v, nil
}

func hostKey(host string, port int) string { return fmt.Sprintf("%s:%d", host, port) }

// secretFor finds the variable whose provider the compiler bound to a local
// server's host, by the provider's name.
func secretFor(d *compiler.Document, server, provider string) string {
	for _, name := range d.MCPNames() {
		s := d.MCP[name]
		if s.Remote() || (server != "" && name != server) {
			continue
		}
		for _, v := range s.Secrets {
			if compiler.SecretProvider(v) == provider {
				return v
			}
		}
	}
	return ""
}

// markProject flags the hosts and paths the folder's own fenzi.yaml lists,
// so a screen can offer to change those and only those.
func markProject(v *jsonPolicyView, project *compiler.Document) {
	if v == nil || project == nil {
		return
	}
	hosts := map[string]bool{}
	for _, h := range project.Hosts {
		port := h.Port
		if port == 0 {
			port = 443
		}
		hosts[hostKey(h.Host, port)] = true
	}
	for i := range v.Hosts {
		v.Hosts[i].Project = hosts[hostKey(v.Hosts[i].Host, v.Hosts[i].Port)]
	}
	paths := map[string]bool{}
	for _, p := range append(append([]string{}, project.Paths.ReadOnly...), project.Paths.ReadWrite...) {
		paths[p] = true
	}
	for i := range v.Paths {
		v.Paths[i].Project = paths[v.Paths[i].Path]
	}
}
