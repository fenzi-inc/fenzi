package compiler

import (
	"bytes"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"
)

// MCPServer is one entry of a document's mcp section. A server has either a
// URL, for a remote server the sandbox checks per tool, or a command, for a
// local server that runs inside the sandbox as a child of the agent.
type MCPServer struct {
	URL     string            `yaml:"url,omitempty"`
	Command []string          `yaml:"command,omitempty"`
	Env     map[string]string `yaml:"env,omitempty"`
	// Token says a token for this server is stored on the machine, with
	// fenzi mcp token <name>. The value never appears in the document.
	Token bool     `yaml:"token,omitempty"`
	Tools MCPTools `yaml:"tools,omitempty"`
}

// MCPTools lists the tools a remote server's tools/call may name. "*" in
// Allow allows every tool; Deny is refused even then.
type MCPTools struct {
	Allow []string `yaml:"allow,omitempty"`
	Deny  []string `yaml:"deny,omitempty"`
}

// AllTools is the Allow entry that allows every tool.
const AllTools = "*"

// MCPVersions are the protocol revisions every remote server rule accepts.
// Codex sends 2025-06-18; Claude Code, OpenCode and Grok send 2025-11-25.
var MCPVersions = []string{"2025-06-18", "2025-11-25"}

// MCPDiscovery are the methods a client sends to connect and list what a
// server offers. They are allowed on every remote server. Reading resources
// and prompts (resources/read, prompts/get) is not.
var MCPDiscovery = []string{
	"initialize",
	"notifications/initialized",
	"notifications/cancelled",
	"ping",
	"tools/list",
	"resources/list",
	"prompts/list",
}

var (
	mcpName  = regexp.MustCompile(`^[a-z][a-z0-9-]{0,30}$`)
	toolName = regexp.MustCompile(`^[A-Za-z0-9_.:/-]{1,128}$`)
	envName  = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`)
)

// MCPProvider is the name of the provider that holds a server's token, and
// of the profile it is created from.
func MCPProvider(server string) string { return "fenzi-mcp-" + server }

// MCPTokenEnv is the variable that holds the token's placeholder inside the
// sandbox. The agent's MCP config puts it in the Authorization header; the
// sandbox replaces it with the token only on that server's endpoint.
func MCPTokenEnv(server string) string {
	return "FENZI_MCP_" + strings.ToUpper(strings.ReplaceAll(server, "-", "_")) + "_TOKEN"
}

// MCPRuleKey is the network policy key of a remote server's rule.
func MCPRuleKey(server string) string { return "mcp_" + strings.ReplaceAll(server, "-", "_") }

// Remote reports whether the server is reached over the network.
func (s MCPServer) Remote() bool { return s.URL != "" }

// AllowsAll reports whether every tool not denied is allowed.
func (t MCPTools) AllowsAll() bool {
	for _, a := range t.Allow {
		if a == AllTools {
			return true
		}
	}
	return false
}

// MCPEndpoint is a remote server's host, port, and path.
type MCPEndpoint struct {
	Host string
	Port int
	Path string
}

// Endpoint parses the URL of a remote server.
func (s MCPServer) Endpoint() (MCPEndpoint, error) {
	u, err := url.Parse(s.URL)
	if err != nil {
		return MCPEndpoint{}, fmt.Errorf("url %q: %v", s.URL, err)
	}
	if u.Scheme != "https" {
		return MCPEndpoint{}, fmt.Errorf("url %q: must start with https://", s.URL)
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return MCPEndpoint{}, fmt.Errorf("url %q: no user, query, or fragment; put a token in fenzi mcp token", s.URL)
	}
	port := 443
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil {
			return MCPEndpoint{}, fmt.Errorf("url %q: bad port", s.URL)
		}
		port = n
	}
	p := u.EscapedPath()
	if p == "" {
		p = "/"
	}
	return MCPEndpoint{Host: strings.ToLower(u.Hostname()), Port: port, Path: p}, nil
}

// MCPNames returns the server names in a stable order.
func (d *Document) MCPNames() []string {
	names := make([]string, 0, len(d.MCP))
	for n := range d.MCP {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// validateMCP checks the mcp section. hosts maps the host:port pairs the
// document's hosts list already uses: a host and port carries one protocol,
// and an MCP rule covers every path on it, so a server cannot share one with
// a host rule or another server.
func (d *Document) validateMCP(hosts map[string]int) []string {
	var p []string
	add := func(format string, args ...any) { p = append(p, fmt.Sprintf(format, args...)) }
	seen := map[string]string{}
	for _, name := range d.MCPNames() {
		s := d.MCP[name]
		f := "mcp." + name
		if !mcpName.MatchString(name) {
			add("%s: a server name is lowercase letters, digits, and dashes, starting with a letter, at most 31 characters", f)
		}
		switch {
		case s.Remote() && len(s.Command) > 0:
			add("%s: set url or command, not both", f)
		case !s.Remote() && len(s.Command) == 0:
			add("%s: set url for a remote server or command for a local one", f)
		}
		for k := range s.Env {
			if !envName.MatchString(k) {
				add("%s.env: %q is not a variable name", f, k)
			}
		}
		if !s.Remote() {
			if s.Token {
				add("%s.token: only for a server with a url", f)
			}
			if len(s.Tools.Allow) > 0 || len(s.Tools.Deny) > 0 {
				add("%s.tools: a local server is not checked per tool; its process is what the sandbox limits", f)
			}
			continue
		}
		if len(s.Env) > 0 {
			add("%s.env: only for a server with a command", f)
		}
		ep, err := s.Endpoint()
		if err != nil {
			add("%s.%v", f, err)
			continue
		}
		if err := checkHost(ep.Host); err != nil {
			add("%s.url: %v", f, err)
		}
		if ep.Port < 1 || ep.Port > 65535 || blockedPorts[ep.Port] {
			add("%s.url: port %d is not accepted", f, ep.Port)
		}
		key := fmt.Sprintf("%s:%d", ep.Host, ep.Port)
		if i, ok := hosts[key]; ok {
			add("%s.url: %s is also in hosts[%d]; a host and port is either an MCP server or a host rule", f, key, i)
		}
		if other, ok := seen[key]; ok {
			add("%s.url: %s is also mcp.%s; one MCP server per host and port", f, key, other)
		}
		seen[key] = name
		if len(s.Tools.Allow) == 0 {
			add("%s.tools.allow: list the tools the agent may call, or %q for all of them", f, AllTools)
		}
		for i, t := range s.Tools.Allow {
			if t != AllTools && !toolName.MatchString(t) {
				add("%s.tools.allow[%d]: %q is not a tool name", f, i, t)
			}
		}
		for i, t := range s.Tools.Deny {
			if !toolName.MatchString(t) {
				add("%s.tools.deny[%d]: %q is not a tool name", f, i, t)
			}
		}
	}
	return p
}

// mcpRules adds a rule per remote server: the discovery methods, the allowed
// tools, the denied ones, the accepted revisions, and the token binding. The
// agent's binaries are the only programs that reach it.
func mcpRules(p *Policy, d *Document, bins []Binary) error {
	for _, name := range d.MCPNames() {
		s := d.MCP[name]
		if !s.Remote() {
			continue
		}
		ep, err := s.Endpoint()
		if err != nil {
			return fmt.Errorf("mcp.%s: %v", name, err)
		}
		e := Endpoint{
			Host:        ep.Host,
			Port:        ep.Port,
			Path:        ep.Path,
			Protocol:    "mcp",
			Enforcement: "enforce",
			MCP:         &MCPOptions{Versions: append([]string(nil), MCPVersions...)},
		}
		for _, m := range MCPDiscovery {
			e.Rules = append(e.Rules, Rule{Allow: Match{Method: m}})
		}
		if s.Tools.AllowsAll() {
			e.Rules = append(e.Rules, Rule{Allow: Match{Method: "tools/call"}})
		} else {
			for _, t := range s.Tools.Allow {
				e.Rules = append(e.Rules, Rule{Allow: Match{Method: "tools/call", Tool: t}})
			}
		}
		for _, t := range s.Tools.Deny {
			e.DenyRules = append(e.DenyRules, DenyRule{Method: "tools/call", Tool: t})
		}
		if s.Token {
			e.CredentialBinding = &CredentialBinding{Provider: MCPProvider(name)}
		}
		key := MCPRuleKey(name)
		if _, dup := p.NetworkPolicies[key]; dup {
			return fmt.Errorf("mcp.%s: rule name %q collides with another rule", name, key)
		}
		p.NetworkPolicies[key] = NetworkRule{Name: ep.Host, Endpoints: []Endpoint{e}, Binaries: bins}
	}
	return nil
}

// HasMCP reports whether the policy has a rule the prover cannot model.
func (p *Policy) HasMCP() bool {
	for _, r := range p.NetworkPolicies {
		for _, e := range r.Endpoints {
			if e.Protocol == "mcp" {
				return true
			}
		}
	}
	return false
}

// WithoutMCP is the policy as the prover sees it: openshell-prover 0.1.2
// returns unsupported for any policy with a protocol: mcp rule, in the
// candidate or the boundary. MCP rules are checked by CheckMCP instead.
func (p *Policy) WithoutMCP() *Policy {
	out := *p
	out.NetworkPolicies = map[string]NetworkRule{}
	for k, r := range p.NetworkPolicies {
		if !hasMCPEndpoint(r.Endpoints) {
			out.NetworkPolicies[k] = r
		}
	}
	if len(out.NetworkPolicies) == 0 {
		out.NetworkPolicies = nil
	}
	return &out
}

func hasMCPEndpoint(eps []Endpoint) bool {
	for _, e := range eps {
		if e.Protocol == "mcp" {
			return true
		}
	}
	return false
}

// StripMCP removes the network rules with an MCP endpoint from a policy as
// OpenShell prints it (sandbox get --policy-only), for the prover. Other
// keys are kept as they are.
func StripMCP(policyYAML []byte) ([]byte, error) {
	var doc map[string]any
	if err := yaml.Unmarshal(policyYAML, &doc); err != nil {
		return nil, fmt.Errorf("reading the policy: %w", err)
	}
	if np, ok := doc["network_policies"].(map[string]any); ok {
		for k, v := range np {
			rule, _ := v.(map[string]any)
			eps, _ := rule["endpoints"].([]any)
			for _, e := range eps {
				if em, _ := e.(map[string]any); em != nil && em["protocol"] == "mcp" {
					delete(np, k)
					break
				}
			}
		}
		if len(np) == 0 {
			delete(doc, "network_policies")
		}
	}
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(doc); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// CheckMCP checks a document's MCP servers against a team boundary's, the
// check the prover cannot do. A remote server must be one the boundary
// lists, at the same URL; it may allow only tools the boundary allows and
// must deny every tool the boundary denies. A local server must be in the
// boundary with the same command.
func CheckMCP(doc, boundary *Document) error {
	return checkMCP(doc, boundary, "the team", "team boundary: ")
}

// checkMCP is CheckMCP with the owner of the boundary named in the messages.
func checkMCP(doc, boundary *Document, owner, pre string) error {
	var p []string
	for _, name := range doc.MCPNames() {
		s := doc.MCP[name]
		b, ok := boundary.MCP[name]
		f := "mcp." + name
		switch {
		case !ok:
			p = append(p, fmt.Sprintf("%s: not an MCP server "+owner+" allows", f))
			continue
		case s.URL != b.URL:
			p = append(p, fmt.Sprintf("%s.url: "+owner+" allows %s", f, firstNonEmpty(b.URL, "a local command")))
			continue
		case !s.Remote() && !sameOrder(s.Command, b.Command):
			p = append(p, fmt.Sprintf("%s.command: "+owner+" allows %q", f, strings.Join(b.Command, " ")))
			continue
		}
		if !s.Remote() {
			continue
		}
		if s.Tools.AllowsAll() && !b.Tools.AllowsAll() {
			p = append(p, fmt.Sprintf("%s.tools.allow: every tool; "+owner+" allows %s", f, strings.Join(b.Tools.Allow, ", ")))
		} else if !b.Tools.AllowsAll() {
			for _, t := range s.Tools.Allow {
				if !contains(b.Tools.Allow, t) {
					p = append(p, fmt.Sprintf("%s.tools.allow: %s is not a tool "+owner+" allows", f, t))
				}
			}
		}
		for _, t := range b.Tools.Deny {
			if !contains(s.Tools.Deny, t) && (s.Tools.AllowsAll() || contains(s.Tools.Allow, t)) {
				p = append(p, fmt.Sprintf("%s.tools: "+owner+" denies %s", f, t))
			}
		}
	}
	if len(p) == 0 {
		return nil
	}
	return &ValidationError{Problems: prefix(pre, p)}
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func sameOrder(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func firstNonEmpty(s ...string) string {
	for _, x := range s {
		if x != "" {
			return x
		}
	}
	return ""
}

// checkMCPHosts refuses a remote server on a host the agent already reaches:
// its model endpoint or a host it needs to start. One host and port carries
// one protocol.
func checkMCPHosts(d *Document, a Agent) error {
	taken := map[string]string{}
	for _, m := range a.Model {
		port := m.Port
		if port == 0 {
			port = 443
		}
		taken[fmt.Sprintf("%s:%d", m.Host, port)] = "the " + a.Name + " model API"
	}
	for _, h := range a.Hosts {
		port := h.Port
		if port == 0 {
			port = 443
		}
		taken[fmt.Sprintf("%s:%d", h.Host, port)] = "a host " + a.Name + " needs to start"
	}
	var p []string
	for _, name := range d.MCPNames() {
		s := d.MCP[name]
		if !s.Remote() {
			continue
		}
		ep, err := s.Endpoint()
		if err != nil {
			continue
		}
		key := fmt.Sprintf("%s:%d", ep.Host, ep.Port)
		if what, ok := taken[key]; ok {
			p = append(p, fmt.Sprintf("mcp.%s.url: %s is %s; a host and port carries one protocol", name, key, what))
		}
	}
	if len(p) == 0 {
		return nil
	}
	return &ValidationError{Problems: p}
}

// mergeMCP layers a project's servers over the base's. A new name is added.
// A name the base has keeps the base's URL or command and may only narrow
// it: fewer tools, more denied.
func mergeMCP(out, project *Document) []string {
	var p []string
	if len(project.MCP) == 0 {
		return nil
	}
	if out.MCP == nil {
		out.MCP = map[string]MCPServer{}
	}
	for _, name := range project.MCPNames() {
		s := project.MCP[name].clone()
		b, ok := out.MCP[name]
		if !ok {
			out.MCP[name] = s
			continue
		}
		if err := checkMCP(&Document{MCP: map[string]MCPServer{name: s}}, &Document{MCP: map[string]MCPServer{name: b}}, "the layer below", ""); err != nil {
			var ve *ValidationError
			if errors.As(err, &ve) {
				for _, msg := range ve.Problems {
					p = append(p, msg+"; a project can only narrow a server the machine file or the base policy already has")
				}
				continue
			}
			p = append(p, err.Error())
			continue
		}
		s.Token = s.Token || b.Token
		out.MCP[name] = s
	}
	return p
}

// sameMCP reports whether two documents give the agent the same servers.
func sameMCP(a, b map[string]MCPServer) bool {
	if len(a) != len(b) {
		return false
	}
	for n, x := range a {
		y, ok := b[n]
		if !ok || x.URL != y.URL || x.Token != y.Token || !sameOrder(x.Command, y.Command) ||
			!sameStrings(x.Tools.Allow, y.Tools.Allow) || !sameStrings(x.Tools.Deny, y.Tools.Deny) || len(x.Env) != len(y.Env) {
			return false
		}
		for k, v := range x.Env {
			if y.Env[k] != v {
				return false
			}
		}
	}
	return true
}
