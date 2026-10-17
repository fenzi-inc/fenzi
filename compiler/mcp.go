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

// MCPServer is one entry of a document's mcp section. A server has a URL,
// for a remote server the sandbox checks per tool; a command, for a local
// server that runs inside the sandbox as a child of the agent; or an
// account, for the connectors an agent's vendor account brings.
type MCPServer struct {
	URL string `yaml:"url,omitempty"`
	// Account is "claude" for the connectors of the Claude account Claude
	// Code is signed in with (Linear, Apollo.io and the like, added on
	// claude.ai). Claude Code finds them itself and reaches them all through
	// one host; the sandbox checks each call per tool there, as for a URL.
	Account string            `yaml:"account,omitempty"`
	Command []string          `yaml:"command,omitempty"`
	Env     map[string]string `yaml:"env,omitempty"`
	// Token says a token for this server is stored on the machine, with
	// fenzi mcp token <name>. The value never appears in the document.
	Token bool `yaml:"token,omitempty"`
	// TokenHeader is the header a remote server reads its token from, for a
	// server that does not take Authorization: Bearer. The token goes in as
	// it is, with no scheme.
	TokenHeader string   `yaml:"token_header,omitempty"`
	Tools       MCPTools `yaml:"tools,omitempty"`
	// Secrets are the variables a local server reads that hold a
	// credential, such as DIGITALOCEAN_API_TOKEN. Each is stored on the
	// machine with fenzi mcp token --env; the agent and the server see a
	// placeholder, and the sandbox puts the value only on requests to Hosts.
	Secrets []string `yaml:"secrets,omitempty"`
	// Hosts are the hosts a local server calls, over HTTPS on port 443.
	Hosts []string `yaml:"hosts,omitempty"`
}

// MCPTools lists the tools a remote server's tools/call may name. "*" in
// Allow allows every tool; Deny is refused even then.
type MCPTools struct {
	Allow []string `yaml:"allow,omitempty"`
	Deny  []string `yaml:"deny,omitempty"`
}

// AllTools is the Allow entry that allows every tool.
const AllTools = "*"

// AccountClaude is the account entry for Claude's account connectors.
const AccountClaude = "claude"

// ClaudeConnectorsHost is where Claude Code reaches every connector of its
// account, one path per connector: /v1/mcp/<connector id> (Claude Code
// 2.1.288, MCP_PROXY_URL and MCP_PROXY_PATH). It sends its own sign-in token
// there, so the rule binds no provider. Claude Code lists the connectors
// from api.anthropic.com, its model host. Seen on OpenShell 0.1.2: initialize,
// tools/list and tools/call for three connectors passed an MCP rule on this
// host with the usual revisions, and the log named each tool.
const ClaudeConnectorsHost = "mcp-proxy.anthropic.com"

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
	mcpName = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
	// secretName and secretValue spot a variable that holds a credential:
	// by its name, or by the prefix of a well-known token format.
	secretName  = regexp.MustCompile(`(?i)(TOKEN|SECRET|PASSWORD|PASSWD|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY|CREDENTIAL|AUTH)`)
	secretValue = regexp.MustCompile(`^(dop_v1_|ghp_|gho_|ghs_|ghu_|github_pat_|glpat-|sk-|sk_live_|rk_live_|xox[abprs]-|AKIA|ASIA|AIza|lin_api_|ntn_|secret_|pat-|eyJ)`)
	toolName    = regexp.MustCompile(`^[A-Za-z0-9_.:/-]{1,128}$`)
	envName     = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`)
	headerName  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,63}$`)
	// reservedEnv are names a secret cannot take: OpenShell keeps v<digits>_
	// for its revision placeholders (provider profiles page), and FENZI_ and
	// OPENSHELL_ belong to Fenzi and the sandbox.
	reservedEnv = regexp.MustCompile(`^(v[0-9]+_|FENZI_|OPENSHELL_)`)
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

// SecretProvider is the name of the provider that holds a local server's
// secret, and of its profile. It is named for the variable, not the server,
// so every server that reads the variable shares one stored value, and the
// sandbox exposes the placeholder under the variable's own name.
func SecretProvider(variable string) string {
	return "fenzi-secret-" + strings.ToLower(strings.ReplaceAll(variable, "_", "-"))
}

// MCPRuleKey is the network policy key of a remote server's rule.
func MCPRuleKey(server string) string { return "mcp_" + strings.ReplaceAll(server, "-", "_") }

// Remote reports whether the server is reached over the network, at its URL
// or through its account's host.
func (s MCPServer) Remote() bool { return s.URL != "" || s.Account != "" }

// Connectors reports whether the entry is an account's connectors. The agent
// finds those itself, so its MCP config does not list them.
func (s MCPServer) Connectors() bool { return s.Account != "" }

// For reports whether the entry gives the named agent anything. Account
// connectors are only the account's agent's: another agent gets no rule for
// them.
func (s MCPServer) For(agent string) bool { return s.Account == "" || s.Account == agent }

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

// Endpoint parses the URL of a remote server. Account connectors are the
// whole of their host: OpenShell 0.1.2 handles every path on an MCP host and
// port with one rule, and each connector is a path there.
func (s MCPServer) Endpoint() (MCPEndpoint, error) {
	if s.Account == AccountClaude {
		return MCPEndpoint{Host: ClaudeConnectorsHost, Port: 443}, nil
	}
	if s.Account != "" {
		return MCPEndpoint{}, fmt.Errorf("account: %q is not an account Fenzi knows; the only one is %s, for Claude's account connectors", s.Account, AccountClaude)
	}
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
			add("%s: a server name is lowercase letters, digits, and dashes, starting with a letter, at most 63 characters", f)
		}
		switch {
		case s.Account != "" && (s.URL != "" || len(s.Command) > 0):
			add("%s: account entries take no url or command; Claude Code finds its connectors itself", f)
		case s.URL != "" && len(s.Command) > 0:
			add("%s: set url or command, not both", f)
		case !s.Remote() && len(s.Command) == 0:
			add("%s: set url for a remote server or command for a local one", f)
		}
		for _, k := range sortedEnv(s.Env) {
			if !envName.MatchString(k) {
				add("%s.env: %q is not a variable name", f, k)
			}
			if SecretEnv(k, s.Env[k]) {
				add("%s.env.%s: looks like a secret. fenzi.yaml is a plain file that the repository and the sandbox can read, so it never holds one; list %s under secrets and the hosts the server calls under hosts, then store the value with fenzi mcp token %s --env %s", f, k, k, name, k)
			}
		}
		if !s.Remote() {
			if s.Token {
				add("%s.token: only for a server with a url; a local server lists its variables under secrets", f)
			}
			if len(s.Tools.Allow) > 0 || len(s.Tools.Deny) > 0 {
				add("%s.tools: a local server is not checked per tool; its process is what the sandbox limits", f)
			}
			p = append(p, s.validateLocal(f)...)
			continue
		}
		if s.Connectors() && s.Token {
			add("%s.token: Claude Code sends its own sign-in to its connectors; leave token out", f)
		}
		if len(s.Env) > 0 {
			add("%s.env: only for a server with a command", f)
		}
		if len(s.Secrets) > 0 {
			add("%s.secrets: only for a server with a command; a remote server's token is token: true", f)
		}
		if len(s.Hosts) > 0 {
			add("%s.hosts: only for a server with a command; a remote server is reached at its url", f)
		}
		if h := s.TokenHeader; h != "" {
			switch {
			case !s.Token:
				add("%s.token_header: only with token: true", f)
			case !headerName.MatchString(h):
				add("%s.token_header: %q is not a header name", f, h)
			case strings.EqualFold(h, "authorization"):
				add("%s.token_header: leave it out for Authorization: Bearer, the default", f)
			case reservedHeaders[strings.ToLower(h)]:
				add("%s.token_header: %s is set by the agent's MCP client", f, h)
			}
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
			at := f + ".url"
			if s.Connectors() {
				at = f
			}
			add("%s: %s is also in hosts[%d]; a host and port is either an MCP server or a host rule", at, key, i)
		}
		if other, ok := seen[key]; ok {
			if s.Connectors() || d.MCP[other].Connectors() {
				add("%s: %s is also mcp.%s; one entry covers every connector of the account", f, key, other)
			} else {
				add("%s.url: %s is also mcp.%s; one MCP server per host and port", f, key, other)
			}
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
	if len(p) > 0 {
		return p
	}
	// Local servers' hosts, once every remote server's host is known. A
	// host is reached by every server that lists it, so it carries one
	// secret at most: OpenShell binds one provider to an endpoint.
	carries := map[string]string{}
	by := map[string]string{}
	for _, name := range d.MCPNames() {
		s := d.MCP[name]
		if s.Remote() {
			continue
		}
		f := "mcp." + name
		for _, h := range s.Hosts {
			key := h + ":443"
			if other, ok := seen[key]; ok {
				add("%s.hosts: %s is the MCP server mcp.%s; a host and port carries one protocol", f, key, other)
				continue
			}
			for _, v := range s.Secrets {
				if prev, ok := carries[h]; ok && prev != v {
					add("%s.hosts: %s would carry %s (mcp.%s) and %s; the sandbox puts one secret on a host", f, h, prev, by[h], v)
					continue
				}
				carries[h], by[h] = v, name
			}
		}
	}
	return p
}

// CheckSecretName reports why a variable cannot be a local server's secret.
func CheckSecretName(v string) error {
	switch {
	case !envName.MatchString(v):
		return fmt.Errorf("%q is not a variable name; use capitals, digits, and underscores", v)
	case reservedEnv.MatchString(v):
		return fmt.Errorf("%s starts with a prefix the sandbox keeps for itself", v)
	}
	return nil
}

// reservedHeaders are headers an MCP client sets itself.
var reservedHeaders = map[string]bool{
	"host": true, "content-type": true, "content-length": true, "accept": true, "connection": true,
	"cookie": true, "transfer-encoding": true, "mcp-protocol-version": true, "mcp-session-id": true,
}

// validateLocal checks a local server's secrets and hosts.
func (s MCPServer) validateLocal(f string) []string {
	var p []string
	add := func(format string, args ...any) { p = append(p, fmt.Sprintf(format, args...)) }
	seen := map[string]bool{}
	for i, v := range s.Secrets {
		if err := CheckSecretName(v); err != nil {
			add("%s.secrets[%d]: %v", f, i, err)
		}
		switch {
		case seen[v]:
			add("%s.secrets[%d]: %s is listed twice", f, i, v)
		}
		if _, ok := s.Env[v]; ok {
			add("%s.secrets[%d]: %s is also in env; a secret's value is stored with fenzi mcp token, not written here", f, i, v)
		}
		seen[v] = true
	}
	hosts := map[string]bool{}
	for i, h := range s.Hosts {
		if err := checkHost(h); err != nil {
			add("%s.hosts[%d]: %v", f, i, err)
		} else if hosts[h] {
			add("%s.hosts[%d]: %s is listed twice", f, i, h)
		}
		hosts[h] = true
	}
	if len(s.Secrets) > 0 && len(s.Hosts) == 0 {
		add("%s.hosts: list the hosts the server sends its secrets to; the sandbox puts %s on requests to those hosts only", f, strings.Join(s.Secrets, " and "))
	}
	return p
}

// mcpRules adds a rule per remote server: the discovery methods, the allowed
// tools, the denied ones, the accepted revisions, and the token binding. The
// agent's binaries are the only programs that reach it. Account connectors
// get a rule only for their account's agent.
func mcpRules(p *Policy, d *Document, agent string, bins []Binary) error {
	for _, name := range d.MCPNames() {
		s := d.MCP[name]
		if !s.Remote() || !s.For(agent) {
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

// localHostRules adds a REST rule for each host a local server calls, for
// the agent's binaries: the server is the agent's child, and OpenShell
// matches a request by the program and its ancestors (recorded on
// OpenShell 0.1.2: the server's node and Go processes matched a rule naming
// only claude.exe). A host that
// carries a secret binds that secret's provider with credential_binding, so
// the proxy puts the value in place of the placeholder on that host only. A
// host already in the policy keeps its rule and its access, and gets the
// binding added.
func localHostRules(p *Policy, d *Document, bins []Binary) {
	carries := map[string]string{}
	var hosts []string
	for _, name := range d.MCPNames() {
		s := d.MCP[name]
		if s.Remote() {
			continue
		}
		for _, h := range s.Hosts {
			if _, ok := carries[h]; !ok {
				hosts = append(hosts, h)
				carries[h] = ""
			}
			if len(s.Secrets) > 0 {
				carries[h] = s.Secrets[0]
			}
		}
	}
	sort.Strings(hosts)
	for _, h := range hosts {
		var bind *CredentialBinding
		if v := carries[h]; v != "" {
			bind = &CredentialBinding{Provider: SecretProvider(v)}
		}
		key := ruleKey(h, 443)
		if r, ok := p.NetworkPolicies[key]; ok {
			if bind == nil {
				continue
			}
			eps := append([]Endpoint(nil), r.Endpoints...)
			for i := range eps {
				eps[i].CredentialBinding = bind
			}
			r.Endpoints = eps
			p.NetworkPolicies[key] = r
			continue
		}
		p.NetworkPolicies[key] = NetworkRule{
			Name:      h,
			Endpoints: []Endpoint{{Host: h, Port: 443, Protocol: "rest", Enforcement: "enforce", Access: AccessReadWrite, AllowEncodedSlash: true, CredentialBinding: bind}},
			Binaries:  bins,
		}
	}
}

// Secrets returns the secret variables the document's local servers read,
// sorted, each once.
func (d *Document) Secrets() []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range d.MCP {
		if s.Remote() {
			continue
		}
		for _, v := range s.Secrets {
			if !seen[v] {
				seen[v] = true
				out = append(out, v)
			}
		}
	}
	sort.Strings(out)
	return out
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

// Unprovable reports whether the policy has something the prover cannot
// model: an MCP rule, a credential binding on a REST rule, or
// allow_encoded_slash.
func (p *Policy) Unprovable() bool {
	for _, r := range p.NetworkPolicies {
		for _, e := range r.Endpoints {
			if e.Protocol == "mcp" || e.CredentialBinding != nil || e.AllowEncodedSlash {
				return true
			}
		}
	}
	return false
}

// ForProver is the policy as the prover sees it. openshell-prover 0.1.2
// returns unsupported for any policy with a protocol: mcp rule, and for a
// REST rule with credential_binding ("uses authority outside the initial
// model"), in the candidate or the boundary. MCP rules are left
// out and checked by CheckMCP. A bound REST rule stays, without its binding:
// the prover still checks its host, methods, and programs. The binding only
// says where a stored secret may go, and CheckMCP holds a server's secrets
// to the boundary's. allow_encoded_slash is left out too (unsupported since
// 0.1.2): Compile sets it only on preset endpoints, which allow every path.
func (p *Policy) ForProver() *Policy {
	out := *p
	out.NetworkPolicies = map[string]NetworkRule{}
	for k, r := range p.NetworkPolicies {
		if hasMCPEndpoint(r.Endpoints) {
			continue
		}
		eps := make([]Endpoint, len(r.Endpoints))
		for i, e := range r.Endpoints {
			e.CredentialBinding = nil
			e.AllowEncodedSlash = false
			eps[i] = e
		}
		r.Endpoints = eps
		out.NetworkPolicies[k] = r
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

// UnprovableYAML reports whether a policy as OpenShell prints it has a rule
// ForProverYAML changes.
func UnprovableYAML(policyYAML []byte) bool {
	return bytes.Contains(policyYAML, []byte("protocol: mcp")) || bytes.Contains(policyYAML, []byte("credential_binding")) ||
		bytes.Contains(policyYAML, []byte("allow_encoded_slash"))
}

// ForProverYAML is ForProver for a policy as OpenShell prints it (sandbox
// get --policy-only): it removes the network rules with an MCP endpoint, and
// the credential_binding and allow_encoded_slash of every other endpoint. Other keys are kept as
// they are.
func ForProverYAML(policyYAML []byte) ([]byte, error) {
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
			for _, e := range eps {
				if em, _ := e.(map[string]any); em != nil {
					delete(em, "credential_binding")
					delete(em, "allow_encoded_slash")
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
// boundary with the same command, and may list only secrets and hosts the
// boundary's entry lists.
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
		case s.Account != b.Account:
			p = append(p, fmt.Sprintf("%s: "+owner+" allows %s", f, firstNonEmpty(accountLabel(b.Account), b.URL, "a local command")))
			continue
		case s.URL != b.URL:
			p = append(p, fmt.Sprintf("%s.url: "+owner+" allows %s", f, firstNonEmpty(b.URL, "a local command")))
			continue
		case !s.Remote() && !sameOrder(s.Command, b.Command):
			p = append(p, fmt.Sprintf("%s.command: "+owner+" allows %q", f, strings.Join(b.Command, " ")))
			continue
		}
		if !s.Remote() {
			for _, v := range s.Secrets {
				if !contains(b.Secrets, v) {
					p = append(p, fmt.Sprintf("%s.secrets: %s is not a secret "+owner+" gives this server", f, v))
				}
			}
			for _, h := range s.Hosts {
				if !contains(b.Hosts, h) {
					p = append(p, fmt.Sprintf("%s.hosts: %s is not a host "+owner+" lets this server call", f, h))
				}
			}
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

func accountLabel(a string) string {
	if a == "" {
		return ""
	}
	return "the " + a + " account's connectors"
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

// checkMCPHosts refuses a server on a host the agent already reaches: its
// model endpoint or a host it needs to start. One host and port carries one
// protocol, and a server's secret must not reach the agent's own hosts.
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
		if !s.For(a.Name) {
			continue
		}
		if !s.Remote() {
			for _, h := range s.Hosts {
				if what, ok := taken[h+":443"]; ok {
					p = append(p, fmt.Sprintf("mcp.%s.hosts: %s is %s; a server cannot share it", name, h, what))
				}
			}
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
		if !ok || x.URL != y.URL || x.Account != y.Account || x.Token != y.Token || x.TokenHeader != y.TokenHeader || !sameOrder(x.Command, y.Command) ||
			!sameStrings(x.Tools.Allow, y.Tools.Allow) || !sameStrings(x.Tools.Deny, y.Tools.Deny) || len(x.Env) != len(y.Env) ||
			!sameStrings(x.Secrets, y.Secrets) || !sameStrings(x.Hosts, y.Hosts) {
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

// SecretEnv reports whether a variable of a local server looks like it holds
// a credential, by its name or its value. Such a variable is never written
// to a policy file.
func SecretEnv(key, value string) bool {
	if value == "" {
		return false
	}
	return secretName.MatchString(key) || secretValue.MatchString(value)
}

func sortedEnv(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
