package compiler

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

// DefaultWorkdir is the sandbox working directory the project is uploaded to.
// Upstream examples use /sandbox, and OpenShell 0.1.2 uploads there.
const DefaultWorkdir = "/sandbox"

// baselineReadOnly and baselineReadWrite are the paths OpenShell adds when a
// policy has network rules (Default Policy and Baseline Paths). Listing them
// ourselves keeps the effective policy equal to the compiled one, which the
// prover needs because it compares paths one by one. /bin is from the
// restrictive default.
var (
	baselineReadOnly  = []string{"/bin", "/usr", "/lib", "/etc", "/app", "/var/log", "/proc", "/dev/urandom"}
	baselineReadWrite = []string{"/tmp", "/dev/null"}
)

// Agent is what the compiler needs to know about one agent from the catalog.
type Agent struct {
	Name string
	// Binaries are the real paths of the programs that open connections:
	// the agent itself and interpreters such as python3.12 or node.
	Binaries []string
	// Model lists the endpoints the agent's provider profile contributes to
	// the effective policy. They are not compiled into the candidate (the
	// provider adds them) but must be in the boundary, or the check of the
	// effective policy fails.
	Model []ModelEndpoint
	// Hosts the agent cannot start without, such as a vendor's connectivity
	// check. Compiled read-only for the agent's binaries, in the candidate and
	// so in the boundary. A host the document lists keeps the document's rule.
	Hosts []AgentHost
}

// AgentHost is a host the agent needs that is not a model endpoint.
type AgentHost struct {
	Host string
	Port int
}

// ModelEndpoint mirrors one endpoint of the provider profile.
type ModelEndpoint struct {
	Host string
	Port int
	// Protocol, Access, and Enforcement as written in the profile. An empty
	// Protocol means a plain L4 endpoint.
	Protocol    string
	Access      string
	Enforcement string
	// Binaries defaults to the agent's binaries when empty.
	Binaries []string
}

// Target describes the sandbox a policy is compiled for.
type Target struct {
	Agent   Agent
	Workdir string
}

// Compile produces the candidate policy passed to `openshell sandbox create --policy`.
func Compile(doc *Document, t Target) (*Policy, error) {
	d := doc.WithDefaults()
	if err := d.Validate(); err != nil {
		return nil, err
	}
	if t.Workdir == "" {
		t.Workdir = DefaultWorkdir
	}
	if err := checkTarget(d, t); err != nil {
		return nil, err
	}

	fs, err := filesystem(d, t.Workdir)
	if err != nil {
		return nil, err
	}
	p := &Policy{
		Version:          1,
		FilesystemPolicy: fs,
		Landlock:         &Landlock{Compatibility: "hard_requirement"},
		Process:          &Process{RunAsUser: "sandbox", RunAsGroup: "sandbox"},
		NetworkPolicies:  map[string]NetworkRule{},
	}
	bins := binaries(t.Agent.Binaries)
	for _, h := range d.Hosts {
		ep := Endpoint{Host: h.Host, Port: h.Port, Protocol: "rest", Enforcement: "enforce"}
		switch h.Access {
		case AccessReadOnly:
			ep.Access = AccessReadOnly
		case AccessReadWrite:
			for _, line := range h.Allow {
				m, path, _ := parseAllow(line)
				ep.Rules = append(ep.Rules, Rule{Allow: Match{Method: m, Path: path}})
			}
		}
		// No allow_encoded_slash: prover 0.1.2 returns unsupported for it, and
		// the read-only preset already allows npm's @scope%2fname paths.
		key := ruleKey(h.Host, h.Port)
		if _, dup := p.NetworkPolicies[key]; dup {
			return nil, fmt.Errorf("hosts %s:%d: rule name %q collides with another host", h.Host, h.Port, key)
		}
		p.NetworkPolicies[key] = NetworkRule{Name: h.Host, Endpoints: []Endpoint{ep}, Binaries: bins}
	}
	for _, h := range t.Agent.Hosts {
		port := h.Port
		if port == 0 {
			port = 443
		}
		key := ruleKey(h.Host, port)
		if _, listed := p.NetworkPolicies[key]; listed {
			continue
		}
		p.NetworkPolicies[key] = NetworkRule{
			Name:      h.Host,
			Endpoints: []Endpoint{{Host: h.Host, Port: port, Protocol: "rest", Enforcement: "enforce", Access: AccessReadOnly}},
			Binaries:  bins,
		}
	}
	if len(p.NetworkPolicies) == 0 {
		p.NetworkPolicies = nil
	}
	return p, nil
}

// Boundary produces the most access the candidate may have once providers
// have added their rules. On the Free plan it is derived from the same
// document. A team can publish a boundary document of its own instead;
// TeamBoundary compiles that one.
func Boundary(doc *Document, t Target) (*Policy, error) {
	p, err := Compile(doc, t)
	if err != nil {
		return nil, err
	}
	if p.NetworkPolicies == nil {
		p.NetworkPolicies = map[string]NetworkRule{}
	}
	listed := map[string]bool{}
	for _, r := range p.NetworkPolicies {
		for _, e := range r.Endpoints {
			listed[fmt.Sprintf("%s:%d", e.Host, e.Port)] = true
		}
	}
	for _, m := range t.Agent.Model {
		port := m.Port
		if port == 0 {
			port = 443
		}
		if listed[fmt.Sprintf("%s:%d", m.Host, port)] {
			// The prover returns unsupported when a host and port has both a
			// REST endpoint and one without request rules.
			return nil, fmt.Errorf("hosts: %s:%d is the %s model API; remove it from hosts, the provider adds it", m.Host, port, t.Agent.Name)
		}
		bins := m.Binaries
		if len(bins) == 0 {
			bins = t.Agent.Binaries
		}
		p.NetworkPolicies["model_"+ruleKey(m.Host, port)] = NetworkRule{
			Name:      m.Host,
			Endpoints: []Endpoint{{Host: m.Host, Port: port, Protocol: m.Protocol, Access: m.Access, Enforcement: m.Enforcement}},
			Binaries:  binaries(bins),
		}
	}
	if len(p.NetworkPolicies) == 0 {
		p.NetworkPolicies = nil
	}
	return p, nil
}

// ErrNotInBoundary means the team boundary does not name the agent, so no
// policy for that agent can be inside it.
var ErrNotInBoundary = errors.New("the team boundary does not name this agent")

// TeamBoundary compiles a team's boundary document for one agent. A boundary
// uses the same schema as a policy and means the most any policy of the team
// may allow. Its workspace, paths, and hosts compile exactly as a policy's
// do, and the agent's model endpoints are added as Boundary adds them.
func TeamBoundary(b *Document, t Target) (*Policy, error) {
	if err := CheckBoundary(b); err != nil {
		return nil, err
	}
	if !slices.Contains(b.Agents, t.Agent.Name) {
		return nil, fmt.Errorf("%w: %s", ErrNotInBoundary, t.Agent.Name)
	}
	p, err := Boundary(b, t)
	if err != nil {
		return nil, fmt.Errorf("team boundary: %w", err)
	}
	return p, nil
}

// CheckBoundary checks what a boundary needs beyond what a policy needs: the
// agents it covers. Its values are checked when it is compiled for each one.
func CheckBoundary(b *Document) error {
	if b == nil || len(b.Agents) == 0 {
		return errors.New("team boundary: name the agents it covers")
	}
	return nil
}

func checkTarget(d *Document, t Target) error {
	var p []string
	if t.Agent.Name == "" {
		p = append(p, "agent: no agent given")
	} else if len(d.Agents) > 0 && !slices.Contains(d.Agents, t.Agent.Name) {
		p = append(p, fmt.Sprintf("agent: %s is not in this policy's agents list %v", t.Agent.Name, d.Agents))
	}
	if len(t.Agent.Binaries) == 0 && len(d.Hosts) > 0 {
		p = append(p, fmt.Sprintf("agent %s: no binaries in the catalog, so no network rule could match", t.Agent.Name))
	}
	for _, b := range t.Agent.Binaries {
		if err := checkBinary(b); err != nil {
			p = append(p, fmt.Sprintf("agent %s binary: %v", t.Agent.Name, err))
		}
	}
	for _, m := range t.Agent.Model {
		if err := checkHost(m.Host); err != nil {
			p = append(p, fmt.Sprintf("agent %s model endpoint: %v", t.Agent.Name, err))
		}
		for _, b := range m.Binaries {
			if err := checkBinary(b); err != nil {
				p = append(p, fmt.Sprintf("agent %s model binary: %v", t.Agent.Name, err))
			}
		}
	}
	model := map[string]bool{}
	for _, m := range t.Agent.Model {
		model[m.Host] = true
	}
	for _, h := range t.Agent.Hosts {
		if err := checkHost(h.Host); err != nil {
			p = append(p, fmt.Sprintf("agent %s host: %v", t.Agent.Name, err))
		}
		if model[h.Host] {
			p = append(p, fmt.Sprintf("agent %s host: %s is a model endpoint; the provider adds it", t.Agent.Name, h.Host))
		}
	}
	if len(t.Agent.Hosts) > 0 && len(t.Agent.Binaries) == 0 {
		p = append(p, fmt.Sprintf("agent %s: hosts given but no binaries", t.Agent.Name))
	}
	if err := checkPath(t.Workdir, true); err != nil {
		p = append(p, fmt.Sprintf("workdir: %v", err))
	}
	if len(p) > 0 {
		return &ValidationError{Problems: p}
	}
	return nil
}

// checkBinary requires exact, absolute paths. The prover returns unsupported
// when a candidate's exact path is covered by a glob in the boundary.
func checkBinary(b string) error {
	switch {
	case !strings.HasPrefix(b, "/"):
		return fmt.Errorf("%q is not absolute", b)
	case strings.ContainsAny(b, "*?["):
		return fmt.Errorf("%q is a glob; use the exact real path", b)
	case !isASCII(b):
		return errors.New("non-ASCII binary paths cannot be checked by the prover")
	}
	return nil
}

func filesystem(d *Document, workdir string) (*FilesystemPolicy, error) {
	user := map[string]bool{}
	for _, p := range append(slices.Clone(d.Paths.ReadOnly), d.Paths.ReadWrite...) {
		user[p] = true
	}
	if user[workdir] {
		return nil, &ValidationError{Problems: []string{fmt.Sprintf("paths: %s is the workspace; set workspace instead", workdir)}}
	}
	// include_workdir stays false and the working directory is listed by path:
	// the prover returns unsupported for results that depend on the working directory.
	fs := &FilesystemPolicy{}
	if d.Workspace == WorkspaceReadOnly {
		fs.ReadOnly = append(fs.ReadOnly, workdir)
	} else {
		fs.ReadWrite = append(fs.ReadWrite, workdir)
	}
	for _, p := range baselineReadOnly {
		if !user[p] {
			fs.ReadOnly = append(fs.ReadOnly, p)
		}
	}
	fs.ReadOnly = append(fs.ReadOnly, d.Paths.ReadOnly...)
	for _, p := range baselineReadWrite {
		if !user[p] {
			fs.ReadWrite = append(fs.ReadWrite, p)
		}
	}
	fs.ReadWrite = append(fs.ReadWrite, d.Paths.ReadWrite...)
	if n := countPaths(fs); n > maxPaths {
		return nil, &ValidationError{Problems: []string{fmt.Sprintf("paths: %d paths after adding the baseline; OpenShell accepts at most %d", n, maxPaths)}}
	}
	return fs, nil
}

func binaries(paths []string) []Binary {
	out := make([]Binary, 0, len(paths))
	seen := map[string]bool{}
	for _, p := range paths {
		if !seen[p] {
			out = append(out, Binary{Path: p})
			seen[p] = true
		}
	}
	return out
}

// ruleKey turns host and port into a rule name. Keys never start with
// "_provider_", which OpenShell reserves, because host names cannot start with "_".
func ruleKey(host string, port int) string {
	var b strings.Builder
	for _, r := range host {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	if port != 443 {
		fmt.Fprintf(&b, "_%d", port)
	}
	return b.String()
}
