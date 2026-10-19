package run

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"fenzi/agents"
	"fenzi/compiler"
	"fenzi/policies"
)

// ProjectFile is the optional policy file in a project root.
const ProjectFile = "fenzi.yaml"

// Resolved is the policy a run uses: on the Free plan, or the team's signed
// revision on a signed-in machine.
type Resolved struct {
	Doc          *compiler.Document
	Sources      string
	TeamRevision int
	// Boundary is the team's signed boundary document, when the team has one.
	// The policy is then proved against it instead of against the boundary
	// derived from Doc. BoundarySource names it for people.
	Boundary       *compiler.Document
	BoundarySource string
}

// MachineMCP returns the path of this machine's MCP file, which holds the
// servers a person uses in every project. The CLI sets it; nil means none.
var MachineMCP func() string

// MachineMCPSource is how the machine file is named in a policy's sources.
const MachineMCPSource = "~/.config/fenzi/mcp.yaml"

// LoadMachineMCP reads the machine's MCP file. It holds only version and
// mcp. A missing file is nil with no error.
func LoadMachineMCP() (*compiler.Document, error) {
	if MachineMCP == nil {
		return nil, nil
	}
	path := MachineMCP()
	if path == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	d, err := compiler.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if d.Workspace != "" || d.Approvals != "" || d.Name != "" || len(d.Agents) > 0 || len(d.Hosts) > 0 || len(d.Paths.ReadOnly) > 0 || len(d.Paths.ReadWrite) > 0 {
		return nil, fmt.Errorf("%s: holds only version and mcp; hosts and paths go in a project's fenzi.yaml", path)
	}
	return d, nil
}

// ResolveFree layers ./fenzi.yaml (or the file given) over developer-default,
// with the machine's MCP servers in between, so a project can add servers
// and narrow the machine's.
func ResolveFree(repo, file string) (Resolved, error) {
	base := policies.DeveloperDefault()
	sources := "developer-default (built in)"
	machine, err := LoadMachineMCP()
	if err != nil {
		return Resolved{}, err
	}
	if machine != nil {
		if base, err = compiler.Merge(base, machine); err != nil {
			return Resolved{}, fmt.Errorf("%s: %w", MachineMCPSource, err)
		}
		sources += " + " + MachineMCPSource
	}
	if file == "" {
		file = filepath.Join(repo, ProjectFile)
		if _, err := os.Stat(file); errors.Is(err, fs.ErrNotExist) {
			return Resolved{Doc: base, Sources: sources}, nil
		}
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		return Resolved{}, err
	}
	project, err := compiler.Parse(raw)
	if err != nil {
		return Resolved{}, fmt.Errorf("%s: %w", file, err)
	}
	merged, err := compiler.Merge(base, project)
	if err != nil {
		return Resolved{}, fmt.Errorf("%s: %w", file, err)
	}
	return Resolved{Doc: merged, Sources: sources + " + " + relTo(repo, file)}, nil
}

// WithTeamBoundary adds the boundary document from a team's signed bundle.
// An empty one leaves r as it is, so the boundary is derived from the policy.
func (r Resolved) WithTeamBoundary(raw []byte, tenant string, revision int) (Resolved, error) {
	if len(raw) == 0 {
		return r, nil
	}
	b, err := compiler.Parse(raw)
	if err != nil {
		return Resolved{}, fmt.Errorf("team boundary: %w", err)
	}
	if err := compiler.CheckBoundary(b); err != nil {
		return Resolved{}, err
	}
	r.Boundary = b
	r.BoundarySource = fmt.Sprintf("the %s boundary in r%d (signed)", tenant, revision)
	return r, nil
}

// HostInBoundary says whether the team boundary, compiled for the agent, has
// a rule for destination ("host:port"). It compares the host and port only,
// not methods or paths: the prover checks those when a revision is published.
// Without a team boundary it is true. An agent the boundary does not name
// has no destination inside it.
func (r Resolved) HostInBoundary(agent agents.Entry, destination string) (bool, error) {
	if r.Boundary == nil {
		return true, nil
	}
	b, err := compiler.TeamBoundary(r.Boundary, compiler.Target{Agent: agent.CompilerAgent(), Workdir: compiler.DefaultWorkdir})
	if errors.Is(err, compiler.ErrNotInBoundary) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	for _, rule := range b.NetworkPolicies {
		for _, e := range rule.Endpoints {
			if fmt.Sprintf("%s:%d", e.Host, e.Port) == destination {
				return true, nil
			}
		}
	}
	return false, nil
}

// Compiled is a candidate and boundary written to disk for openshell and the
// prover. ProvePolicy and ProveBoundary are the same without MCP rules, which
// openshell-prover 0.1.2 cannot model; CheckMCP covers those instead. MCP
// counts the remote servers left out.
type Compiled struct {
	Policy        string
	Boundary      string
	ProvePolicy   string
	ProveBoundary string
	Revision      string
	MCP           int
}

// WriteCompiled compiles the resolved policy for an agent and writes
// policy.yaml and boundary.yaml into dir. The boundary is the team's when r
// carries one, and is derived from the policy otherwise.
func WriteCompiled(r Resolved, agent agents.Entry, dir string) (Compiled, error) {
	target := compiler.Target{Agent: agent.CompilerAgent(), Workdir: compiler.DefaultWorkdir}
	p, err := compiler.Compile(r.Doc, target)
	if err != nil {
		return Compiled{}, err
	}
	var b *compiler.Policy
	from := r.Sources
	if r.Boundary != nil {
		b, err = compiler.TeamBoundary(r.Boundary, target)
		from = r.BoundarySource
	} else {
		b, err = compiler.Boundary(r.Doc, target)
	}
	if err != nil {
		return Compiled{}, err
	}
	if r.Boundary != nil {
		if err := compiler.CheckMCP(r.Doc, r.Boundary); err != nil {
			return Compiled{}, err
		}
	}
	pol, err := p.YAML("Generated by fenzi from " + r.Sources + " for " + agent.Name + ". Do not edit.")
	if err != nil {
		return Compiled{}, err
	}
	bnd, err := b.YAML("Boundary generated by fenzi from " + from + " for " + agent.Name + ". Do not edit.")
	if err != nil {
		return Compiled{}, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return Compiled{}, err
	}
	c := Compiled{Policy: filepath.Join(dir, "policy.yaml"), Boundary: filepath.Join(dir, "boundary.yaml")}
	if err := os.WriteFile(c.Policy, pol, 0o600); err != nil {
		return Compiled{}, err
	}
	if err := os.WriteFile(c.Boundary, bnd, 0o600); err != nil {
		return Compiled{}, err
	}
	c.ProvePolicy, c.ProveBoundary = c.Policy, c.Boundary
	if p.Unprovable() || b.Unprovable() {
		pp, err := p.ForProver().YAML(proverNote + "generated by fenzi from " + r.Sources + " for " + agent.Name + ". Do not edit.")
		if err != nil {
			return Compiled{}, err
		}
		pb, err := b.ForProver().YAML(proverNote + "boundary generated by fenzi from " + from + " for " + agent.Name + ". Do not edit.")
		if err != nil {
			return Compiled{}, err
		}
		c.ProvePolicy, c.ProveBoundary = filepath.Join(dir, "prove.policy.yaml"), filepath.Join(dir, "prove.boundary.yaml")
		if err := os.WriteFile(c.ProvePolicy, pp, 0o600); err != nil {
			return Compiled{}, err
		}
		if err := os.WriteFile(c.ProveBoundary, pb, 0o600); err != nil {
			return Compiled{}, err
		}
		for _, n := range r.Doc.MCPNames() {
			if m := r.Doc.MCP[n]; m.Remote() && m.For(agent.Name) {
				c.MCP++
			}
		}
	}
	sum := sha256.Sum256(pol)
	c.Revision = "local-" + hex.EncodeToString(sum[:])[:8]
	return c, nil
}

// proverNote heads the copies the prover reads: openshell-prover 0.1.2
// cannot read MCP rules, credential bindings or allow_encoded_slash.
const proverNote = "For the prover, without MCP rules, secret bindings or allow_encoded_slash: "

func relTo(base, p string) string {
	if r, err := filepath.Rel(base, p); err == nil && !filepath.IsAbs(r) && r != "" && r[0] != '.' {
		return "./" + r
	}
	return p
}
