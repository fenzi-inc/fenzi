package compiler

import (
	"bytes"
	"fmt"

	"go.yaml.in/yaml/v3"
)

// Policy is the subset of the OpenShell sandbox policy schema (version 1) the
// compiler emits. Field names and meanings follow the upstream Policy Schema
// Reference. network_middlewares is never emitted in the MVP.
type Policy struct {
	Version          int                    `yaml:"version"`
	FilesystemPolicy *FilesystemPolicy      `yaml:"filesystem_policy,omitempty"`
	Landlock         *Landlock              `yaml:"landlock,omitempty"`
	Process          *Process               `yaml:"process,omitempty"`
	NetworkPolicies  map[string]NetworkRule `yaml:"network_policies,omitempty"`
}

type FilesystemPolicy struct {
	IncludeWorkdir bool     `yaml:"include_workdir"`
	ReadOnly       []string `yaml:"read_only,omitempty"`
	ReadWrite      []string `yaml:"read_write,omitempty"`
}

type Landlock struct {
	Compatibility string `yaml:"compatibility"`
}

type Process struct {
	RunAsUser  string `yaml:"run_as_user,omitempty"`
	RunAsGroup string `yaml:"run_as_group,omitempty"`
}

type NetworkRule struct {
	Name      string     `yaml:"name,omitempty"`
	Endpoints []Endpoint `yaml:"endpoints"`
	Binaries  []Binary   `yaml:"binaries"`
}

type Endpoint struct {
	Host string `yaml:"host"`
	Port int    `yaml:"port"`
	// Path, DenyRules, MCP, and CredentialBinding are set only on an MCP
	// server's endpoint (protocol mcp), as recorded on OpenShell 0.1.2.
	Path              string             `yaml:"path,omitempty"`
	Protocol          string             `yaml:"protocol,omitempty"`
	Enforcement       string             `yaml:"enforcement,omitempty"`
	Access            string             `yaml:"access,omitempty"`
	Rules             []Rule             `yaml:"rules,omitempty"`
	AllowEncodedSlash bool               `yaml:"allow_encoded_slash,omitempty"`
	DenyRules         []DenyRule         `yaml:"deny_rules,omitempty"`
	MCP               *MCPOptions        `yaml:"mcp,omitempty"`
	CredentialBinding *CredentialBinding `yaml:"credential_binding,omitempty"`
}

type Rule struct {
	Allow Match `yaml:"allow"`
}

// Match is a REST method and path, or an MCP method and, for tools/call,
// a tool name.
type Match struct {
	Method string `yaml:"method"`
	Path   string `yaml:"path,omitempty"`
	Tool   string `yaml:"tool,omitempty"`
}

// DenyRule refuses an MCP method, or one tool of tools/call, even when an
// allow rule matches.
type DenyRule struct {
	Method string `yaml:"method"`
	Tool   string `yaml:"tool,omitempty"`
}

// MCPOptions are the protocol revisions an MCP endpoint accepts.
type MCPOptions struct {
	Versions []string `yaml:"versions"`
}

// CredentialBinding names the provider whose token the sandbox puts on this
// endpoint's requests. The provider's profile has no endpoints of its own.
type CredentialBinding struct {
	Provider string `yaml:"provider"`
}

type Binary struct {
	Path string `yaml:"path"`
}

// YAML renders the policy with a header naming its source. Map keys are
// sorted, so the output is stable for golden tests and signing.
func (p *Policy) YAML(header string) ([]byte, error) {
	var buf bytes.Buffer
	if header != "" {
		fmt.Fprintf(&buf, "# %s\n", header)
	}
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(p); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
