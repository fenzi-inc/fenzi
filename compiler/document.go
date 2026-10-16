// Package compiler turns a Fenzi policy document into an OpenShell sandbox
// policy and the boundary the policy prover checks it against.
//
// The package has no dependency on a running gateway. It must not import
// os/exec or anything under cli/.
package compiler

import (
	"bytes"
	"errors"
	"fmt"

	"go.yaml.in/yaml/v3"
)

const (
	WorkspaceReadWrite = "read-write"
	WorkspaceReadOnly  = "read-only"

	AccessReadOnly  = "read-only"
	AccessReadWrite = "read-write"

	ApprovalsPerson = "person"
)

// Document is the org policy document (fenzi.yaml). It is smaller than
// OpenShell's schema and only expresses what OpenShell enforces and the
// prover models.
type Document struct {
	Version   int      `yaml:"version"`
	Name      string   `yaml:"name,omitempty"`
	Agents    []string `yaml:"agents,omitempty"`
	Workspace string   `yaml:"workspace,omitempty"`
	Paths     Paths    `yaml:"paths,omitempty"`
	Hosts     []Host   `yaml:"hosts,omitempty"`
	Approvals string   `yaml:"approvals,omitempty"`
}

type Paths struct {
	ReadOnly  []string `yaml:"read_only,omitempty"`
	ReadWrite []string `yaml:"read_write,omitempty"`
}

type Host struct {
	Host   string   `yaml:"host"`
	Port   int      `yaml:"port,omitempty"`
	Access string   `yaml:"access"`
	Allow  []string `yaml:"allow,omitempty"`
}

// Parse reads a document and rejects unknown fields and duplicate keys.
// It does not validate values; call Validate for that.
func Parse(data []byte) (*Document, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var d Document
	if err := dec.Decode(&d); err != nil {
		return nil, fmt.Errorf("parse policy document: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); err == nil {
		return nil, errors.New("parse policy document: more than one YAML document in file")
	}
	return &d, nil
}

// WithDefaults returns a copy with defaults filled in: workspace read-write,
// approvals by a person, port 443.
func (d *Document) WithDefaults() *Document {
	out := d.clone()
	if out.Workspace == "" {
		out.Workspace = WorkspaceReadWrite
	}
	if out.Approvals == "" {
		out.Approvals = ApprovalsPerson
	}
	for i := range out.Hosts {
		if out.Hosts[i].Port == 0 {
			out.Hosts[i].Port = 443
		}
	}
	return out
}

func (d *Document) clone() *Document {
	out := *d
	out.Agents = append([]string(nil), d.Agents...)
	out.Paths.ReadOnly = append([]string(nil), d.Paths.ReadOnly...)
	out.Paths.ReadWrite = append([]string(nil), d.Paths.ReadWrite...)
	out.Hosts = make([]Host, len(d.Hosts))
	for i, h := range d.Hosts {
		h.Allow = append([]string(nil), h.Allow...)
		out.Hosts[i] = h
	}
	return &out
}
