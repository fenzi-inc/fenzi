package main

// approve --save: the host an approved request names, written into the
// project's boundlane.yaml so the next sandbox in that folder starts with it.

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"

	"boundlane/compiler"
	"boundlane/policies"
)

// savedHost is one hosts entry of a project file, made from a request.
type savedHost struct {
	Host   string
	Port   int
	Access string
	Allow  []string
	// L4 means the request named no method or path.
	L4 bool
	// Widened means the request allowed only GET or HEAD on one path, saved
	// as the read-only level, which allows them on every path.
	Widened bool
	// Rule is the request's rule as the runtime printed it.
	Rule string
}

func (h savedHost) key() string { return fmt.Sprintf("%s:%d", h.Host, h.Port) }

// endpointLine is the Endpoints line of `openshell rule get`. The shapes
// recorded from OpenShell 0.1.2 are:
//
//	paste.example.net:443 [L4]
//	registry.npmjs.org:443 [L7 rest, access=read-only]
//	www.example.com:443 [L7 rest, allow GET /]
//
// A line with more than one endpoint, more than one allow rule, or any other
// access level has not been recorded, so it is not saved.
var (
	endpointLine = regexp.MustCompile(`^([a-z0-9][a-z0-9.-]*):(\d+) \[([^\]]+)\]$`)
	l7Access     = regexp.MustCompile(`^L7 rest, access=read-only$`)
	l7Allow      = regexp.MustCompile(`^L7 rest, allow ([A-Z]+) (/\S*)$`)
)

// requestHost maps a request's Endpoints line to a project file entry.
func requestHost(endpoints string) (savedHost, error) {
	m := endpointLine.FindStringSubmatch(strings.TrimSpace(endpoints))
	if m == nil {
		return savedHost{}, fmt.Errorf("its rule (%s) is in a form boundlane cannot save yet", endpoints)
	}
	port, err := strconv.Atoi(m[2])
	if err != nil {
		return savedHost{}, fmt.Errorf("its rule (%s) has no usable port", endpoints)
	}
	h := savedHost{Host: m[1], Port: port, Rule: m[3]}
	switch rule := m[3]; {
	case rule == "L4":
		h.Access, h.L4 = compiler.AccessReadOnly, true
	case l7Access.MatchString(rule):
		h.Access = compiler.AccessReadOnly
	case l7Allow.MatchString(rule):
		a := l7Allow.FindStringSubmatch(rule)
		if a[1] == "GET" || a[1] == "HEAD" {
			h.Access, h.Widened = compiler.AccessReadOnly, true
		} else {
			h.Access, h.Allow = compiler.AccessReadWrite, []string{a[1] + " " + a[2]}
		}
	default:
		return savedHost{}, fmt.Errorf("its rule (%s) is in a form boundlane cannot save yet", rule)
	}
	return h, nil
}

// projectFile is a boundlane.yaml read as YAML nodes, so its comments and
// order survive an edit.
type projectFile struct {
	path string
	doc  yaml.Node
	mode fs.FileMode
}

// loadProject reads path, or starts an empty document when there is none.
func loadProject(path string) (*projectFile, error) {
	p := &projectFile{path: path, mode: 0o644}
	raw, err := os.ReadFile(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		raw = nil
	case err != nil:
		return nil, err
	default:
		if info, err := os.Stat(path); err == nil {
			p.mode = info.Mode().Perm()
		}
	}
	if err := yaml.Unmarshal(raw, &p.doc); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if len(p.doc.Content) > 0 {
		if _, err := compiler.Parse(raw); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
	} else {
		// No document, at most comments: start one and keep them on top.
		p.doc = yaml.Node{Kind: yaml.DocumentNode, HeadComment: strings.TrimSpace(string(raw))}
	}
	if len(p.doc.Content) == 0 {
		p.doc.Content = []*yaml.Node{{Kind: yaml.MappingNode, Tag: "!!map"}}
	}
	if p.doc.Content[0].Kind != yaml.MappingNode {
		return nil, fmt.Errorf("%s: the top level is not a mapping", path)
	}
	root := p.doc.Content[0]
	if value(root, "version") == nil {
		root.Content = append([]*yaml.Node{scalar("version"), {Kind: yaml.ScalarNode, Tag: "!!int", Value: "1"}}, root.Content...)
	}
	return p, nil
}

// value returns the node for key in a mapping, or nil.
func value(m *yaml.Node, key string) *yaml.Node {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

func scalar(s string) *yaml.Node { return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: s} }

// hosts returns the hosts sequence, creating it when the key is missing or
// empty. Comments on an empty value move to the new sequence.
func (p *projectFile) hosts() *yaml.Node {
	root := p.doc.Content[0]
	for i := 0; i+1 < len(root.Content); i += 2 {
		if root.Content[i].Value != "hosts" {
			continue
		}
		v := root.Content[i+1]
		if v.Kind == yaml.SequenceNode {
			return v
		}
		seq := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", HeadComment: v.HeadComment, LineComment: v.LineComment, FootComment: v.FootComment}
		root.Content[i+1] = seq
		return seq
	}
	seq := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	root.Content = append(root.Content, scalar("hosts"), seq)
	return seq
}

// entryPort is an entry's port, 443 when it names none.
func entryPort(e *yaml.Node) int {
	if v := value(e, "port"); v != nil {
		if n, err := strconv.Atoi(v.Value); err == nil {
			return n
		}
	}
	return 443
}

// saveOutcome says what happened to boundlane.yaml.
type saveOutcome struct {
	Saved bool
	// Detail is one line for the person: what was written, or why not.
	Detail string
}

// add puts h into the hosts list. A host the project already lists on the
// same port is left alone unless both are read-write, where the allow line
// is added. A host developer-default lists is left alone too, because a
// project entry replaces it rather than adding to it.
func (p *projectFile) add(h savedHost) saveOutcome {
	seq := p.hosts()
	for _, e := range seq.Content {
		if e.Kind != yaml.MappingNode || value(e, "host") == nil || value(e, "host").Value != h.Host || entryPort(e) != h.Port {
			continue
		}
		access := ""
		if v := value(e, "access"); v != nil {
			access = v.Value
		}
		switch {
		case access == h.Access && h.Access == compiler.AccessReadOnly:
			return saveOutcome{Detail: h.Host + " is already read-only in " + projectName}
		case access == h.Access && h.Access == compiler.AccessReadWrite:
			allow := value(e, "allow")
			if allow == nil {
				allow = &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
				e.Content = append(e.Content, scalar("allow"), allow)
			}
			for _, line := range allow.Content {
				if line.Value == h.Allow[0] {
					return saveOutcome{Detail: h.Host + " already allows " + h.Allow[0] + " in " + projectName}
				}
			}
			allow.Content = append(allow.Content, scalar(h.Allow[0]))
			return saveOutcome{Saved: true, Detail: h.Host + ", read-write, added " + h.Allow[0]}
		default:
			return saveOutcome{Detail: fmt.Sprintf("%s is %s in %s; saving %s there would change what it allows. Edit that entry by hand", h.Host, access, projectName, describe(h))}
		}
	}
	for _, b := range policies.DeveloperDefault().Hosts {
		port := b.Port
		if port == 0 {
			port = 443
		}
		if b.Host != h.Host || port != h.Port {
			continue
		}
		if b.Access == h.Access && h.Access == compiler.AccessReadOnly {
			return saveOutcome{Detail: h.Host + " is already read-only in developer-default"}
		}
		return saveOutcome{Detail: fmt.Sprintf("developer-default makes %s %s, and a project entry would replace that. Add %s to %s by hand, with the requests you still need", h.Host, b.Access, describe(h), projectName)}
	}
	entry := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	entry.Content = append(entry.Content, scalar("host"), scalar(h.Host))
	if h.Port != 443 {
		entry.Content = append(entry.Content, scalar("port"), &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!int", Value: strconv.Itoa(h.Port)})
	}
	entry.Content = append(entry.Content, scalar("access"), scalar(h.Access))
	if len(h.Allow) > 0 {
		allow := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
		for _, l := range h.Allow {
			allow.Content = append(allow.Content, scalar(l))
		}
		entry.Content = append(entry.Content, scalar("allow"), allow)
	}
	seq.Content = append(seq.Content, entry)
	return saveOutcome{Saved: true, Detail: h.Host + ", " + describe(h)}
}

// projectName is how messages name the project file.
const projectName = "boundlane.yaml"

func describe(h savedHost) string {
	if len(h.Allow) > 0 {
		return h.Access + ", " + strings.Join(h.Allow, ", ")
	}
	return h.Access
}

// bytes encodes the document with two-space indentation.
func (p *projectFile) bytes() ([]byte, error) {
	var b bytes.Buffer
	enc := yaml.NewEncoder(&b)
	enc.SetIndent(2)
	if err := enc.Encode(&p.doc); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// write checks that the edited file is still a project file developer-default
// accepts, then writes it.
func (p *projectFile) write() error {
	out, err := p.bytes()
	if err != nil {
		return err
	}
	doc, err := compiler.Parse(out)
	if err != nil {
		return err
	}
	merged, err := compiler.Merge(policies.DeveloperDefault(), doc)
	if err != nil {
		return err
	}
	if err := merged.WithDefaults().Validate(); err != nil {
		return err
	}
	return os.WriteFile(p.path, out, p.mode)
}
