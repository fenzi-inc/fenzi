package main

// approve --save: the host an approved request names, written into the
// project's boundlane.yaml so the next sandbox in that folder starts with it.

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"

	"boundlane/agents"
	"boundlane/cli/internal/config"
	"boundlane/cli/internal/openshell"
	"boundlane/cli/internal/run"
	"boundlane/cli/internal/tui"
	"boundlane/cli/internal/workspace"
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
	// Already means the file or developer-default has the host at that level.
	Already bool
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
			return saveOutcome{Already: true, Detail: h.Host + " is already read-only in " + projectName}
		case access == h.Access && h.Access == compiler.AccessReadWrite:
			allow := value(e, "allow")
			if allow == nil {
				allow = &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
				e.Content = append(e.Content, scalar("allow"), allow)
			}
			for _, line := range allow.Content {
				if line.Value == h.Allow[0] {
					return saveOutcome{Already: true, Detail: h.Host + " already allows " + h.Allow[0] + " in " + projectName}
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
			return saveOutcome{Already: true, Detail: h.Host + " is already read-only in developer-default"}
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
	if err := checkProject(out); err != nil {
		return err
	}
	return os.WriteFile(p.path, out, p.mode)
}

// checkProject says whether raw is a project file developer-default accepts.
func checkProject(raw []byte) error {
	doc, err := compiler.Parse(raw)
	if err != nil {
		return err
	}
	merged, err := compiler.Merge(policies.DeveloperDefault(), doc)
	if err != nil {
		return err
	}
	return merged.WithDefaults().Validate()
}

// savePreview is what approve --save would do to boundlane.yaml, worked out
// without approving the request or writing the file.
type savePreview struct {
	Path   string
	Exists bool
	Mode   fs.FileMode
	Before []byte
	After  []byte
	// From is the --policy-from file, or empty when the edit is generated.
	From string
	Host savedHost
	// HostErr is set when the request's rule is in a form that cannot be
	// saved. Only --policy-from goes on with it, since the person wrote the file.
	HostErr error
	// Outcome is what adding the host to the current file does.
	Outcome saveOutcome
	Note    string
	Sources string
	Agent   agents.Entry
	Check   openshell.Result
}

// Changed says whether the file would be different.
func (pv *savePreview) Changed() bool {
	return !bytes.Equal(pv.Before, pv.After) || !pv.Exists && len(pv.After) > 0
}

// previewSave works out the new boundlane.yaml for a request in sb: the
// generated edit, or the content of from when it is given. It then runs the
// check boundlane policy check runs on that content, written to a temporary
// folder. The project file itself is only read.
func previewSave(e env, sb config.Sandbox, p openshell.Proposal, from string) (*savePreview, error) {
	host, hostErr := requestHost(p.Endpoints)
	if hostErr != nil && from == "" {
		return nil, hostErr
	}
	repo := sb.Repo
	if repo == "" {
		var err error
		if repo, err = cwd(); err != nil {
			return nil, err
		}
	}
	pv := &savePreview{Path: filepath.Join(repo, projectName), Mode: 0o644, From: from, Host: host, HostErr: hostErr}
	raw, err := os.ReadFile(pv.Path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return nil, err
	default:
		pv.Exists, pv.Before = true, raw
		if info, err := os.Stat(pv.Path); err == nil {
			pv.Mode = info.Mode().Perm()
		}
	}
	current, err := loadProject(pv.Path)
	if err != nil {
		return nil, err
	}
	if hostErr == nil {
		pv.Outcome = current.add(host)
	}
	pv.After = pv.Before
	switch {
	case from != "":
		if pv.After, err = os.ReadFile(from); err != nil {
			return nil, err
		}
		if len(bytes.TrimSpace(pv.After)) == 0 {
			return nil, fmt.Errorf("%s is empty", from)
		}
		if err := checkProject(pv.After); err != nil {
			return nil, fmt.Errorf("%s: %w", from, err)
		}
		pv.Note = pv.fromNote()
	case pv.Outcome.Saved:
		if pv.After, err = current.bytes(); err != nil {
			return nil, err
		}
		if err := checkProject(pv.After); err != nil {
			return nil, err
		}
		pv.Note = widenedNote(host)
	default:
		pv.Note = pv.Outcome.Detail
	}

	name := sb.Agent
	if name == "" {
		name = defaultAgent()
	}
	if pv.Agent, err = agents.Get(name); err != nil {
		return nil, err
	}
	tmp, err := os.MkdirTemp("", "boundlane-save-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)
	if len(pv.After) > 0 {
		if err := os.WriteFile(filepath.Join(tmp, projectName), pv.After, 0o600); err != nil {
			return nil, err
		}
	}
	resolved, err := run.ResolveFree(tmp, "")
	if err != nil {
		return nil, err
	}
	pv.Sources = resolved.Sources
	if pv.Check, err = proveResolved(e, resolved, pv.Agent, ""); err != nil {
		return nil, err
	}
	return pv, nil
}

// fromNote says when the file given does not have the request's host.
func (pv *savePreview) fromNote() string {
	if pv.HostErr != nil {
		return "boundlane cannot turn this request's rule into an entry, so the file given is used as it is."
	}
	given := &projectFile{}
	if err := yaml.Unmarshal(pv.After, &given.doc); err != nil || len(given.doc.Content) == 0 || given.doc.Content[0].Kind != yaml.MappingNode {
		return ""
	}
	if out := given.add(pv.Host); out.Saved {
		return "The file given does not list " + pv.Host.Host + ", " + describe(pv.Host) + ". This sandbox gets the approval; the next one in this folder asks again."
	}
	return ""
}

// widenedNote explains a saved line that allows other requests than the
// one approved.
func widenedNote(h savedHost) string {
	switch {
	case h.L4:
		return "The request named no method or path, so the approved rule lets any traffic through to " + h.key() + ". The saved line is read-only: GET, HEAD, and OPTIONS. Change it in " + projectName + " if the agent needs more."
	case h.Widened:
		return "The request allowed " + strings.TrimPrefix(h.Rule, "L7 rest, allow ") + " only. The saved line is read-only, the closest level " + projectName + " has: GET, HEAD, and OPTIONS on every path."
	}
	return ""
}

// unifiedDiff is a unified diff of boundlane.yaml before and after, or ""
// when nothing changes.
func unifiedDiff(existed bool, before, after []byte) string {
	if bytes.Equal(before, after) && (existed || len(after) == 0) {
		return ""
	}
	hunks, ok := workspace.Hunks(before, after)
	if !ok {
		return ""
	}
	var b strings.Builder
	if existed {
		b.WriteString("--- a/" + projectName + "\n")
	} else {
		b.WriteString("--- /dev/null\n")
	}
	b.WriteString("+++ b/" + projectName + "\n")
	for _, h := range hunks {
		fmt.Fprintf(&b, "@@ -%s +%s @@\n", hunkRange(h.OldStart, h.OldLines), hunkRange(h.NewStart, h.NewLines))
		for _, o := range h.Ops {
			b.WriteByte(o.Kind)
			b.WriteString(o.Text)
			b.WriteByte('\n')
		}
	}
	return b.String()
}

// hunkRange is one side of a hunk header. An empty side names the line
// before it, as diff -u does.
func hunkRange(start, lines int) string {
	if lines == 0 {
		start--
	}
	return fmt.Sprintf("%d,%d", start, lines)
}

// jsonSavePreview is what approve --save --dry-run --json prints.
type jsonSavePreview struct {
	// File is the absolute path of the project file, and Exists whether it
	// is there now.
	File   string `json:"file"`
	Exists bool   `json:"exists"`
	Before string `json:"before"`
	After  string `json:"after"`
	// Diff is the unified diff from Before to After, empty when they match.
	Diff string `json:"diff"`
	// Host, Port, Access and Allow are the entry the request becomes. Host
	// and Access are empty when the request's rule cannot be an entry.
	Host   string   `json:"host"`
	Port   int      `json:"port,omitempty"`
	Access string   `json:"access"`
	Allow  []string `json:"allow"`
	// Already is true when the current file or developer-default has the
	// host at that level, so there is nothing to add.
	Already bool   `json:"already"`
	Note    string `json:"note"`
	// From is the --policy-from file, when one was given.
	From  string        `json:"from,omitempty"`
	Check jsonSaveCheck `json:"check"`
}

// jsonSaveCheck is the policy check of the file as it would be.
type jsonSaveCheck struct {
	Passed bool `json:"passed"`
	// Result is the prover's word, as in boundlane policy check --json.
	Result  string `json:"result"`
	Checked string `json:"checked"`
	Agent   string `json:"agent"`
	Example string `json:"example"`
	Reason  string `json:"reason"`
}

func (pv *savePreview) json() jsonSavePreview {
	doc := jsonSavePreview{
		File: pv.Path, Exists: pv.Exists, Before: string(pv.Before), After: string(pv.After),
		Diff: unifiedDiff(pv.Exists, pv.Before, pv.After), Allow: []string{},
		Already: pv.Outcome.Already, Note: pv.Note, From: pv.From,
		Check: jsonSaveCheck{Passed: pv.Check.Passed(), Result: pv.Check.Result, Checked: pv.Sources, Agent: pv.Agent.Display, Example: pv.Check.Example(), Reason: pv.Check.Reason},
	}
	if pv.HostErr == nil {
		doc.Host, doc.Port, doc.Access = pv.Host.Host, pv.Host.Port, pv.Host.Access
		if len(pv.Host.Allow) > 0 {
			doc.Allow = pv.Host.Allow
		}
	}
	return doc
}

// printPreview shows the change approve --save would make, and its check.
func printPreview(u *tui.UI, pv *savePreview, id string) {
	u.Title("Preview of approve --save", "nothing is approved or written")
	state := "exists"
	if !pv.Exists {
		state = "new file"
	}
	u.Println(fmt.Sprintf("    %s  %s, %s", u.Bold("File"), tilde(pv.Path, homeDir()), state))
	if pv.From != "" {
		u.Println(fmt.Sprintf("    %s  %s", u.Bold("From"), pv.From))
	}
	switch {
	case pv.From != "" || pv.HostErr != nil:
	case pv.Outcome.Saved:
		u.Println(fmt.Sprintf("    %s  %s, %s", u.Bold("Adds"), pv.Host.Host, describe(pv.Host)))
	default:
		u.Println(fmt.Sprintf("    %s  nothing", u.Bold("Adds")))
	}
	if pv.Note != "" {
		u.Note(pv.Note)
	}
	u.Blank()
	if d := unifiedDiff(pv.Exists, pv.Before, pv.After); d != "" {
		for _, line := range strings.Split(strings.TrimSuffix(d, "\n"), "\n") {
			switch {
			case strings.HasPrefix(line, "+++"), strings.HasPrefix(line, "---"), strings.HasPrefix(line, "@@"):
				line = u.Dim(line)
			case strings.HasPrefix(line, "+"):
				line = u.Allow(line)
			case strings.HasPrefix(line, "-"):
				line = u.Deny(line)
			}
			u.Println("    " + line)
		}
	} else {
		u.Note(projectName + " stays as it is.")
	}
	printCheck(u, pv.Check, pv.Sources, "", pv.Agent)
	if !pv.Check.Passed() {
		u.Note("Nothing was approved or written.")
		u.Blank()
		return
	}
	switch {
	case pv.From != "":
		u.Command("boundlane approve "+shortID(id)+" --save --policy-from "+pv.From, "approves it and writes this file")
	case pv.Changed():
		u.Command("boundlane approve "+shortID(id)+" --save", "approves it and writes this")
	default:
		u.Command("boundlane approve "+shortID(id), "approves it for this sandbox")
	}
	u.Blank()
}
