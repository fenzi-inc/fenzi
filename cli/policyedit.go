package main

// fenzi policy host and fenzi policy path: edit this folder's fenzi.yaml one
// entry at a time, so nobody has to write YAML by hand. The file is read as
// YAML nodes, so comments and order survive, and the result is checked over
// developer-default before it is written.

import (
	"fmt"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"

	"fenzi/cli/internal/tui"
	"fenzi/compiler"
)

// jsonPolicyEdit is what --json prints after an edit.
type jsonPolicyEdit struct {
	File    string `json:"file"`
	Changed bool   `json:"changed"`
	// Detail is one line for the person: what was written, or why nothing was.
	Detail string `json:"detail"`
	// removed is set when the edit took something out, for the wording.
	removed bool
}

func cmdPolicyHost(e env, args []string) (int, error) {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		subHelp(e, "policy host", "Add, change or remove a host in this folder's fenzi.yaml. The next sandbox started here gets it.", [][2]string{
			{"policy host set <host>", "Read only, or --write \"METHOD /path\" for each request it may make"},
			{"policy host remove <host>", "Take it out of fenzi.yaml"},
		}, "--port when it is not 443. A host developer-default lists is changed by a fenzi.yaml entry, not removed.")
		return 0, nil
	}
	sub := args[0]
	if sub != "set" && sub != "remove" {
		return 1, fmt.Errorf("%q is not a host command; try fenzi policy host set or remove", sub)
	}
	fs := newFlags("policy host "+sub, e.stderr)
	port := fs.Int("port", 443, "the host's port")
	var write stringList
	if sub == "set" {
		fs.Var(&write, "write", `a request it may make, "METHOD /path"; repeat it. Without it the host is read only`)
	}
	asJSON := jsonFlag(fs)
	pos, err := parse(fs, args[1:])
	if err != nil {
		return 1, err
	}
	if len(pos) != 1 {
		return 1, fmt.Errorf("name the host: fenzi policy host %s api.example.com", sub)
	}
	host := strings.ToLower(strings.TrimSpace(pos[0]))
	p, err := loadHere()
	if err != nil {
		return 1, err
	}
	var out jsonPolicyEdit
	if sub == "set" {
		out = p.setHost(host, *port, write)
	} else {
		out = p.removeHost(host, *port)
	}
	return finishEdit(e, p, out, *asJSON)
}

func cmdPolicyPath(e env, args []string) (int, error) {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		subHelp(e, "policy path", "Add or remove a path inside the sandbox in this folder's fenzi.yaml. Paths are fixed when a sandbox is made, so the next new sandbox gets the change.", [][2]string{
			{"policy path add <path>", "Read only, or --write to let the agent change it"},
			{"policy path remove <path>", "Take it out of fenzi.yaml"},
		}, "")
		return 0, nil
	}
	sub := args[0]
	if sub != "add" && sub != "remove" {
		return 1, fmt.Errorf("%q is not a path command; try fenzi policy path add or remove", sub)
	}
	fs := newFlags("policy path "+sub, e.stderr)
	var writable *bool
	if sub == "add" {
		writable = fs.Bool("write", false, "the agent may change it")
	}
	asJSON := jsonFlag(fs)
	pos, err := parse(fs, args[1:])
	if err != nil {
		return 1, err
	}
	if len(pos) != 1 {
		return 1, fmt.Errorf("name the path: fenzi policy path %s /opt/fixtures", sub)
	}
	path := strings.TrimSpace(pos[0])
	p, err := loadHere()
	if err != nil {
		return 1, err
	}
	var out jsonPolicyEdit
	if sub == "add" {
		out = p.addPath(path, *writable)
	} else {
		out = p.removePath(path)
	}
	return finishEdit(e, p, out, *asJSON)
}

// loadHere reads ./fenzi.yaml, or starts one.
func loadHere() (*projectFile, error) {
	repo, err := cwd()
	if err != nil {
		return nil, err
	}
	return loadProject(filepath.Join(repo, projectName))
}

// finishEdit writes the file when it changed and says what happened.
func finishEdit(e env, p *projectFile, out jsonPolicyEdit, asJSON bool) (int, error) {
	out.File = p.path
	if out.Changed {
		if err := p.write(); err != nil {
			return 1, err
		}
	}
	if asJSON {
		return 0, writeJSON(e.stdout, out)
	}
	u := tui.New(e.stdin, e.stdout)
	u.Blank()
	switch {
	case out.Changed && out.removed:
		u.Done("Removed", strings.TrimPrefix(out.Detail, "removed "))
		u.Note("The next sandbox started in this folder goes without it.")
	case out.Changed:
		u.Done("Saved", out.Detail)
		u.Note("The next sandbox started in this folder gets it.")
	default:
		u.Skip("Nothing changed", out.Detail)
	}
	u.Blank()
	return 0, nil
}

// setHost puts host in the hosts list at the access the write lines give:
// read only without any, read-write with exactly those requests. An entry
// for the same host and port is replaced, not merged, so the list says
// what the person chose.
func (p *projectFile) setHost(host string, port int, write []string) jsonPolicyEdit {
	access := compiler.AccessReadOnly
	if len(write) > 0 {
		access = compiler.AccessReadWrite
	}
	entry := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	entry.Content = append(entry.Content, scalar("host"), scalar(host))
	if port != 443 {
		entry.Content = append(entry.Content, scalar("port"), &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!int", Value: strconv.Itoa(port)})
	}
	entry.Content = append(entry.Content, scalar("access"), scalar(access))
	if len(write) > 0 {
		allow := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
		for _, l := range write {
			allow.Content = append(allow.Content, scalar(strings.Join(strings.Fields(l), " ")))
		}
		entry.Content = append(entry.Content, scalar("allow"), allow)
	}
	label := host
	if port != 443 {
		label = fmt.Sprintf("%s:%d", host, port)
	}
	what := "read only"
	if len(write) > 0 {
		what = "read-write, " + strings.Join(write, ", ")
	}
	seq := p.hosts()
	for i, e := range seq.Content {
		if e.Kind == yaml.MappingNode && value(e, "host") != nil && value(e, "host").Value == host && entryPort(e) == port {
			entry.HeadComment, entry.LineComment, entry.FootComment = e.HeadComment, e.LineComment, e.FootComment
			seq.Content[i] = entry
			return jsonPolicyEdit{Changed: true, Detail: label + ", " + what}
		}
	}
	seq.Content = append(seq.Content, entry)
	return jsonPolicyEdit{Changed: true, Detail: label + ", " + what}
}

func (p *projectFile) removeHost(host string, port int) jsonPolicyEdit {
	seq := p.hosts()
	for i, e := range seq.Content {
		if e.Kind == yaml.MappingNode && value(e, "host") != nil && value(e, "host").Value == host && entryPort(e) == port {
			seq.Content = slices.Delete(seq.Content, i, i+1)
			return jsonPolicyEdit{Changed: true, removed: true, Detail: "removed " + host + " from " + projectName}
		}
	}
	return jsonPolicyEdit{Detail: host + " is not in " + projectName}
}

// pathList returns the list for key under paths, creating both.
func (p *projectFile) pathList(key string) *yaml.Node {
	root := p.doc.Content[0]
	paths := value(root, "paths")
	if paths == nil || paths.Kind != yaml.MappingNode {
		m := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		if paths == nil {
			root.Content = append(root.Content, scalar("paths"), m)
		} else {
			for i := 0; i+1 < len(root.Content); i += 2 {
				if root.Content[i].Value == "paths" {
					root.Content[i+1] = m
				}
			}
		}
		paths = m
	}
	list := value(paths, key)
	if list == nil || list.Kind != yaml.SequenceNode {
		seq := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
		if list == nil {
			paths.Content = append(paths.Content, scalar(key), seq)
		} else {
			for i := 0; i+1 < len(paths.Content); i += 2 {
				if paths.Content[i].Value == key {
					paths.Content[i+1] = seq
				}
			}
		}
		list = seq
	}
	return list
}

func (p *projectFile) addPath(path string, writable bool) jsonPolicyEdit {
	key, other := "read_only", "read_write"
	what := "read only"
	if writable {
		key, other, what = "read_write", "read_only", "read and write"
	}
	// A path is in one list: moving it between them is a change of access.
	p.dropPath(other, path)
	list := p.pathList(key)
	for _, n := range list.Content {
		if n.Value == path {
			return jsonPolicyEdit{Detail: path + " is already " + what}
		}
	}
	list.Content = append(list.Content, scalar(path))
	p.tidyPaths()
	return jsonPolicyEdit{Changed: true, Detail: path + ", " + what}
}

func (p *projectFile) removePath(path string) jsonPolicyEdit {
	removed := p.dropPath("read_only", path) || p.dropPath("read_write", path)
	p.tidyPaths()
	if !removed {
		return jsonPolicyEdit{Detail: path + " is not in " + projectName}
	}
	return jsonPolicyEdit{Changed: true, removed: true, Detail: "removed " + path + " from " + projectName}
}

func (p *projectFile) dropPath(key, path string) bool {
	paths := value(p.doc.Content[0], "paths")
	if paths == nil || paths.Kind != yaml.MappingNode {
		return false
	}
	list := value(paths, key)
	if list == nil || list.Kind != yaml.SequenceNode {
		return false
	}
	for i, n := range list.Content {
		if n.Value == path {
			list.Content = slices.Delete(list.Content, i, i+1)
			return true
		}
	}
	return false
}

// tidyPaths drops empty path lists, and paths itself when it is empty.
func (p *projectFile) tidyPaths() {
	root := p.doc.Content[0]
	for i := 0; i+1 < len(root.Content); i += 2 {
		if root.Content[i].Value != "paths" || root.Content[i+1].Kind != yaml.MappingNode {
			continue
		}
		m := root.Content[i+1]
		for j := 0; j+1 < len(m.Content); {
			if m.Content[j+1].Kind == yaml.SequenceNode && len(m.Content[j+1].Content) == 0 {
				m.Content = slices.Delete(m.Content, j, j+2)
				continue
			}
			j += 2
		}
		if len(m.Content) == 0 {
			root.Content = slices.Delete(root.Content, i, i+2)
		}
		return
	}
}
