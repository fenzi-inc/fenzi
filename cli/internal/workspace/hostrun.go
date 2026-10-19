package workspace

import (
	"bytes"
	"encoding/json"
	"strings"
)

// hostRunFiles are files another tool on this machine runs, or reads for a
// command to run, with no further step from the person: entering the
// folder, opening it in an editor, or the next git commit. Names compare in
// any case, at any depth: on a case-insensitive disk .ENVRC is .envrc. A
// file with root set counts only at the top of the project, where its tool
// reads it.
var hostRunFiles = []hostRunFile{
	{name: ".envrc", why: "direnv runs it when you enter the folder"},
	{dir: ".vscode", name: "tasks.json", why: "VS Code can run its tasks when the folder opens"},
	{dir: ".vscode", name: "settings.json", why: "VS Code applies it when the folder opens"},
	{name: ".pre-commit-config.yaml", why: "pre-commit runs its hooks on git commit"},
	// An agent's own settings in the project: the permissions it stored, the
	// commands it may run without asking next time, and the servers it
	// starts. An agent in the sandbox can widen them for the agent on this
	// machine.
	{dir: ".claude", name: "settings.json", why: agentConfig("Claude Code")},
	{dir: ".claude", name: "settings.local.json", why: agentConfig("Claude Code")},
	{dir: ".codex", name: "config.toml", why: agentConfig("Codex")},
	{dir: ".cursor", name: "mcp.json", why: agentConfig("Cursor")},
	{name: "opencode.json", root: true, why: agentConfig("OpenCode")},
}

type hostRunFile struct {
	dir  string // the folder the file sits in; "" for any
	name string
	root bool // only at the top of the project
	why  string
}

// hostRunDirs are folders whose files git runs as hooks, or an agent reads
// as its configuration. A folder with in set counts only inside that parent;
// one with root set only at the top of the project.
var hostRunDirs = []hostRunDir{
	{dir: ".husky", why: "a git hook; git runs it on commit or push"},
	{dir: ".githooks", why: "a git hook; git runs it on commit or push"},
	{in: ".cursor", dir: "rules", why: agentConfig("Cursor")},
	{dir: ".opencode", root: true, why: agentConfig("OpenCode")},
}

type hostRunDir struct {
	in   string // the folder's parent; "" for any
	dir  string
	root bool // only at the top of the project
	why  string
}

// agentConfig is the label for a file that configures an agent on this
// machine: what it may run without asking next time.
func agentConfig(agent string) string {
	return "configures " + agent + " on this machine: what it may run without asking"
}

// HostRun says why an added or modified file runs on this machine once it
// is applied, or "" when it does not. before and after are the file's
// contents; nil means it was not read, except before an added file, which
// was not there. Only package.json needs them: it is labelled when its
// scripts changed, or when they could not be compared. It labels only;
// apply still writes the file.
func HostRun(c Change, before, after []byte) string {
	switch c.Kind {
	case Deleted:
		return ""
	case Added:
		before = []byte{}
	}
	parts := strings.Split(c.Path, "/")
	name := parts[len(parts)-1]
	parent := ""
	if len(parts) > 1 {
		parent = parts[len(parts)-2]
	}
	for _, f := range hostRunFiles {
		if !strings.EqualFold(name, f.name) {
			continue
		}
		if f.root && len(parts) != 1 {
			continue
		}
		if f.dir == "" || strings.EqualFold(parent, f.dir) {
			return f.why
		}
	}
	for _, d := range hostRunDirs {
		for i, p := range parts[:len(parts)-1] {
			if !strings.EqualFold(p, d.dir) {
				continue
			}
			if d.root && i != 0 {
				continue
			}
			if d.in == "" || (i > 0 && strings.EqualFold(parts[i-1], d.in)) {
				return d.why
			}
		}
	}
	if strings.EqualFold(name, "package.json") && !sameScripts(before, after) {
		return "its scripts changed; npm runs them on install"
	}
	return ""
}

// sameScripts reports whether two package.json files have equal "scripts".
// A file that was not read, or is not JSON, does not compare equal. Empty
// stands for a file that did not exist.
func sameScripts(before, after []byte) bool {
	a, ok := scripts(before)
	if !ok {
		return false
	}
	b, ok := scripts(after)
	if !ok {
		return false
	}
	return bytes.Equal(a, b)
}

// scripts returns the "scripts" value re-encoded, so key order and spacing
// do not count as a change. The key is matched exactly, as npm reads it; a
// struct tag would also match "SCRIPTS" and could hide the real one.
func scripts(b []byte) ([]byte, bool) {
	if b == nil {
		return nil, false
	}
	if len(bytes.TrimSpace(b)) == 0 {
		return []byte("null"), true
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, false
	}
	var v any
	if raw, ok := doc["scripts"]; ok {
		if err := json.Unmarshal(raw, &v); err != nil {
			return nil, false
		}
	}
	out, err := json.Marshal(v)
	return out, err == nil
}
