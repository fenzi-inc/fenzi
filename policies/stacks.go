package policies

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"fenzi/compiler"
)

// Stack is a set of read-only package hosts that a project gets on the Free
// plan when a file of its kind is in the folder: Go modules for go.mod,
// crates for Cargo.toml. developer-default carries npm, PyPI and GitHub for
// every project; a stack adds the rest only where the project uses them, so
// the agent does not have to ask for its own package manager.
type Stack struct {
	Name string
	// Files are the names that select the stack, matched in the project
	// folder and in the folders one level down. "*.csproj" matches by
	// extension.
	Files []string
	Hosts []compiler.Host
}

// stacks are read-only on purpose: installing reads, publishing writes.
var stacks = []Stack{
	{Name: "go", Files: []string{"go.mod"}, Hosts: readOnly("proxy.golang.org", "sum.golang.org")},
	{Name: "rust", Files: []string{"Cargo.toml"}, Hosts: readOnly("index.crates.io", "static.crates.io", "crates.io")},
	{Name: "ruby", Files: []string{"Gemfile"}, Hosts: readOnly("rubygems.org", "index.rubygems.org")},
	{Name: "php", Files: []string{"composer.json"}, Hosts: readOnly("repo.packagist.org")},
	{Name: "java", Files: []string{"pom.xml", "build.gradle", "build.gradle.kts"}, Hosts: readOnly("repo.maven.apache.org", "plugins.gradle.org")},
	{Name: "dotnet", Files: []string{"*.csproj", "*.fsproj", "*.sln"}, Hosts: readOnly("api.nuget.org")},
	{Name: "yarn", Files: []string{"yarn.lock"}, Hosts: readOnly("registry.yarnpkg.com")},
}

func readOnly(hosts ...string) []compiler.Host {
	out := make([]compiler.Host, len(hosts))
	for i, h := range hosts {
		out[i] = compiler.Host{Host: h, Access: compiler.AccessReadOnly}
	}
	return out
}

// Stacks returns every stack, in a fixed order.
func Stacks() []Stack {
	out := make([]Stack, len(stacks))
	for i, s := range stacks {
		s.Files = append([]string(nil), s.Files...)
		s.Hosts = append([]compiler.Host(nil), s.Hosts...)
		out[i] = s
	}
	return out
}

// skipDirs are folders whose files say nothing about the project's own stack.
var skipDirs = map[string]bool{"node_modules": true, "vendor": true, "target": true, "dist": true, "build": true}

// DetectStacks returns the stacks whose files are in dir or in a folder one
// level down, in the order of Stacks. A folder it cannot read adds nothing.
func DetectStacks(dir string) []Stack {
	if dir == "" {
		return nil
	}
	names := map[string]bool{}
	add := func(d string) {
		entries, err := os.ReadDir(d)
		if err != nil {
			return
		}
		for _, e := range entries {
			if !e.IsDir() {
				names[e.Name()] = true
			}
		}
	}
	add(dir)
	if entries, err := os.ReadDir(dir); err == nil {
		for _, e := range entries {
			if e.IsDir() && !strings.HasPrefix(e.Name(), ".") && !skipDirs[e.Name()] {
				add(filepath.Join(dir, e.Name()))
			}
		}
	}
	var out []Stack
	for _, s := range Stacks() {
		if s.matches(names) {
			out = append(out, s)
		}
	}
	return out
}

func (s Stack) matches(names map[string]bool) bool {
	for _, f := range s.Files {
		if ext, ok := strings.CutPrefix(f, "*"); ok {
			for n := range names {
				if strings.HasSuffix(n, ext) {
					return true
				}
			}
			continue
		}
		if names[f] {
			return true
		}
	}
	return false
}

// WithStacks adds the stacks' hosts to a copy of base. A host base already
// lists on the same port keeps base's rule.
func WithStacks(base *compiler.Document, list []Stack) *compiler.Document {
	if len(list) == 0 {
		return base
	}
	extra := &compiler.Document{Version: 1}
	listed := map[string]bool{}
	for _, h := range base.Hosts {
		listed[hostKey(h)] = true
	}
	for _, s := range list {
		for _, h := range s.Hosts {
			if !listed[hostKey(h)] {
				listed[hostKey(h)] = true
				extra.Hosts = append(extra.Hosts, h)
			}
		}
	}
	out, err := compiler.Merge(base, extra)
	if err != nil {
		panic("policies: a stack does not merge: " + err.Error())
	}
	return out
}

// StackNames is how sources name the stacks: "go, rust".
func StackNames(list []Stack) string {
	names := make([]string, len(list))
	for i, s := range list {
		names[i] = s.Name
	}
	return strings.Join(names, ", ")
}

func hostKey(h compiler.Host) string {
	port := h.Port
	if port == 0 {
		port = 443
	}
	return h.Host + ":" + strconv.Itoa(port)
}
