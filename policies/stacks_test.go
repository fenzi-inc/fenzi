package policies

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"fenzi/compiler"
)

// The compiler's golden files are compiled from a copy of developer-default.
func TestGoldenInputIsDeveloperDefault(t *testing.T) {
	golden, err := os.ReadFile(filepath.Join("..", "compiler", "testdata", "default.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(golden, DeveloperDefaultYAML()) {
		t.Error("compiler/testdata/default.yaml differs from developer-default.yaml; copy it and run make golden")
	}
}

func TestDeveloperDefaultKeepsPushClosed(t *testing.T) {
	for _, h := range DeveloperDefault().Hosts {
		for _, line := range h.Allow {
			if line != "GET /**" && line != "HEAD /**" && line != "OPTIONS /**" && line != "POST /**/git-upload-pack" {
				t.Errorf("%s allows %s; developer-default only reads", h.Host, line)
			}
		}
	}
}

func TestEveryStackIsReadOnlyAndValid(t *testing.T) {
	for _, s := range Stacks() {
		d := WithStacks(&compiler.Document{Version: 1}, []Stack{s})
		if err := d.WithDefaults().Validate(); err != nil {
			t.Errorf("%s: %v", s.Name, err)
		}
		for _, h := range s.Hosts {
			if h.Access != compiler.AccessReadOnly {
				t.Errorf("%s: %s is %s", s.Name, h.Host, h.Access)
			}
		}
	}
}

func touch(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestDetectStacks(t *testing.T) {
	dir := t.TempDir()
	touch(t, filepath.Join(dir, "go.mod"))
	touch(t, filepath.Join(dir, "api", "Cargo.toml"))
	touch(t, filepath.Join(dir, "App", "Web.csproj"))
	// A dependency's files and anything two levels down say nothing.
	touch(t, filepath.Join(dir, "node_modules", "Gemfile"))
	touch(t, filepath.Join(dir, "a", "b", "pom.xml"))
	touch(t, filepath.Join(dir, ".hidden", "composer.json"))

	if got := StackNames(DetectStacks(dir)); got != "go, rust, dotnet" {
		t.Errorf("stacks = %q", got)
	}
	if got := DetectStacks(t.TempDir()); got != nil {
		t.Errorf("an empty folder has stacks: %v", got)
	}
	if got := DetectStacks(""); got != nil {
		t.Errorf("no folder has stacks: %v", got)
	}
}

func TestWithStacksKeepsTheBaseRule(t *testing.T) {
	base := &compiler.Document{Version: 1, Hosts: []compiler.Host{
		{Host: "proxy.golang.org", Access: compiler.AccessReadWrite, Allow: []string{"GET /x"}},
	}}
	got := WithStacks(base, stacksNamed("go"))
	if len(got.Hosts) != 2 || got.Hosts[0].Access != compiler.AccessReadWrite || got.Hosts[1].Host != "sum.golang.org" {
		t.Errorf("hosts = %+v", got.Hosts)
	}
	if len(base.Hosts) != 1 {
		t.Error("WithStacks changed the base")
	}
}

// stacksNamed returns the named stacks.
func stacksNamed(names ...string) []Stack {
	var out []Stack
	for _, s := range Stacks() {
		for _, n := range names {
			if s.Name == n {
				out = append(out, s)
			}
		}
	}
	return out
}
