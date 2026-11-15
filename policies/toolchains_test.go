package policies

import (
	"os"
	"path/filepath"
	"testing"
)

// A Symfony project with a front end in a folder one level down, and a
// crate below vendor, which says nothing about the project.
func TestDetectToolchains(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "composer.json"), []byte("{}"), 0o644)
	os.Mkdir(filepath.Join(dir, "assets"), 0o755)
	os.WriteFile(filepath.Join(dir, "assets", "package.json"), []byte("{}"), 0o644)
	os.MkdirAll(filepath.Join(dir, "vendor", "x"), 0o755)
	os.WriteFile(filepath.Join(dir, "vendor", "Cargo.toml"), nil, 0o644)

	got := detectToolchains(dir, "")
	if names := ToolchainNames(got); names != "node, php" {
		t.Fatalf("toolchains %q", names)
	}
	if got[0].Adds() || !got[1].Adds() {
		t.Errorf("node is in the agent images and php is added: %+v", got)
	}
	if detectToolchains(dir, dir) != nil {
		t.Error("the home folder was read")
	}
}

// Every toolchain names its commands, and one Fenzi does not add says why.
func TestEveryToolchainIsComplete(t *testing.T) {
	seen := map[string]bool{}
	for _, tc := range Toolchains() {
		if seen[tc.Name] {
			t.Errorf("%s twice", tc.Name)
		}
		seen[tc.Name] = true
		if len(tc.Files) == 0 || len(tc.Commands) == 0 {
			t.Errorf("%s: no files or no commands", tc.Name)
		}
		if tc.Adds() && tc.Missing != "" {
			t.Errorf("%s is added and says why it is not", tc.Name)
		}
	}
	for _, name := range []string{"rust", "dotnet"} {
		for _, tc := range Toolchains() {
			if tc.Name == name && tc.Missing == "" {
				t.Errorf("%s is not added and does not say why", name)
			}
		}
	}
}
