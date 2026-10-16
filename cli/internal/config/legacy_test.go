package config

import (
	"os"
	"path/filepath"
	"testing"
)

// A machine set up as Boundlane keeps its state when the CLI becomes Fenzi.
func TestDefaultMovesTheBoundlaneFolders(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("XDG_CACHE_HOME", "")
	old := filepath.Join(home, ".config", "boundlane")
	if err := os.MkdirAll(old, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(old, "state.json"), []byte(`{"sandboxes":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	d, err := Default()
	if err != nil {
		t.Fatal(err)
	}
	if d.Config != filepath.Join(home, ".config", "fenzi") {
		t.Fatalf("config %s", d.Config)
	}
	if _, err := os.Stat(filepath.Join(d.Config, "state.json")); err != nil {
		t.Fatalf("state did not move: %v", err)
	}
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Fatalf("old folder still there: %v", err)
	}
}
