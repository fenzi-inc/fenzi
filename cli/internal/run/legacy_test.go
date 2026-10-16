package run

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A project policy saved as boundlane.yaml is still read, and --save renames it.
func TestLegacyProjectFile(t *testing.T) {
	repo := t.TempDir()
	doc, err := os.ReadFile(filepath.Join("..", "..", "..", "compiler", "testdata", "project.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, LegacyProjectFile), doc, 0o644); err != nil {
		t.Fatal(err)
	}
	r, err := ResolveFree(repo, "")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(r.Sources, LegacyProjectFile) {
		t.Fatalf("legacy file not read: %s", r.Sources)
	}
	moved, err := MigrateProjectFile(repo)
	if err != nil || !moved {
		t.Fatalf("moved=%v err=%v", moved, err)
	}
	if _, err := os.Stat(filepath.Join(repo, ProjectFile)); err != nil {
		t.Fatal(err)
	}
	if moved, _ := MigrateProjectFile(repo); moved {
		t.Fatal("moved twice")
	}
}
