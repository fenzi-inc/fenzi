package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"fenzi/cli/internal/openshell"
)

func TestToolsNamesWhatTheFolderNeeds(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "composer.json"), []byte("{}"), 0o644)
	os.WriteFile(filepath.Join(dir, "package.json"), []byte("{}"), 0o644)
	os.WriteFile(filepath.Join(dir, "Cargo.toml"), nil, 0o644)
	t.Chdir(dir)
	old := newClient
	newClient = func() openshell.Client { return openshell.Client{R: &openshell.Fake{}} }
	t.Cleanup(func() { newClient = old })

	var out bytes.Buffer
	e := env{ctx: context.Background(), stdin: strings.NewReader(""), stdout: &out, stderr: &out}
	if code, err := cmdTools(e, []string{"--json", "claude"}); code != 0 || err != nil {
		t.Fatalf("%d %v\n%s", code, err, out.String())
	}
	var got jsonTools
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	if got.Agent != "claude" || !strings.HasPrefix(got.Image, "fenzi/claude:2.1.288-php-") {
		t.Errorf("agent %q image %q", got.Agent, got.Image)
	}
	// Built depends on the images on this machine, so it is not checked.
	want := map[string]string{"node": "image", "php": "added", "rust": "missing"}
	if len(got.Toolchains) != len(want) {
		t.Fatalf("toolchains %+v", got.Toolchains)
	}
	for _, tc := range got.Toolchains {
		if want[tc.Name] != tc.Source {
			t.Errorf("%s from %q, want %q", tc.Name, tc.Source, want[tc.Name])
		}
		if (tc.Source == "missing") != (tc.Note != "") {
			t.Errorf("%s: note %q", tc.Name, tc.Note)
		}
	}

	out.Reset()
	if code, err := cmdTools(e, []string{"claude"}); code != 0 || err != nil {
		t.Fatalf("%d %v", code, err)
	}
	for _, s := range []string{"php", "composer, added to a copy of the Claude Code image", "cargo, rustc missing: Fenzi does not add Rust yet"} {
		if !strings.Contains(out.String(), s) {
			t.Errorf("output lacks %q:\n%s", s, out.String())
		}
	}
}

// --build with nothing to add builds nothing, and does not print JSON.
func TestToolsBuildWithNothingToAdd(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "package.json"), []byte("{}"), 0o644)
	t.Chdir(dir)
	var out bytes.Buffer
	e := env{ctx: context.Background(), stdin: strings.NewReader(""), stdout: &out, stderr: &out}
	if code, err := cmdTools(e, []string{"--build", "claude"}); code != 0 || err != nil || !strings.Contains(out.String(), "nothing to add here") {
		t.Fatalf("%d %v\n%s", code, err, out.String())
	}
	if _, err := cmdTools(e, []string{"--build", "--json", "claude"}); err == nil {
		t.Error("--build --json was accepted")
	}
}
