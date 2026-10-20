package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"fenzi/compiler"
)

func readDoc(t *testing.T, path string) (*compiler.Document, string) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := compiler.Parse(raw)
	if err != nil {
		t.Fatalf("%v\n%s", err, raw)
	}
	return doc, string(raw)
}

func TestPolicyHostSetAndRemove(t *testing.T) {
	repo := t.TempDir()
	t.Chdir(repo)
	file := filepath.Join(repo, "fenzi.yaml")
	if err := os.WriteFile(file, []byte("# Our project.\nversion: 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out jsonPolicyEdit
	if stderr, code := runJSON(t, &out, "policy", "host", "set", "api.stripe.com", "--json"); code != 0 || !out.Changed {
		t.Fatalf("set: exit %d %s %+v", code, stderr, out)
	}
	doc, raw := readDoc(t, file)
	if !strings.Contains(raw, "# Our project.") || len(doc.Hosts) != 1 || doc.Hosts[0].Access != compiler.AccessReadOnly {
		t.Fatalf("after set:\n%s", raw)
	}
	// Set again with write lines: the entry is replaced, not doubled.
	if stderr, code := runJSON(t, &out, "policy", "host", "set", "api.stripe.com", "--write", "POST /v1/refunds", "--write", "GET  /v1/charges/**", "--json"); code != 0 {
		t.Fatalf("set again: exit %d %s", code, stderr)
	}
	doc, raw = readDoc(t, file)
	if len(doc.Hosts) != 1 || doc.Hosts[0].Access != compiler.AccessReadWrite || strings.Join(doc.Hosts[0].Allow, "|") != "POST /v1/refunds|GET /v1/charges/**" {
		t.Fatalf("after replace:\n%s", raw)
	}
	if stderr, code := runJSON(t, &out, "policy", "host", "remove", "api.stripe.com", "--json"); code != 0 || !out.Changed {
		t.Fatalf("remove: exit %d %s %+v", code, stderr, out)
	}
	if doc, raw = readDoc(t, file); len(doc.Hosts) != 0 {
		t.Fatalf("after remove:\n%s", raw)
	}
	if _, code := runJSON(t, &out, "policy", "host", "remove", "api.stripe.com", "--json"); code != 0 || out.Changed {
		t.Fatalf("a second remove changed something: %+v", out)
	}
}

func TestPolicyHostRefusesABadRequestLine(t *testing.T) {
	repo := t.TempDir()
	t.Chdir(repo)
	var out jsonPolicyEdit
	if _, code := runJSON(t, &out, "policy", "host", "set", "api.example.com", "--write", "FETCH everything", "--json"); code == 0 {
		t.Fatal("a request line that is not METHOD /path was written")
	}
	if _, err := os.Stat(filepath.Join(repo, "fenzi.yaml")); err == nil {
		t.Fatal("a refused edit left a file behind")
	}
}

func TestPolicyPathAddMoveRemove(t *testing.T) {
	repo := t.TempDir()
	t.Chdir(repo)
	file := filepath.Join(repo, "fenzi.yaml")
	var out jsonPolicyEdit
	if stderr, code := runJSON(t, &out, "policy", "path", "add", "/opt/fixtures", "--json"); code != 0 {
		t.Fatalf("add: exit %d %s", code, stderr)
	}
	doc, raw := readDoc(t, file)
	if len(doc.Paths.ReadOnly) != 1 || len(doc.Paths.ReadWrite) != 0 {
		t.Fatalf("after add:\n%s", raw)
	}
	// Adding it writable moves it to the other list.
	if _, code := runJSON(t, &out, "policy", "path", "add", "/opt/fixtures", "--write", "--json"); code != 0 {
		t.Fatal("add --write failed")
	}
	if doc, raw = readDoc(t, file); len(doc.Paths.ReadOnly) != 0 || len(doc.Paths.ReadWrite) != 1 {
		t.Fatalf("after move:\n%s", raw)
	}
	if _, code := runJSON(t, &out, "policy", "path", "remove", "/opt/fixtures", "--json"); code != 0 || !out.Changed {
		t.Fatal("remove failed")
	}
	if _, raw = readDoc(t, file); strings.Contains(raw, "paths") {
		t.Fatalf("an empty paths section was left:\n%s", raw)
	}
}
