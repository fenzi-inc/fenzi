package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"boundlane/cli/internal/config"
	"boundlane/cli/internal/openshell"
	"boundlane/cli/internal/team"
	"boundlane/compiler"
)

func TestRequestHostFromRecordedRules(t *testing.T) {
	byHost := map[string]openshell.Proposal{}
	for _, p := range openshell.ParseRules([]byte(mixedRules)) {
		byHost[p.Destination()] = p
	}
	l4, err := requestHost(byHost["github.com:443"].Endpoints)
	if err != nil || l4.Host != "github.com" || l4.Port != 443 || l4.Access != compiler.AccessReadOnly || !l4.L4 || len(l4.Allow) > 0 {
		t.Errorf("L4: %+v, %v", l4, err)
	}
	get, err := requestHost(byHost["www.example.com:443"].Endpoints)
	if err != nil || get.Access != compiler.AccessReadOnly || !get.Widened || get.L4 {
		t.Errorf("allow GET /: %+v, %v", get, err)
	}
	// Recorded from OpenShell 0.1.2.
	ro, err := requestHost("registry.npmjs.org:443 [L7 rest, access=read-only]")
	if err != nil || ro.Access != compiler.AccessReadOnly || ro.Widened || ro.L4 {
		t.Errorf("access=read-only: %+v, %v", ro, err)
	}
	// The recorded allow shape with a write method in place of GET.
	post, err := requestHost("api.example.com:8443 [L7 rest, allow POST /v1/things]")
	if err != nil || post.Access != compiler.AccessReadWrite || post.Port != 8443 || len(post.Allow) != 1 || post.Allow[0] != "POST /v1/things" {
		t.Errorf("allow POST: %+v, %v", post, err)
	}
	for _, unknown := range []string{
		"api.example.com:443 [L7 rest, access=full]",
		"api.example.com:443 [L7 rest, allow GET /, allow POST /x]",
		"api.example.com:443, api.example.org:443 [L4]",
		"",
	} {
		if _, err := requestHost(unknown); err == nil {
			t.Errorf("%q was accepted", unknown)
		}
	}
}

func TestSaveKeepsCommentsInAStarterFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "boundlane.yaml")
	if err := os.WriteFile(path, []byte(initTemplate), 0o644); err != nil {
		t.Fatal(err)
	}
	p, err := loadProject(path)
	if err != nil {
		t.Fatal(err)
	}
	if out := p.add(savedHost{Host: "github.com", Port: 443, Access: compiler.AccessReadOnly}); !out.Saved {
		t.Fatalf("not saved: %+v", out)
	}
	if out := p.add(savedHost{Host: "api.example.com", Port: 8443, Access: compiler.AccessReadWrite, Allow: []string{"POST /v1/things"}}); !out.Saved {
		t.Fatalf("not saved: %+v", out)
	}
	if err := p.write(); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	for _, want := range []string{
		"# Boundlane project policy.",
		"# Hosts this project needs beyond developer-default.",
		"#  - host: api.stripe.com",
		"#      - POST /repos/acme/web/pulls",
		"# Extra paths inside the sandbox.",
		"#   read_only: [/opt/fixtures]",
		"  - host: github.com\n    access: read-only\n",
		"  - host: api.example.com\n    port: 8443\n    access: read-write\n    allow:\n      - POST /v1/things\n",
	} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("missing %q in:\n%s", want, raw)
		}
	}
	doc, err := compiler.Parse(raw)
	if err != nil || doc.Version != 1 || len(doc.Hosts) != 2 {
		t.Fatalf("%+v, %v\n%s", doc, err, raw)
	}
}

func TestSaveAddsToAnExistingEntry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "boundlane.yaml")
	file := "version: 1\nhosts:\n  # Our API.\n  - host: api.example.com\n    access: read-write\n    allow:\n      - GET /v1/** # reads\n  - host: cdn.example.com\n    access: read-only\n"
	if err := os.WriteFile(path, []byte(file), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := loadProject(path)
	if err != nil {
		t.Fatal(err)
	}
	if out := p.add(savedHost{Host: "api.example.com", Port: 443, Access: compiler.AccessReadWrite, Allow: []string{"POST /v1/things"}}); !out.Saved {
		t.Fatalf("not saved: %+v", out)
	}
	if out := p.add(savedHost{Host: "api.example.com", Port: 443, Access: compiler.AccessReadWrite, Allow: []string{"POST /v1/things"}}); out.Saved || !strings.Contains(out.Detail, "already allows") {
		t.Errorf("a second save: %+v", out)
	}
	if out := p.add(savedHost{Host: "cdn.example.com", Port: 443, Access: compiler.AccessReadOnly}); out.Saved || !strings.Contains(out.Detail, "already read-only") {
		t.Errorf("same level: %+v", out)
	}
	if out := p.add(savedHost{Host: "cdn.example.com", Port: 443, Access: compiler.AccessReadWrite, Allow: []string{"PUT /x"}}); out.Saved || !strings.Contains(out.Detail, "by hand") {
		t.Errorf("a different level: %+v", out)
	}
	if out := p.add(savedHost{Host: "api.github.com", Port: 443, Access: compiler.AccessReadWrite, Allow: []string{"POST /markdown"}}); out.Saved || !strings.Contains(out.Detail, "developer-default") {
		t.Errorf("a developer-default host: %+v", out)
	}
	if out := p.add(savedHost{Host: "pypi.org", Port: 443, Access: compiler.AccessReadOnly}); out.Saved {
		t.Errorf("already in developer-default: %+v", out)
	}
	if err := p.write(); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	want := "version: 1\nhosts:\n  # Our API.\n  - host: api.example.com\n    access: read-write\n    allow:\n      - GET /v1/** # reads\n      - POST /v1/things\n  - host: cdn.example.com\n    access: read-only\n"
	if string(raw) != want {
		t.Errorf("got:\n%s\nwant:\n%s", raw, want)
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
		t.Errorf("mode changed to %v", info.Mode().Perm())
	}
}

func TestSaveIntoAFileOfComments(t *testing.T) {
	path := filepath.Join(t.TempDir(), "boundlane.yaml")
	if err := os.WriteFile(path, []byte("# Hosts for the web app.\n# Ask Ana first.\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	p, err := loadProject(path)
	if err != nil {
		t.Fatal(err)
	}
	p.add(savedHost{Host: "github.com", Port: 443, Access: compiler.AccessReadOnly})
	if err := p.write(); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	if want := "# Hosts for the web app.\n# Ask Ana first.\n\nversion: 1\nhosts:\n  - host: github.com\n    access: read-only\n"; string(raw) != want {
		t.Errorf("got:\n%s", raw)
	}
}

func TestSaveRefusesABrokenFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "boundlane.yaml")
	if err := os.WriteFile(path, []byte("version: 1\nhosts: [\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadProject(path); err == nil {
		t.Error("a file that does not parse was loaded")
	}
}

// saveFixture is a running sandbox in a project folder, a runtime that lists
// the recorded requests, and a prover that passes.
func saveFixture(t *testing.T) string {
	t.Helper()
	fakeRuntime(t, map[string]reply{"rule get": {out: mixedRules}}, proverWithin)
	repo := t.TempDir()
	seedState(t, config.Sandbox{Name: "bl-web-1a2b", Agent: "claude", Repo: repo, Created: time.Now(), Running: true})
	return repo
}

func TestApproveSaveWritesTheHost(t *testing.T) {
	repo := saveFixture(t)
	out, code := runCLI(t, "", "approve", "59b83e6d", "--save", "--sandbox", "bl-web-1a2b")
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	out = strings.Join(strings.Fields(out), " ")
	for _, want := range []string{"Approved", "Saved", "github.com, read-only", "lets any traffic through to github.com:443", "GET, HEAD, and OPTIONS", "Policy check", "inside the boundary", "developer-default (built in) + ./boundlane.yaml"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	raw, err := os.ReadFile(filepath.Join(repo, "boundlane.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != "version: 1\nhosts:\n  - host: github.com\n    access: read-only\n" {
		t.Errorf("file:\n%s", raw)
	}

	out, code = runCLI(t, "", "approve", "ccd96a39", "--save", "--sandbox", "bl-web-1a2b")
	out = strings.Join(strings.Fields(out), " ")
	if code != 0 || !strings.Contains(out, "allowed GET / only") || !strings.Contains(out, "www.example.com, read-only") {
		t.Errorf("exit %d:\n%s", code, out)
	}
	raw, _ = os.ReadFile(filepath.Join(repo, "boundlane.yaml"))
	if !strings.Contains(string(raw), "- host: github.com") || !strings.Contains(string(raw), "- host: www.example.com") {
		t.Errorf("file:\n%s", raw)
	}
}

func TestApproveSaveRefusedOnATeamMachine(t *testing.T) {
	calls := recordingRuntime(t)
	dirs, err := config.Default()
	if err != nil {
		t.Fatal(err)
	}
	if err := (team.Enrollment{Server: "https://boundlane.example", Token: "t", Email: "ana@acme.dev", Tenant: "acme", Machine: "m"}).Save(dirs); err != nil {
		t.Fatal(err)
	}
	out, code := runCLI(t, "", "approve", "59b83e6d", "--save", "--sandbox", "bl-web-1a2b")
	if code != 1 || !strings.Contains(out, "team policy") || !strings.Contains(out, "https://boundlane.example/console") {
		t.Errorf("exit %d:\n%s", code, out)
	}
	if b, _ := os.ReadFile(calls); len(b) > 0 {
		t.Errorf("the runtime was called:\n%s", b)
	}
	if _, code := runCLI(t, "", "approve", "59b83e6d", "--save", "--json"); code != 1 {
		t.Errorf("--save --json: exit %d", code)
	}
}
