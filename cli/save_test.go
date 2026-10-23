package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"fenzi/cli/internal/config"
	"fenzi/cli/internal/openshell"
	"fenzi/cli/internal/team"
	"fenzi/compiler"
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
	path := filepath.Join(t.TempDir(), "fenzi.yaml")
	if err := os.WriteFile(path, []byte(initTemplate), 0o644); err != nil {
		t.Fatal(err)
	}
	p, err := loadProject(path)
	if err != nil {
		t.Fatal(err)
	}
	if out := p.add(savedHost{Host: "gitlab.com", Port: 443, Access: compiler.AccessReadOnly}); !out.Saved {
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
		"# Fenzi project policy.",
		"# Hosts this project needs beyond developer-default.",
		"#  - host: api.stripe.com",
		"#      - POST /repos/acme/web/pulls",
		"# Extra paths inside the sandbox.",
		"#   read_only: [/opt/fixtures]",
		"  - host: gitlab.com\n    access: read-only\n",
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
	path := filepath.Join(t.TempDir(), "fenzi.yaml")
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
	path := filepath.Join(t.TempDir(), "fenzi.yaml")
	if err := os.WriteFile(path, []byte("# Hosts for the web app.\n# Ask Ana first.\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	p, err := loadProject(path)
	if err != nil {
		t.Fatal(err)
	}
	p.add(savedHost{Host: "gitlab.com", Port: 443, Access: compiler.AccessReadOnly})
	if err := p.write(); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	if want := "# Hosts for the web app.\n# Ask Ana first.\n\nversion: 1\nhosts:\n  - host: gitlab.com\n    access: read-only\n"; string(raw) != want {
		t.Errorf("got:\n%s", raw)
	}
}

func TestSaveRefusesABrokenFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fenzi.yaml")
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
	// git's draft for github.com, moved to a host developer-default does
	// not list, since developer-default opens github.com for fetches.
	rules := strings.NewReplacer("github.com", "gitlab.com", "github_com", "gitlab_com").Replace(mixedRules)
	fakeRuntime(t, map[string]reply{"rule get": {out: rules}}, proverWithin)
	repo := t.TempDir()
	seedState(t, config.Sandbox{Name: "fenzi-web-1a2b", Agent: "claude", Repo: repo, Created: time.Now(), Running: true})
	return repo
}

func TestApproveSaveWritesTheHost(t *testing.T) {
	repo := saveFixture(t)
	out, code := runCLI(t, "", "approve", "59b83e6d", "--save", "--sandbox", "fenzi-web-1a2b")
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	out = strings.Join(strings.Fields(out), " ")
	for _, want := range []string{"Approved", "Saved", "gitlab.com, read-only", "lets any traffic through to gitlab.com:443", "GET, HEAD, and OPTIONS", "Policy check", "inside the boundary", "developer-default (built in) + ./fenzi.yaml"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	raw, err := os.ReadFile(filepath.Join(repo, "fenzi.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != "version: 1\nhosts:\n  - host: gitlab.com\n    access: read-only\n" {
		t.Errorf("file:\n%s", raw)
	}

	out, code = runCLI(t, "", "approve", "ccd96a39", "--save", "--sandbox", "fenzi-web-1a2b")
	out = strings.Join(strings.Fields(out), " ")
	if code != 0 || !strings.Contains(out, "allowed GET / only") || !strings.Contains(out, "www.example.com, read-only") {
		t.Errorf("exit %d:\n%s", code, out)
	}
	raw, _ = os.ReadFile(filepath.Join(repo, "fenzi.yaml"))
	if !strings.Contains(string(raw), "- host: gitlab.com") || !strings.Contains(string(raw), "- host: www.example.com") {
		t.Errorf("file:\n%s", raw)
	}
}

func TestApproveSaveRefusedOnATeamMachine(t *testing.T) {
	calls := recordingRuntime(t)
	dirs, err := config.Default()
	if err != nil {
		t.Fatal(err)
	}
	if err := (team.Enrollment{Server: "https://fenzi.example", Token: "t", Email: "ana@acme.dev", Tenant: "acme", Machine: "m"}).Save(dirs); err != nil {
		t.Fatal(err)
	}
	out, code := runCLI(t, "", "approve", "59b83e6d", "--save", "--sandbox", "fenzi-web-1a2b")
	if code != 1 || !strings.Contains(out, "team policy") || !strings.Contains(out, "https://fenzi.example/console") {
		t.Errorf("exit %d:\n%s", code, out)
	}
	// The runtime lists nothing here, so the full id is unknown: the console
	// itself is named, and nothing but that read reached the runtime.
	if b, _ := os.ReadFile(calls); strings.Contains(string(b), "rule approve") || strings.Contains(out, "/console/requests/") {
		t.Errorf("calls:\n%s\nout:\n%s", b, out)
	}
	if _, code := runCLI(t, "", "approve", "59b83e6d", "--save", "--json"); code != 1 {
		t.Errorf("--save --json: exit %d", code)
	}
}

func TestApproveSaveOnATeamMachineNamesTheRequestPage(t *testing.T) {
	repo := saveFixture(t)
	dirs, err := config.Default()
	if err != nil {
		t.Fatal(err)
	}
	if err := (team.Enrollment{Server: "https://fenzi.example/", Token: "t", Email: "ana@acme.dev", Tenant: "acme", Machine: "m"}).Save(dirs); err != nil {
		t.Fatal(err)
	}
	page := "https://fenzi.example/console/requests/fenzi-web-1a2b/59b83e6d-8a8a-43e4-a597-066a5d16fc36"
	for _, args := range [][]string{
		{"approve", "59b83e6d", "--save", "--sandbox", "fenzi-web-1a2b"},
		{"approve", "59b83e6d", "--save", "--dry-run", "--sandbox", "fenzi-web-1a2b"},
		{"approve", "59b83e6d-8a8a-43e4-a597-066a5d16fc36", "--save", "--dry-run", "--json", "--sandbox", "fenzi-web-1a2b"},
		{"approve", "59b83e6d", "--save", "--policy-from", filepath.Join(repo, "edited.yaml"), "--sandbox", "fenzi-web-1a2b"},
	} {
		var stdout, stderr strings.Builder
		code := cli(args, strings.NewReader(""), &stdout, &stderr)
		if code != 1 || stdout.Len() > 0 || !strings.Contains(stderr.String(), "publishes it from the console: "+page+".") {
			t.Errorf("%v: exit %d\nstdout %q\nstderr %q", args, code, stdout.String(), stderr.String())
		}
	}
	if called(t, "rule approve") {
		t.Errorf("approved on a team machine: %q", runtimeCalls(t))
	}
	if _, err := os.Stat(filepath.Join(repo, "fenzi.yaml")); err == nil {
		t.Error("fenzi.yaml was written")
	}
}

func TestApproveSaveDryRunChangesNothing(t *testing.T) {
	repo := saveFixture(t)
	path := filepath.Join(repo, "fenzi.yaml")
	before := "# Hosts for the web app.\nversion: 1\nhosts:\n  - host: cdn.example.com\n    access: read-only\n"
	if err := os.WriteFile(path, []byte(before), 0o600); err != nil {
		t.Fatal(err)
	}
	out, code := runCLI(t, "", "approve", "59b83e6d", "--save", "--dry-run", "--sandbox", "fenzi-web-1a2b")
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	for _, want := range []string{
		"Preview of approve --save", "nothing is approved or written",
		"fenzi.yaml, exists", "Adds  gitlab.com, read-only",
		"--- a/fenzi.yaml\n", "+++ b/fenzi.yaml\n", "@@ -3,3 +3,5 @@\n",
		"      access: read-only\n    +  - host: gitlab.com\n    +    access: read-only\n",
		"Policy check", "inside the boundary", "developer-default (built in) + ./fenzi.yaml",
		"fenzi approve 59b83e6d --save",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if raw, _ := os.ReadFile(path); string(raw) != before {
		t.Errorf("the file changed:\n%s", raw)
	}
	if called(t, "rule approve") {
		t.Errorf("approved in a dry run: %q", runtimeCalls(t))
	}

	var doc jsonSavePreview
	stderr, code := runJSON(t, &doc, "approve", "59b83e6d", "--save", "--dry-run", "--json", "--sandbox", "fenzi-web-1a2b")
	if code != 0 || stderr != "" {
		t.Fatalf("exit %d stderr %q", code, stderr)
	}
	after := before + "  - host: gitlab.com\n    access: read-only\n"
	if doc.File != path || !doc.Exists || doc.Before != before || doc.After != after || doc.Host != "gitlab.com" || doc.Port != 443 || doc.Access != "read-only" || doc.Already || len(doc.Allow) != 0 || doc.Allow == nil {
		t.Errorf("preview = %+v", doc)
	}
	if !strings.Contains(doc.Note, "lets any traffic through") || !strings.HasPrefix(doc.Diff, "--- a/fenzi.yaml\n+++ b/fenzi.yaml\n@@ -3,3 +3,5 @@\n") || !strings.HasSuffix(doc.Diff, "+  - host: gitlab.com\n+    access: read-only\n") {
		t.Errorf("note %q diff:\n%s", doc.Note, doc.Diff)
	}
	if want := (jsonSaveCheck{Passed: true, Result: "within_boundary", Checked: "developer-default (built in) + ./fenzi.yaml", Agent: "Claude Code"}); doc.Check != want {
		t.Errorf("check = %+v", doc.Check)
	}
	if raw, _ := os.ReadFile(path); string(raw) != before || called(t, "rule approve") {
		t.Errorf("the JSON dry run changed something:\n%s\n%q", raw, runtimeCalls(t))
	}
}

func TestApproveSaveDryRunNewFileAndAlreadyThere(t *testing.T) {
	repo := saveFixture(t)
	var doc jsonSavePreview
	if stderr, code := runJSON(t, &doc, "approve", "ccd96a39", "--save", "--dry-run", "--json", "--sandbox", "fenzi-web-1a2b"); code != 0 {
		t.Fatalf("exit %d stderr %q", code, stderr)
	}
	if doc.Exists || doc.Before != "" || doc.After != "version: 1\nhosts:\n  - host: www.example.com\n    access: read-only\n" || doc.Host != "www.example.com" || !strings.Contains(doc.Note, "allowed GET / only") {
		t.Errorf("new file: %+v", doc)
	}
	if !strings.HasPrefix(doc.Diff, "--- /dev/null\n+++ b/fenzi.yaml\n@@ -0,0 +1,4 @@\n+version: 1\n") {
		t.Errorf("diff:\n%s", doc.Diff)
	}
	if _, err := os.Stat(filepath.Join(repo, "fenzi.yaml")); err == nil {
		t.Fatal("a dry run wrote fenzi.yaml")
	}

	if err := os.WriteFile(filepath.Join(repo, "fenzi.yaml"), []byte("version: 1\nhosts:\n  - host: gitlab.com\n    access: read-only\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	doc = jsonSavePreview{}
	if stderr, code := runJSON(t, &doc, "approve", "59b83e6d", "--save", "--dry-run", "--json", "--sandbox", "fenzi-web-1a2b"); code != 0 {
		t.Fatalf("exit %d stderr %q", code, stderr)
	}
	if !doc.Already || doc.Diff != "" || doc.Before != doc.After || !strings.Contains(doc.Note, "already read-only") || !doc.Check.Passed {
		t.Errorf("already there: %+v", doc)
	}
	out, code := runCLI(t, "", "approve", "59b83e6d", "--save", "--dry-run", "--sandbox", "fenzi-web-1a2b")
	if code != 0 || !strings.Contains(out, "Adds  nothing") || !strings.Contains(out, "fenzi.yaml stays as it is.") || !strings.Contains(out, "fenzi approve 59b83e6d  ") {
		t.Errorf("exit %d:\n%s", code, out)
	}
}

// proverExceeds is proverWithin with the result and counterexample of a
// policy that reaches past its boundary.
var proverExceeds = strings.Replace(strings.Replace(proverWithin, `"result":"within_boundary"`, `"result":"exceeds_boundary"`, 1),
	`"counterexample":null`, `"counterexample":{"domain":"network","host":"paste.example.net","port":443,"method":"GET","path":"/"}`, 1)

func TestApproveSaveDryRunFailingCheck(t *testing.T) {
	fakeRuntime(t, map[string]reply{"rule get": {out: mixedRules}}, proverExceeds)
	seedState(t, config.Sandbox{Name: "fenzi-web-1a2b", Agent: "claude", Repo: t.TempDir(), Created: time.Now(), Running: true})
	var doc jsonSavePreview
	stderr, code := runJSON(t, &doc, "approve", "59b83e6d", "--save", "--dry-run", "--json", "--sandbox", "fenzi-web-1a2b")
	if code != 2 || !strings.Contains(stderr, "policy check") {
		t.Fatalf("exit %d, want 2; stderr %q", code, stderr)
	}
	if doc.Check.Passed || doc.Check.Result != "exceeds_boundary" || doc.Check.Example != "any program can GET paste.example.net:443/" {
		t.Errorf("check = %+v", doc.Check)
	}
	out, code := runCLI(t, "", "approve", "59b83e6d", "--save", "--dry-run", "--sandbox", "fenzi-web-1a2b")
	if code != 2 || !strings.Contains(out, "exceeds_boundary") || !strings.Contains(out, "Nothing was approved or written.") || strings.Contains(out, "fenzi approve 59b83e6d --save") {
		t.Errorf("exit %d:\n%s", code, out)
	}
	if called(t, "rule approve") {
		t.Errorf("approved: %q", runtimeCalls(t))
	}
}

func TestApproveSavePolicyFrom(t *testing.T) {
	repo := saveFixture(t)
	path := filepath.Join(repo, "fenzi.yaml")
	if err := os.WriteFile(path, []byte("version: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	edited := filepath.Join(t.TempDir(), "edited.yaml")
	text := "version: 1\nhosts:\n  # Docs the agent reads.\n  - host: docs.example.org\n    access: read-only\n"
	if err := os.WriteFile(edited, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}

	// The preview of the edited text: its diff and its check, nothing else.
	var doc jsonSavePreview
	if stderr, code := runJSON(t, &doc, "approve", "59b83e6d", "--save", "--dry-run", "--json", "--policy-from", edited, "--sandbox", "fenzi-web-1a2b"); code != 0 {
		t.Fatalf("exit %d stderr %q", code, stderr)
	}
	if doc.From != edited || doc.Before != "version: 1\n" || doc.After != text || !strings.Contains(doc.Diff, "+  # Docs the agent reads.\n") || !doc.Check.Passed {
		t.Errorf("preview = %+v", doc)
	}
	if !strings.Contains(doc.Note, "does not list gitlab.com, read-only") {
		t.Errorf("note %q", doc.Note)
	}
	if raw, _ := os.ReadFile(path); string(raw) != "version: 1\n" || called(t, "rule approve") {
		t.Fatalf("the preview changed something:\n%s", raw)
	}

	out, code := runCLI(t, "", "approve", "59b83e6d", "--save", "--policy-from", edited, "--sandbox", "fenzi-web-1a2b")
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	for _, want := range []string{"Approved", "Saved", "inside the boundary", "developer-default (built in) + ./fenzi.yaml"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if !called(t, "rule approve fenzi-web-1a2b --chunk-id 59b83e6d-8a8a-43e4-a597-066a5d16fc36") {
		t.Errorf("not approved: %q", runtimeCalls(t))
	}
	if raw, _ := os.ReadFile(path); string(raw) != text {
		t.Errorf("file:\n%s", raw)
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
		t.Errorf("mode changed to %v", info.Mode().Perm())
	}
}

func TestApproveSavePolicyFromRefusesAFailingFile(t *testing.T) {
	fakeRuntime(t, map[string]reply{"rule get": {out: mixedRules}}, proverExceeds)
	repo := t.TempDir()
	seedState(t, config.Sandbox{Name: "fenzi-web-1a2b", Agent: "claude", Repo: repo, Created: time.Now(), Running: true})
	edited := filepath.Join(t.TempDir(), "edited.yaml")
	if err := os.WriteFile(edited, []byte("version: 1\nhosts:\n  - host: gitlab.com\n    access: read-only\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out, code := runCLI(t, "", "approve", "59b83e6d", "--save", "--policy-from", edited, "--sandbox", "fenzi-web-1a2b")
	if code != 2 || !strings.Contains(out, "exceeds_boundary") || !strings.Contains(out, "Nothing was approved, and fenzi.yaml was not changed.") {
		t.Errorf("exit %d:\n%s", code, out)
	}

	// A file that is not a project file is refused before the prover runs.
	broken := filepath.Join(t.TempDir(), "broken.yaml")
	if err := os.WriteFile(broken, []byte("version: 1\nhosts: [\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out, code = runCLI(t, "", "approve", "59b83e6d", "--save", "--policy-from", broken, "--sandbox", "fenzi-web-1a2b")
	if code != 1 || !strings.Contains(out, "not approved: "+broken) {
		t.Errorf("exit %d:\n%s", code, out)
	}
	if called(t, "rule approve") {
		t.Errorf("approved: %q", runtimeCalls(t))
	}
	if _, err := os.Stat(filepath.Join(repo, "fenzi.yaml")); err == nil {
		t.Error("fenzi.yaml was written")
	}
}

func TestApproveSaveFlagsGoTogether(t *testing.T) {
	recordingRuntime(t)
	for args, want := range map[string]string{
		"approve 59b83e6d --dry-run":           "--dry-run previews --save",
		"approve 59b83e6d --policy-from x.yml": "--policy-from goes with --save",
		"approve 59b83e6d --save --json":       "add --dry-run for the preview as JSON",
	} {
		out, code := runCLI(t, "", strings.Fields(args)...)
		if code != 1 || !strings.Contains(out, want) {
			t.Errorf("%s: exit %d:\n%s", args, code, out)
		}
	}
}

// developer-default opens github.com for fetches with allow lines. A read is
// already there; a write is saved with those lines, since the project's
// entry replaces developer-default's.
func TestSaveOnAHostDeveloperDefaultOpensForFetches(t *testing.T) {
	p, err := loadProject(filepath.Join(t.TempDir(), "fenzi.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if out := p.add(savedHost{Host: "github.com", Port: 443, Access: compiler.AccessReadOnly, Widened: true}); out.Saved || !out.Already {
		t.Errorf("read: %+v", out)
	}
	if out := p.add(savedHost{Host: "github.com", Port: 443, Access: compiler.AccessReadOnly, L4: true}); out.Saved || out.Already || !strings.Contains(out.Detail, "by hand") {
		t.Errorf("L4: %+v", out)
	}
	if out := p.add(savedHost{Host: "github.com", Port: 443, Access: compiler.AccessReadWrite, Allow: []string{"POST /**/git-upload-pack"}}); out.Saved || !out.Already {
		t.Errorf("a line developer-default has: %+v", out)
	}
	out := p.add(savedHost{Host: "github.com", Port: 443, Access: compiler.AccessReadWrite, Allow: []string{"POST /acme/web.git/git-receive-pack"}})
	if !out.Saved {
		t.Fatalf("push: %+v", out)
	}
	raw, err := p.bytes()
	if err != nil {
		t.Fatal(err)
	}
	want := "version: 1\nhosts:\n  - host: github.com\n    access: read-write\n    allow:\n      - GET /**\n      - HEAD /**\n      - OPTIONS /**\n      - POST /**/git-upload-pack\n      - POST /acme/web.git/git-receive-pack\n"
	if string(raw) != want {
		t.Errorf("file:\n%s", raw)
	}
	if err := checkProject(raw); err != nil {
		t.Error(err)
	}
}

// A host a stack opens for the project's folder is already there.
func TestSaveOnAStackHost(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	p, err := loadProject(filepath.Join(dir, "fenzi.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if out := p.add(savedHost{Host: "proxy.golang.org", Port: 443, Access: compiler.AccessReadOnly}); out.Saved || !out.Already || !strings.Contains(out.Detail, "the go stack") {
		t.Errorf("%+v", out)
	}
}
