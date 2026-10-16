package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"fenzi/cli/internal/team"
	"fenzi/teamapi"
)

// roleConsole serves a good bundle and answers /v1/me with me, or with 404
// when me is nil, like a server from before /v1/me reported a role.
type roleConsole struct {
	mu        sync.Mutex
	bundle    teamapi.Wire
	me        map[string]any
	published int
}

func (c *roleConsole) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c.mu.Lock()
	defer c.mu.Unlock()
	switch r.URL.Path {
	case "/v1/policy":
		json.NewEncoder(w).Encode(c.bundle)
	case "/v1/me":
		if c.me == nil {
			http.NotFound(w, r)
			return
		}
		json.NewEncoder(w).Encode(c.me)
	case "/v1/revisions":
		c.published++
		http.Error(w, "publishing needs a team admin", http.StatusForbidden)
	case "/v1/heartbeat":
		w.WriteHeader(http.StatusNoContent)
	default:
		http.NotFound(w, r)
	}
}

func TestStatusShowsTheRoleTheServerReports(t *testing.T) {
	fakeRuntime(t, nil, "")
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	console := &roleConsole{bundle: teamapi.ToWire(signed(key, 2))}
	srv := httptest.NewServer(console)
	t.Cleanup(srv.Close)
	dirs := enrollCached(t, srv.URL, key)

	// A server from before roles: the stored admin flag decides, as before.
	var doc jsonStatus
	if stderr, code := runJSON(t, &doc, "status", "--json"); code != 0 || doc.Role != "member" {
		t.Fatalf("old server: exit %d stderr %q role %q", code, stderr, doc.Role)
	}

	// The role changed in the console after login: status asks and shows it.
	console.mu.Lock()
	console.me = map[string]any{"email": "dana@acme.dev", "tenant": "acme", "machine": "mbp", "admin": false, "role": "reviewer"}
	console.mu.Unlock()
	if stderr, code := runJSON(t, &doc, "status", "--json"); code != 0 || doc.Role != "reviewer" {
		t.Fatalf("exit %d stderr %q role %q", code, stderr, doc.Role)
	}
	out, code := runCLI(t, "", "status")
	if code != 0 || !strings.Contains(out, "dana@acme.dev, reviewer, team acme") {
		t.Fatalf("status: exit %d\n%s", code, out)
	}
	en, err := team.Load(dirs)
	if err != nil || en.Role != "reviewer" || en.RoleName() != "reviewer" {
		t.Fatalf("stored role %q err %v", en.Role, err)
	}

	// A server with /v1/me but no role field still reads as admin or member.
	console.mu.Lock()
	console.me = map[string]any{"email": "dana@acme.dev", "admin": true}
	console.mu.Unlock()
	if stderr, code := runJSON(t, &doc, "status", "--json"); code != 0 || doc.Role != "admin" {
		t.Fatalf("admin flag only: exit %d stderr %q role %q", code, stderr, doc.Role)
	}
}

func TestPublishNamesTheRoleThatCannotPublish(t *testing.T) {
	fakeRuntime(t, nil, "")
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	console := &roleConsole{
		bundle: teamapi.ToWire(signed(key, 2)),
		me:     map[string]any{"email": "dana@acme.dev", "admin": false, "role": "auditor"},
	}
	srv := httptest.NewServer(console)
	t.Cleanup(srv.Close)
	enrollCached(t, srv.URL, key)
	path := t.TempDir() + "/policy.yaml"
	if err := os.WriteFile(path, []byte(teamDoc), 0o600); err != nil {
		t.Fatal(err)
	}

	out, code := runCLI(t, "", "policy", "publish", path)
	if code == 0 || !strings.Contains(out, "publishing needs a team admin, and dana@acme.dev is an auditor") {
		t.Fatalf("exit %d\n%s", code, out)
	}
	if console.published != 0 {
		t.Fatal("the CLI sent a publish it knew would be refused")
	}
}

func TestWithArticle(t *testing.T) {
	for role, want := range map[string]string{"admin": "an admin", "auditor": "an auditor", "reviewer": "a reviewer", "developer": "a developer", "member": "a member"} {
		if got := withArticle(role); got != want {
			t.Errorf("withArticle(%q) = %q, want %q", role, got, want)
		}
	}
}
