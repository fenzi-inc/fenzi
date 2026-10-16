package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"fenzi/cli/internal/config"
	"fenzi/cli/internal/team"
	"fenzi/teamapi"
)

// refusingConsole serves a policy bundle this machine must not take, and
// records the heartbeats it gets.
type refusingConsole struct {
	mu     sync.Mutex
	bundle teamapi.Wire
	beats  []team.Beat
}

func (c *refusingConsole) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/v1/policy":
		json.NewEncoder(w).Encode(c.bundle)
	case "/v1/heartbeat":
		var b team.Beat
		raw, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(raw, &b); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		c.mu.Lock()
		c.beats = append(c.beats, b)
		c.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	case "/v1/applies":
		w.Write([]byte(`{"applies":[]}`))
	default:
		http.NotFound(w, r)
	}
}

func signed(key ed25519.PrivateKey, rev int) teamapi.Bundle {
	b := teamapi.Bundle{Tenant: "acme", Revision: rev, Document: []byte(teamDoc), Published: time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)}
	b.Signature = ed25519.Sign(key, teamapi.Message(b))
	return b
}

const teamDoc = "version: 1\nname: acme\nagents: [claude]\nworkspace: read-write\napprovals: person\n"

// enrollCached signs this test's config folder in with r2 cached.
func enrollCached(t *testing.T, server string, key ed25519.PrivateKey) config.Dirs {
	t.Helper()
	dirs, err := config.Default()
	if err != nil {
		t.Fatal(err)
	}
	en := team.Enrollment{
		Server: server, Token: "tok", Email: "dana@acme.dev", Tenant: "acme", Machine: "mbp",
		PublicKey: base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey)),
	}
	if err := en.Take(signed(key, 2)); err != nil {
		t.Fatal(err)
	}
	if err := en.Save(dirs); err != nil {
		t.Fatal(err)
	}
	return dirs
}

func TestARefusedBundleKeepsTheCachedRevision(t *testing.T) {
	fakeRuntime(t, nil, "")
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	console := &refusingConsole{bundle: teamapi.ToWire(signed(other, 3))}
	srv := httptest.NewServer(console)
	t.Cleanup(srv.Close)
	dirs := enrollCached(t, srv.URL, key)

	const tampered = "the server sent r3, which failed the signature check; still on r2"
	var status jsonStatus
	stderr, code := runJSON(t, &status, "status", "--json")
	if code != 0 || status.PolicyRevision != 2 || len(status.Notes) != 1 || status.Notes[0] != tampered {
		t.Fatalf("exit %d stderr %q status %+v", code, stderr, status)
	}
	out, code := runCLI(t, "", "sync")
	if code != 0 || !strings.Contains(out, tampered) {
		t.Fatalf("sync: exit %d\n%s", code, out)
	}
	console.mu.Lock()
	beats := append([]team.Beat(nil), console.beats...)
	console.mu.Unlock()
	if len(beats) != 2 || len(beats[0].Notes) != 1 || beats[0].Notes[0] != tampered || beats[1].PolicyRevision != 2 || beats[1].Notes[0] != tampered {
		t.Fatalf("heartbeats %+v", beats)
	}
	en, err := team.Load(dirs)
	if err != nil || en.Revision != 2 {
		t.Fatalf("cache r%d err %v", en.Revision, err)
	}

	// An older revision, correctly signed, is refused the same way.
	console.bundle = teamapi.ToWire(signed(key, 1))
	out, code = runCLI(t, "", "status")
	if code != 0 || !strings.Contains(out, "the server sent r1, older than r2; still on r2") {
		t.Fatalf("status: exit %d\n%s", code, out)
	}

	// A good bundle clears the note, and the next heartbeat says so.
	console.bundle = teamapi.ToWire(signed(key, 3))
	if out, code = runCLI(t, "", "sync"); code != 0 || strings.Contains(out, "still on") {
		t.Fatalf("sync: exit %d\n%s", code, out)
	}
	console.mu.Lock()
	last := console.beats[len(console.beats)-1]
	console.mu.Unlock()
	if last.PolicyRevision != 3 || len(last.Notes) != 0 {
		t.Fatalf("last heartbeat %+v", last)
	}
}

func TestARefusedBundleWithNothingCachedIsAnError(t *testing.T) {
	fakeRuntime(t, nil, "")
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	console := &refusingConsole{bundle: teamapi.ToWire(signed(other, 1))}
	srv := httptest.NewServer(console)
	t.Cleanup(srv.Close)
	dirs, err := config.Default()
	if err != nil {
		t.Fatal(err)
	}
	en := team.Enrollment{Server: srv.URL, Token: "tok", Email: "dana@acme.dev", Tenant: "acme", Machine: "mbp",
		PublicKey: base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey))}
	if err := en.Save(dirs); err != nil {
		t.Fatal(err)
	}
	if out, code := runCLI(t, "", "status"); code == 0 {
		t.Fatalf("status took a forged first bundle:\n%s", out)
	}
}
