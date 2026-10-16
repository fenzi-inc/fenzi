package team

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"boundlane/teamapi"
)

// fakeConsole answers like the hosted control plane: the device login, then a
// signed policy. key signs; revision is what /v1/policy returns.
type fakeConsole struct {
	key      ed25519.PrivateKey
	revision int
	pending  int
	status   int
}

func (f *fakeConsole) bundle(rev int) teamapi.Wire {
	b := teamapi.Bundle{Tenant: "acme", Revision: rev, Document: []byte("version: 1\n"), Published: time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)}
	b.Signature = ed25519.Sign(f.key, teamapi.Message(b))
	return teamapi.ToWire(b)
}

func (f *fakeConsole) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if f.status != 0 {
		http.Error(w, "sign in with boundlane login", f.status)
		return
	}
	switch r.URL.Path {
	case "/v1/device/start":
		json.NewEncoder(w).Encode(map[string]any{"device_code": "dev", "user_code": "ABCD-EFGH", "verification_url": "https://console.test/device", "interval": 1})
	case "/v1/device/token":
		if f.pending > 0 {
			f.pending--
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "authorization_pending"})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{
			"token": "tok", "email": "dana@acme.dev", "name": "Dana", "tenant": "acme", "machine": "mbp", "admin": true,
			"public_key": base64.StdEncoding.EncodeToString(f.key.Public().(ed25519.PublicKey)), "bundle": f.bundle(1),
		})
	case "/v1/policy":
		if r.Header.Get("Authorization") != "Bearer tok" {
			http.Error(w, "sign in with boundlane login", http.StatusUnauthorized)
			return
		}
		json.NewEncoder(w).Encode(f.bundle(f.revision))
	default:
		http.NotFound(w, r)
	}
}

func newFake(t *testing.T) (*fakeConsole, Client) {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeConsole{key: key, revision: 1, pending: 2}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return f, Client{Base: srv.URL}
}

func TestLoginWaitsForApprovalAndVerifiesThePolicy(t *testing.T) {
	_, c := newFake(t)
	var out strings.Builder
	en, err := Login(context.Background(), c, "mbp", &out)
	if err != nil {
		t.Fatal(err)
	}
	if en.Tenant != "acme" || en.Revision != 1 || en.Token != "tok" {
		t.Fatalf("enrollment %+v", en)
	}
	if !strings.Contains(out.String(), "ABCD-EFGH") || !strings.Contains(out.String(), "verified and cached") {
		t.Fatalf("login output:\n%s", out.String())
	}
	if _, err := en.Bundle(); err != nil {
		t.Fatalf("cached bundle does not verify: %v", err)
	}
}

func TestRefreshTakesNewerAndKeepsTheCacheOnAForgedOrOlderBundle(t *testing.T) {
	f, c := newFake(t)
	en, err := Login(context.Background(), c, "mbp", &strings.Builder{})
	if err != nil {
		t.Fatal(err)
	}
	f.revision = 2
	if en, _, err = Refresh(context.Background(), c, en); err != nil || en.Revision != 2 {
		t.Fatalf("revision %d err %v", en.Revision, err)
	}

	// A lower revision: r2 stays, checked again, and the note says why.
	f.revision = 1
	got, note, err := Refresh(context.Background(), c, en)
	if err != nil || got.Revision != 2 || note != "the server sent r1, older than r2; still on r2" || got.Refused != note {
		t.Fatalf("older: revision %d note %q refused %q err %v", got.Revision, note, got.Refused, err)
	}
	if _, err := got.Bundle(); err != nil {
		t.Fatalf("cached bundle after a refusal: %v", err)
	}

	// A tampered bundle: signed with another key.
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	good := f.key
	f.key, f.revision = other, 3
	got, note, err = Refresh(context.Background(), c, got)
	if err != nil || got.Revision != 2 || note != "the server sent r3, which failed the signature check; still on r2" || got.Refused != note {
		t.Fatalf("forged: revision %d note %q err %v", got.Revision, note, err)
	}

	// A good bundle clears the note.
	f.key = good
	got, note, err = Refresh(context.Background(), c, got)
	if err != nil || got.Revision != 3 || note != "" || got.Refused != "" {
		t.Fatalf("good after forged: revision %d note %q refused %q err %v", got.Revision, note, got.Refused, err)
	}

	// With nothing cached, a forged bundle is still refused outright.
	empty := got
	empty.Revision, empty.Document, empty.Published, empty.Signature = 0, "", "", ""
	f.key = other
	if _, _, err := Refresh(context.Background(), c, empty); err == nil || !strings.Contains(err.Error(), "does not verify") {
		t.Fatalf("forged revision accepted with nothing cached: %v", err)
	}

	// A cached bundle that no longer verifies is not kept either.
	f.key, f.revision = good, 1
	broken := got
	broken.Document = "version: 1\nname: changed\n"
	if _, _, err := Refresh(context.Background(), c, broken); err == nil {
		t.Fatal("a tampered cache was kept")
	}
}

func TestRefreshKeepsThePolicyWhenSignedOutOrUnreachable(t *testing.T) {
	f, c := newFake(t)
	en, err := Login(context.Background(), c, "mbp", &strings.Builder{})
	if err != nil {
		t.Fatal(err)
	}
	f.status = http.StatusUnauthorized
	got, note, err := Refresh(context.Background(), c, en)
	if err != nil || got.Revision != 1 || !strings.Contains(note, "signed out of team acme, still using r1") {
		t.Fatalf("revision %d note %q err %v", got.Revision, note, err)
	}
	got, note, err = Refresh(context.Background(), Client{Base: "http://127.0.0.1:1"}, en)
	if err != nil || got.Revision != 1 || !strings.Contains(note, "unreachable, using acme r1") {
		t.Fatalf("revision %d note %q err %v", got.Revision, note, err)
	}
}

func TestDefaultServerIsTheHostedConsole(t *testing.T) {
	if (Client{}).base() != "https://boundlane.dev" {
		t.Fatalf("default server %s", Client{}.base())
	}
}
