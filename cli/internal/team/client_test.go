//go:build team

package team

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"fenzi/cli/internal/config"
	"fenzi/controlplane"
)

func TestLoginCachesASignedPolicy(t *testing.T) {
	s, err := controlplane.Open(filepath.Join(t.TempDir(), "team.db"), checker{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	if _, err := s.Publish(context.Background(), "acme", []byte(org)); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(controlplane.Handler(s))
	t.Cleanup(srv.Close)
	c := Client{Base: srv.URL}

	start, err := c.StartDevice(context.Background(), "test-host")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Exchange(context.Background(), start.DeviceCode); err != ErrPending {
		t.Fatalf("before approval: %v", err)
	}
	res, err := http.PostForm(srv.URL+"/device", url.Values{"code": {start.UserCode}, "email": {"dana@acme.dev"}})
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("approve status %d", res.StatusCode)
	}

	en, err := c.Exchange(context.Background(), start.DeviceCode)
	if err != nil {
		t.Fatal(err)
	}
	if en.Email != "dana@acme.dev" || !en.Admin || en.Role != "admin" || en.Revision != 1 {
		t.Fatalf("enrollment %+v", en)
	}
	if _, err := en.Bundle(); err != nil {
		t.Fatal(err)
	}

	dirs := config.Dirs{Config: t.TempDir()}
	if err := en.Save(dirs); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(dirs)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Token != en.Token || loaded.Revision != 1 {
		t.Fatalf("loaded %+v", loaded)
	}

	li, err := loginAs(c, "li@acme.dev")
	if err != nil {
		t.Fatal(err)
	}
	if li.Admin || li.RoleName() != "developer" {
		t.Fatalf("li is a developer, got admin=%v role %q", li.Admin, li.RoleName())
	}
	if me, err := c.Me(context.Background(), li.Token); err != nil || me.Role != "developer" || me.Admin {
		t.Fatalf("me %+v err %v", me, err)
	}
	if _, err := c.Publish(context.Background(), li.Token, org); err == nil {
		t.Fatal("a member must not publish")
	}

	srv.Close()
	kept, note, err := Refresh(context.Background(), c, loaded)
	if err != nil {
		t.Fatal(err)
	}
	if kept.Revision != 1 || !strings.Contains(note, "unreachable") {
		t.Fatalf("offline note %q revision %d", note, kept.Revision)
	}
}

func loginAs(c Client, email string) (Enrollment, error) {
	start, err := c.StartDevice(context.Background(), "test-host")
	if err != nil {
		return Enrollment{}, err
	}
	res, err := http.PostForm(c.Base+"/device", url.Values{"code": {start.UserCode}, "email": {email}})
	if err != nil {
		return Enrollment{}, err
	}
	res.Body.Close()
	return c.Exchange(context.Background(), start.DeviceCode)
}

type checker struct{}

func (checker) Check(context.Context, []byte, []byte) (bool, string, error) { return true, "", nil }

const org = `version: 1
name: acme
agents: [claude]
workspace: read-write
hosts:
  - host: example.com
    access: read-only
approvals: person
`

func TestServerErrorsAreClassified(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "too many decisions in one batch", http.StatusBadRequest)
	}))
	c := Client{Base: srv.URL}
	_, err := c.Ingest(context.Background(), "t", []int{})
	if Unreachable(err) || Status(err) != http.StatusBadRequest {
		t.Fatalf("a refusal is an answer: %v", err)
	}
	srv.Close()
	_, err = c.Ingest(context.Background(), "t", []int{})
	if !Unreachable(err) || Status(err) != 0 {
		t.Fatalf("a closed server is unreachable: %v", err)
	}
}

func TestRefreshSaysWhenTheMachineWasSignedOut(t *testing.T) {
	s, err := controlplane.Open(filepath.Join(t.TempDir(), "team.db"), checker{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	b, err := s.Publish(context.Background(), "acme", []byte("version: 1\nname: acme\nagents: [claude]\nworkspace: read-write\napprovals: person\n"))
	if err != nil {
		t.Fatal(err)
	}
	en := Enrollment{Tenant: "acme", Token: "revoked", PublicKey: base64.StdEncoding.EncodeToString(s.PublicKey)}
	if err := en.Take(b); err != nil {
		t.Fatal(err)
	}
	// The hosted control plane answers a revoked machine token like this.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "sign in with fenzi login", http.StatusUnauthorized)
	}))
	defer srv.Close()
	got, note, err := Refresh(context.Background(), Client{Base: srv.URL}, en)
	if err != nil {
		t.Fatal(err)
	}
	if got.Revision != 1 || !strings.Contains(note, "signed out of team acme, still using r1") {
		t.Fatalf("revision %d note %q", got.Revision, note)
	}
	srv.Close()
	if _, note, _ := Refresh(context.Background(), Client{Base: srv.URL}, en); !strings.Contains(note, "unreachable") {
		t.Fatalf("a dead server is still unreachable: %q", note)
	}
}
