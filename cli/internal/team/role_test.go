package team

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"fenzi/cli/internal/config"
)

// A server before roles sends only the admin flag; a server with roles sends
// both. Either way RoleName says something true.
func TestRoleNameFromOldAndNewServers(t *testing.T) {
	for _, tc := range []struct {
		body string
		want string
	}{
		{`{"token":"t","admin":true}`, "admin"},
		{`{"token":"t","admin":false}`, "member"},
		{`{"token":"t","admin":false,"role":"reviewer"}`, "reviewer"},
		{`{"token":"t","admin":true,"role":"admin"}`, "admin"},
		{`{"token":"t","admin":false,"role":"auditor"}`, "auditor"},
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(tc.body))
		}))
		en, err := Client{Base: srv.URL}.Exchange(context.Background(), "dev")
		srv.Close()
		if err != nil {
			t.Fatal(err)
		}
		if got := en.RoleName(); got != tc.want {
			t.Errorf("%s: RoleName = %q, want %q", tc.body, got, tc.want)
		}
	}
}

func TestMeAndWithRole(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/me" || r.Header.Get("Authorization") != "Bearer tok" {
			http.NotFound(w, r)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"email": "li@acme.dev", "tenant": "acme", "machine": "x1", "admin": false, "role": "developer", "version": "", "driver": "", "revision": 0})
	}))
	defer srv.Close()
	me, err := Client{Base: srv.URL}.Me(context.Background(), "tok")
	if err != nil {
		t.Fatal(err)
	}
	en := Enrollment{Email: "li@acme.dev", Admin: true}.WithRole(me)
	if en.Admin || en.Role != "developer" || en.RoleName() != "developer" {
		t.Fatalf("enrollment %+v", en)
	}
	if _, err := (Client{Base: srv.URL}).Me(context.Background(), "wrong"); err == nil {
		t.Fatal("a refused /v1/me must be an error, so the stored role stays")
	}
}

// An enrollment saved by a CLI before roles has no role field. It loads,
// and reads as it did.
func TestAnOldEnrollmentFileLoads(t *testing.T) {
	dirs := config.Dirs{Config: t.TempDir()}
	old := Enrollment{Server: "https://fenzi.dev", Token: "t", Email: "dana@acme.dev", Tenant: "acme", Machine: "mbp", Admin: true}
	if err := old.Save(dirs); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path(dirs))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if _, ok := m["role"]; ok {
		t.Fatal("an empty role must not be written: the file reads as it did before roles")
	}
	en, err := Load(dirs)
	if err != nil {
		t.Fatal(err)
	}
	if en.Role != "" || en.RoleName() != "admin" {
		t.Fatalf("loaded %+v", en)
	}
}
