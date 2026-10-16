package team

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"boundlane/cli/internal/config"
	"boundlane/teamapi"
)

// A bundle with the team boundary is cached with it and verified again on
// every load. A cache edited to drop or change the boundary does not load.
func TestEnrollmentKeepsTheSignedBoundary(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	dirs := config.Dirs{Config: t.TempDir()}
	b := teamapi.Bundle{
		Tenant: "acme", Revision: 2, Format: teamapi.FormatBoundary,
		Document: []byte("version: 1\nagents: [claude]\n"), Boundary: []byte("version: 1\nagents: [claude]\n"),
		Published: time.Date(2026, 10, 16, 9, 0, 0, 0, time.UTC),
	}
	b.Signature = ed25519.Sign(key, teamapi.Message(b))
	e := Enrollment{Tenant: "acme", PublicKey: base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey))}
	if err := e.Take(b); err != nil {
		t.Fatal(err)
	}
	if err := e.Save(dirs); err != nil {
		t.Fatal(err)
	}
	back, err := Load(dirs)
	if err != nil {
		t.Fatal(err)
	}
	got, err := back.Bundle()
	if err != nil {
		t.Fatal(err)
	}
	if got.Format != teamapi.FormatBoundary || string(got.Boundary) != string(b.Boundary) {
		t.Fatalf("cached bundle %+v", got)
	}

	for name, edit := range map[string]func(*map[string]any){
		"boundary dropped":     func(m *map[string]any) { delete(*m, "boundary"); delete(*m, "format") },
		"boundary changed":     func(m *map[string]any) { (*m)["boundary"] = "version: 1\nagents: [claude, codex]\n" },
		"format set back to 1": func(m *map[string]any) { delete(*m, "format") },
	} {
		raw, err := os.ReadFile(path(dirs))
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatal(err)
		}
		edit(&m)
		bad := config.Dirs{Config: t.TempDir()}
		raw, _ = json.Marshal(m)
		if err := os.WriteFile(path(bad), raw, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(bad); err == nil || !(strings.Contains(err.Error(), "does not verify") || strings.Contains(err.Error(), "does not cover")) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
