package teamapi

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestSignedBundleRoundTrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	b := Bundle{Tenant: "acme", Revision: 2, Document: []byte("version: 1\n"), Published: time.Date(2026, 10, 15, 12, 0, 0, 100_000_000, time.UTC)}
	b.Signature = ed25519.Sign(priv, Message(b))
	if got := string(Message(b)); got != "acme\n2\n2026-10-15T12:00:00.1Z\nversion: 1\n" {
		t.Fatalf("message %q", got)
	}
	raw, err := json.Marshal(ToWire(b))
	if err != nil {
		t.Fatal(err)
	}
	back, err := ParseBundle(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := Accept(pub, 1, back); err != nil {
		t.Fatal(err)
	}
	if err := Accept(pub, 2, back); err == nil || !strings.Contains(err.Error(), "not newer") {
		t.Fatalf("same revision accepted: %v", err)
	}
	back.Document = []byte("version: 2\n")
	if err := Verify(pub, back); err == nil || !strings.Contains(err.Error(), "does not verify") {
		t.Fatalf("changed document verified: %v", err)
	}
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	if err := Verify(other, b); err == nil {
		t.Fatal("another team's key verified")
	}
}
