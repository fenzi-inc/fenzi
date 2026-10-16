package teamapi

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// Test vectors. A signer written in another language can check itself
// against the same seed, messages, and signatures: Ed25519 signatures are
// deterministic, so equal signatures mean equal signed bytes.
var (
	vectorSeed      = []byte("0123456789abcdef0123456789abcdef")
	vectorPublished = time.Date(2026, 10, 15, 12, 0, 0, 100_000_000, time.UTC)
)

const (
	vectorDocument = "version: 1\nagents: [claude]\n"
	vectorBoundary = "version: 1\nagents: [claude, codex]\n"
	vectorV1Sig    = "dssKPLiFqdSsPecARPrMZK1p+GoZqCd3qlgAiAQNp/qKJvmzfzpoXhzzeXXnHVU1g70xBnqLPuLrmbzcHjFFBA=="
	vectorV2Sig    = "QOI0fWnFc7pJcZH6r3GlfDwOJ0t/1BljciUKLfnZJry29v+NC5I9TREC0Pe1oWBqWqs7yK3VB++dR/SKuw5zAA=="
)

func vectorKey() ed25519.PrivateKey { return ed25519.NewKeyFromSeed(vectorSeed) }

func vectorBundle(format int) Bundle {
	b := Bundle{Tenant: "acme", Revision: 4, Format: format, Document: []byte(vectorDocument), Published: vectorPublished}
	if format == FormatBoundary {
		b.Boundary = []byte(vectorBoundary)
	}
	return b
}

func TestFormatOneIsTheMessageOldClientsVerify(t *testing.T) {
	for _, format := range []int{0, FormatDocument} {
		b := vectorBundle(format)
		if got := string(Message(b)); got != "acme\n4\n2026-10-15T12:00:00.1Z\n"+vectorDocument {
			t.Fatalf("format %d message %q", format, got)
		}
		b.Signature = ed25519.Sign(vectorKey(), Message(b))
		if got := base64.StdEncoding.EncodeToString(b.Signature); got != vectorV1Sig {
			t.Fatalf("format %d signature %s", format, got)
		}
	}
	// The JSON is what a CLI from before boundaries parses: no new keys.
	b := vectorBundle(FormatDocument)
	b.Signature = ed25519.Sign(vectorKey(), Message(b))
	raw, err := json.Marshal(ToWire(b))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "format") || strings.Contains(string(raw), "boundary") {
		t.Fatalf("a format 1 bundle grew fields: %s", raw)
	}
}

func TestFormatTwoSignsTheBoundary(t *testing.T) {
	b := vectorBundle(FormatBoundary)
	want := "boundlane bundle 2\nacme\n4\n2026-10-15T12:00:00.1Z\n" +
		"28\n" + vectorDocument + "35\n" + vectorBoundary
	if got := string(Message(b)); got != want {
		t.Fatalf("message %q", got)
	}
	b.Signature = ed25519.Sign(vectorKey(), Message(b))
	if got := base64.StdEncoding.EncodeToString(b.Signature); got != vectorV2Sig {
		t.Fatalf("signature %s", got)
	}
	if FormatFor(b.Boundary) != FormatBoundary || FormatFor(nil) != FormatDocument {
		t.Fatal("FormatFor")
	}
}

// A new CLI accepts both formats from the wire, and refuses a format 2
// bundle that lost or changed its boundary on the way.
func TestBothFormatsRoundTrip(t *testing.T) {
	pub := vectorKey().Public().(ed25519.PublicKey)
	for _, format := range []int{FormatDocument, FormatBoundary} {
		b := vectorBundle(format)
		b.Signature = ed25519.Sign(vectorKey(), Message(b))
		raw, err := json.Marshal(ToWire(b))
		if err != nil {
			t.Fatal(err)
		}
		back, err := ParseBundle(raw)
		if err != nil {
			t.Fatal(err)
		}
		if err := Accept(pub, 3, back); err != nil {
			t.Fatalf("format %d: %v", format, err)
		}
		if string(back.Boundary) != string(b.Boundary) {
			t.Fatalf("format %d boundary %q", format, back.Boundary)
		}
	}

	b := vectorBundle(FormatBoundary)
	b.Signature = ed25519.Sign(vectorKey(), Message(b))

	stripped := b
	stripped.Format, stripped.Boundary = 0, nil
	if err := Verify(pub, stripped); err == nil || !strings.Contains(err.Error(), "does not verify") {
		t.Errorf("a boundary taken off verified: %v", err)
	}
	widened := b
	widened.Boundary = []byte(vectorBoundary + "hosts: [{host: paste.example.net, access: read-only}]\n")
	if err := Verify(pub, widened); err == nil || !strings.Contains(err.Error(), "does not verify") {
		t.Errorf("a changed boundary verified: %v", err)
	}
	// Moving bytes between the document and the boundary changes the lengths.
	shifted := b
	shifted.Document = []byte(vectorDocument + vectorBoundary[:5])
	shifted.Boundary = []byte(vectorBoundary[5:])
	if err := Verify(pub, shifted); err == nil {
		t.Error("bytes moved from the boundary to the document verified")
	}
	unsigned := vectorBundle(FormatDocument)
	unsigned.Signature = ed25519.Sign(vectorKey(), Message(unsigned))
	unsigned.Boundary = []byte(vectorBoundary)
	if err := Verify(pub, unsigned); err == nil || !strings.Contains(err.Error(), "does not cover") {
		t.Errorf("a boundary outside a format 1 signature: %v", err)
	}
	future := b
	future.Format = 3
	if err := Verify(pub, future); err == nil || !strings.Contains(err.Error(), "boundlane update") {
		t.Errorf("format 3: %v", err)
	}
}
