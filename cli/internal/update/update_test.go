package update

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestNewer(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"0.1.1", "0.1.0", true},
		{"0.2.0", "0.1.9", true},
		{"0.10.0", "0.9.0", true},
		{"0.1.0", "0.1.0", false},
		{"0.1.0", "0.1.1", false},
		{"0.1.1", "dev", false},
		{"", "0.1.0", false},
	}
	for _, c := range cases {
		if got := Newer(c.a, c.b); got != c.want {
			t.Errorf("Newer(%q, %q) = %v", c.a, c.b, got)
		}
	}
}

type release struct {
	files map[string][]byte
	hits  atomic.Int32
}

func (r *release) serve(t *testing.T) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.hits.Add(1)
		b, ok := r.files[req.URL.Path[1:]]
		if !ok {
			http.NotFound(w, req)
			return
		}
		_, _ = w.Write(b)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func newRelease(bin []byte) *release {
	sum := sha256.Sum256(bin)
	return &release{files: map[string][]byte{
		"latest.txt":                  []byte("0.1.2\n"),
		"fenzi-0.1.2-linux-amd64": bin,
		"fenzi-0.1.2-sha256.txt":  []byte(hex.EncodeToString(sum[:]) + "  fenzi-0.1.2-linux-amd64\n"),
	}}
}

func TestInstallReplacesOnlyWhenTheChecksumMatches(t *testing.T) {
	r := newRelease([]byte("new binary"))
	srv := r.serve(t)
	exe := filepath.Join(t.TempDir(), "fenzi")
	if err := os.WriteFile(exe, []byte("old binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if v, err := Latest(ctx, srv.Client(), srv.URL); err != nil || v != "0.1.2" {
		t.Fatalf("latest %q, %v", v, err)
	}
	if err := Install(ctx, srv.Client(), srv.URL, "0.1.2", "darwin", "arm64", exe); err == nil {
		t.Fatal("installed a platform that has no checksum")
	}
	r.files["fenzi-0.1.2-linux-amd64"] = []byte("tampered")
	if err := Install(ctx, srv.Client(), srv.URL, "0.1.2", "linux", "amd64", exe); err == nil {
		t.Fatal("installed a binary with the wrong checksum")
	}
	if b, _ := os.ReadFile(exe); string(b) != "old binary" {
		t.Fatalf("binary changed after a failed update: %q", b)
	}
	r.files["fenzi-0.1.2-linux-amd64"] = []byte("new binary")
	if err := Install(ctx, srv.Client(), srv.URL, "0.1.2", "linux", "amd64", exe); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(exe); string(b) != "new binary" {
		t.Fatalf("binary is %q", b)
	}
	if fi, _ := os.Stat(exe); fi.Mode().Perm() != 0o755 {
		t.Fatalf("mode %v", fi.Mode())
	}
	left, _ := filepath.Glob(filepath.Join(filepath.Dir(exe), ".fenzi-update-*"))
	if len(left) != 0 {
		t.Fatalf("temporary files left: %v", left)
	}
}

func TestNotifierAsksOnceADay(t *testing.T) {
	r := newRelease([]byte("x"))
	srv := r.serve(t)
	t.Setenv("FENZI_DOWNLOAD_BASE", srv.URL)
	dir := t.TempDir()
	now := time.Date(2026, 10, 6, 9, 0, 0, 0, time.UTC)

	if v := Start(context.Background(), dir, "0.1.1", now).Available(2 * time.Second); v != "0.1.2" {
		t.Fatalf("first check: %q", v)
	}
	if v := Start(context.Background(), dir, "0.1.1", now.Add(time.Hour)).Available(0); v != "0.1.2" {
		t.Fatalf("cached answer: %q", v)
	}
	if n := r.hits.Load(); n != 1 {
		t.Fatalf("asked %d times within a day", n)
	}
	if v := Start(context.Background(), dir, "0.1.2", now.Add(time.Hour)).Available(0); v != "" {
		t.Fatalf("offered the version already running: %q", v)
	}
	Start(context.Background(), dir, "0.1.1", now.Add(25*time.Hour)).Available(2 * time.Second)
	if n := r.hits.Load(); n != 2 {
		t.Fatalf("asked %d times after a day", n)
	}
}
