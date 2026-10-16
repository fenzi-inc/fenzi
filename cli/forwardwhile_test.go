package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"fenzi/cli/internal/config"
	"fenzi/teamapi"
)

func quietEnv() env {
	return env{ctx: context.Background(), stdin: strings.NewReader(""), stdout: io.Discard, stderr: io.Discard}
}

func fastForward(t *testing.T) {
	t.Helper()
	every, last := forwardEvery, forwardLastWait
	forwardEvery, forwardLastWait = 20*time.Millisecond, 5*time.Second
	t.Cleanup(func() { forwardEvery, forwardLastWait = every, last })
}

func (c *refusingConsole) beatCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.beats)
}

// On Free, or for a sandbox not started from a team revision, nothing forwards:
// no pass, no lock file, no call to any server.
func TestForwardWhileDoesNothingOnFree(t *testing.T) {
	fakeRuntime(t, nil, "")
	fastForward(t)
	dirs, err := config.Default()
	if err != nil {
		t.Fatal(err)
	}
	for _, rev := range []int{0, 2} {
		stop := forwardWhile(quietEnv(), rev)
		time.Sleep(60 * time.Millisecond)
		if !stop() {
			t.Fatalf("r%d: a Free run reported the console as not reached", rev)
		}
	}
	if _, err := os.Stat(filepath.Join(dirs.Config, "relay.lock")); !os.IsNotExist(err) {
		t.Fatalf("a Free run took the relay lock: %v", err)
	}
}

// Signed in, a team run forwards every few seconds while the agent runs and once
// more when it stops, without fenzi forward or the Mac app.
func TestForwardWhileForwardsDuringTheRunAndAtTheEnd(t *testing.T) {
	fakeRuntime(t, nil, "")
	fastForward(t)
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	console := &refusingConsole{bundle: teamapi.ToWire(signed(key, 2))}
	srv := httptest.NewServer(console)
	t.Cleanup(srv.Close)
	enrollCached(t, srv.URL, key)

	stop := forwardWhile(quietEnv(), 2)
	deadline := time.Now().Add(5 * time.Second)
	for console.beatCount() < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	during := console.beatCount()
	if during < 2 {
		t.Fatalf("%d passes while the agent ran, want at least 2", during)
	}
	if !stop() {
		t.Fatal("the console was reached, but stop said it was not")
	}
	if after := console.beatCount(); after <= during {
		t.Fatalf("no last pass at the end: %d heartbeats before stop, %d after", during, after)
	}
}

// When another forwarder holds the lock (the Mac app's, or fenzi forward),
// the run skips its passes instead of queueing, and still makes the last one.
func TestForwardWhileSkipsWhileAnotherForwarderRuns(t *testing.T) {
	fakeRuntime(t, nil, "")
	fastForward(t)
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	console := &refusingConsole{bundle: teamapi.ToWire(signed(key, 2))}
	srv := httptest.NewServer(console)
	t.Cleanup(srv.Close)
	dirs := enrollCached(t, srv.URL, key)

	unlock, err := lockRelay(context.Background(), dirs, 0)
	if err != nil {
		t.Fatal(err)
	}
	stop := forwardWhile(quietEnv(), 2)
	time.Sleep(120 * time.Millisecond)
	if n := console.beatCount(); n != 0 {
		t.Fatalf("%d passes while another forwarder held the lock", n)
	}
	unlock()
	stop()
	if n := console.beatCount(); n == 0 {
		t.Fatal("no last pass once the other forwarder let go")
	}
}

// A console that cannot be reached is said once, after the agent exits.
func TestForwardWhileSaysWhenTheConsoleWasNotReached(t *testing.T) {
	fakeRuntime(t, nil, "")
	fastForward(t)
	forwardLastWait = 2 * time.Second
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	srv := httptest.NewServer(&refusingConsole{bundle: teamapi.ToWire(signed(key, 2))})
	url := srv.URL
	srv.Close()
	enrollCached(t, url, key)

	stop := forwardWhile(quietEnv(), 2)
	time.Sleep(60 * time.Millisecond)
	if stop() {
		t.Fatal("stop said the console was reached, but nothing listens there")
	}
}
