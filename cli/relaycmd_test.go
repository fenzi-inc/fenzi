package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"boundlane/cli/internal/config"
)

func TestRelayPassesTakeTurns(t *testing.T) {
	dirs := config.Dirs{Config: t.TempDir()}
	unlock, err := lockRelay(context.Background(), dirs, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lockRelay(context.Background(), dirs, 200*time.Millisecond); err == nil || !strings.Contains(err.Error(), "another boundlane sync or forward is running") {
		t.Fatalf("a second pass while the first runs: err %v", err)
	}
	// The second pass waits for the first instead of failing at once.
	go func() {
		time.Sleep(150 * time.Millisecond)
		unlock()
	}()
	again, err := lockRelay(context.Background(), dirs, 5*time.Second)
	if err != nil {
		t.Fatalf("after the first pass ended: %v", err)
	}
	again()
}
