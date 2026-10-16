package main

import (
	"context"
	"io"
	"sync"
	"time"

	"fenzi/cli/internal/config"
	"fenzi/cli/internal/team"
)

// forwardEvery is how often a run on a signed-in machine sends decisions and
// requests to the team console, the same as fenzi forward's default.
var forwardEvery = 5 * time.Second

// forwardLastWait bounds the last pass after the agent exits, so a console
// that does not answer cannot hold the terminal.
var forwardLastWait = 20 * time.Second

// forwardWhile forwards to the team console in the background while an agent
// runs, so a request the agent files reaches the console without the Mac app or
// a separate fenzi forward. It starts only on a machine signed in to a team,
// for a sandbox started from the team's policy; on Free it does nothing.
//
// Passes take turns with any other forwarder through relay.lock: when one is
// already running (the Mac app's, or fenzi forward), this one skips that
// pass rather than queue behind it. Nothing is written to the agent's terminal.
//
// The returned stop ends the loop and makes one last pass, so what the session
// logged at the end reaches the console too. It reports whether the console
// was reached at least once, for one quiet line after the agent exits.
func forwardWhile(e env, teamRevision int) (stop func() (reached bool)) {
	if teamRevision <= 0 {
		return func() bool { return true }
	}
	dirs, err := config.Default()
	if err != nil {
		return func() bool { return true }
	}
	if _, err := team.Load(dirs); err != nil {
		return func() bool { return true }
	}
	quiet := env{ctx: e.ctx, stdin: e.stdin, stdout: io.Discard, stderr: io.Discard}
	ctx, cancel := context.WithCancel(e.ctx)
	var (
		mu      sync.Mutex
		reached bool
		wg      sync.WaitGroup
	)
	pass := func(ctx context.Context, wait time.Duration) {
		// A pass that could not reach the console still succeeds: it keeps the
		// cached policy and queues the records. Only an answered pass counts.
		if rep, err := relayOnceWait(ctx, quiet, wait); err == nil && !rep.Unreachable {
			mu.Lock()
			reached = true
			mu.Unlock()
		}
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			pass(ctx, 0)
			timer := time.NewTimer(forwardEvery)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		}
	}()
	return func() bool {
		cancel()
		wg.Wait()
		last, done := context.WithTimeout(e.ctx, forwardLastWait)
		defer done()
		pass(last, forwardLastWait)
		mu.Lock()
		defer mu.Unlock()
		return reached
	}
}
