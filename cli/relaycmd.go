package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"time"

	"boundlane/cli/internal/config"
	"boundlane/cli/internal/openshell"
	"boundlane/cli/internal/relay"
	"boundlane/cli/internal/team"
	"boundlane/cli/internal/tui"
)

func cmdSync(e env, args []string) (int, error) {
	if _, err := parse(newFlags("sync", e.stderr), args); err != nil {
		return 1, err
	}
	rep, err := relayOnce(e.ctx, e)
	if err != nil {
		return 1, err
	}
	printReport(e, "Sync", rep)
	return 0, nil
}

func cmdForward(e env, args []string) (int, error) {
	fs := newFlags("forward", e.stderr)
	once := fs.Bool("once", false, "upload one batch and exit")
	every := fs.Duration("every", 5*time.Second, "how often to look")
	if _, err := parse(fs, args); err != nil {
		return 1, err
	}
	ctx, stop := signal.NotifyContext(e.ctx, os.Interrupt)
	defer stop()
	for {
		rep, err := relayOnce(ctx, e)
		if err != nil && ctx.Err() != nil {
			// Ctrl-C during a pass. What was spooled stays for the next run.
			return 0, nil
		}
		if err != nil {
			return 1, err
		}
		printReport(e, "Forward", rep)
		if *once {
			return 0, nil
		}
		timer := time.NewTimer(*every)
		select {
		case <-ctx.Done():
			timer.Stop()
			return 0, nil
		case <-timer.C:
		}
	}
}

func relayOnce(ctx context.Context, e env) (relay.Report, error) {
	dirs, err := config.Default()
	if err != nil {
		return relay.Report{}, err
	}
	en, err := team.Load(dirs)
	if errors.Is(err, team.ErrNotEnrolled) {
		return relay.Report{}, errors.New("sign in first (boundlane login)")
	}
	if err != nil {
		return relay.Report{}, err
	}
	// A server that accepts the connection and never answers must not hold
	// the pass, which also does the gateway's work.
	tc := team.Client{Base: en.Server, HTTP: &http.Client{Timeout: 30 * time.Second}}
	en, note, err := team.Refresh(ctx, tc, en)
	switch {
	case errors.Is(err, team.ErrNoPolicy):
		// Nothing to sync, but decisions can still be spooled.
		note = err.Error()
	case err != nil:
		return relay.Report{}, err
	}
	if err := en.Save(dirs); err != nil {
		return relay.Report{}, err
	}
	var doc []byte
	if en.Revision > 0 {
		b, err := en.Bundle()
		if err != nil {
			return relay.Report{}, err
		}
		doc = b.Document
	}
	watch := openshell.NewWatch(client())
	defer watch.Close()
	rep, err := relay.Pass(ctx, relay.Option{
		Gateway:  client(),
		Stream:   watch,
		Client:   tc,
		Token:    en.Token,
		Tenant:   en.Tenant,
		Machine:  en.Machine,
		Revision: en.Revision,
		Document: doc,
		Dirs:     dirs,
	})
	if note != "" {
		rep.Notes = append([]string{note}, rep.Notes...)
	}
	if err != nil && strings.Contains(err.Error(), "No active gateway") {
		return rep, errors.New("OpenShell gateway is not ready. Run boundlane doctor")
	}
	return rep, err
}

func printReport(e env, title string, rep relay.Report) {
	u := tui.New(e.stdin, e.stdout)
	u.Title(title, "")
	u.Done("Decisions", fmt.Sprintf("%d", rep.Decisions))
	u.Done("Requests", fmt.Sprintf("%d", rep.Requests))
	u.Done("Applied", fmt.Sprintf("%d", rep.Applied))
	for _, n := range rep.Notes {
		u.Note(n)
	}
	u.Blank()
}
