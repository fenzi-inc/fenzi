package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"fenzi/cli/internal/config"
	"fenzi/cli/internal/openshell"
	"fenzi/cli/internal/relay"
	"fenzi/cli/internal/team"
	"fenzi/cli/internal/tui"
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
	install := fs.Bool("install", false, "keep forwarding in the background, after the terminal closes and at each login")
	uninstall := fs.Bool("uninstall", false, "stop the background forwarder and remove it")
	svc := fs.Bool("service", false, "run as the background forwarder; --install sets this up")
	if _, err := parse(fs, args); err != nil {
		return 1, err
	}
	switch {
	case *install && *uninstall:
		return 1, errors.New("choose --install or --uninstall")
	case *install:
		return cmdForwardInstall(e)
	case *uninstall:
		return cmdForwardUninstall(e)
	}
	// launchd and systemd stop a service with SIGTERM.
	ctx, stop := signal.NotifyContext(e.ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	var log *serviceLog
	if *svc {
		log = &serviceLog{w: e.stdout}
		if dirs, err := config.Default(); err == nil {
			log.path = forwardLogPath(dirs)
		}
	}
	if !*once {
		dirs, err := config.Default()
		if err != nil {
			return 1, err
		}
		who := holderForward
		if *svc {
			who = holderService
		}
		release, err := holdForwarder(ctx, dirs, who, func(other string) {
			if log != nil {
				log.say(fmt.Sprintf("%s is forwarding; this one takes over when it stops", other))
				return
			}
			u := tui.New(e.stdin, e.stdout)
			u.Note(fmt.Sprintf("%s is already forwarding on this machine. This one waits and takes over when it stops.", capitalize(other)))
		})
		if err != nil {
			if ctx.Err() != nil {
				return 0, nil
			}
			return 1, err
		}
		defer release()
	}
	for {
		rep, err := relayOnce(ctx, e)
		switch {
		case err != nil && ctx.Err() != nil:
			// Ctrl-C during a pass. What was spooled stays for the next run.
			return 0, nil
		case log != nil && errors.Is(err, errSignIn):
			// A clean exit: neither launchd nor systemd starts it again.
			log.say("this machine is signed out; the background forwarder stops")
			return 0, nil
		case log != nil && err != nil:
			// The service keeps going: the gateway may not be up yet after a
			// login, or the network may be away.
			log.say(err.Error())
		case err != nil:
			return 1, err
		case log != nil:
			log.report(rep)
		default:
			printReport(e, "Forward", rep)
		}
		if *once {
			if err != nil {
				return 1, err
			}
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

// capitalize starts a holder name with a capital, for the start of a sentence.
func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// errSignIn is what a pass says on a machine that is not signed in.
var errSignIn = errors.New("sign in first (fenzi login)")

func relayOnce(ctx context.Context, e env) (relay.Report, error) {
	return relayOnceWait(ctx, e, relayLockWait)
}

// relayOnceWait is one pass that waits at most wait for another pass to finish.
// With 0 it tries once and gives up, which the background forwarder in
// fenzi run wants: the other forwarder is already doing the work.
func relayOnceWait(ctx context.Context, e env, wait time.Duration) (relay.Report, error) {
	dirs, err := config.Default()
	if err != nil {
		return relay.Report{}, err
	}
	if _, err := loadEnrollment(dirs); err != nil {
		return relay.Report{}, err
	}
	// Two passes at once would each rewrite the spool and the cursors, and
	// one could drop a record the other had read. Passes take turns.
	unlock, err := lockRelay(ctx, dirs, wait)
	if err != nil {
		return relay.Report{}, err
	}
	defer unlock()
	// Read the sign-in again under the lock. fenzi logout clears it under the
	// same lock, and a pass that read it before would save it back below.
	en, err := loadEnrollment(dirs)
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
	var doc, boundary []byte
	if en.Revision > 0 {
		b, err := en.Bundle()
		if err != nil {
			return relay.Report{}, err
		}
		doc, boundary = b.Document, b.Boundary
	}
	watch := openshell.NewWatch(client())
	defer watch.Close()
	rep, err := relay.Pass(ctx, relay.Option{
		Gateway:   client(),
		Stream:    watch,
		Client:    tc,
		Token:     en.Token,
		Tenant:    en.Tenant,
		Machine:   en.Machine,
		Revision:  en.Revision,
		Document:  doc,
		Boundary:  boundary,
		Dirs:      dirs,
		Prover:    prover(),
		BeatNotes: beatNotes(en),
	})
	if note != "" {
		rep.Notes = append([]string{note}, rep.Notes...)
	}
	if err != nil && strings.Contains(err.Error(), "No active gateway") {
		return rep, errors.New("OpenShell gateway is not ready. Run fenzi doctor")
	}
	return rep, err
}

func loadEnrollment(dirs config.Dirs) (team.Enrollment, error) {
	en, err := team.Load(dirs)
	if errors.Is(err, team.ErrNotEnrolled) {
		return en, errSignIn
	}
	return en, err
}

// beatNotes is what the heartbeat tells the console about this machine's
// policy: a bundle it refused while it keeps the cached revision.
func beatNotes(en team.Enrollment) []string {
	if en.Refused == "" {
		return []string{}
	}
	return []string{en.Refused}
}

// relayLockWait is how long a pass waits for another one to finish.
var relayLockWait = 60 * time.Second

// lockRelay holds relay.lock in the config folder until unlock is called.
// It waits while another fenzi sync or forward holds it, up to wait.
func lockRelay(ctx context.Context, dirs config.Dirs, wait time.Duration) (unlock func(), err error) {
	if err := os.MkdirAll(dirs.Config, 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(dirs.Config, "relay.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(wait)
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return func() {
				_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
				f.Close()
			}, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) {
			f.Close()
			return nil, err
		}
		if time.Now().After(deadline) {
			f.Close()
			return nil, errors.New("another fenzi sync or forward is running; try again when it finishes")
		}
		select {
		case <-ctx.Done():
			f.Close()
			return nil, ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
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
