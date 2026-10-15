//go:build team

package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"boundlane/cli/internal/config"
	"boundlane/cli/internal/tui"
	"boundlane/controlplane"
)

// includedTeam is true in a build that carries the local team server.
const includedTeam = true

func cmdServer(e env, args []string) (int, error) {
	fs := newFlags("server", e.stderr)
	addr := fs.String("addr", "127.0.0.1:8787", "listen address, localhost only")
	proveOnly := fs.Bool("prove", false, "serve only POST /v1/prove, for the hosted control plane")
	if _, err := parse(fs, args); err != nil {
		return 1, err
	}
	host, _, err := net.SplitHostPort(*addr)
	if err != nil {
		return 1, err
	}
	if ip := net.ParseIP(host); host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return 1, errors.New("the local team server only listens on localhost")
	}
	if *proveOnly {
		return serveProve(e, *addr)
	}
	dirs, err := config.Default()
	if err != nil {
		return 1, err
	}
	if err := os.MkdirAll(dirs.Config, 0o700); err != nil {
		return 1, err
	}
	dbPath := filepath.Join(dirs.Config, "server.db")
	u := tui.New(e.stdin, e.stdout)
	u.Title("Team server", "localhost only")
	u.Done("Listen", "http://"+*addr)
	u.Done("Database", tilde(dbPath, homeDir()))
	s, err := controlplane.Open(dbPath, proverChecker{})
	if err != nil {
		return 1, err
	}
	defer s.Close()
	if _, err := s.Current("acme"); err != nil {
		u.Note("Proving developer-default.")
	}
	if b, created, err := s.SeedDeveloperDefault(e.ctx); err != nil {
		u.Problem("Policy", "not seeded ("+err.Error()+")")
		u.Note("Sign in still works. Publish with boundlane policy publish once the prover runs.")
	} else if created {
		u.Done("Policy", fmt.Sprintf("developer-default r%d, proved and signed", b.Revision))
	} else {
		u.Done("Policy", fmt.Sprintf("r%d already published", b.Revision))
	}
	users, err := s.Users()
	if err != nil {
		return 1, err
	}
	for _, user := range users {
		role := "member"
		if user.Admin {
			role = "admin"
		}
		u.Done("User", user.Email+", "+role)
	}
	u.Note("Press Ctrl-C to stop. Sign in from another terminal with boundlane login --server http://" + *addr + ".")
	u.Blank()
	srv := &http.Server{Addr: *addr, Handler: controlplane.Handler(s)}
	ctx, stop := signal.NotifyContext(e.ctx, os.Interrupt)
	defer stop()
	go func() {
		<-ctx.Done()
		shut, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(shut)
	}()
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return 1, err
	}
	return 0, nil
}

// serveProve compiles and proves documents for the hosted control plane,
// which does not run openshell-prover itself. BOUNDLANE_PROVE_TOKEN, when set,
// must be sent as X-Prove-Token.
func serveProve(e env, addr string) (int, error) {
	u := tui.New(e.stdin, e.stdout)
	u.Title("Prove server", "localhost only")
	u.Done("Listen", "http://"+addr+"/v1/prove")
	token := os.Getenv("BOUNDLANE_PROVE_TOKEN")
	if token == "" {
		u.Note("BOUNDLANE_PROVE_TOKEN is not set. Any local process can ask for a proof.")
	}
	srv := &http.Server{Addr: addr, Handler: controlplane.ProveHandler(proverChecker{}, token), ReadHeaderTimeout: 10 * time.Second}
	ctx, stop := signal.NotifyContext(e.ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shut, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(shut)
	}()
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return 1, err
	}
	return 0, nil
}

type proverChecker struct{}

func (proverChecker) Check(ctx context.Context, policy, boundary []byte) (bool, string, error) {
	dir, err := os.MkdirTemp("", "boundlane-prove-")
	if err != nil {
		return false, "", err
	}
	defer os.RemoveAll(dir)
	pol, bnd := filepath.Join(dir, "policy.yaml"), filepath.Join(dir, "boundary.yaml")
	if err := os.WriteFile(pol, policy, 0o600); err != nil {
		return false, "", err
	}
	if err := os.WriteFile(bnd, boundary, 0o600); err != nil {
		return false, "", err
	}
	r, err := prover().Check(ctx, pol, bnd)
	if err != nil {
		return false, "", err
	}
	if r.Passed() {
		return true, "", nil
	}
	detail := r.Result
	if ex := r.Example(); ex != "" {
		detail += ": " + ex
	}
	return false, detail, nil
}
