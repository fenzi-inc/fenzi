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
	"boundlane/cli/internal/relay"
	"boundlane/cli/internal/run"
	"boundlane/cli/internal/screen"
	"boundlane/cli/internal/team"
	"boundlane/cli/internal/tui"
	"boundlane/compiler"
	"boundlane/controlplane"
)

const includedTeam = true

func reportAccount(e env, line func(status, check, detail string)) {
	switch en, err := team.Load(configDirs(e)); {
	case errors.Is(err, team.ErrNotEnrolled) || err != nil && en.Email == "":
		if err != nil && !errors.Is(err, team.ErrNotEnrolled) {
			line("FAIL", "Plan", err.Error())
		} else {
			line("--", "Plan", "Free, this machine")
		}
	case en.Revision == 0:
		line("ok", "Plan", en.Email+", "+en.Tenant+", no policy yet")
	default:
		line("ok", "Plan", fmt.Sprintf("%s, %s, revision %d", en.Email, en.Tenant, en.Revision))
	}
}

func cmdPublish(e env, args []string) (int, error) {
	fs := newFlags("policy publish", e.stderr)
	pos, err := parse(fs, args)
	if err != nil {
		return 1, err
	}
	if len(pos) != 1 {
		return 1, errors.New("usage: boundlane policy publish <file>")
	}
	dirs, err := config.Default()
	if err != nil {
		return 1, err
	}
	en, err := team.Load(dirs)
	if errors.Is(err, team.ErrNotEnrolled) {
		return 1, errors.New("sign in first (boundlane login)")
	}
	if err != nil {
		return 1, err
	}
	if !en.Admin {
		return 1, errors.New("publishing needs an admin. Sign in as dana@acme.dev on the local server")
	}
	raw, err := os.ReadFile(pos[0])
	if err != nil {
		return 1, err
	}
	b, err := team.Client{Base: en.Server}.Publish(e.ctx, en.Token, string(raw))
	if err != nil {
		return 1, err
	}
	if err := en.Take(b); err != nil {
		return 1, err
	}
	if err := en.Save(dirs); err != nil {
		return 1, err
	}
	u := tui.New(e.stdin, e.stdout)
	u.Title("Published", "")
	u.Done("Policy", fmt.Sprintf("%s r%d, proved and signed", b.Tenant, b.Revision))
	u.Blank()
	return 0, nil
}

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
	u.Note("Press Ctrl-C to stop. Sign in from another terminal with boundlane login.")
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

func cmdLogin(e env, args []string) (int, error) {
	fs := newFlags("login", e.stderr)
	server := fs.String("server", team.DefaultServer, "team server")
	if _, err := parse(fs, args); err != nil {
		return 1, err
	}
	dirs, err := config.Default()
	if err != nil {
		return 1, err
	}
	host, _ := os.Hostname()
	ctx, cancel := context.WithTimeout(e.ctx, 2*time.Minute)
	defer cancel()
	en, err := team.Login(ctx, team.Client{Base: *server}, host, e.stdout)
	if err != nil {
		return 1, err
	}
	return 0, en.Save(dirs)
}

func cmdLogout(e env, args []string) (int, error) {
	if _, err := parse(newFlags("logout", e.stderr), args); err != nil {
		return 1, err
	}
	dirs, err := config.Default()
	if err != nil {
		return 1, err
	}
	if err := team.Clear(dirs); err != nil {
		return 1, err
	}
	u := tui.New(e.stdin, e.stdout)
	u.Title("Signed out", "")
	u.Done("This machine", "the sign-in is forgotten")
	u.Note("A sandbox that is already running keeps its policy.")
	u.Blank()
	return 0, nil
}

func cmdStatus(e env, args []string) (int, error) {
	if _, err := parse(newFlags("status", e.stderr), args); err != nil {
		return 1, err
	}
	dirs, err := config.Default()
	if err != nil {
		return 1, err
	}
	u := tui.New(e.stdin, e.stdout)
	en, err := team.Load(dirs)
	if errors.Is(err, team.ErrNotEnrolled) {
		u.Title("This machine", "")
		u.Skip("Account", "none, Free plan")
		u.Command("boundlane login", "sign this machine in")
		u.Blank()
		return 0, nil
	}
	if err != nil {
		return 1, err
	}
	en, note, err := team.Refresh(e.ctx, team.Client{Base: en.Server}, en)
	if err != nil {
		return 1, err
	}
	if err := en.Save(dirs); err != nil {
		return 1, err
	}
	role := "member"
	if en.Admin {
		role = "admin"
	}
	u.Title("This machine", "")
	u.Done("Account", fmt.Sprintf("%s, %s, team %s", en.Email, role, en.Tenant))
	u.Done("Machine", en.Machine)
	u.Done("Server", en.Server)
	u.Done("Console", en.Server+"/console")
	if en.Revision == 0 {
		u.Skip("Policy", "none published yet")
	} else {
		u.Done("Policy", fmt.Sprintf("r%d, verified", en.Revision))
	}
	if note != "" {
		u.Note(note)
	}
	u.Blank()
	_ = team.Client{Base: en.Server}.Heartbeat(e.ctx, en.Token, relay.Beat(e.ctx, client(), dirs, en.Revision))
	return 0, nil
}

// resolvePolicy uses the signed team policy when this machine is signed in,
// and the Free plan otherwise.
func resolvePolicy(e env, dirs config.Dirs, repo, file string) (run.Resolved, error) {
	en, err := team.Load(dirs)
	if errors.Is(err, team.ErrNotEnrolled) {
		return run.ResolveFree(repo, file)
	}
	if err != nil {
		return run.Resolved{}, err
	}
	if file != "" {
		return run.Resolved{}, errors.New("this machine uses the team policy; --policy is for the Free plan")
	}
	en, note, err := team.Refresh(e.ctx, team.Client{Base: en.Server}, en)
	if err != nil {
		return run.Resolved{}, err
	}
	if err := en.Save(dirs); err != nil {
		return run.Resolved{}, err
	}
	if note != "" {
		screen.New(e.stdout).Label("policy", note)
	}
	if en.Revision == 0 {
		return run.Resolved{}, errors.New("no team policy yet; an admin publishes one with boundlane policy publish")
	}
	b, err := en.Bundle()
	if err != nil {
		return run.Resolved{}, err
	}
	doc, err := compiler.Parse(b.Document)
	if err != nil {
		return run.Resolved{}, err
	}
	if _, err := os.Stat(filepath.Join(repo, run.ProjectFile)); err == nil {
		screen.New(e.stdout).Label("policy", "project file not used; the team policy applies")
	}
	return run.Resolved{Doc: doc, Sources: fmt.Sprintf("%s r%d (signed)", en.Tenant, en.Revision), TeamRevision: en.Revision}, nil
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
