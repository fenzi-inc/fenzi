package main

// The Team plan's client commands: login, logout, status, policy publish,
// and the policy an enrolled machine runs. The control plane is the hosted
// service at https://boundlane.dev; nothing here holds a model key or source.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"boundlane/cli/internal/config"
	"boundlane/cli/internal/relay"
	"boundlane/cli/internal/run"
	"boundlane/cli/internal/screen"
	"boundlane/cli/internal/team"
	"boundlane/cli/internal/tui"
	"boundlane/compiler"
)

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
		return run.Resolved{}, errors.New("no team policy yet; an admin publishes one in the console or with boundlane policy publish")
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
