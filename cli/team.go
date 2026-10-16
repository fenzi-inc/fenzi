package main

// The Team plan's client commands: login, logout, status, policy publish,
// and the policy an enrolled machine runs. The control plane is the hosted
// service at https://fenzi.dev; nothing here holds a model key or source.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"fenzi/agents"
	"fenzi/cli/internal/config"
	"fenzi/cli/internal/relay"
	"fenzi/cli/internal/run"
	"fenzi/cli/internal/screen"
	"fenzi/cli/internal/team"
	"fenzi/cli/internal/tui"
	"fenzi/compiler"
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
		return 1, errors.New("usage: fenzi policy publish <file>")
	}
	dirs, err := config.Default()
	if err != nil {
		return 1, err
	}
	en, err := team.Load(dirs)
	if errors.Is(err, team.ErrNotEnrolled) {
		return 1, errors.New("sign in first (fenzi login)")
	}
	if err != nil {
		return 1, err
	}
	// The role may have changed in the console since login. Ask; when the
	// server cannot be reached, the stored role decides and the publish
	// below fails on its own.
	if me, err := teamClient(en.Server).Me(e.ctx, en.Token); err == nil {
		en = en.WithRole(me)
	}
	if !en.Admin {
		who, where := "this account", "the console"
		if en.Email != "" {
			who = en.Email
		}
		if en.Server != "" {
			where = en.Server + "/console"
		}
		return 1, fmt.Errorf("publishing needs a team admin, and %s is %s. An admin publishes from %s, or signs in on this machine with fenzi login", who, withArticle(en.RoleName()), where)
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
	if errors.Is(err, context.DeadlineExceeded) {
		return 1, errors.New("no approval after two minutes, nothing was stored. Run fenzi login for a new code")
	}
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
	fs := newFlags("status", e.stderr)
	asJSON := jsonFlag(fs)
	if _, err := parse(fs, args); err != nil {
		return 1, err
	}
	dirs, err := config.Default()
	if err != nil {
		return 1, err
	}
	u := tui.New(e.stdin, e.stdout)
	en, err := team.Load(dirs)
	if errors.Is(err, team.ErrNotEnrolled) {
		if *asJSON {
			return 0, writeJSON(e.stdout, jsonStatus{Notes: []string{}})
		}
		u.Title("This machine", "")
		u.Skip("Account", "none, Free plan")
		u.Command("fenzi login", "sign this machine in")
		u.Blank()
		return 0, nil
	}
	if err != nil {
		return 1, err
	}
	tc := teamClient(en.Server)
	en, note, err := team.Refresh(e.ctx, tc, en)
	if err != nil {
		return 1, err
	}
	// An admin may have changed the role since login.
	if me, err := tc.Me(e.ctx, en.Token); err == nil {
		en = en.WithRole(me)
	}
	if err := en.Save(dirs); err != nil {
		return 1, err
	}
	role := en.RoleName()
	if *asJSON {
		doc := jsonStatus{
			SignedIn: true, Email: en.Email, Role: role, Team: en.Tenant, Machine: en.Machine,
			Server: en.Server, ConsoleURL: en.Server + "/console", PolicyRevision: en.Revision, Notes: []string{},
		}
		if note != "" {
			doc.Notes = append(doc.Notes, note)
		}
		if err := writeJSON(e.stdout, doc); err != nil {
			return 1, err
		}
		_ = tc.Heartbeat(e.ctx, en.Token, statusBeat(e, dirs, en))
		return 0, nil
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
	_ = tc.Heartbeat(e.ctx, en.Token, statusBeat(e, dirs, en))
	return 0, nil
}

// statusBeat is the heartbeat status sends, with the same notes as a
// forwarder pass.
func statusBeat(e env, dirs config.Dirs, en team.Enrollment) team.Beat {
	b := relay.Beat(e.ctx, client(), dirs, en.Revision)
	b.Notes = beatNotes(en)
	return b
}

// teamClient talks to the team server with a time limit: a server that
// accepts the connection and never answers must not hold the command.
func teamClient(server string) team.Client {
	return team.Client{Base: server, HTTP: &http.Client{Timeout: teamTimeout}}
}

// withArticle reads a role in a sentence: "an admin", "a reviewer".
func withArticle(role string) string {
	switch role {
	case "admin", "auditor":
		return "an " + role
	default:
		return "a " + role
	}
}

// teamTimeout bounds each request to the team server.
var teamTimeout = 30 * time.Second

// withCachedBoundary adds the team boundary from the signed revision this
// machine has cached. It does not ask the server. A machine that is not
// signed in, or whose team has no boundary, leaves r as it is.
func withCachedBoundary(r run.Resolved) (run.Resolved, error) {
	dirs, err := config.Default()
	if err != nil {
		return r, err
	}
	en, err := team.Load(dirs)
	if errors.Is(err, team.ErrNotEnrolled) {
		return r, nil
	}
	if err != nil || en.Revision == 0 {
		return r, err
	}
	b, err := en.Bundle()
	if err != nil {
		return r, err
	}
	return r.WithTeamBoundary(b.Boundary, en.Tenant, en.Revision)
}

// checkTeamBoundary refuses to approve a request for a destination
// ("host:port") the team boundary cached on this machine has no rule for.
// It compares the host and port only, not methods or paths. Without a team
// boundary every destination passes, as before.
func checkTeamBoundary(sb config.Sandbox, destination string) error {
	res, err := withCachedBoundary(run.Resolved{})
	if err != nil || res.Boundary == nil {
		return err
	}
	name := sb.Agent
	if name == "" {
		name = defaultAgent()
	}
	entry, err := agents.Get(name)
	if err != nil {
		return err
	}
	ok, err := res.HostInBoundary(entry, destination)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("not approved: %s is outside %s. An admin adds it to the team boundary in the console before it can be approved", orUnknown(destination), res.BoundarySource)
	}
	return nil
}

func orUnknown(destination string) string {
	if destination == "" {
		return "a request with no destination"
	}
	return destination
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
	en, note, err := team.Refresh(e.ctx, teamClient(en.Server), en)
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
		return run.Resolved{}, errors.New("no team policy yet; an admin publishes one in the console or with fenzi policy publish")
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
	res := run.Resolved{Doc: doc, Sources: fmt.Sprintf("%s r%d (signed)", en.Tenant, en.Revision), TeamRevision: en.Revision}
	return res.WithTeamBoundary(b.Boundary, en.Tenant, en.Revision)
}
