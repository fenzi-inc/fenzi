package main

import (
	"context"
	"errors"
	"os"
	"time"

	"boundlane/agents"
	"boundlane/cli/internal/config"
	"boundlane/cli/internal/team"
	"boundlane/cli/internal/tui"
	"boundlane/cli/internal/workspace"
)

// cmdHome is `boundlane` with no command on a terminal: what is going on in
// this folder, and the next things a person usually does.
func cmdHome(e env, _ []string) (int, error) {
	u := tui.New(e.stdin, e.stdout)
	dirs, err := config.Default()
	if err != nil {
		return 1, err
	}
	home := homeDir()
	dir, _ := cwd()

	agent, _ := agents.Get("claude")
	if s, ok := dirs.LoadSetup(); ok {
		if a, err := agents.Get(s.Agent); err == nil {
			agent = a
		}
	}

	ctx, cancel := context.WithTimeout(e.ctx, 5*time.Second)
	live, liveErr := running(env{ctx: ctx, stdin: e.stdin, stdout: e.stdout, stderr: e.stderr}, dirs)
	cancel()

	var waiting review
	if s, err := dirs.LoadState(); err == nil {
		if sb, ok := s.LatestIn(dir, false); ok && !sb.Running {
			if sb, base, files, changes, err := staged(e, sb.Name); err == nil && len(changes) > 0 {
				waiting = newReview(sb, base, files, changes, "")
			}
		}
	}

	lines := []string{
		row(u, "Folder", tilde(dir, home)),
		row(u, "Agent", agent.Display+" "+agent.Version),
	}
	switch {
	case liveErr != nil:
		lines = append(lines, row(u, "Running", u.Dim("unknown, the gateway did not answer")))
	case len(live) == 0:
		lines = append(lines, row(u, "Running", u.Dim("no sandboxes")))
	default:
		lines = append(lines, row(u, "Running", plural(len(live), "sandbox", "sandboxes")))
	}
	if waiting.changes != nil {
		lines = append(lines, row(u, "Waiting", plural(len(waiting.changes), "changed file", "changed files")+", not applied yet"))
	}
	plan := "Free plan, this machine"
	if en, err := team.Load(configDirs(e)); err == nil && en.Tenant != "" {
		plan = "Team " + en.Tenant + ", " + en.Server
	}
	lines = append(lines, "", u.Dim(plan))
	u.Blank()
	u.Box("Boundlane "+Version, lines)
	u.Blank()

	type choice struct {
		id string
		tui.Option
	}
	var choices []choice
	add := func(id, label, hint string) {
		choices = append(choices, choice{id, tui.Option{Label: label, Hint: hint}})
	}
	if waiting.changes != nil {
		add("review", "Review the agent's changes", plural(len(waiting.changes), "file", "files")+" waiting")
	}
	if workspace.CheckFolder(dir, home) == nil {
		add("start", "Start "+agent.Display+" here", "boundlane run")
	} else {
		add("start", "Start "+agent.Display+" in a project folder", "boundlane run")
	}
	if len(live) > 0 {
		add("connect", "Connect to a running sandbox", "boundlane connect")
		add("requests", "Requests for more access", "boundlane requests")
	}
	add("doctor", "Check this machine", "boundlane doctor")
	add("setup", "Change the agent, key, or folder", "boundlane setup")
	add("help", "All commands", "boundlane help")
	add("quit", "Quit", "")

	opts := make([]tui.Option, len(choices))
	for i, c := range choices {
		opts[i] = c.Option
	}
	i, err := u.Select("What would you like to do?", opts, 0)
	if errors.Is(err, tui.ErrCancelled) {
		return 0, nil
	}
	if err != nil {
		return 1, err
	}
	switch choices[i].id {
	case "review":
		return waiting.offer(e)
	case "start":
		if workspace.CheckFolder(dir, home) != nil {
			p, err := setupProject(u, agent, false)
			if errors.Is(err, tui.ErrCancelled) {
				return 0, nil
			}
			if err != nil {
				return 1, err
			}
			if err := os.Chdir(p); err != nil {
				return 1, err
			}
		}
		u.Blank()
		return cmdRun(e, []string{agent.Name})
	case "connect":
		return cmdConnect(e, nil)
	case "requests":
		return cmdRequests(e, nil)
	case "doctor":
		return cmdDoctor(e, nil)
	case "setup":
		return cmdSetup(e, nil)
	case "help":
		writeHelp(e.stdout)
	}
	return 0, nil
}

// defaultAgent is the agent setup chose, or Claude Code.
func defaultAgent() string {
	if dirs, err := config.Default(); err == nil {
		if s, ok := dirs.LoadSetup(); ok && s.Agent != "" {
			return s.Agent
		}
	}
	return "claude"
}
