package main

// fenzi policy apply: on the Free plan, bring a change to ./fenzi.yaml
// to the sandboxes already running from this folder. A host change loads onto
// them the way sync loads a team revision: compiled, proved, then policy set
// and policy list. A change to the workspace or paths is fixed when the
// sandbox is created, so it waits for the next run and nothing changes here.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"fenzi/agents"
	"fenzi/cli/internal/config"
	"fenzi/cli/internal/run"
	"fenzi/cli/internal/team"
	"fenzi/cli/internal/tui"
	"fenzi/compiler"
)

func cmdPolicyApply(e env, args []string) (int, error) {
	fs := newFlags("policy apply", e.stderr)
	policyFile := fs.String("policy", "", "policy file to use instead of ./fenzi.yaml, as given to fenzi run")
	if _, err := parse(fs, args); err != nil {
		return 1, err
	}
	dirs, err := config.Default()
	if err != nil {
		return 1, err
	}
	switch _, err := team.Load(dirs); {
	case err == nil:
		return 1, errors.New("this machine is signed in to a team, so its policy comes from the console. fenzi sync loads a published host change onto running sandboxes")
	case !errors.Is(err, team.ErrNotEnrolled):
		return 1, err
	}
	repo, err := cwd()
	if err != nil {
		return 1, err
	}
	next, err := run.ResolveFree(repo, *policyFile)
	if err != nil {
		return 1, err
	}
	live, err := client().Sandboxes(e.ctx)
	if err != nil {
		return 1, &run.GatewayError{Err: err}
	}
	running := map[string]bool{}
	for _, n := range live {
		running[n] = true
	}
	state, err := dirs.LoadState()
	if err != nil {
		return 1, err
	}
	var targets []config.Sandbox
	for _, sb := range state.Sandboxes {
		if running[sb.Name] && sb.Repo != "" && filepath.Clean(sb.Repo) == filepath.Clean(repo) {
			targets = append(targets, sb)
		}
	}

	u := tui.New(e.stdin, e.stdout)
	u.Title("Policy apply", filepath.Base(repo))
	u.Done("Policy", next.Sources)
	if len(targets) == 0 {
		u.Skip("Sandboxes", "none running from this folder")
		u.Note("The next fenzi run here uses this policy.")
		u.Blank()
		return 0, nil
	}
	var refused error
	changed := false
	for _, sb := range targets {
		sbRun := dirs.Run(sb.Name)
		prev, err := run.LoadResolved(sbRun)
		if errors.Is(err, run.ErrNoResolved) {
			u.Skip(sb.Name, "started before Fenzi saved the policy it runs; the next run uses this one")
			continue
		}
		if err != nil {
			return 1, err
		}
		// Hosts approved for this sandbox while it ran stay with it.
		mine := next
		if hosts, err := run.LoadApproved(sbRun); err == nil {
			for _, h := range hosts {
				if doc, _, err := run.WithHost(mine.Doc, h); err == nil {
					mine.Doc = doc
				}
			}
		}
		switch compiler.Effect(prev, mine.Doc) {
		case compiler.EffectSame:
			u.Done(sb.Name, "already runs this policy")
			continue
		case compiler.EffectWall:
			u.Skip(sb.Name, "not changed. "+compiler.EffectNote(compiler.EffectWall))
			u.Note("Workspace and path rules are fixed when a sandbox is created. fenzi stop " + sb.Name + ", then fenzi run, starts one with them.")
			continue
		}
		line, rev, err := loadHosts(e, dirs, sb, mine)
		var pe *run.PolicyError
		switch {
		case errors.As(err, &pe):
			u.Problem(sb.Name, "not changed, the policy check returned "+pe.Result.Result)
			if ex := pe.Result.Example(); ex != "" {
				u.Println("    " + u.Bold("Example") + "  " + ex)
			}
			refused = err
			continue
		case err != nil:
			return 1, err
		}
		u.Done(sb.Name, line)
		for i := range state.Sandboxes {
			if state.Sandboxes[i].Name == sb.Name {
				state.Sandboxes[i].Revision = rev
			}
		}
		changed = true
	}
	u.Blank()
	if changed {
		if err := dirs.SaveState(state); err != nil {
			return 1, err
		}
	}
	if refused != nil {
		return 0, refused
	}
	return 0, nil
}

// loadHosts compiles the new document for one sandbox, proves it, and loads
// it. Only after the load does the run folder take the new policy, so a
// refused change leaves the record of what the sandbox runs as it was. It
// returns the line to show and the new local revision.
func loadHosts(e env, dirs config.Dirs, sb config.Sandbox, next run.Resolved) (line, rev string, err error) {
	entry, err := agents.Get(sb.Agent)
	if err != nil {
		return "", "", err
	}
	tmp, err := os.MkdirTemp("", "fenzi-apply-")
	if err != nil {
		return "", "", err
	}
	defer os.RemoveAll(tmp)
	c, err := run.WriteCompiled(next, entry, tmp)
	if err != nil {
		return "", "", err
	}
	if _, err := run.Prove(e.ctx, prover(), c, "policy for "+sb.Name); err != nil {
		return "", "", err
	}
	loaded, err := run.LoadNetwork(e.ctx, client(), sb.Name, c.Policy)
	if err != nil {
		return "", "", err
	}
	runDir := dirs.Run(sb.Name)
	if err := run.SaveResolved(runDir, next.Doc); err != nil {
		return "", "", err
	}
	for _, f := range []string{"policy.yaml", "boundary.yaml"} {
		b, err := os.ReadFile(filepath.Join(tmp, f))
		if err != nil {
			return "", "", err
		}
		if err := os.WriteFile(filepath.Join(runDir, f), b, 0o600); err != nil {
			return "", "", err
		}
	}
	switch loaded {
	case run.LoadLoaded:
		return fmt.Sprintf("hosts loaded, %s. %s", c.Revision, compiler.EffectNote(compiler.EffectNetwork)), c.Revision, nil
	case run.LoadPending:
		return fmt.Sprintf("hosts pending, %s. The sandbox loads them on its next poll.", c.Revision), c.Revision, nil
	default:
		return fmt.Sprintf("hosts accepted, %s. The runtime did not report them loaded yet.", c.Revision), c.Revision, nil
	}
}
