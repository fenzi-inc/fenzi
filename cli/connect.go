package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"fenzi/agents"
	"fenzi/cli/internal/config"
	"fenzi/cli/internal/openshell"
	"fenzi/cli/internal/run"
	"fenzi/cli/internal/tui"
)

// splitDash separates the arguments before "--" from those after it.
func splitDash(args []string) ([]string, []string) {
	for i, a := range args {
		if a == "--" {
			return args[:i], args[i+1:]
		}
	}
	return args, nil
}

// running refreshes the state from the gateway and returns the running
// sandboxes Fenzi started, newest first.
func running(e env, dirs config.Dirs) ([]config.Sandbox, error) {
	names, err := client().Sandboxes(e.ctx)
	if err != nil {
		return nil, err
	}
	live := map[string]bool{}
	for _, n := range names {
		live[n] = true
	}
	s, err := dirs.LoadState()
	if err != nil {
		return nil, err
	}
	var out []config.Sandbox
	for i := range s.Sandboxes {
		s.Sandboxes[i].Running = live[s.Sandboxes[i].Name]
		if s.Sandboxes[i].Running {
			out = append(out, s.Sandboxes[i])
		}
	}
	_ = dirs.SaveState(s)
	sort.Slice(out, func(i, j int) bool { return out[i].Created.After(out[j].Created) })
	return out, nil
}

// chooseRunning picks a running sandbox: the one named, the newest for this
// folder, the only one, or one the person picks.
func chooseRunning(e env, u *tui.UI, dirs config.Dirs, name, purpose string) (config.Sandbox, error) {
	list, err := running(e, dirs)
	if err != nil {
		return config.Sandbox{}, err
	}
	if name != "" {
		for _, sb := range list {
			if sb.Name == name {
				return sb, nil
			}
		}
		return config.Sandbox{}, fmt.Errorf("%s is not running; fenzi ps lists the ones that are", name)
	}
	if len(list) == 0 {
		return config.Sandbox{}, errors.New("no sandbox is running. fenzi run starts one")
	}
	if dir, err := cwd(); err == nil {
		if sb, ok := (&config.State{Sandboxes: list}).LatestIn(dir, true); ok {
			return sb, nil
		}
	}
	if len(list) == 1 {
		return list[0], nil
	}
	if !u.Interactive() {
		return config.Sandbox{}, errors.New("several sandboxes are running; name one, fenzi ps lists them")
	}
	home := homeDir()
	opts := make([]tui.Option, len(list))
	for i, sb := range list {
		opts[i] = tui.Option{Label: sb.Name, Hint: dash(sb.Agent) + "  " + dash(tilde(sb.Repo, home)) + "  " + started(sb)}
	}
	i, err := u.Select(purpose, opts, 0)
	if err != nil {
		return config.Sandbox{}, err
	}
	return list[i], nil
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func started(sb config.Sandbox) string {
	if sb.Created.IsZero() {
		return "-"
	}
	return sb.Created.Local().Format("Jan 2 15:04")
}

func cmdConnect(e env, args []string) (int, error) {
	before, agentArgs := splitDash(args)
	fs := newFlags("connect", e.stderr)
	shell := fs.Bool("shell", false, "open a shell in the sandbox instead of the agent")
	fresh := fs.Bool("new", false, "start a new agent session instead of resuming the last one")
	pos, err := parse(fs, before)
	if err != nil {
		return 1, err
	}
	dirs, err := config.Default()
	if err != nil {
		return 1, err
	}
	u := tui.New(e.stdin, e.stdout)
	name := ""
	if len(pos) > 0 {
		name = pos[0]
	}
	// A sandbox in phase Error is listed but has nothing to connect to.
	if name != "" && isLost(e, name) {
		sayLost(u, name)
		return 1, nil
	}
	sb, err := chooseRunning(e, u, dirs, name, "Which sandbox?")
	if err != nil {
		return 1, err
	}
	return connectTo(e, u, sb, agentArgs, *shell, *fresh)
}

// isLost says whether the runtime lists name in phase Error. A list that
// fails says no: the caller goes on and reports what it finds.
func isLost(e env, name string) bool {
	lost, err := client().Lost(e.ctx)
	return err == nil && slices.Contains(lost, name)
}

// sayLost explains a sandbox whose container stopped, with the two ways
// out that fenzi ps names too.
func sayLost(u *tui.UI, name string) {
	u.Blank()
	u.Problem("Stopped", name+" is not running: its container stopped, as it does when the container runtime restarts. There is no agent in it to connect to.")
	u.Commands([2]string{"fenzi stop " + name, "start it again to bring its changes back, or delete it"}, [2]string{"fenzi rm " + name, "delete it and the files in it"})
	u.Blank()
}

// connectTo opens the agent, or a shell, in a running sandbox. The agent
// resumes its last session there unless fresh is set; when it has none to
// resume, a new one starts.
func connectTo(e env, u *tui.UI, sb config.Sandbox, agentArgs []string, shell, fresh bool) (int, error) {
	var argv []string
	envv := map[string]string{}
	what := "a shell"
	resumed := false
	if shell {
		argv = append([]string{"sh"}, agentArgs...)
	} else {
		a, err := agents.Get(sb.Agent)
		if err != nil {
			return 1, fmt.Errorf("%s was not started by fenzi run, so its agent is not known; use --shell", sb.Name)
		}
		// The MCP servers the sandbox was started with: their config files
		// are still in it, and their flags and variables go on again.
		if dirs, err := config.Default(); err == nil {
			if doc, err := run.LoadResolved(dirs.Run(sb.Name)); err == nil {
				if a, _, err = a.WithMCP(doc); err != nil {
					return 1, err
				}
			}
		}
		argv, envv, what = a.Argv(agentArgs), a.Env, a.Display
		if r := a.ResumeArgv(agentArgs); r != nil && !fresh {
			argv, resumed = resumeOrStart(r, argv, a.Display, a.ResumeWhen), true
		}
	}
	workdir := ""
	if sb.Repo != "" {
		workdir = run.ProjectDir(sb.Repo)
	}

	u.Blank()
	u.Println(fmt.Sprintf("  %s %s  %s", u.Accent("■"), u.Bold("Connecting to "+sb.Name), u.Dim(tilde(sb.Repo, homeDir()))))
	// In the Fenzi app (FENZI_APP set) the pane sits under the sandbox's
	// buttons, so the notes name those instead of commands.
	inApp := os.Getenv("FENZI_APP") != ""
	switch {
	case resumed && inApp:
		u.Note(what + " continues its last session here, with the same policy and files. The sandbox keeps running when you close this tab.")
	case resumed:
		u.Note(what + " continues its last session in the sandbox, with the same policy and the files as the agent left them. fenzi connect --new starts a new session. The sandbox keeps running when you exit.")
	case inApp:
		u.Note("This starts " + what + " in the sandbox, with the same policy and files. The sandbox keeps running when you close this tab.")
	default:
		u.Note("This starts " + what + " in the sandbox, with the same policy and the files as the agent left them. The sandbox keeps running when you exit.")
	}
	u.Blank()
	// The same background forwarding as fenzi run, for a team sandbox.
	stopForward := forwardWhile(e, sb.TeamRevision)
	err := client().Exec(e.ctx, sb.Name, workdir, envv, argv...)
	if !stopForward() {
		u.Note("The team console was not reached during this session. Run fenzi forward to send what is queued.")
	}
	code := openshell.ExitCode(err)
	// The sandbox can stop while the session runs, or between the list
	// and the exec: the runtime then refuses the exec (0.1.4: "sandbox
	// '<name>' is not ready (phase: Error)"). Say so instead of "Still
	// running".
	if err != nil && isLost(e, sb.Name) {
		sayLost(u, sb.Name)
		return 1, nil
	}
	if code < 0 && err != nil {
		return 1, err
	}
	u.Blank()
	if inApp {
		u.Skip("Still running", sb.Name+". Resume opens it again; Stop ends it and brings its changes back.")
		return max(code, 0), nil
	}
	u.Skip("Still running", sb.Name)
	u.Commands([2]string{"fenzi connect " + sb.Name, "come back to it"}, [2]string{"fenzi stop " + sb.Name, "end it and review the changes"})
	return max(code, 0), nil
}

// resumeOrStart runs resume in the sandbox's shell, or start when there is
// nothing to resume. With when (the agent's resume_when test), it asks
// first: no session there means a new one at once. Without it, or when the
// test passes, a resume that fails within resumeGrace seconds starts a new
// session too. An agent with no session to resume exits with an error
// (grok 1.0.46: "No session found for current directory", exit 1; claude
// 2.1.288: "No conversation found to continue", exit 1); a session the
// person used and left exits much later, and its exit code is kept.
func resumeOrStart(resume, start []string, display, when string) []string {
	fresh := "echo " + shellQuote("No "+display+" session to resume here yet; starting a new one.") + "; exec " + shellJoin(start)
	try := "t0=$(date +%s); " + shellJoin(resume) + "; c=$?; " +
		"if [ $c -ne 0 ] && [ $(( $(date +%s) - t0 )) -lt " + resumeGrace + " ]; then echo; " + fresh + "; fi; exit $c"
	if when == "" {
		return []string{"sh", "-c", try}
	}
	return []string{"sh", "-c", "if " + when + "; then " + try + "; else " + fresh + "; fi"}
}

// resumeGrace is how many seconds count as failing at once. A first start
// in a new sandbox was seen to take more than 5 before giving up.
const resumeGrace = "20"

func shellJoin(argv []string) string {
	q := make([]string, len(argv))
	for i, a := range argv {
		q[i] = shellQuote(a)
	}
	return strings.Join(q, " ")
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// runningFor is the newest running sandbox started from repo with agent.
func runningFor(e env, dirs config.Dirs, repo, agent string) (config.Sandbox, bool) {
	list, err := running(e, dirs)
	if err != nil {
		return config.Sandbox{}, false
	}
	for _, sb := range list {
		if sb.Agent == agent && sb.Repo != "" && filepath.Clean(sb.Repo) == filepath.Clean(repo) {
			return sb, true
		}
	}
	return config.Sandbox{}, false
}
