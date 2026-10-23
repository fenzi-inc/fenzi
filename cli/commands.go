package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"fenzi/agents"
	"fenzi/cli/internal/config"
	"fenzi/cli/internal/engine"
	"fenzi/cli/internal/forward"
	"fenzi/cli/internal/openshell"
	"fenzi/cli/internal/run"
	"fenzi/cli/internal/screen"
	"fenzi/cli/internal/team"
	"fenzi/cli/internal/tui"
	"fenzi/cli/internal/workspace"
	"fenzi/compiler"
	"fenzi/policies"
)

func client() openshell.Client { return newClient() }

// newClient makes the gateway client; tests replace it with a fake.
var newClient = func() openshell.Client { return openshell.Client{R: openshell.Exec{Bin: "openshell"}} }

func prover() openshell.Prover { return openshell.Prover{R: openshell.Exec{Bin: "openshell-prover"}} }

// imageBuilder picks docker or podman to match the gateway's compute driver:
// the one the connected gateway names, else compute_driver in the local
// gateway config. When neither says, docker comes first, then podman.
func imageBuilder(e env, out io.Writer) (engine.Builder, error) {
	driver := ""
	if drivers, err := client().ComputeDrivers(e.ctx); err == nil {
		driver = engine.Driver(drivers)
	}
	if driver == "" {
		driver = engine.Driver([]string{openshell.ConfiguredDriver()})
	}
	return engine.DetectFor(out, driver)
}

func cmdDoctor(e env, args []string) (int, error) {
	fs := newFlags("doctor", e.stderr)
	fix := fs.Bool("fix", false, "remove gateway-wide settings that weaken or block Fenzi")
	asJSON := jsonFlag(fs)
	if _, err := parse(fs, args); err != nil {
		return 1, err
	}
	failed := false
	u := tui.New(e.stdin, e.stdout)
	if !*asJSON {
		u.Title("Checking this machine", "")
	}
	checks := []jsonCheck{}
	line := func(status, check, detail string) {
		switch status {
		case "FAIL":
			failed = true
			checks = append(checks, jsonCheck{check, "fail", detail})
			if !*asJSON {
				u.Problem(check, detail)
			}
		case "ok":
			checks = append(checks, jsonCheck{check, "ok", detail})
			if !*asJSON {
				u.Done(check, detail)
			}
		default:
			checks = append(checks, jsonCheck{check, "skip", detail})
			if !*asJSON {
				u.Skip(check, detail)
			}
		}
	}
	// changing says what --fix is about to change, before it changes it. With
	// --json it goes to standard error, so standard output stays one document.
	changing := func(what string) {
		if *asJSON {
			fmt.Fprintln(e.stderr, "fenzi doctor --fix: "+what)
			return
		}
		u.Note("Changing: " + what)
	}
	oc := client()
	if !openshell.Installed("openshell") {
		line("FAIL", "Runtime", fmt.Sprintf("OpenShell %s is not installed. The packages are on https://fenzi.dev/docs/install", openshell.Pinned))
	} else {
		out, err := oc.Version(e.ctx)
		if v, ok := openshell.Pinned.Contains(out); err == nil && ok {
			// An older patch still works, so it is a note, not a failure.
			if _, behind := openshell.Behind(out); behind {
				v += ", older than " + openshell.InstallVersion + ". Upstream fixes only the newest patch; run fenzi setup to upgrade. " + restartWarning(e.ctx, oc)
			}
			line("ok", "Runtime", v)
		} else {
			line("FAIL", "Runtime", fmt.Sprintf("%q is outside %s. Install a release from that line.", strings.TrimSpace(out), openshell.Pinned))
		}
		if err := oc.Ready(e.ctx); err != nil {
			msg := err.Error()
			if d := openshell.Diagnose(); d.None || d.Orphan || (len(d.Running) == 0 && len(d.Stopped) > 0) {
				msg = d.Summary() + " Run fenzi setup to fix it."
			}
			line("FAIL", "Gateway", msg)
		} else {
			line("ok", "Gateway", "connected")
		}
		if drivers, err := oc.ComputeDrivers(e.ctx); err != nil || len(drivers) == 0 {
			line("FAIL", "Sandbox driver", fmt.Sprintf("none reported (%v)", err))
		} else {
			line("ok", "Sandbox driver", strings.Join(drivers, ", "))
		}
		switch mode, err := oc.GlobalSetting(e.ctx, "proposal_approval_mode"); {
		case err != nil:
			line("FAIL", "Approvals", err.Error())
		case mode == "auto" && *fix:
			changing("removing the gateway-wide proposal_approval_mode (auto), so a person approves each request.")
			if err := oc.GlobalSettingDelete(e.ctx, "proposal_approval_mode"); err != nil {
				line("FAIL", "Approvals", "could not turn off automatic approval: "+err.Error())
			} else {
				line("ok", "Approvals", "fixed: a person approves each request")
			}
		case mode == "auto":
			line("FAIL", "Approvals", "requests are approved with no person. Run fenzi doctor --fix to turn that off")
		case mode == "" || mode == openshell.Unset:
			line("ok", "Approvals", "a person approves each request")
		default:
			line("ok", "Approvals", mode)
		}
		switch bad, err := run.SettingConflicts(e.ctx, oc); {
		case err != nil:
			line("FAIL", "Log and requests", err.Error())
		case len(bad) == 0:
			line("ok", "Log and requests", "can be turned on")
		default:
			keys := make([]string, 0, len(bad))
			for k := range bad {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				if !*fix {
					line("FAIL", "Log and requests", fmt.Sprintf("the gateway sets %s to %s for every sandbox, so fenzi run cannot turn it on. Run fenzi doctor --fix to remove it", k, bad[k]))
					continue
				}
				changing(fmt.Sprintf("removing the gateway-wide %s (%s), so fenzi run can turn it on for each sandbox.", k, bad[k]))
				if oc.GlobalSettingDelete(e.ctx, k) != nil {
					line("FAIL", "Log and requests", "could not remove the gateway-wide "+k)
				} else {
					line("ok", "Log and requests", "fixed: removed the gateway-wide "+k)
				}
			}
		}
		line("ok", "Bad policy", failureMode())
		doctorDNS(e, oc, line)
	}
	if openshell.Installed("openshell-prover") {
		line("ok", "Policy check", "installed")
	} else {
		line("FAIL", "Policy check", "missing. It ships with the runtime's Homebrew, Debian, and RPM packages")
	}
	if b, err := imageBuilder(e, e.stdout); err != nil {
		line("FAIL", "Image builds", err.Error())
	} else {
		line("ok", "Image builds", b.Bin+" is available")
	}
	reportAccount(e, line)
	if *asJSON {
		if err := writeJSON(e.stdout, jsonDoctor{Checks: checks, Ready: !failed}); err != nil {
			return 1, err
		}
		if failed {
			return 3, nil
		}
		return 0, nil
	}
	u.Blank()
	if failed {
		u.Println("  " + u.Bold("Some checks need you.") + " " + u.Dim("Each ! line says what to change."))
		u.Commands([2]string{"fenzi setup", "fixes most of them for you"}, [2]string{"fenzi doctor", "checks again"})
		u.Note("Help for each line: https://fenzi.dev/docs/troubleshooting#doctor")
		u.Blank()
		return 3, nil
	}
	u.Println("  " + u.Bold("This machine is ready."))
	if _, ok := configDirs(e).LoadSetup(); ok {
		u.Command("fenzi run", "start the agent in this folder")
	} else {
		u.Command("fenzi setup", "choose an agent, store its key, pick a folder")
	}
	u.Blank()
	return 0, nil
}

var failureModeLine = regexp.MustCompile(`(?m)^\s*policy_validation_failure_mode\s*=\s*"([a-z_]+)"`)

// failureMode reports policy_validation_failure_mode for a local gateway. It
// lives in gateway.toml, not in gateway settings, and defaults to fail_closed.
// The paths are the documented Homebrew and Linux package locations.
func failureMode() string {
	home, _ := os.UserHomeDir()
	paths := []string{filepath.Join(home, ".config", "openshell", "gateway.toml")}
	if x := os.Getenv("XDG_CONFIG_HOME"); x != "" {
		paths = append([]string{filepath.Join(x, "openshell", "gateway.toml")}, paths...)
	}
	paths = append(paths, "/opt/homebrew/var/openshell/gateway.toml")
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		if m := failureModeLine.FindSubmatch(b); m != nil {
			mode := string(m[1])
			if mode == "fail_closed" {
				return "a bad policy is refused"
			}
			return mode + ", from " + p
		}
		return "a bad policy is refused"
	}
	return "a bad policy is refused"
}

const initTemplate = `# Fenzi project policy. Merged over developer-default on the Free plan.
# Reference: https://fenzi.dev/docs/policy
version: 1

# Hosts this project needs beyond developer-default.
hosts:
#  - host: api.stripe.com
#    access: read-only
#  - host: api.github.com
#    access: read-write
#    allow:
#      - GET /repos/acme/web/**
#      - POST /repos/acme/web/pulls

# Extra paths inside the sandbox. Changing these needs a new sandbox.
# paths:
#   read_only: [/opt/fixtures]
`

func cmdInit(e env, args []string) (int, error) {
	fs := newFlags("init", e.stderr)
	if _, err := parse(fs, args); err != nil {
		return 1, err
	}
	dir, err := cwd()
	if err != nil {
		return 1, err
	}
	path := filepath.Join(dir, run.ProjectFile)
	if _, err := os.Stat(path); err == nil {
		return 1, fmt.Errorf("%s already exists here; edit it, or delete it to start over", run.ProjectFile)
	}
	if err := os.WriteFile(path, []byte(initTemplate), 0o644); err != nil {
		return 1, err
	}
	u := tui.New(e.stdin, e.stdout)
	u.Blank()
	u.Done("Wrote", run.ProjectFile)
	u.Note("Every line is commented out, so nothing changes until you uncomment one. The next fenzi run in this folder uses it.")
	u.Command("fenzi policy check", "see that it stays inside developer-default")
	u.Blank()
	return 0, nil
}

func cmdRun(e env, args []string) (int, error) {
	fs := newFlags("run", e.stderr)
	keep := fs.Bool("keep", false, "keep the sandbox when the agent exits (the default)")
	remove := fs.Bool("rm", false, "delete the sandbox when the agent exits, after the review of its changes")
	fresh := fs.Bool("new", false, "start a new sandbox even when one for this folder and agent is still running")
	name := fs.String("name", "", "sandbox name, at most 19 characters (default fenzi-<folder>-<id>)")
	policyFile := fs.String("policy", "", "policy file to use instead of ./fenzi.yaml")
	noUpload := fs.Bool("no-upload", false, "start with an empty working folder")
	allowSecrets := fs.Bool("allow-secrets", false, "copy files that look like secrets without asking; the warning is still printed")
	signIn := fs.Bool("sign-in", false, "start without the stored key, so the agent signs in itself: Claude Code with your Claude subscription")
	headless := fs.Bool("headless", false, "run unattended: the agent's own non-interactive mode on --task or --task-text, no terminal, a time limit, a summary")
	taskFile := fs.String("task", "", "with --headless: file that holds the task, - for standard input")
	taskText := fs.String("task-text", "", "with --headless: the task itself")
	timeout := fs.Duration("timeout", 30*time.Minute, "with --headless: time limit for the whole run, 0 for none")
	requestTimeout := fs.Duration("request-timeout", 0, "with --headless: how long a request the agent files waits for a reviewer before it stays refused (default: until the time limit)")
	outDir := fs.String("out", "", "with --headless: folder for summary.json, summary.md and branch.bundle")
	if err := fs.Parse(args); err != nil {
		return 1, err
	}
	if flag := runFlagAfterAgent(fs.Args()); flag != "" {
		agent := fs.Args()[0]
		return 1, fmt.Errorf("%s is a flag of fenzi run, and everything after the agent's name goes to the agent. Put it before the name: fenzi run %s ... %s. To pass it to the agent anyway, write %s -- %s", flag, flag, agent, agent, flag)
	}
	rest := runArgs(fs.Args())
	var unattended *run.Headless
	if *headless {
		task, err := readTask(e, *taskFile, *taskText)
		if err != nil {
			return 1, err
		}
		if *signIn {
			return 1, errors.New("--headless runs with a key; signing in takes a person at a browser. Drop --sign-in")
		}
		if *timeout < 0 || *requestTimeout < 0 {
			return 1, errors.New("--timeout and --request-timeout cannot be negative")
		}
		unattended = &run.Headless{Task: task, Timeout: *timeout, RequestTimeout: *requestTimeout}
	} else if *taskFile != "" || *taskText != "" || *outDir != "" || *requestTimeout != 0 || *timeout != 30*time.Minute {
		return 1, errors.New("--task, --task-text, --timeout, --request-timeout and --out go with --headless")
	}
	// The folder is checked before anything else, so a run from the home
	// folder never reaches the gateway.
	repo, err := cwd()
	if err != nil {
		return 1, err
	}
	if err := workspace.CheckFolder(repo, homeDir()); err != nil {
		return 1, fmt.Errorf("fenzi run copies the folder it starts in, and %v. cd into one project folder first", err)
	}
	entry, err := agents.Get(rest[0])
	if err != nil {
		return 1, err
	}
	if unattended != nil {
		if err := entry.CanRunHeadless(); err != nil {
			return 1, err
		}
	}
	if *signIn && !entry.CanSignIn() {
		return 1, fmt.Errorf("%s does not sign in itself; it runs with a key. Drop --sign-in", entry.Display)
	}
	profile, err := entry.Profile()
	if err != nil {
		return 1, err
	}
	dirs, err := config.Default()
	if err != nil {
		return 1, err
	}
	resolved, err := resolvePolicy(e, dirs, repo, *policyFile)
	if err != nil {
		return 1, err
	}
	u := tui.New(e.stdin, e.stdout)
	// A sandbox already running for this folder and agent holds the agent's
	// session; going back to it keeps the conversation.
	if !*fresh && *name == "" && *policyFile == "" && unattended == nil && u.Interactive() {
		// With --sign-in, only a sandbox that was started without the key.
		if sb, ok := runningFor(e, dirs, repo, entry.Name); ok && (!*signIn || sb.SignIn) {
			u.Title(sb.Name+" is still running", tilde(repo, homeDir()))
			i, err := u.Select("Go back to it?", []tui.Option{
				{Label: "Resume " + sb.Name, Hint: entry.Display + " continues its last session there, with the files as it left them"},
				{Label: "Start a new sandbox", Hint: "copies this folder again; fenzi run --new skips this question"},
			}, 0)
			if errors.Is(err, tui.ErrCancelled) {
				return 1, nil
			}
			if err != nil {
				return 1, err
			}
			if i == 0 {
				return connectTo(e, u, sb, rest[1:], false, false)
			}
		}
	}
	images, err := imageBuilder(e, e.stdout)
	if err != nil {
		return 1, err
	}
	var confirmSecrets func([]string) (bool, error)
	if !*allowSecrets && unattended == nil && u.Interactive() {
		confirmSecrets = func([]string) (bool, error) {
			i, err := u.Select("Copy them into the sandbox?", []tui.Option{
				{Label: "No, stop here", Hint: "nothing is created; add them to .gitignore, then run again"},
				{Label: "Yes, copy them", Hint: "fenzi run --allow-secrets skips this question"},
			}, 0)
			if errors.Is(err, tui.ErrCancelled) {
				return false, nil
			}
			return i == 1, err
		}
	}
	reviewed := false
	// On a machine signed in to a team, requests and decisions reach the
	// console while the agent runs, without the Mac app or fenzi forward.
	stopForward := forwardWhile(e, resolved.TeamRevision)
	forwarded := false
	finishForward := func() {
		if !forwarded {
			forwarded = true
			if !stopForward() {
				u.Note("The team console was not reached during this run. Run fenzi forward to send what is queued.")
			}
		}
	}
	defer finishForward()
	onExit := func(sandbox string) (bool, error) {
		// The agent has exited: send its last decisions and requests before
		// the questions, while the sandbox still exists.
		finishForward()
		if u.Interactive() {
			u.Title(entry.Display+" exited", sandbox)
			if sb, base, files, changes, err := staged(e, sandbox); err == nil && len(changes) > 0 {
				reviewed = true
				if _, err := newReview(sb, base, files, changes, "").offer(e); err != nil {
					return true, err
				}
				u.Blank()
			}
		}
		// The sandbox stays by default: it holds the agent's session, its
		// files, and the approvals from this run.
		return !*remove, nil
	}
	if unattended != nil {
		// Nobody reviews at the end, and the sandbox goes unless --keep:
		// the commits are back as a branch, the files are staged.
		onExit = func(string) (bool, error) {
			finishForward()
			return false, nil
		}
	}
	res, err := run.Run(e.ctx, run.Deps{
		OpenShell: client(),
		Prover:    prover(),
		Images:    images,
		Dirs:      dirs,
		Out:       e.stdout,
		Getenv:    os.Getenv,
		Now:       time.Now,
		Filter:    workspace.GitFilter,
	}, run.Options{
		Agent: entry, Profile: profile, Args: rest[1:], Repo: repo, Policy: resolved,
		Name: *name, Keep: *keep, NoUpload: *noUpload, SignIn: *signIn, ConfirmSecrets: confirmSecrets,
		OnExit: onExit, Headless: unattended,
	})
	if errors.Is(err, run.ErrSecretsDeclined) {
		u.Blank()
		u.Skip("Stopped", "nothing was created")
		u.Note("Add those files to .gitignore, or move them out of this folder, then run fenzi run again.")
		u.Blank()
		return 1, nil
	}
	if err != nil {
		return 1, err
	}
	if unattended != nil {
		return finishHeadless(e, repo, *outDir, res)
	}
	if res.StoppedElsewhere {
		// The window that stopped it shows the changes; this one points at them.
		if len(res.Changes) > 0 {
			u.Note("The changes came back before the sandbox was deleted. From " + tilde(repo, homeDir()) + ":")
			flag := sandboxFlag(res.Sandbox)
			u.Commands([2]string{"fenzi diff" + flag, "see them"}, [2]string{"fenzi apply" + flag, "apply them"})
			u.Blank()
		}
		return 0, nil
	}
	if res.Kept {
		u.Note("The sandbox keeps " + entry.Display + "'s session, its files and the approvals from this run. fenzi run --rm deletes it when the agent exits.")
		u.Commands(
			[2]string{"fenzi connect " + res.Sandbox, "resume " + entry.Display + " where it stopped"},
			[2]string{"fenzi stop " + res.Sandbox, "end it and bring the changes back"},
		)
		u.Blank()
	}
	if len(res.Changes) > 0 && !reviewed {
		if sb, base, files, changes, err := staged(e, res.Sandbox); err == nil && len(changes) > 0 {
			if _, err := newReview(sb, base, files, changes, "").offer(e); err != nil {
				return 1, err
			}
		}
	}
	return res.ExitCode, nil
}

// runArgs puts the agent first: `run`, `run claude`, `run -- claude --resume`,
// `run claude -- --resume`, and `run -- --resume` all work. Without a name it
// is the agent setup chose.
// runOnlyFlags are fenzi run's own flags that no supported agent takes, so
// one written after the agent's name is a mistake, not an agent argument.
var runOnlyFlags = map[string]bool{"headless": true, "task-text": true, "request-timeout": true, "no-upload": true, "allow-secrets": true, "sign-in": true, "rm": true}

// runFlagAfterAgent returns the first of runOnlyFlags written after the
// agent's name and before any --, or "" when there is none.
func runFlagAfterAgent(rest []string) string {
	if len(rest) < 2 || strings.HasPrefix(rest[0], "-") {
		return ""
	}
	for _, a := range rest[1:] {
		if a == "--" {
			return ""
		}
		if !strings.HasPrefix(a, "-") {
			continue
		}
		name := strings.TrimLeft(a, "-")
		if i := strings.IndexByte(name, '='); i >= 0 {
			name = name[:i]
		}
		if runOnlyFlags[name] {
			return "--" + name
		}
	}
	return ""
}

func runArgs(rest []string) []string {
	if len(rest) == 0 || strings.HasPrefix(rest[0], "-") {
		rest = append([]string{defaultAgent()}, rest...)
	}
	if len(rest) > 1 && rest[1] == "--" {
		rest = append(rest[:1:1], rest[2:]...)
	}
	return rest
}

// refusedTool is a tool on a listed MCP server that the sandbox refused,
// with how often.
type refusedTool struct {
	Server, Tool string
	Times        int
}

// refusedMCPTools reads the sandbox's recent decisions for tool calls the
// policy refused, and names each one's server from the rule that refused
// it (compiler.MCPRuleKey). A rule fenzi did not write is left out.
func refusedMCPTools(e env, dirs config.Dirs, sb config.Sandbox) []refusedTool {
	doc, err := run.LoadResolved(dirs.Run(sb.Name))
	if err != nil || doc == nil || len(doc.MCP) == 0 {
		return nil
	}
	servers := map[string]string{}
	for name := range doc.MCP {
		servers[compiler.MCPRuleKey(name)] = name
	}
	log, err := client().LogLines(e.ctx, sb.Name, openshell.RequestLogWindow)
	if err != nil {
		return nil
	}
	var out []refusedTool
	at := map[[2]string]int{}
	for _, line := range strings.Split(string(log), "\n") {
		r, ok := forward.FromShorthand(line, sb.Name)
		if !ok || !r.Denied() || r.MCPTool == "" {
			continue
		}
		server := servers[r.Rule]
		if server == "" {
			continue
		}
		key := [2]string{server, r.MCPTool}
		if i, seen := at[key]; seen {
			out[i].Times++
			continue
		}
		at[key] = len(out)
		out = append(out, refusedTool{Server: server, Tool: r.MCPTool, Times: 1})
	}
	return out
}

// showRefusedMCP lists the refused tools and how to allow each.
func showRefusedMCP(u *tui.UI, tools []refusedTool) {
	if len(tools) == 0 {
		return
	}
	u.Title(plural(len(tools), "MCP tool the policy refused", "MCP tools the policy refused"), "not requests: the agent cannot ask for these")
	var hints [][2]string
	for _, t := range tools {
		times := ""
		if t.Times > 1 {
			times = fmt.Sprintf(", %d times", t.Times)
		}
		u.Problem(t.Tool, "on "+t.Server+times+": not in the server's list")
		hints = append(hints, [2]string{"fenzi mcp allow " + t.Server + " " + t.Tool, "let agents call it, from the next fenzi run"})
	}
	u.Blank()
	u.Commands(hints...)
	u.Blank()
}

func cmdRequests(e env, args []string) (int, error) {
	fs := newFlags("requests", e.stderr)
	sandbox := fs.String("sandbox", "", "sandbox name (default: the latest running one for this folder)")
	all := fs.Bool("all", false, "also list the drafts the sandbox made from refused connections")
	asJSON := jsonFlag(fs)
	if _, err := parse(fs, args); err != nil {
		return 1, err
	}
	dirs, err := config.Default()
	if err != nil {
		return 1, err
	}
	u := tui.New(e.stdin, e.stdout)
	var sb config.Sandbox
	if *sandbox == "" {
		sb, err = chooseRunning(e, u, dirs, "", "Requests from which sandbox?")
	} else {
		sb, err = pickSandbox(e, dirs, *sandbox, true)
	}
	if err != nil {
		return 1, err
	}
	out, err := client().PendingRules(e.ctx, sb.Name)
	if err != nil {
		return 1, err
	}
	// Refused MCP tools are not requests: an agent cannot ask for one, so
	// they are listed after the requests with the command that allows them.
	if !*asJSON {
		defer showRefusedMCP(u, refusedMCPTools(e, dirs, sb))
	}
	list := openshell.ParseRules(out)
	if len(list) == 0 {
		if strings.Contains(string(out), "Chunk") {
			if *asJSON {
				return 1, errors.New("the runtime listed requests in a form this release does not read; run fenzi requests without --json")
			}
			// The text format changed; show it rather than hide requests.
			e.stdout.Write(out)
			return 0, nil
		}
		if *asJSON {
			return 0, writeJSON(e.stdout, []jsonRequest{})
		}
		u.Blank()
		u.Done("No requests", "waiting in "+sb.Name)
		u.Note("When the agent asks for more access, the request shows up here.")
		u.Blank()
		return 0, nil
	}
	var filed map[string]bool
	if log, err := client().LogLines(e.ctx, sb.Name, openshell.RequestLogWindow); err == nil {
		filed = openshell.AgentFiled(log)
	}
	var asked, drafts []openshell.Proposal
	for _, p := range list {
		if !p.IsDraft(filed) {
			asked = append(asked, p)
		} else {
			drafts = append(drafts, p)
		}
	}
	shown := asked
	if *all {
		shown = append(append([]openshell.Proposal(nil), asked...), drafts...)
	}
	if *asJSON {
		docs := make([]jsonRequest, 0, len(shown))
		for i, p := range shown {
			docs = append(docs, requestJSON(p, i >= len(asked)))
		}
		return 0, writeJSON(e.stdout, docs)
	}
	flag := ""
	if *sandbox != "" {
		flag = " --sandbox " + sb.Name
	}
	hidden := len(drafts) > 0 && !*all
	allHint := [2]string{"fenzi requests --all" + flag, "list the drafts too"}
	draftNote := func() {
		if hidden {
			u.Note(plural(len(drafts), "more was", "more were") + " drafted by the sandbox from refused connections, not asked for by the agent: " + destinations(drafts) + ".")
			u.Blank()
		}
	}
	if len(shown) == 0 {
		u.Blank()
		u.Done("No requests from the agent", "waiting in "+sb.Name)
		draftNote()
		u.Commands(allHint)
		u.Blank()
		return 0, nil
	}
	if len(asked) > 0 {
		u.Title(plural(len(asked), "request from the agent", "requests from the agent"), sb.Name)
		for _, p := range asked {
			showRequest(u, p)
		}
	}
	if *all && len(drafts) > 0 {
		u.Title(plural(len(drafts), "draft from refused connections", "drafts from refused connections"), sb.Name)
		u.Note("The sandbox wrote these when a connection was refused. The agent did not ask for them.")
		u.Blank()
		for _, p := range drafts {
			showRequest(u, p)
		}
	}
	draftNote()
	list = shown
	// On the Free plan the first answer keeps the approval in fenzi.yaml, so
	// the next sandbox in this folder does not ask again. On a team the
	// policy is the team's, and an admin adds the host in the console.
	_, enrolled := team.Load(dirs)
	canSave := errors.Is(enrolled, team.ErrNotEnrolled)
	if !u.Interactive() {
		hints := [][2]string{{"fenzi approve <id>" + flag, "let it through"}, {`fenzi deny <id> --reason "..."` + flag, "refuse; the agent sees the reason"}}
		if canSave {
			hints = append([][2]string{{"fenzi approve <id> --save" + flag, "let it through, and keep it in " + run.ProjectFile + " for the next sandbox here"}, {"fenzi approve <id>" + flag, "let it through for this sandbox only"}}, hints[1:]...)
		}
		if hidden {
			hints = append(hints, allHint)
		}
		u.Commands(hints...)
		u.Blank()
		return 0, nil
	}
	if hidden {
		u.Commands(allHint)
	}
	for _, p := range list {
		id := shortID(p.Chunk)
		for {
			u.Blank()
			options := []tui.Option{
				{Label: "Approve", Hint: "the agent can retry in about 10 seconds"},
				{Label: "Deny", Hint: "you give a reason; the agent sees it"},
				{Label: "Decide later"},
			}
			// save is the option that also writes fenzi.yaml, first when offered.
			save := -1
			if canSave && !p.MCP() {
				save = 0
				options = append([]tui.Option{
					{Label: "Approve and save", Hint: "also in " + run.ProjectFile + ", so the next sandbox here has it"},
					{Label: "Approve once", Hint: "this sandbox only"},
				}, options[1:]...)
			}
			i, err := u.Select(id+"  "+p.Destination(), options, 0)
			if errors.Is(err, tui.ErrCancelled) {
				return 0, nil
			}
			if err != nil {
				return 1, err
			}
			if save == 0 {
				// Shift so the rest reads as without the save option.
				if i == 0 {
					repo, file, host, err := prepareSave(sb, p)
					if err != nil {
						u.Problem("Not approved", id+" "+p.Destination())
						u.Note(err.Error())
						continue
					}
					if err := approveOne(e, u, sb, p); err != nil {
						return 1, err
					}
					// A failed check is printed with the save; the next
					// request is still asked.
					var failed *run.PolicyError
					if _, err := saveApproved(e, u, sb, repo, file, host); err != nil && !errors.As(err, &failed) {
						return 1, err
					}
					break
				}
				i--
			}
			if i == 0 {
				if err := checkTeamBoundary(sb, p.Destination()); err != nil {
					u.Problem("Not approved", id+" "+p.Destination())
					u.Note(err.Error())
					break
				}
				if err := approveOne(e, u, sb, p); err != nil {
					return 1, err
				}
			} else if i == 1 {
				reason, err := u.Ask("Why? The agent sees this.", "", true)
				if errors.Is(err, tui.ErrBack) || (err == nil && strings.TrimSpace(reason) == "") {
					continue
				}
				if errors.Is(err, tui.ErrCancelled) {
					return 0, nil
				}
				if err != nil {
					return 1, err
				}
				if err := denyOne(e, u, sb, p.Chunk, reason); err != nil {
					return 1, err
				}
			} else {
				u.Skip("Later", id+" is still waiting")
			}
			break
		}
	}
	u.Blank()
	return 0, nil
}

func shortID(id string) string { return id[:min(8, len(id))] }

// destinations names the hosts of a few requests, for a one-line summary.
func destinations(list []openshell.Proposal) string {
	var hosts []string
	seen := map[string]bool{}
	for _, p := range list {
		d := p.Destination()
		if d == "" || seen[d] {
			continue
		}
		seen[d] = true
		hosts = append(hosts, d)
	}
	if len(hosts) > 3 {
		hosts = append(hosts[:3], fmt.Sprintf("%d others", len(hosts)-3))
	}
	return strings.Join(hosts, ", ")
}

func showRequest(u *tui.UI, p openshell.Proposal) {
	u.Println(fmt.Sprintf("    %s  %s", u.Bold(shortID(p.Chunk)), p.Destination()))
	var detail []string
	if p.Binary != "" {
		detail = append(detail, p.Binary)
	}
	if p.Rationale != "" {
		detail = append(detail, "“"+p.Rationale+"”")
	}
	if len(detail) > 0 {
		u.Println("              " + u.Dim(strings.Join(detail, "  ")))
	}
	u.Blank()
}

// approvedNote is what approve says after the runtime took the approval.
const approvedNote = "The sandbox loads it on its next poll, about 10 seconds. The agent can retry then."

func deniedNote(reason string) string { return "The agent sees: " + reason }

// errMCPApproval is approve's answer to an MCP request.
func errMCPApproval(p openshell.Proposal, sandbox string) error {
	if p.Connectors() {
		return fmt.Errorf("This request is for Claude's account connectors, which Fenzi allows per tool and not as a host. Add the tools the agent needs (fenzi mcp add claude-ai --claude-account --tool <tool>) and start a new run, or deny the request: fenzi deny %s --sandbox %s --reason \"...\"", shortID(p.Chunk), sandbox)
	}
	return fmt.Errorf("%s. Add the tool the agent needs to the server's entry (fenzi mcp add <name> <url> --tool <tool>) and start a new run, or deny the request: fenzi deny %s --sandbox %s --reason \"...\"", openshell.MCPApprovalRefused, shortID(p.Chunk), sandbox)
}

func approveOne(e env, u *tui.UI, sb config.Sandbox, p openshell.Proposal) error {
	id := p.Chunk
	if p.MCP() {
		return errMCPApproval(p, sb.Name)
	}
	if err := client().RuleApprove(e.ctx, sb.Name, id); err != nil {
		return err
	}
	u.Println(fmt.Sprintf("  %s %s %s in %s", u.Allow("✓"), u.Allow(fmt.Sprintf("%-*s", tui.LabelWidth, "Approved")), shortID(id), sb.Name))
	u.Note(approvedNote)
	if dirs, err := config.Default(); err == nil {
		r := sameKind(e, dirs, sb, p)
		if line := r.line(p.Destination()); line != "" {
			u.Note(line)
		} else if r.Skipped != "" {
			u.Note(r.Skipped + ".")
		}
	}
	return nil
}

func denyOne(e env, u *tui.UI, sb config.Sandbox, id, reason string) error {
	if err := client().RuleReject(e.ctx, sb.Name, id, reason); err != nil {
		return err
	}
	u.Denied("Denied", shortID(id)+" in "+sb.Name)
	u.Note(deniedNote(reason))
	return nil
}

// chunk expands a request id prefix against the sandbox's pending requests.
func chunk(e env, sandbox, prefix string) (string, error) {
	p, err := pending(e, sandbox, prefix)
	return p.Chunk, err
}

func cmdApprove(e env, args []string) (int, error) {
	fs := newFlags("approve", e.stderr)
	sandbox := fs.String("sandbox", "", "sandbox name (default: the latest running one for this folder)")
	save := fs.Bool("save", false, "also add the host to the project's fenzi.yaml, so the next sandbox there has it (Free plan)")
	dryRun := fs.Bool("dry-run", false, "with --save: show the change to fenzi.yaml and its policy check; approve nothing, write nothing")
	policyFrom := fs.String("policy-from", "", "with --save: use this file as the new fenzi.yaml. It is checked first; when the check fails, nothing is approved or written")
	asJSON := jsonFlag(fs)
	pos, err := parse(fs, args)
	if err != nil {
		return 1, err
	}
	if len(pos) != 1 {
		return 1, errors.New("name the request: fenzi approve <id>. fenzi requests lists them and can approve them for you")
	}
	switch {
	case *dryRun && !*save:
		return 1, errors.New("--dry-run previews --save: fenzi approve <id> --save --dry-run")
	case *policyFrom != "" && !*save:
		return 1, errors.New("--policy-from goes with --save: fenzi approve <id> --save --policy-from <file>")
	case *save && *asJSON && !*dryRun:
		return 1, errors.New("--save prints what it wrote and the policy check; drop --json, or add --dry-run for the preview as JSON")
	}
	dirs, err := config.Default()
	if err != nil {
		return 1, err
	}
	if *save {
		if err := refuseTeamSave(e, dirs, *sandbox, pos[0]); err != nil {
			return 1, err
		}
	}
	sb, err := pickSandbox(e, dirs, *sandbox, true)
	if err != nil {
		return 1, err
	}
	p, err := pending(e, sb.Name, pos[0])
	if err != nil {
		return 1, err
	}
	id := p.Chunk
	if p.MCP() {
		return 1, errMCPApproval(p, sb.Name)
	}
	if err := checkTeamBoundary(sb, p.Destination()); err != nil {
		return 1, err
	}
	if *save && (*dryRun || *policyFrom != "") {
		return approveFromPreview(e, sb, p, *policyFrom, *dryRun, *asJSON)
	}
	if *asJSON {
		if err := client().RuleApprove(e.ctx, sb.Name, id); err != nil {
			return 1, err
		}
		r := sameKind(e, dirs, sb, p)
		note := approvedNote
		if line := r.line(p.Destination()); line != "" {
			note += " " + line
		}
		return 0, writeJSON(e.stdout, jsonAnswer{ID: id, Sandbox: sb.Name, Result: "approved", Note: note, SameKind: r.Loaded, AlsoApproved: r.Also, Skipped: r.Skipped})
	}
	u := tui.New(e.stdin, e.stdout)
	if *save {
		return approveAndSave(e, u, sb, p)
	}
	if err := approveOne(e, u, sb, p); err != nil {
		return 1, err
	}
	return 0, nil
}

// approveAndSave approves p and adds its host to the project's fenzi.yaml.
// Everything that could stop the save is checked before the approval, so a
// refusal leaves nothing half done.
func approveAndSave(e env, u *tui.UI, sb config.Sandbox, p openshell.Proposal) (int, error) {
	repo, file, host, err := prepareSave(sb, p)
	if err != nil {
		return 1, err
	}
	if err := approveOne(e, u, sb, p); err != nil {
		return 1, err
	}
	return saveApproved(e, u, sb, repo, file, host)
}

// prepareSave reads what approveAndSave needs before it approves: the
// request as a hosts entry and the project file it goes in.
func prepareSave(sb config.Sandbox, p openshell.Proposal) (string, *projectFile, savedHost, error) {
	host, err := requestHost(p.Endpoints)
	if err != nil {
		return "", nil, host, fmt.Errorf("not approved: %v. Approve it without --save and add the host to %s by hand", err, run.ProjectFile)
	}
	repo := sb.Repo
	if repo == "" {
		if repo, err = cwd(); err != nil {
			return "", nil, host, err
		}
	}
	file, err := loadProject(filepath.Join(repo, run.ProjectFile))
	if err != nil {
		return "", nil, host, fmt.Errorf("not approved: %w", err)
	}
	return repo, file, host, nil
}

// approveFromPreview is approve --save with --dry-run or --policy-from. The
// dry run prints the change and its check and stops there. With
// --policy-from alone, the file given is checked first, and only a file that
// passes is written, after the request is approved.
func approveFromPreview(e env, sb config.Sandbox, p openshell.Proposal, from string, dryRun, asJSON bool) (int, error) {
	pv, err := previewSave(e, sb, p, from)
	if err != nil {
		if dryRun {
			return 1, err
		}
		return 1, fmt.Errorf("not approved: %w", err)
	}
	var fail error
	if !pv.Check.Passed() {
		fail = &run.PolicyError{Stage: "policy check", Result: pv.Check}
	}
	if dryRun {
		if asJSON {
			if err := writeJSON(e.stdout, pv.json()); err != nil {
				return 1, err
			}
		} else {
			printPreview(tui.New(e.stdin, e.stdout), pv, p.Chunk)
		}
		return 0, fail
	}
	u := tui.New(e.stdin, e.stdout)
	if fail != nil {
		printCheck(u, pv.Check, pv.Sources, "", pv.Agent)
		u.Note("Nothing was approved, and " + run.ProjectFile + " was not changed.")
		u.Blank()
		return 0, fail
	}
	if err := approveOne(e, u, sb, p); err != nil {
		return 1, err
	}
	if !pv.Changed() {
		u.Skip("Not changed", run.ProjectFile+" is the same as "+from)
	} else if err := os.WriteFile(pv.Path, pv.After, pv.Mode); err != nil {
		return 1, fmt.Errorf("approved, but %s was not changed: %w", run.ProjectFile, err)
	} else {
		u.Done("Saved", tilde(pv.Path, homeDir()))
		u.Note("The next sandbox in this folder starts with it. This one already has the approval.")
	}
	if pv.Note != "" {
		u.Note(pv.Note)
	}
	printCheck(u, pv.Check, pv.Sources, "", pv.Agent)
	return 0, nil
}

// refuseTeamSave stops approve --save on a signed-in machine: its policy is
// the team's signed revision, and a project file is not used. It names the
// request's page in the console when it can tell the sandbox and the full id.
func refuseTeamSave(e env, dirs config.Dirs, sandbox, id string) error {
	en, err := team.Load(dirs)
	if errors.Is(err, team.ErrNotEnrolled) {
		return nil
	}
	if err != nil {
		return err
	}
	where := "the console"
	if en.Server != "" {
		where = "the console: " + consoleRequestURL(e, dirs, en.Server, sandbox, id)
	}
	return fmt.Errorf("this machine uses the team policy, so --save has nowhere to write. An admin adds the host to the team policy and publishes it from %s. Approve without --save to let this sandbox through now", where)
}

// fullChunk is the shape of a request's full id.
var fullChunk = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// consoleRequestURL is <server>/console/requests/<sandbox>/<id> for a
// request, or <server>/console when the sandbox or the full id is unknown.
func consoleRequestURL(e env, dirs config.Dirs, server, sandbox, id string) string {
	server = strings.TrimRight(server, "/")
	sb, err := pickSandbox(e, dirs, sandbox, true)
	if err != nil {
		return server + "/console"
	}
	if !fullChunk.MatchString(id) {
		p, err := pending(e, sb.Name, id)
		if err != nil || !fullChunk.MatchString(p.Chunk) {
			return server + "/console"
		}
		id = p.Chunk
	}
	return server + "/console/requests/" + url.PathEscape(sb.Name) + "/" + url.PathEscape(id)
}

// saveApproved writes the approved host into the project file, then runs
// the check fenzi policy check runs and prints its result.
func saveApproved(e env, u *tui.UI, sb config.Sandbox, repo string, file *projectFile, host savedHost) (int, error) {
	out := file.add(host)
	if !out.Saved {
		u.Skip("Not saved", out.Detail)
		u.Blank()
		return 0, nil
	}
	if err := file.write(); err != nil {
		return 1, fmt.Errorf("approved, but %s was not changed: %w", run.ProjectFile, err)
	}
	u.Done("Saved", out.Detail+", in "+tilde(file.path, homeDir()))
	if note := widenedNote(host); note != "" {
		u.Note(note)
	}
	u.Note("The next sandbox in this folder starts with it. This one already has the approval.")
	name := sb.Agent
	if name == "" {
		name = defaultAgent()
	}
	entry, err := agents.Get(name)
	if err != nil {
		return 1, err
	}
	resolved, err := run.ResolveFree(repo, "")
	if err != nil {
		return 1, err
	}
	r, err := proveResolved(e, resolved, entry, "")
	if err != nil {
		return 1, err
	}
	printCheck(u, r, resolved.Sources, "", entry)
	if !r.Passed() {
		return 0, &run.PolicyError{Stage: "policy check", Result: r}
	}
	return 0, nil
}

// pending finds a request by id prefix among the sandbox's pending requests.
func pending(e env, sandbox, prefix string) (openshell.Proposal, error) {
	out, err := client().PendingRules(e.ctx, sandbox)
	if err != nil {
		return openshell.Proposal{}, err
	}
	list := openshell.ParseRules(out)
	id, err := openshell.ResolveChunk(list, prefix)
	if err != nil {
		return openshell.Proposal{}, err
	}
	for _, p := range list {
		if p.Chunk == id {
			return p, nil
		}
	}
	return openshell.Proposal{Chunk: id}, nil
}

func cmdDeny(e env, args []string) (int, error) {
	fs := newFlags("deny", e.stderr)
	sandbox := fs.String("sandbox", "", "sandbox name (default: the latest running one for this folder)")
	reason := fs.String("reason", "", "why; the agent sees this")
	asJSON := jsonFlag(fs)
	pos, err := parse(fs, args)
	if err != nil {
		return 1, err
	}
	if len(pos) != 1 || strings.TrimSpace(*reason) == "" {
		return 1, errors.New(`name the request and say why: fenzi deny <id> --reason "text". The agent sees the reason`)
	}
	dirs, err := config.Default()
	if err != nil {
		return 1, err
	}
	sb, err := pickSandbox(e, dirs, *sandbox, true)
	if err != nil {
		return 1, err
	}
	id, err := chunk(e, sb.Name, pos[0])
	if err != nil {
		return 1, err
	}
	if *asJSON {
		if err := client().RuleReject(e.ctx, sb.Name, id, *reason); err != nil {
			return 1, err
		}
		return 0, writeJSON(e.stdout, jsonAnswer{ID: id, Sandbox: sb.Name, Result: "denied", Note: deniedNote(*reason)})
	}
	if err := denyOne(e, tui.New(e.stdin, e.stdout), sb, id, *reason); err != nil {
		return 1, err
	}
	return 0, nil
}

func cmdLog(e env, args []string) (int, error) {
	fs := newFlags("log", e.stderr)
	sandbox := fs.String("sandbox", "", "sandbox name (default: the latest for this folder)")
	deny := fs.Bool("deny", false, "denies only")
	since := fs.String("since", "", "only decisions newer than this, for example 10m or 2h")
	follow := fs.Bool("follow", false, "keep printing new decisions (running sandboxes)")
	rawOut := fs.Bool("raw", false, "print the sandbox's full log as OpenShell wrote it, not only decisions")
	requests := fs.Bool("requests", false, "also list the requests the agent filed and the approvals, as the runtime logged them")
	asJSON := jsonFlag(fs)
	if _, err := parse(fs, args); err != nil {
		return 1, err
	}
	if *rawOut && *asJSON {
		return 1, errors.New("--raw prints the runtime's own lines; drop it or drop --json")
	}
	if *rawOut && *requests {
		return 1, errors.New("--raw prints the runtime's own lines, requests included; drop it or drop --requests")
	}
	var cut time.Time
	if *since != "" {
		d, err := time.ParseDuration(*since)
		if err != nil {
			return 1, fmt.Errorf("--since: %w", err)
		}
		cut = time.Now().Add(-d)
	}
	dirs, err := config.Default()
	if err != nil {
		return 1, err
	}
	sb, err := pickSandbox(e, dirs, *sandbox, false)
	if err != nil {
		return 1, err
	}
	c := client()
	if sb.Running && *follow {
		switch {
		case *asJSON:
			return 0, followJSON(e, sb.Name, *since, *deny, *requests)
		case *rawOut:
			return 0, c.Logs(e.ctx, sb.Name, *since, true)
		}
		return 0, followTable(e, sb.Name, *since, *deny, *requests)
	}
	var raw []byte
	if sb.Running {
		raw, err = c.LogLines(e.ctx, sb.Name, 100000)
	} else {
		raw, err = os.ReadFile(filepath.Join(dirs.Run(sb.Name), run.LogFile))
	}
	if err != nil {
		return 1, fmt.Errorf("no saved log for %s: %w", sb.Name, err)
	}
	if *rawOut {
		e.stdout.Write(raw)
		return 0, nil
	}
	readLog := forward.ReadShorthand
	if *requests {
		readLog = forward.ReadEvents
	}
	recs, err := readLog(strings.NewReader(string(raw)), sb.Name)
	if err != nil {
		return 1, err
	}
	if !cut.IsZero() {
		kept := recs[:0]
		for _, r := range recs {
			if r.Time.After(cut) {
				kept = append(kept, r)
			}
		}
		recs = kept
	}
	if *asJSON {
		docs := []jsonDecision{}
		for _, r := range recs {
			if !*deny || (r.Denied() && !r.Reset()) {
				docs = append(docs, decisionJSON(r))
			}
		}
		return 0, writeJSON(e.stdout, docs)
	}
	rows := [][]screen.Cell{logHeader(*deny)}
	for _, r := range recs {
		if row, ok := logRow(r, *deny); ok {
			rows = append(rows, row)
		}
	}
	u := tui.New(e.stdin, e.stdout)
	if len(rows) == 1 {
		what := "No decisions recorded"
		if *deny {
			what = "No denies recorded"
		}
		u.Blank()
		u.Done(what, sb.Name)
		u.Blank()
		return 0, nil
	}
	title := plural(len(rows)-1, "decision", "decisions")
	if *deny {
		title = plural(len(rows)-1, "deny", "denies")
	}
	state := "finished"
	if sb.Running {
		state = "running"
	}
	u.Title(title, sb.Name+", "+state+", "+dash(tilde(sb.Repo, homeDir())))
	screen.New(e.stdout).Indented(4).Table(rows)
	u.Blank()
	return 0, nil
}

// logHeader is the first row of the log table.
func logHeader(deny bool) []screen.Cell {
	if deny {
		return []screen.Cell{{Text: "time"}, {Text: "process"}, {Text: "destination"}, {Text: "reason"}}
	}
	return []screen.Cell{{Text: "time"}, {Text: "action"}, {Text: "process"}, {Text: "destination"}, {Text: "rule"}}
}

// logRow is one decision as a table row. ok is false for a record the view
// leaves out: with deny, anything but a deny.
func logRow(r forward.Record, deny bool) ([]screen.Cell, bool) {
	proc := "-"
	if r.Process != "" {
		proc = filepath.Base(r.Process)
	}
	t := r.Time.Local().Format("15:04:05")
	switch {
	case deny && r.Config():
		return nil, false
	case r.Config():
		// A request the agent filed, or an approval, with --requests: the
		// chunk's short id where a decision has its rule.
		return []screen.Cell{{Text: t}, {Text: strings.ToLower(r.Action)}, {Text: proc}, {Text: r.What()}, {Text: shortID(r.Chunk)}}, true
	case deny && r.Denied() && !r.Reset():
		return []screen.Cell{{Text: t}, {Text: proc}, {Text: r.What()}, {Text: dash(r.Reason), Tone: "deny"}}, true
	case deny:
		return nil, false
	case r.Reset():
		return []screen.Cell{{Text: t}, {Text: "reset"}, {Text: proc}, {Text: r.What()}, {Text: "policy changed, the client reconnects"}}, true
	}
	action := strings.ToLower(r.Action)
	tone := ""
	switch action {
	case "allowed":
		tone = "allow"
	case "denied":
		tone = "deny"
	}
	return []screen.Cell{{Text: t}, {Text: action, Tone: tone}, {Text: proc}, {Text: r.What()}, {Text: dash(r.Rule)}}, true
}

// followWidths are the column widths of log --follow, which prints each row
// as it arrives and so cannot measure the rows first. The last column is
// not padded.
var followWidths = map[bool][]int{
	false: {10, 9, 18, 44},
	true:  {10, 18, 44},
}

// followTable is log --follow as text: the same rows as the table, from the
// same decisions --json prints, one line each as they arrive.
func followTable(e env, sandbox, since string, denyOnly, requests bool) error {
	scr := screen.New(e.stdout)
	widths := followWidths[denyOnly]
	line := func(row []screen.Cell, header bool) error {
		var b strings.Builder
		b.WriteString("    ")
		for i, c := range row {
			text := c.Text
			if i < len(widths) && len(text) < widths[i] {
				text += strings.Repeat(" ", widths[i]-len(text))
			} else if i < len(widths) {
				text += "  "
			}
			switch {
			case header:
				text = scr.Dim(text)
			case c.Tone == "allow":
				text = scr.Allow(text)
			case c.Tone == "deny":
				text = scr.Deny(text)
			}
			b.WriteString(text)
		}
		_, err := fmt.Fprintln(e.stdout, strings.TrimRight(b.String(), " "))
		return err
	}
	if err := line(logHeader(denyOnly), true); err != nil {
		return err
	}
	return followRecords(e, sandbox, since, requests, func(r forward.Record) error {
		row, ok := logRow(r, denyOnly)
		if !ok {
			return nil
		}
		return line(row, false)
	})
}

// staged loads the snapshot and staged copy for a sandbox.
func staged(e env, name string) (config.Sandbox, workspace.Manifest, string, []workspace.Change, error) {
	dirs, err := config.Default()
	if err != nil {
		return config.Sandbox{}, nil, "", nil, err
	}
	sb, err := pickSandbox(e, dirs, name, false)
	if err != nil {
		return sb, nil, "", nil, err
	}
	dir := dirs.Staging(sb.Name)
	base, err := workspace.Load(filepath.Join(dir, "base.json"))
	if errors.Is(err, fs.ErrNotExist) {
		return sb, nil, "", nil, fmt.Errorf("nothing staged for %s", sb.Name)
	}
	if err != nil {
		return sb, nil, "", nil, err
	}
	files := filepath.Join(dir, "files")
	if _, err := os.Stat(files); err != nil {
		if sb.Running {
			return sb, nil, "", nil, fmt.Errorf("nothing staged for %s; fenzi stop %s brings back what the agent changed", sb.Name, sb.Name)
		}
		if _, err := os.Stat(filepath.Join(dir, run.AppliedMark)); err == nil {
			return sb, nil, "", nil, fmt.Errorf("nothing staged for %s; its changes were applied", sb.Name)
		}
		return sb, nil, "", nil, fmt.Errorf("nothing staged for %s; the copy of its files is missing and no apply was recorded, so %s was not changed", sb.Name, tilde(sb.Repo, homeDir()))
	}
	changes, err := workspace.Changes(base, files, workspace.GitFilter(sb.Repo))
	return sb, base, files, changes, err
}

// appliedFor says whether fenzi apply wrote a sandbox's changes: its
// staging folder holds the apply mark and no copy of the files, the case
// fenzi diff reports as "its changes were applied".
func appliedFor(dirs config.Dirs, name string) bool {
	dir := dirs.Staging(name)
	if _, err := os.Stat(filepath.Join(dir, "files")); err == nil {
		return false
	}
	_, err := os.Stat(filepath.Join(dir, run.AppliedMark))
	return err == nil
}

func cmdPolicy(e env, args []string) (int, error) {
	if len(args) > 0 && args[0] == "publish" {
		return cmdPublish(e, args[1:])
	}
	if len(args) > 0 && args[0] == "apply" {
		return cmdPolicyApply(e, args[1:])
	}
	if len(args) > 0 && args[0] == "host" {
		return cmdPolicyHost(e, args[1:])
	}
	if len(args) > 0 && args[0] == "path" {
		return cmdPolicyPath(e, args[1:])
	}
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		subHelp(e, "policy", "The policy for this folder is the one fenzi run uses: developer-default plus ./fenzi.yaml, if there is one, or the team's signed revision on a signed-in machine.", [][2]string{
			{"policy check [file]", "Prove it stays inside the org boundary"},
			{"policy compile [file]", "Print the OpenShell policy it becomes"},
			{"policy host set|remove <host>", "Change a host in ./fenzi.yaml"},
			{"policy path add|remove <path>", "Change a path in ./fenzi.yaml"},
			{"policy apply", "Load host changes onto running sandboxes (Free plan)"},
			{"policy publish <file>", "Send an org policy to the team (Team plan)"},
		}, "--org treats the file as a whole org policy. --agent picks the agent, claude by default.")
		return 0, nil
	}
	if args[0] != "compile" && args[0] != "check" {
		return 1, fmt.Errorf("%q is not a policy command; try fenzi policy check, compile, host, path, apply, or publish", args[0])
	}
	sub := args[0]
	fs := newFlags("policy "+sub, e.stderr)
	agentName := fs.String("agent", "claude", "agent to compile for")
	org := fs.Bool("org", false, "the file is a complete org policy, not a project file merged over developer-default")
	output := fs.String("o", "", "write the compiled policy to this file (compile)")
	boundary := fs.String("boundary", "", "boundary file (check; default: the team's boundary on a signed-in machine whose team has one, else derived from the same policy)")
	emit := fs.String("emit", "policy", "what compile prints: policy or boundary")
	asJSON := jsonFlag(fs)
	pos, err := parse(fs, args[1:])
	if err != nil {
		return 1, err
	}
	if sub == "compile" && *asJSON {
		return 1, errors.New("--json is for fenzi policy check; compile prints the policy as YAML")
	}
	file := ""
	if len(pos) > 0 {
		file = pos[0]
	}
	entry, err := agents.Get(*agentName)
	if err != nil {
		return 1, err
	}
	repo, err := cwd()
	if err != nil {
		return 1, err
	}
	var resolved run.Resolved
	if *org {
		if file == "" {
			return 1, errors.New("--org needs a file")
		}
		raw, err := os.ReadFile(file)
		if err != nil {
			return 1, err
		}
		doc, err := compiler.Parse(raw)
		if err != nil {
			return 1, err
		}
		resolved = run.Resolved{Doc: doc, Sources: file}
	} else if file == "" {
		// The policy fenzi run uses here: the signed team revision on a
		// signed-in machine, developer-default plus ./fenzi.yaml on the
		// Free plan. Its labels go to standard error, so standard output keeps
		// only the YAML or the JSON document.
		dirs, err := config.Default()
		if err != nil {
			return 1, err
		}
		labels := env{ctx: e.ctx, stdin: e.stdin, stdout: e.stderr, stderr: e.stderr}
		if resolved, err = resolvePolicy(labels, dirs, repo, ""); err != nil {
			return 1, err
		}
	} else if resolved, err = run.ResolveFree(repo, file); err != nil {
		return 1, err
	}
	switch {
	case *boundary != "":
		// The file given replaces any team boundary.
		resolved.Boundary, resolved.BoundarySource = nil, ""
	case file != "":
		// A file checked on a signed-in machine is proved against the
		// team's boundary, as a revision built from it would be.
		if resolved, err = withCachedBoundary(resolved); err != nil {
			return 1, err
		}
	}

	if sub == "check" {
		r, err := proveResolved(e, resolved, entry, *boundary)
		if err != nil {
			return 1, err
		}
		from := resolved.Sources
		if from == "" {
			from = "developer-default"
		}
		if *asJSON {
			missing := r.MissingDomains()
			if missing == nil {
				missing = []string{}
			}
			doc := jsonPolicyCheck{Passed: r.Passed(), Result: r.Result, Checked: from, Boundary: resolved.BoundarySource, Agent: entry.Display, Example: r.Example(), Reason: r.Reason, NotChecked: missing}
			if doc.Policy, err = policyView(resolved, entry); err != nil {
				return 1, err
			}
			if resolved.TeamRevision == 0 && file == "" {
				// A missing or broken file marks nothing; check says why.
				project, _ := readProjectDoc(repo)
				markProject(doc.Policy, project)
			}
			if err := writeJSON(e.stdout, doc); err != nil {
				return 1, err
			}
		} else {
			u := tui.New(e.stdin, e.stdout)
			printCheck(u, r, from, resolved.BoundarySource, entry)
			if n := remoteMCP(resolved.Doc); n > 0 {
				u.Note(fmt.Sprintf("MCP: %d remote %s left out of the prover, which cannot read MCP rules; Fenzi checks those itself.", n, map[bool]string{true: "server", false: "servers"}[n == 1]))
				u.Blank()
			}
		}
		if !r.Passed() {
			return 0, &run.PolicyError{Stage: "policy check", Result: r}
		}
		return 0, nil
	}

	tmp, err := os.MkdirTemp("", "fenzi-policy-")
	if err != nil {
		return 1, err
	}
	defer os.RemoveAll(tmp)
	c, err := run.WriteCompiled(resolved, entry, tmp)
	if err != nil {
		return 1, err
	}

	src := c.Policy
	switch *emit {
	case "policy":
	case "boundary":
		src = c.Boundary
	default:
		return 1, fmt.Errorf("--emit is policy or boundary, not %q", *emit)
	}
	out, err := os.ReadFile(src)
	if err != nil {
		return 1, err
	}
	if *output != "" {
		return 0, os.WriteFile(*output, out, 0o644)
	}
	e.stdout.Write(out)
	return 0, nil
}

// proveResolved compiles a resolved policy for an agent and runs the prover
// on it, against boundary or, when that is "", the boundary derived from the
// same policy. This is fenzi policy check.
func proveResolved(e env, resolved run.Resolved, entry agents.Entry, boundary string) (openshell.Result, error) {
	tmp, err := os.MkdirTemp("", "fenzi-policy-")
	if err != nil {
		return openshell.Result{}, err
	}
	defer os.RemoveAll(tmp)
	c, err := run.WriteCompiled(resolved, entry, tmp)
	if err != nil {
		return openshell.Result{}, err
	}
	if boundary == "" {
		boundary = c.ProveBoundary
	} else if raw, err := os.ReadFile(boundary); err == nil && compiler.UnprovableYAML(raw) {
		// The prover cannot read MCP rules or secret bindings; CheckMCP
		// covers them.
		stripped, err := compiler.ForProverYAML(raw)
		if err != nil {
			return openshell.Result{}, err
		}
		boundary = filepath.Join(tmp, "given.boundary.yaml")
		if err := os.WriteFile(boundary, stripped, 0o600); err != nil {
			return openshell.Result{}, err
		}
	}
	return prover().Check(e.ctx, c.ProvePolicy, boundary)
}

// printCheck prints a policy check result as fenzi policy check does.
// against names the team boundary it was proved against, or is empty for the
// boundary derived from the same policy.
func printCheck(u *tui.UI, r openshell.Result, from, against string, entry agents.Entry) {
	u.Blank()
	if r.Passed() {
		u.Done("Policy check", "inside the boundary")
	} else {
		u.Problem("Policy check", r.Result)
	}
	u.Note("Checked " + from + " for " + entry.Display + ".")
	if against != "" {
		u.Note("Proved against " + against + ".")
	}
	if ex := r.Example(); ex != "" {
		u.Println("    " + u.Bold("Example") + "  " + ex)
	}
	if r.Reason != "" {
		u.Println("    " + u.Bold("Reason") + "   " + r.Reason)
	}
	if m := r.MissingDomains(); len(m) > 0 {
		u.Println("    " + u.Bold("Not checked") + "  " + strings.Join(m, ", "))
	}
	u.Blank()
}

// subHelp is what a command with subcommands prints when given none.
func subHelp(e env, name, intro string, rows [][2]string, foot string) {
	u := tui.New(e.stdin, e.stdout)
	u.Title("fenzi "+name, "")
	if intro != "" {
		u.Note(intro)
		u.Blank()
	}
	width := 0
	for _, r := range rows {
		width = max(width, len("fenzi "+r[0]))
	}
	for _, r := range rows {
		u.Println(fmt.Sprintf("    %s  %s", u.Bold(fmt.Sprintf("%-*s", width, "fenzi "+r[0])), u.Dim(r[1])))
	}
	if foot != "" {
		u.Blank()
		u.Note(foot)
	}
	u.Blank()
}

func cmdAgents(e env, args []string) (int, error) {
	if len(args) >= 1 && args[0] == "build" {
		if len(args) != 2 {
			return 1, errors.New("usage: fenzi agents build <name>")
		}
		entry, err := agents.Get(args[1])
		if err != nil {
			return 1, err
		}
		df, err := entry.Dockerfile()
		if err != nil {
			return 1, err
		}
		b, err := imageBuilder(e, e.stdout)
		if err != nil {
			return 1, err
		}
		u := tui.New(e.stdin, e.stdout)
		u.Title("Building "+entry.Display, entry.Tag())
		return 0, b.Build(e.ctx, entry.Tag(), df)
	}
	fs := newFlags("agents", e.stderr)
	asJSON := jsonFlag(fs)
	pos, err := parse(fs, args)
	if err != nil {
		return 1, err
	}
	if len(pos) > 0 {
		return 1, fmt.Errorf("%q is not an agents command; fenzi agents lists them, fenzi agents build <name> builds an image", pos[0])
	}
	all, err := agents.All()
	if err != nil {
		return 1, err
	}
	if *asJSON {
		docs := make([]jsonAgent, 0, len(all))
		for _, a := range all {
			_, perr := a.Profile()
			docs = append(docs, jsonAgent{Name: a.Name, Display: a.Display, Version: a.Version, KeyEnv: a.Key.Env, Status: a.Status, Available: perr == nil, SignIn: a.CanSignIn()})
		}
		return 0, writeJSON(e.stdout, docs)
	}
	u := tui.New(e.stdin, e.stdout)
	u.Title("Agents", "allowed by developer-default: "+strings.Join(policies.DeveloperDefault().Agents, ", "))
	rows := [][]screen.Cell{{{Text: "agent"}, {Text: "name"}, {Text: "version"}, {Text: "key"}, {Text: "status"}}}
	for _, a := range all {
		key := a.Key.Env
		if key == "" {
			key = "to confirm"
		}
		rows = append(rows, []screen.Cell{{Text: a.Name}, {Text: a.Display}, {Text: a.Version}, {Text: key}, {Text: a.Status}})
	}
	screen.New(e.stdout).Indented(4).Table(rows)
	u.Blank()
	u.Commands([2]string{"fenzi run <agent>", "start one in this folder"}, [2]string{"fenzi agents build <agent>", "build its image ahead of time"})
	u.Blank()
	return 0, nil
}

func cmdPs(e env, args []string) (int, error) {
	fs := newFlags("ps", e.stderr)
	all := fs.Bool("all", false, "include finished sandboxes")
	asJSON := jsonFlag(fs)
	if _, err := parse(fs, args); err != nil {
		return 1, err
	}
	dirs, err := config.Default()
	if err != nil {
		return 1, err
	}
	listed, err := client().List(e.ctx)
	if err != nil {
		return 1, err
	}
	// A sandbox in phase Error is listed but not running: its container
	// stopped, as when the container runtime restarts.
	live, lost := map[string]bool{}, map[string]bool{}
	var names []string
	for _, l := range listed {
		names = append(names, l.Name)
		if l.Phase == openshell.PhaseError {
			lost[l.Name] = true
		} else {
			live[l.Name] = true
		}
	}
	s, err := dirs.LoadState()
	if err != nil {
		return 1, err
	}
	// The gateway is the source of truth; fix records of sandboxes deleted
	// some other way.
	known := map[string]bool{}
	changed := false
	for i := range s.Sandboxes {
		sb := &s.Sandboxes[i]
		known[sb.Name] = true
		if sb.Running != live[sb.Name] {
			sb.Running = live[sb.Name]
			changed = true
		}
	}
	for _, n := range names {
		if !known[n] {
			s.Put(config.Sandbox{Name: n, Running: live[n]})
			changed = true
		}
	}
	// Written only when a record changed: a program that polls ps should not
	// rewrite the state file every few seconds.
	if changed {
		_ = dirs.SaveState(s)
	}

	list := append([]config.Sandbox(nil), s.Sandboxes...)
	sort.Slice(list, func(i, j int) bool { return list[i].Created.After(list[j].Created) })
	if *asJSON {
		docs := []jsonSandbox{}
		for _, sb := range list {
			if sb.Running || lost[sb.Name] || *all {
				d := sandboxJSON(sb)
				d.Lost = lost[sb.Name]
				d.Applied = !sb.Running && appliedFor(dirs, sb.Name)
				docs = append(docs, d)
			}
		}
		return 0, writeJSON(e.stdout, docs)
	}
	u := tui.New(e.stdin, e.stdout)
	home := homeDir()
	rows := [][]screen.Cell{{{Text: "sandbox"}, {Text: "agent"}, {Text: "folder"}, {Text: "started"}, {Text: "state"}}}
	running, finished := 0, 0
	stopped := 0
	for _, sb := range list {
		switch {
		case sb.Running:
			running++
		case lost[sb.Name]:
			stopped++
		default:
			finished++
			if !*all {
				continue
			}
		}
		state := screen.Cell{Text: "finished", Tone: "dim"}
		switch {
		case sb.Running:
			state = screen.Cell{Text: "running", Tone: "accent"}
		case lost[sb.Name]:
			state = screen.Cell{Text: "stopped", Tone: "deny"}
		}
		rows = append(rows, []screen.Cell{{Text: sb.Name}, {Text: dash(sb.Agent)}, {Text: dash(tilde(sb.Repo, home))}, {Text: started(sb)}, state})
	}
	if len(rows) == 1 {
		u.Blank()
		u.Done("No sandboxes running", "")
		hints := [][2]string{{"fenzi run", "start the agent in this folder"}}
		if finished > 0 {
			hints = append(hints, [2]string{"fenzi ps --all", "include the " + plural(finished, "finished one", "finished ones")})
		}
		u.Commands(hints...)
		u.Blank()
		return 0, nil
	}
	title := plural(running, "sandbox running", "sandboxes running")
	if stopped > 0 {
		title += ", " + plural(stopped, "stopped", "stopped")
	}
	if *all {
		title += ", " + plural(finished, "finished", "finished")
	}
	u.Title(title, "")
	screen.New(e.stdout).Indented(4).Table(rows)
	u.Blank()
	var hints [][2]string
	if running > 0 {
		hints = append(hints, [2]string{"fenzi connect [sandbox]", "open its agent again"}, [2]string{"fenzi stop [sandbox]", "end it and review the changes"})
	}
	if stopped > 0 {
		hints = append(hints, [2]string{"fenzi stop <sandbox>", "start a stopped one again to bring its changes back, or delete it"})
	}
	if !*all && finished > 0 {
		hints = append(hints, [2]string{"fenzi ps --all", "include the finished ones"})
	}
	u.Commands(hints...)
	u.Blank()
	return 0, nil
}

func cmdStop(e env, args []string) (int, error) {
	fs := newFlags("stop", e.stderr)
	yes := fs.Bool("yes", false, "do not ask")
	pos, err := parse(fs, args)
	if err != nil {
		return 1, err
	}
	dirs, err := config.Default()
	if err != nil {
		return 1, err
	}
	name := ""
	if len(pos) > 0 {
		name = pos[0]
	}
	u := tui.New(e.stdin, e.stdout)
	if name != "" {
		lost, err := client().Lost(e.ctx)
		if err != nil {
			return 1, err
		}
		if slices.Contains(lost, name) {
			return stopLost(e, u, dirs, name, *yes)
		}
	}
	sb, err := chooseRunning(e, u, dirs, name, "Stop which sandbox?")
	if err != nil {
		return 1, err
	}
	if !*yes {
		u.Blank()
		u.Println(fmt.Sprintf("  %s %s  %s", u.Accent("■"), u.Bold("Stop "+sb.Name+"?"), u.Dim(dash(tilde(sb.Repo, homeDir())))))
		u.Note("The agent in it is ended. Its changes come back to this machine first, and you choose whether to apply them.")
		u.Blank()
		var ok bool
		if u.Interactive() {
			ok, err = u.Confirm("Stop it?", "Stop it", "Keep it running")
			if errors.Is(err, tui.ErrCancelled) {
				err = nil
			}
		} else {
			a, _ := u.Input("Stop it? [y/N]", "")
			a = strings.ToLower(strings.TrimSpace(a))
			ok = a == "y" || a == "yes"
		}
		if err != nil {
			return 1, err
		}
		if !ok {
			u.Skip("Still running", sb.Name)
			return 0, nil
		}
	}
	changes, err := run.Stop(e.ctx, run.Deps{OpenShell: client(), Dirs: dirs, Out: e.stdout, Filter: workspace.GitFilter}, sb)
	if err != nil {
		return 1, err
	}
	if len(changes) > 0 {
		if sb, base, files, changes, err := staged(e, sb.Name); err == nil && len(changes) > 0 {
			return newReview(sb, base, files, changes, sandboxFlag(sb.Name)).offer(e)
		}
	}
	return 0, nil
}

// stopLost stops a sandbox in phase Error. OpenShell starts it again when
// it can, and the stop goes on as usual. When it cannot, which is the case
// after the container runtime restarted, its files cannot be copied out, and
// it is deleted only when the person agrees.
func stopLost(e env, u *tui.UI, dirs config.Dirs, name string, yes bool) (int, error) {
	oc := client()
	u.Blank()
	u.Println(fmt.Sprintf("  %s %s", u.Accent("■"), u.Bold(name+" is not running")))
	u.Note("Its container stopped, as it does when the container runtime restarts. Fenzi asks OpenShell to start it again, so its changes can come back.")
	u.Blank()
	startErr := oc.Start(e.ctx, name)
	if startErr == nil {
		for i := 0; i < 30; i++ {
			running, err := oc.Sandboxes(e.ctx)
			if err != nil {
				return 1, err
			}
			if slices.Contains(running, name) {
				u.Done("Started", name)
				return cmdStop(e, append([]string{name}, yesFlag(yes)...))
			}
			time.Sleep(startPoll)
		}
		startErr = errors.New("it did not come back within a minute")
	}
	sb := config.Sandbox{Name: name}
	if s, err := dirs.LoadState(); err == nil {
		if found, ok := s.Find(name); ok {
			sb = found
		}
	}
	u.Problem("Not started", openshell.ErrorMessage(startErr))
	u.Note("OpenShell cannot start " + name + " again, so the files the agent changed in it cannot be copied out. Deleting it removes them for good.")
	u.Blank()
	ok := yes
	if !yes {
		var err error
		if u.Interactive() {
			ok, err = u.Confirm("Delete it?", "Delete it", "Keep it")
			if errors.Is(err, tui.ErrCancelled) {
				ok, err = false, nil
			}
		} else {
			a, _ := u.Input("Delete it? [y/N]", "")
			a = strings.ToLower(strings.TrimSpace(a))
			ok = a == "y" || a == "yes"
		}
		if err != nil {
			return 1, err
		}
	}
	if !ok {
		u.Skip("Kept", name+"; fenzi rm "+name+" deletes it")
		return 0, nil
	}
	if err := run.Discard(e.ctx, run.Deps{OpenShell: oc, Dirs: dirs, Out: e.stdout}, sb); err != nil {
		return 1, err
	}
	return 0, nil
}

// startPoll is how often stopLost looks for a started sandbox, 30 times.
var startPoll = 2 * time.Second

func yesFlag(yes bool) []string {
	if yes {
		return []string{"--yes"}
	}
	return nil
}

func cmdKey(e env, args []string) (int, error) {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		subHelp(e, "key", "Model keys stay on this machine, in the sandbox runtime. The agent only ever sees a placeholder.", [][2]string{
			{"key list", "Which agents have a key stored"},
			{"key set <agent>", "Store or replace a key; it is hidden as you type"},
			{"key remove <agent>", "Forget a key"},
		}, "")
		return 0, nil
	}
	oc := client()
	u := tui.New(e.stdin, e.stdout)
	switch args[0] {
	case "list":
		fs := newFlags("key list", e.stderr)
		asJSON := jsonFlag(fs)
		if _, err := parse(fs, args[1:]); err != nil {
			return 1, err
		}
		all, err := agents.All()
		if err != nil {
			return 1, err
		}
		if *asJSON {
			docs := make([]jsonKey, 0, len(all))
			for _, a := range all {
				k := jsonKey{Name: a.Name, Display: a.Display, KeyEnv: a.Key.Env, SignIn: a.CanSignIn()}
				if _, err := a.Profile(); err == nil {
					k.Available = true
					if k.Stored, err = run.KeyStored(e.ctx, oc, a); err != nil {
						return 1, err
					}
				}
				docs = append(docs, k)
			}
			return 0, writeJSON(e.stdout, docs)
		}
		u.Title("Model keys", "on this machine")
		for _, a := range all {
			if _, err := a.Profile(); err != nil {
				u.Skip(a.Display, "not available yet")
				continue
			}
			ok, err := run.KeyStored(e.ctx, oc, a)
			if err != nil {
				return 1, err
			}
			if ok {
				u.Done(a.Display, a.Key.Env+" stored")
			} else if a.CanSignIn() {
				u.Skip(a.Display, "no key; signs in when it starts, or fenzi key set "+a.Name)
			} else {
				u.Skip(a.Display, "no key. fenzi key set "+a.Name)
			}
		}
		u.Blank()
		return 0, nil
	case "set", "remove":
		if len(args) != 2 {
			return 1, fmt.Errorf("name the agent: fenzi key %s claude. fenzi agents lists them", args[0])
		}
	default:
		return 1, fmt.Errorf("%q is not a key command; try fenzi key list, set, or remove", args[0])
	}
	a, err := agents.Get(args[1])
	if err != nil {
		return 1, err
	}
	if args[0] == "remove" {
		dirs, err := config.Default()
		if err != nil {
			return 1, err
		}
		removed, err := run.RemoveKey(e.ctx, oc, dirs, a)
		if err != nil {
			return 1, err
		}
		u.Blank()
		if removed {
			u.Done("Removed", "the "+a.Display+" key is gone from this machine")
		} else {
			u.Skip("Nothing to remove", "no "+a.Display+" key was stored")
		}
		u.Blank()
		return 0, nil
	}
	var value string
	if u.Interactive() {
		u.Blank()
		value, err = u.Secret(fmt.Sprintf("Paste the %s key (%s)", a.Display, a.Key.Env))
		if errors.Is(err, tui.ErrCancelled) {
			return 130, nil
		}
	} else {
		value, err = readLine(e)
	}
	if err != nil {
		return 1, err
	}
	if strings.TrimSpace(value) == "" {
		return 1, errors.New("the key was empty; nothing stored")
	}
	replaced, err := run.SetKey(e.ctx, oc, a, value)
	if err != nil {
		return 1, err
	}
	if replaced {
		u.Done("Replaced", "the "+a.Display+" key")
		u.Note("New sandboxes use it. Restart a running agent to be sure it does.")
	} else {
		u.Done("Stored", "the "+a.Display+" key, on this machine")
		u.Note("The agent only ever sees a placeholder.")
	}
	u.Blank()
	return 0, nil
}

func cmdVersion(e env, args []string) (int, error) {
	fs := newFlags("version", e.stderr)
	asJSON := jsonFlag(fs)
	if _, err := parse(fs, args); err != nil {
		return 1, err
	}
	if *asJSON {
		return 0, writeJSON(e.stdout, jsonVersion{Version: Version})
	}
	u := tui.New(e.stdin, e.stdout)
	u.Title("Version", "")
	u.Done("Fenzi", Version)
	u.Blank()
	return 0, nil
}

// readLine reads a key from a pipe.
func readLine(e env) (string, error) {
	line, err := bufio.NewReader(e.stdin).ReadString('\n')
	if err != nil && line == "" {
		return "", errors.New("no key on standard input")
	}
	return strings.TrimSpace(line), nil
}

func configDirs(e env) config.Dirs {
	dirs, err := config.Default()
	if err != nil {
		return config.Dirs{}
	}
	return dirs
}
