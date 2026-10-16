package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"fenzi/agents"
	"fenzi/cli/internal/config"
	"fenzi/cli/internal/engine"
	"fenzi/cli/internal/openshell"
	"fenzi/cli/internal/run"
	"fenzi/cli/internal/tui"
	"fenzi/cli/internal/workspace"
	"fenzi/compiler"
)

// quietExit ends a command whose reason is already on screen.
type quietExit int

func (q quietExit) Error() string { return fmt.Sprintf("exit %d", int(q)) }

const setupSteps = 5

func cmdSetup(e env, args []string) (int, error) {
	fs := newFlags("setup", e.stderr)
	if _, err := parse(fs, args); err != nil {
		return 1, err
	}
	u := tui.New(e.stdin, e.stdout)
	dirs, err := config.Default()
	if err != nil {
		return 1, err
	}
	stopped := func() {
		u.Blank()
		u.Println("  Setup stopped. Run fenzi setup to start again.")
	}

	// Raw-key questions read Ctrl-C as a key. Typed answers and checks get
	// SIGINT, which cli otherwise keeps for the agent.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	done := make(chan struct{})
	var once sync.Once
	release := func() { once.Do(func() { signal.Stop(sig); close(done) }) }
	defer release()
	go func() {
		select {
		case <-sig:
			u.Restore()
			stopped()
			os.Exit(130)
		case <-done:
		}
	}()

	err = setup(e, u, dirs, release)
	if errors.Is(err, tui.ErrCancelled) {
		stopped()
		return 130, nil
	}
	return 0, err
}

func setup(e env, u *tui.UI, dirs config.Dirs, release func()) error {
	u.Blank()
	u.Box("Fenzi "+Version, []string{
		u.Bold("Run the agent you already use inside a sandbox on this machine."),
		"",
		"The agent gets a copy of one project folder and the hosts your policy names. Your home folder, your credentials, and everything else stay outside.",
		"",
		u.Dim("Five short steps. Nothing is installed or changed without asking you first."),
	})

	u.Step(1, setupSteps, "This machine")
	if err := setupMachine(e, u); err != nil {
		return err
	}

	var agent agents.Entry
	var project string
	start := false
	// Each step reports whether it asked anything, so going back skips a
	// step that only printed a check.
	steps := []func(back bool) (bool, error){
		func(back bool) (bool, error) {
			u.Step(2, setupSteps, "Agent")
			a, err := setupAgent(u, back)
			agent = a
			return true, err
		},
		func(back bool) (bool, error) {
			u.Step(3, setupSteps, "Model key")
			return true, setupKey(e, u, agent, back)
		},
		func(back bool) (bool, error) {
			u.Step(4, setupSteps, "Project folder")
			p, err := setupProject(u, agent, back)
			project = p
			return true, err
		},
		func(back bool) (bool, error) {
			u.Step(5, setupSteps, "Agent image")
			return setupImage(e, u, dirs, agent, back)
		},
		func(back bool) (bool, error) {
			s, err := setupReady(e, u, dirs, agent, project, back)
			start = s
			return true, err
		},
	}
	var asked []int
	for i := 0; i < len(steps); {
		did, err := steps[i](len(asked) > 0)
		if errors.Is(err, tui.ErrBack) && len(asked) > 0 {
			i, asked = asked[len(asked)-1], asked[:len(asked)-1]
			u.Println("  " + u.Dim("↩ back"))
			continue
		}
		if err != nil {
			return err
		}
		if did {
			asked = append(asked, i)
		}
		i++
	}

	if err := dirs.SaveSetup(config.Setup{Agent: agent.Name, Project: project, Finished: time.Now()}); err != nil {
		return err
	}
	return setupFinish(e, u, agent, project, start, release)
}

func setupMachine(e env, u *tui.UI) error {
	oc := client()

	for !openshell.Installed("openshell") && openshell.FindInstalled() == "" {
		u.Problem("Runtime", "OpenShell is not installed")
		if openshell.NeedsHomebrew() {
			u.Problem("Homebrew", "not installed")
			u.Note("On a Mac, OpenShell's installer uses Homebrew to install the sandbox runtime and to keep its gateway running. Setup can install Homebrew with its official installer, which asks for your password:")
			u.Command(openshell.HomebrewInstallCommand(), "")
			u.Blank()
			const (
				install = "Install Homebrew"
				again   = "Check again"
				quit    = "Quit setup"
			)
			opts := []tui.Option{{Label: install, Hint: "https://brew.sh"}, {Label: again, Hint: "after installing it yourself"}, {Label: quit}}
			i, err := u.Select("Homebrew is needed first. What next?", opts, 0)
			if err != nil {
				return err
			}
			switch opts[i].Label {
			case quit:
				u.Blank()
				u.Note("Install Homebrew from https://brew.sh, then run fenzi setup again.")
				return quietExit(3)
			case install:
				u.Blank()
				if err := openshell.InstallHomebrew(e.ctx, os.Stdin, e.stdout, e.stderr); err != nil {
					u.Blank()
					u.Problem("Homebrew", err.Error())
				}
				u.Blank()
			}
			continue
		}
		u.Note("Fenzi runs each agent inside OpenShell, an open-source sandbox. Setup can install release " + openshell.InstallVersion + " with the upstream installer:")
		u.Command(openshell.InstallCommand(), "")
		u.Blank()
		ok, err := u.Confirm("Install OpenShell "+openshell.InstallVersion+" now?", "Yes, install it", "No, I will install it myself")
		if err != nil {
			return err
		}
		if !ok {
			u.Blank()
			u.Note("Install OpenShell " + openshell.InstallVersion + ", then run fenzi setup again. Guide: https://fenzi.dev/docs/install")
			return quietExit(3)
		}
		u.Blank()
		u.Println("  " + u.Dim("Running the OpenShell installer. It may ask for your password."))
		u.Blank()
		if err := openshell.Install(e.ctx, os.Stdin, e.stdout, e.stderr); err != nil {
			u.Blank()
			u.Problem("Runtime", err.Error())
			retry, err := u.Confirm("Try again?", "Try again", "Quit setup")
			if err != nil {
				return err
			}
			if !retry {
				return quietExit(3)
			}
			continue
		}
		u.Blank()
	}

	if _, err := u.Spin("Runtime", "checking the version", func() (string, error) {
		out, err := oc.Version(e.ctx)
		if err != nil {
			return "", err
		}
		v, ok := openshell.Pinned.Contains(out)
		if !ok {
			return "", fmt.Errorf("%q is outside %s", strings.TrimSpace(out), openshell.Pinned)
		}
		return "OpenShell " + v, nil
	}); err != nil {
		u.Note("Fenzi " + Version + " is built for OpenShell " + openshell.Pinned.String() + ". Install " + openshell.InstallVersion + ", then run fenzi setup again.")
		return quietExit(3)
	}

gateway:
	for {
		_, err := u.Spin("Gateway", "connecting", func() (string, error) {
			return "connected", oc.Ready(e.ctx)
		})
		if err == nil {
			break
		}
		const (
			again   = "Check again"
			start   = "Start the gateway"
			colima  = "Set up the gateway for colima"
			install = "Install colima"
			quit    = "Quit setup"
		)
		var opts []tui.Option
		starts := map[string]openshell.Runtime{}
		d := openshell.Diagnose()
		if s := d.Summary(); s != "" {
			u.Note(s)
		}
		switch {
		case d.None:
			u.Note("On a Mac the gateway runs sandboxes in Docker Desktop, colima, or the MicroVM driver. On Linux it uses Docker Engine 28 or later, or Podman 5. Guide: https://fenzi.dev/docs/install#runtime")
			if openshell.CanInstallColima() {
				opts = append(opts, tui.Option{Label: install, Hint: strings.Join(openshell.InstallColimaCommand, " ")})
			}
		case d.Orphan:
			u.Note("Start the runtime that serves it, or change socket_path in " + tilde(openshell.GatewayConfig(), homeDir()) + ".")
		case len(d.Running) == 0 && len(d.Stopped) > 0:
			for _, r := range d.Stopped {
				label := "Start " + r.Name
				starts[label] = r
				opts = append(opts, tui.Option{Label: label, Hint: r.StartLine() + ", then restarts the gateway"})
			}
		}
		for _, r := range d.Running {
			if !r.Tested {
				u.Note(r.Name + " has not been tested with the gateway yet. If it does not connect, see https://fenzi.dev/docs/troubleshooting#runtimes")
			}
		}
		sock := openshell.ColimaSocket()
		canColima := sock != "" && needsColimaConfig() && openshell.Service("restart") != nil
		if sock != "" && needsColimaConfig() && !canColima {
			u.Note("colima needs three gateway settings: https://fenzi.dev/docs/troubleshooting#colima")
		}
		if canColima {
			opts = append(opts, tui.Option{Label: colima, Hint: "writes " + tilde(openshell.GatewayConfig(), homeDir())})
		}
		if argv := openshell.Service("restart"); argv != nil && len(starts) == 0 {
			opts = append(opts, tui.Option{Label: start, Hint: strings.Join(argv, " ")})
		} else if argv == nil && len(starts) == 0 {
			u.Note("Setup does not know how the gateway was installed here, so it cannot start it. Start it the way you installed it, then choose Check again.")
		}
		opts = append(opts, tui.Option{Label: again}, tui.Option{Label: quit})
		i, err := u.Select("The gateway is not connected. What next?", opts, 0)
		if err != nil {
			return err
		}
		if r, ok := starts[opts[i].Label]; ok {
			if !startRuntime(e, u, r) {
				continue
			}
			if r.Name == "colima" && needsColimaConfig() {
				continue
			}
			if openshell.Service("restart") == nil {
				u.Note("Setup does not know how the gateway was installed here, so it cannot restart it. Restart it the way you installed it, then choose Check again.")
				continue
			}
			if _, err := u.Spin("Gateway", "restarting the service", func() (string, error) {
				return "service restarted", openshell.RunService(e.ctx, "restart")
			}); err != nil {
				continue
			}
			if waitGateway(e, u, oc) {
				break gateway
			}
			continue
		}
		switch opts[i].Label {
		case quit:
			return quietExit(3)
		case install:
			u.Blank()
			u.Println("  " + u.Dim("Running "+strings.Join(openshell.InstallColimaCommand, " ")+"."))
			u.Blank()
			if err := openshell.InstallColima(e.ctx, os.Stdin, e.stdout, e.stderr); err != nil {
				u.Problem("colima", err.Error())
			}
			u.Blank()
		case start:
			if _, err := u.Spin("Gateway", "starting the service", func() (string, error) {
				return "service started", openshell.RunService(e.ctx, "restart")
			}); err != nil {
				continue
			}
			if waitGateway(e, u, oc) {
				break gateway
			}
		case colima:
			u.Note("colima runs sandboxes in its own VM, so the gateway needs colima's Docker socket and an address that VM can reach. Setup writes this file, then restarts the gateway:")
			u.Blank()
			for _, l := range strings.Split(strings.TrimSpace(openshell.ColimaConfig(sock)), "\n") {
				u.Println("      " + u.Dim(l))
			}
			u.Blank()
			ok, err := u.Confirm("Write it and restart the gateway?", "Yes", "No")
			if err != nil {
				return err
			}
			if !ok {
				continue
			}
			if _, err := u.Spin("Gateway", "writing the config and restarting", func() (string, error) {
				if err := openshell.WriteColimaConfig(sock); err != nil {
					return "", err
				}
				return "restarted for colima", openshell.RunService(e.ctx, "restart")
			}); err != nil {
				continue
			}
			if waitGateway(e, u, oc) {
				break gateway
			}
		}
	}

	if _, err := u.Spin("Sandbox driver", "asking the gateway", func() (string, error) {
		drivers, err := oc.ComputeDrivers(e.ctx)
		if err == nil && len(drivers) == 0 {
			err = errors.New("the gateway reports none")
		}
		return strings.Join(drivers, ", "), err
	}); err != nil {
		u.Note("Start Docker, Podman, or the MicroVM driver, then run fenzi setup again.")
		return quietExit(3)
	}

	mode, err := oc.GlobalSetting(e.ctx, "proposal_approval_mode")
	switch {
	case err != nil:
		u.Problem("Approvals", err.Error())
		return quietExit(3)
	case mode == "auto":
		u.Problem("Approvals", "requests are approved with no person")
		u.Note("This gateway approves an agent's requests for more access by itself. Fenzi needs a person to decide.")
		ok, err := u.Confirm("Turn automatic approval off for this gateway?", "Yes, a person approves", "No, quit setup")
		if err != nil {
			return err
		}
		if !ok {
			return quietExit(3)
		}
		if _, err := u.Spin("Approvals", "updating the gateway", func() (string, error) {
			return "a person approves each request", oc.GlobalSettingDelete(e.ctx, "proposal_approval_mode")
		}); err != nil {
			return quietExit(3)
		}
	default:
		u.Done("Approvals", "a person approves each request")
	}

	bad, err := run.SettingConflicts(e.ctx, oc)
	switch {
	case err != nil:
		u.Problem("Log and requests", err.Error())
		return quietExit(3)
	case len(bad) > 0:
		keys := make([]string, 0, len(bad))
		for k := range bad {
			keys = append(keys, k)
		}
		u.Problem("Log and requests", "turned off for every sandbox: "+strings.Join(keys, ", "))
		u.Note("Fenzi turns on the decision log and agent requests for each sandbox. The gateway overrides that for every sandbox.")
		ok, err := u.Confirm("Remove the gateway-wide setting?", "Yes, remove it", "No, quit setup")
		if err != nil {
			return err
		}
		if !ok {
			return quietExit(3)
		}
		for _, k := range keys {
			if err := oc.GlobalSettingDelete(e.ctx, k); err != nil {
				u.Problem("Log and requests", err.Error())
				return quietExit(3)
			}
		}
		u.Done("Log and requests", "can be turned on")
	default:
		u.Done("Log and requests", "can be turned on")
	}

	if openshell.Installed("openshell-prover") {
		u.Done("Policy check", "installed")
	} else {
		u.Problem("Policy check", "openshell-prover is missing")
		u.Note("It ships with the runtime's Homebrew, Debian, and RPM packages. Reinstall OpenShell from one of them, then run fenzi setup again.")
		return quietExit(3)
	}

	if b, err := imageBuilder(e, nil); err != nil {
		u.Problem("Image builds", "Docker or Podman is needed")
		u.Note("Fenzi builds each agent's image on this machine. Install Docker or Podman, then run fenzi setup again.")
		return quietExit(3)
	} else {
		u.Done("Image builds", b.Bin)
	}
	return nil
}

// waitGateway gives a service that was just started time to accept
// connections.
// needsColimaConfig is true until a gateway config exists. Setup never edits one.
func needsColimaConfig() bool {
	_, err := os.Stat(openshell.GatewayConfig())
	return os.IsNotExist(err)
}

func startRuntime(e env, u *tui.UI, r openshell.Runtime) bool {
	if r.Attach {
		u.Blank()
		u.Println("  " + u.Dim("Running "+r.StartLine()+". It may ask for your password."))
		u.Blank()
		if err := openshell.StartRuntime(e.ctx, r, os.Stdin, e.stdout, e.stderr); err != nil {
			u.Problem(r.Name, err.Error())
			return false
		}
		u.Done(r.Name, "running")
		return true
	}
	_, err := u.Spin(r.Name, "starting, this can take a minute", func() (string, error) {
		return "running", openshell.StartRuntime(e.ctx, r, nil, nil, nil)
	})
	return err == nil
}

func waitGateway(e env, u *tui.UI, oc openshell.Client) bool {
	_, err := u.Spin("Gateway", "waiting for it to accept connections", func() (string, error) {
		var err error
		for range 30 {
			if err = oc.Ready(e.ctx); err == nil {
				return "connected", nil
			}
			time.Sleep(time.Second)
		}
		return "", fmt.Errorf("not connected after 30 seconds: %v", err)
	})
	return err == nil
}

func homeDir() string {
	home, _ := os.UserHomeDir()
	return home
}

func setupAgent(u *tui.UI, back bool) (agents.Entry, error) {
	all, err := agents.All()
	if err != nil {
		return agents.Entry{}, err
	}
	opts := make([]tui.Option, len(all))
	def := 0
	for i, a := range all {
		opts[i] = tui.Option{Label: a.Display, Hint: a.Version}
		if _, err := a.Profile(); err != nil {
			opts[i].Disabled = true
			opts[i].Hint = "not available yet"
		}
		if a.Name == "claude" {
			def = i
		}
	}
	i, err := u.Choose("Which agent should run in the sandbox?", opts, def, back)
	if err != nil {
		return agents.Entry{}, err
	}
	return all[i], nil
}

// confirmBack is Confirm with Esc going back.
func confirmBack(u *tui.UI, question, yes, no string, back bool) (bool, error) {
	i, err := u.Choose(question, []tui.Option{{Label: yes}, {Label: no}}, 0, back)
	return i == 0, err
}

func setupKey(e env, u *tui.UI, a agents.Entry, back bool) error {
	oc := client()
	u.Note("The key stays on this machine, in the sandbox runtime's credential store. Inside the sandbox the agent holds a placeholder. The real key is added only on calls to " + modelHost(a) + ".")
	u.Blank()

	stored, err := run.KeyStored(e.ctx, oc, a)
	if err != nil {
		u.Problem("Key", err.Error())
		return quietExit(1)
	}
	env := strings.TrimSpace(os.Getenv(a.Key.Env))
	for {
		// first is true when no question came before the paste prompt in
		// this step, so Esc there leaves the step.
		first := true
		if stored {
			keep, err := confirmBack(u, "A "+a.Display+" key is already stored. Keep it?", "Keep the stored key", "Replace it", back)
			if err != nil {
				return err
			}
			if keep {
				u.Done("Key", "stored on this machine")
				return nil
			}
			first = false
		} else if env != "" {
			use, err := confirmBack(u, a.Key.Env+" is set in this shell. Use it?", "Yes, store that key", "No, paste a different one", back)
			if err != nil {
				return err
			}
			if use {
				return storeKey(e, u, a, env)
			}
			first = false
		}
		err := pasteKey(e, u, a, back || !first)
		if errors.Is(err, tui.ErrBack) && !first {
			continue
		}
		return err
	}
}

func pasteKey(e env, u *tui.UI, a agents.Entry, back bool) error {
	for {
		v, err := u.AskSecret("Paste your "+a.Display+" API key ("+a.Key.Env+")", back)
		if err != nil {
			return err
		}
		if v == "" {
			u.Note("Nothing was pasted. A subscription login does not work here; the agent needs an API key.")
			continue
		}
		if err := storeKey(e, u, a, v); err == nil {
			return nil
		}
		again, err := u.Confirm("Try another key?", "Paste again", "Quit setup")
		if err != nil {
			return err
		}
		if !again {
			return quietExit(1)
		}
	}
}

func storeKey(e env, u *tui.UI, a agents.Entry, v string) error {
	_, err := u.Spin("Key", "storing", func() (string, error) {
		_, err := run.SetKey(e.ctx, client(), a, v)
		return "stored on this machine", err
	})
	return err
}

func modelHost(a agents.Entry) string {
	if len(a.Model) == 0 {
		return "the model's API"
	}
	return a.Model[0].Host
}

func setupProject(u *tui.UI, a agents.Entry, back bool) (string, error) {
	home, _ := os.UserHomeDir()
	def := ""
	if wd, err := cwd(); err == nil && workspace.CheckFolder(wd, home) == nil {
		def = tilde(wd, home)
	}
	u.Note("The agent works on a copy of this folder. .gitignore is respected and .git is left out. Your files change only when you run fenzi apply.")
	u.Blank()
	for {
		answer, err := u.Ask("Which folder should "+a.Display+" work in?", def, back)
		if err != nil {
			return "", err
		}
		if answer == "" {
			u.Note("Type a path, for example ~/code/web.")
			continue
		}
		dir := untilde(answer, home)
		if abs, err := filepath.Abs(dir); err == nil {
			dir = abs
		}
		if err := workspace.CheckFolder(dir, home); err != nil {
			u.Problem("Folder", err.Error()+". Pick one project folder; the sandbox gets a copy of it")
			continue
		}
		u.Done("Folder", tilde(dir, home))
		return dir, nil
	}
}

func setupImage(e env, u *tui.UI, dirs config.Dirs, a agents.Entry, back bool) (bool, error) {
	b, err := imageBuilder(e, nil)
	if err != nil {
		return false, err
	}
	if b.Exists(e.ctx, a.Tag()) {
		u.Done("Image", a.Tag()+", already built")
		return false, nil
	}
	u.Note("Each agent runs from an image built on this machine from a pinned Dockerfile, with " + a.Display + " " + a.Version + " from its vendor's package. The first build downloads its base layers.")
	u.Blank()
	build, err := confirmBack(u, "Build the "+a.Display+" image now?", "Yes, build it now", "Later, on the first run", back)
	if err != nil {
		return true, err
	}
	if !build {
		u.Skip("Image", "builds on the first run")
		return true, nil
	}
	return true, buildImage(e, u, dirs, a, b)
}

func buildImage(e env, u *tui.UI, dirs config.Dirs, a agents.Entry, b engine.Builder) error {
	df, err := a.Dockerfile()
	if err != nil {
		return err
	}
	logDir := filepath.Join(dirs.Cache, "builds")
	if err := os.MkdirAll(logDir, 0o700); err != nil {
		return err
	}
	logPath := filepath.Join(logDir, a.Name+".log")
	f, err := os.Create(logPath)
	if err != nil {
		return err
	}
	defer f.Close()
	b.Out = f
	if _, err := u.Spin("Image", "building "+a.Tag(), func() (string, error) {
		return a.Tag(), b.Build(e.ctx, a.Tag(), df)
	}); err != nil {
		u.Note("The build log is " + logPath)
		retry, err := u.Confirm("Continue without the image?", "Continue, build on the first run", "Quit setup")
		if err != nil {
			return err
		}
		if !retry {
			return quietExit(1)
		}
		u.Skip("Image", "builds on the first run")
	}
	return nil
}

func setupReady(e env, u *tui.UI, dirs config.Dirs, a agents.Entry, project string, back bool) (bool, error) {
	home := homeDir()
	lines := []string{
		row(u, "Agent", a.Display+" "+a.Version),
		row(u, "Folder", tilde(project, home)),
	}
	lines = append(lines, readyPolicy(e, u, dirs, a, project)...)
	u.Blank()
	u.Box("Ready", lines)
	u.Blank()
	return confirmBack(u, "Start "+a.Display+" now?", "Start it in "+tilde(project, home), "Not now", back)
}

// readyPolicy describes the policy fenzi run will use in project,
// resolved the way run resolves it: the signed team revision on a signed-in
// machine, else developer-default with the project's fenzi.yaml over it.
func readyPolicy(e env, u *tui.UI, dirs config.Dirs, a agents.Entry, project string) []string {
	quiet := env{ctx: e.ctx, stdin: e.stdin, stdout: io.Discard, stderr: io.Discard}
	resolved, err := resolvePolicy(quiet, dirs, project, "")
	if err == nil {
		// run compiles it before anything starts; a document that does not
		// compile stops run there.
		_, err = compiler.Compile(resolved.Doc, compiler.Target{Agent: a.CompilerAgent()})
	}
	if err != nil {
		msg := strings.Join(strings.Fields(err.Error()), " ")
		return []string{
			row(u, "Policy", u.Deny("cannot be used: ")+msg),
			strings.Repeat(" ", 10) + "fenzi run stops until it is fixed. fenzi policy check says why.",
		}
	}
	lines := []string{row(u, "Policy", resolved.Sources)}
	if resolved.TeamRevision > 0 {
		if _, err := os.Stat(filepath.Join(project, run.ProjectFile)); err == nil {
			lines = append(lines, strings.Repeat(" ", 10)+u.Dim(run.ProjectFile+" in this folder is not used; the team policy applies"))
		}
	}
	lines = append(lines, "", u.Allow(fmt.Sprintf("%-9s", "Reaches"))+" "+modelHost(a)+", with your key")
	for _, h := range resolved.Doc.WithDefaults().Hosts {
		host := h.Host
		if h.Port != 443 {
			host += fmt.Sprintf(":%d", h.Port)
		}
		access := h.Access
		if len(h.Allow) > 0 {
			access += ": " + strings.Join(h.Allow, ", ")
		}
		lines = append(lines, strings.Repeat(" ", 10)+host+", "+access)
	}
	return append(lines,
		u.Deny(fmt.Sprintf("%-9s", "Waits"))+" any other host, until you approve it",
		u.Dim(fmt.Sprintf("%-9s", "Never"))+" your home folder or the real key",
	)
}

func setupFinish(e env, u *tui.UI, a agents.Entry, project string, start bool, release func()) error {
	home := homeDir()
	if !start {
		u.Blank()
		u.Println("  " + u.Bold("When you are ready"))
		u.Blank()
		u.Command("cd "+shellPath(tilde(project, home)), "")
		u.Command("fenzi run", "")
		u.Note("Or type fenzi on its own for a menu.")
		setupAfter(u)
		return nil
	}
	setupAfter(u)
	u.Blank()
	if err := os.Chdir(project); err != nil {
		return err
	}
	release()
	code, err := cmdRun(e, []string{a.Name})
	if err != nil {
		return err
	}
	if code != 0 {
		return quietExit(code)
	}
	return nil
}

func setupAfter(u *tui.UI) {
	u.Blank()
	u.Println("  " + u.Bold("While the agent works, in another terminal"))
	u.Blank()
	u.Commands(
		[2]string{"fenzi requests", "what it asked for; approve or deny each one"},
		[2]string{"fenzi log --deny", "what was blocked"},
	)
	u.Blank()
	u.Println("  " + u.Bold("When it exits"))
	u.Blank()
	u.Note("Fenzi shows what the agent changed and asks before anything is copied into your folder. Then it asks whether to keep the sandbox running. Keeping it leaves the session and its approvals in place; fenzi connect opens the agent again, and fenzi stop ends it.")
	if p := os.Getenv("FENZI_PATH_PROFILE"); p != "" && !onPath() {
		u.Blank()
		u.Note("The installer added fenzi to PATH in " + p + ". Open a new terminal, or run this, so the current one finds it:")
		u.Command("source "+p, "")
	} else if !onPath() {
		u.Blank()
		u.Note("Your shell cannot find fenzi yet. Add its folder to PATH:")
		if exe, err := os.Executable(); err == nil {
			u.Command(`export PATH="`+filepath.Dir(exe)+`:$PATH"`, "")
		}
	}
	u.Blank()
	u.Println("  " + u.Dim("Docs: https://fenzi.dev/docs"))
}

func row(u *tui.UI, label, value string) string {
	return u.Dim(fmt.Sprintf("%-9s", label)) + " " + value
}

func onPath() bool {
	found, err := exec.LookPath("fenzi")
	if err != nil {
		return false
	}
	exe, err := os.Executable()
	if err != nil {
		return true
	}
	a, _ := filepath.EvalSymlinks(found)
	b, _ := filepath.EvalSymlinks(exe)
	return a == b
}

func tilde(p, home string) string {
	if home != "" && (p == home || strings.HasPrefix(p, home+string(filepath.Separator))) {
		return "~" + p[len(home):]
	}
	return p
}

func untilde(p, home string) string {
	if p == "~" {
		return home
	}
	if strings.HasPrefix(p, "~/") {
		return filepath.Join(home, p[2:])
	}
	return p
}

func shellPath(p string) string {
	if strings.ContainsAny(p, " '\"$`\\") {
		return "'" + strings.ReplaceAll(p, "'", `'\''`) + "'"
	}
	return p
}

// setupNeeded is true on a terminal before setup has finished once.
func setupNeeded(e env) bool {
	if !tui.New(e.stdin, e.stdout).Interactive() {
		return false
	}
	dirs, err := config.Default()
	if err != nil {
		return false
	}
	_, done := dirs.LoadSetup()
	return !done
}
