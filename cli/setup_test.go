package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"fenzi/agents"
	"fenzi/cli/internal/config"
	"fenzi/cli/internal/openshell"
	"fenzi/cli/internal/tui"
)

func TestReadyNamesThePolicyRunWillUse(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	dirs, err := config.Default()
	if err != nil {
		t.Fatal(err)
	}
	claude, err := agents.Get("claude")
	if err != nil {
		t.Fatal(err)
	}
	project := t.TempDir()
	ready := func() string {
		var out bytes.Buffer
		u := tui.New(strings.NewReader("2\n"), &out)
		start, err := setupReady(env{ctx: context.Background(), stdin: strings.NewReader(""), stdout: &out, stderr: &out}, u, dirs, claude, project, false)
		if err != nil || start {
			t.Fatalf("start %v, err %v\n%s", start, err, out.String())
		}
		return out.String()
	}

	out := ready()
	if !strings.Contains(out, "developer-default (built in)") || strings.Contains(out, "fenzi.yaml") || !strings.Contains(out, "api.github.com, read-only") {
		t.Errorf("without a project file:\n%s", out)
	}

	file := "version: 1\nhosts:\n  - host: api.stripe.com\n    access: read-only\n  - host: api.example.com\n    port: 8443\n    access: read-write\n    allow:\n      - POST /v1/things\n"
	if err := os.WriteFile(filepath.Join(project, "fenzi.yaml"), []byte(file), 0o644); err != nil {
		t.Fatal(err)
	}
	out = ready()
	for _, want := range []string{"developer-default (built in) + ./fenzi.yaml", "api.stripe.com, read-only", "api.example.com:8443, read-write: POST /v1/things", "api.github.com, read-only"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}

	if err := os.WriteFile(filepath.Join(project, "fenzi.yaml"), []byte("version: 1\nhosts:\n  - host: x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if out = ready(); !strings.Contains(out, "cannot be used") || !strings.Contains(out, "fenzi run stops until it is fixed") {
		t.Errorf("a broken project file:\n%s", out)
	}
}

func TestTilde(t *testing.T) {
	home := "/Users/ana"
	cases := map[string]string{"/Users/ana/web": "~/web", "/Users/ana": "~", "/Users/anabel": "/Users/anabel", "/tmp": "/tmp"}
	for in, want := range cases {
		if got := tilde(in, home); got != want {
			t.Errorf("tilde(%q) = %q, want %q", in, got, want)
		}
	}
	if got := untilde("~/web", home); got != "/Users/ana/web" {
		t.Errorf("untilde: %q", got)
	}
	if got := shellPath("~/my code"); got != "'~/my code'" {
		t.Errorf("shellPath: %q", got)
	}
}

func TestBareCommandShowsHelpWithoutATerminal(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	var out bytes.Buffer
	if code := cli(nil, strings.NewReader(""), &out, &out); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(out.String(), "setup") || strings.Contains(out.String(), "This machine") {
		t.Fatalf("expected help, got:\n%s", out.String())
	}
}

// upgradeFake answers `openshell --version` in the 0.1.2 shape with the
// release installed, which the fake installer moves to InstallVersion.
func upgradeFake(t *testing.T, version string, install error) (*openshell.Fake, *int, *int) {
	t.Helper()
	installs, restarts := 0, 0
	fake := &openshell.Fake{Answer: func(args []string) (string, bool) {
		if strings.Join(args, " ") == "--version" {
			return "openshell " + version + "\n", true
		}
		return "", false
	}}
	oldInstall, oldService, oldRestart := installOpenShell, gatewayService, restartGateway
	t.Cleanup(func() { installOpenShell, gatewayService, restartGateway = oldInstall, oldService, oldRestart })
	installOpenShell = func(context.Context, io.Reader, io.Writer, io.Writer) error {
		installs++
		if install == nil {
			version = openshell.InstallVersion
		}
		return install
	}
	gatewayService = func(verb string) []string { return []string{"brew", "services", verb, "openshell"} }
	restartGateway = func(context.Context) error { restarts++; return nil }
	return fake, &installs, &restarts
}

func TestSetupOffersTheUpgrade(t *testing.T) {
	upgrade := func(fake *openshell.Fake, answers string) string {
		t.Helper()
		var out bytes.Buffer
		u := tui.New(strings.NewReader(answers), &out)
		if err := setupUpgrade(env{ctx: context.Background(), stdout: &out, stderr: &out}, u, openshell.Client{R: fake}); err != nil {
			t.Fatalf("%v\n%s", err, out.String())
		}
		return out.String()
	}

	// 0.1.0 is older than any InstallVersion this pin can have.
	fake, installs, restarts := upgradeFake(t, "0.1.0", nil)
	out := upgrade(fake, "1\n")
	flat := strings.Join(strings.Fields(out), " ")
	for _, want := range []string{
		"OpenShell 0.1.0 is installed",
		"The upgrade restarts the gateway. No sandbox is running, so nothing is interrupted.",
		"Upgrade OpenShell to " + openshell.InstallVersion + " now?",
		"OpenShell " + openshell.InstallVersion,
		"service restarted",
	} {
		if !strings.Contains(flat, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if !strings.Contains(out, openshell.InstallCommand()) {
		t.Errorf("the installer line is not shown:\n%s", out)
	}
	if strings.Index(flat, "restarts the gateway") < 0 || strings.Index(flat, "restarts the gateway") > strings.Index(flat, "Upgrade OpenShell to") {
		t.Errorf("the restart is said after the question:\n%s", out)
	}
	if *installs != 1 || *restarts != 1 {
		t.Errorf("installs %d, restarts %d, want 1 and 1", *installs, *restarts)
	}

	fake, installs, restarts = upgradeFake(t, "0.1.0", nil)
	out = upgrade(fake, "2\n")
	if *installs != 0 || *restarts != 0 || !strings.Contains(out, "Setup goes on with OpenShell 0.1.0") {
		t.Errorf("no: installs %d, restarts %d:\n%s", *installs, *restarts, out)
	}

	fake, installs, restarts = upgradeFake(t, "0.1.0", errors.New("the OpenShell installer failed: exit status 1"))
	out = upgrade(fake, "1\n1\n1\n2\n")
	if *installs != 2 || *restarts != 0 || !strings.Contains(out, "the OpenShell installer failed") {
		t.Errorf("a failed install, tried twice: installs %d, restarts %d:\n%s", *installs, *restarts, out)
	}

	fake, installs, _ = upgradeFake(t, openshell.InstallVersion, nil)
	out = upgrade(fake, "")
	if *installs != 0 || strings.Contains(out, "Upgrade OpenShell") {
		t.Errorf("up to date: installs %d:\n%s", *installs, out)
	}

	// Where setup knows no service manager it says so instead of restarting.
	fake, installs, restarts = upgradeFake(t, "0.1.0", nil)
	gatewayService = func(string) []string { return nil }
	out = upgrade(fake, "1\n")
	if *installs != 1 || *restarts != 0 || !strings.Contains(strings.Join(strings.Fields(out), " "), "cannot restart it") {
		t.Errorf("no service manager: installs %d, restarts %d:\n%s", *installs, *restarts, out)
	}
}

func TestRestartWarningNamesRunningSandboxes(t *testing.T) {
	// The table `sandbox list --selector fenzi=1` printed in 0.1.2. A sandbox
	// in phase Error is not running, so a restart interrupts nothing in it.
	const header = "NAME                 CREATED              PHASE\n"
	for _, c := range []struct {
		name  string
		reply openshell.Reply
		want  string
	}{
		{"none", openshell.Reply{Out: "No sandboxes found.\n"}, "No sandbox is running, so nothing is interrupted."},
		{"only lost", openshell.Reply{Out: header + "fenzi-rs-brain-8a52  2026-10-17 19:20:02  Error\n"}, "No sandbox is running, so nothing is interrupted."},
		{"one", openshell.Reply{Out: header + "fenzi-rs-brain-8a52  2026-10-17 19:20:02  Error\nfenzi-web-1a2b       2026-10-17 19:32:52  Ready\n"},
			"This sandbox keeps its files but its open session ends: fenzi-web-1a2b. Resume it afterwards with fenzi connect."},
		{"several", openshell.Reply{Out: header + "fenzi-web-1a2b       2026-10-17 19:32:52  Ready\nfenzi-api-3c4d       2026-10-17 19:40:11  Ready\n"},
			"These sandboxes keep their files but their open sessions end: fenzi-web-1a2b, fenzi-api-3c4d. Resume them afterwards with fenzi connect."},
		{"no gateway", openshell.Reply{Exit: 1, Stderr: "connection refused"}, "The upgrade restarts the gateway, which ends the sessions in running sandboxes."},
	} {
		oc := openshell.Client{R: &openshell.Fake{Replies: map[string]openshell.Reply{"sandbox list --selector fenzi=1": c.reply}}}
		got := restartWarning(context.Background(), oc)
		if !strings.HasPrefix(got, "The upgrade restarts the gateway") || !strings.HasSuffix(got, c.want) {
			t.Errorf("%s: %q, want it to end %q", c.name, got, c.want)
		}
	}

	// setup shows the names before it asks.
	fake, _, _ := upgradeFake(t, "0.1.0", nil)
	fake.Replies = map[string]openshell.Reply{"sandbox list --selector fenzi=1": {Out: header + "fenzi-web-1a2b       2026-10-17 19:32:52  Ready\n"}}
	var out bytes.Buffer
	u := tui.New(strings.NewReader("2\n"), &out)
	if err := setupUpgrade(env{ctx: context.Background(), stdout: &out, stderr: &out}, u, openshell.Client{R: fake}); err != nil {
		t.Fatal(err)
	}
	flat := strings.Join(strings.Fields(out.String()), " ")
	if at, ask := strings.Index(flat, "open session ends: fenzi-web-1a2b"), strings.Index(flat, "Upgrade OpenShell to"); at < 0 || at > ask {
		t.Errorf("the running sandbox is not named before the question:\n%s", out.String())
	}
}

func TestSetupRuntimeUpgradesOnlyWithNothingRunning(t *testing.T) {
	const header = "NAME                 CREATED              PHASE\n"
	upgrade := func(fake *openshell.Fake) (string, string, bool) {
		t.Helper()
		var out bytes.Buffer
		u := tui.ForOutput(&out)
		v, ok := runtimeUpgrade(env{ctx: context.Background(), stdout: &out, stderr: &out}, u, openshell.Client{R: fake}, "openshell 0.1.0\n")
		return strings.Join(strings.Fields(out.String()), " "), v, ok
	}

	// Nothing running: it upgrades, restarts the gateway, and reports the new release.
	fake, installs, restarts := upgradeFake(t, "0.1.0", nil)
	fake.Replies = map[string]openshell.Reply{"sandbox list --selector fenzi=1": {Out: header}}
	out, v, ok := upgrade(fake)
	if !ok || v != openshell.InstallVersion || *installs != 1 || *restarts != 1 {
		t.Fatalf("ok %v, version %q, %d installs, %d restarts:\n%s", ok, v, *installs, *restarts, out)
	}
	if !strings.Contains(out, "No sandbox is running, so nothing is interrupted") {
		t.Errorf("the upgrade does not say why it is safe:\n%s", out)
	}

	// A sandbox running: it keeps the installed release and names the sandbox.
	fake, installs, _ = upgradeFake(t, "0.1.0", nil)
	fake.Replies = map[string]openshell.Reply{"sandbox list --selector fenzi=1": {Out: header + "fenzi-web-1a2b       2026-10-17 19:32:52  Ready\n"}}
	out, _, ok = upgrade(fake)
	if ok || *installs != 0 || !strings.Contains(out, "fenzi-web-1a2b") || !strings.Contains(out, "Setup keeps it") {
		t.Fatalf("ok %v, %d installs:\n%s", ok, *installs, out)
	}

	// The sandboxes cannot be listed: it keeps the installed release.
	fake, installs, _ = upgradeFake(t, "0.1.0", nil)
	fake.Replies = map[string]openshell.Reply{"sandbox list --selector fenzi=1": {Exit: 1, Stderr: "Error: connection refused\n"}}
	out, _, ok = upgrade(fake)
	if ok || *installs != 0 || !strings.Contains(out, "could not be listed") {
		t.Fatalf("ok %v, %d installs:\n%s", ok, *installs, out)
	}

	// The installer fails: it goes on with the installed release.
	fake, installs, _ = upgradeFake(t, "0.1.0", errors.New("download failed"))
	fake.Replies = map[string]openshell.Reply{"sandbox list --selector fenzi=1": {Out: header}}
	out, _, ok = upgrade(fake)
	if ok || *installs != 1 || !strings.Contains(out, "the upgrade failed: download failed") || !strings.Contains(out, "goes on with OpenShell 0.1.0") {
		t.Fatalf("ok %v, %d installs:\n%s", ok, *installs, out)
	}

	// The pinned release: nothing to do, and the sandboxes are not even listed.
	fake, installs, _ = upgradeFake(t, openshell.InstallVersion, nil)
	var buf bytes.Buffer
	if _, ok := runtimeUpgrade(env{ctx: context.Background(), stdout: &buf, stderr: &buf}, tui.ForOutput(&buf), openshell.Client{R: fake}, "openshell "+openshell.InstallVersion+"\n"); ok || *installs != 0 || buf.Len() != 0 {
		t.Fatalf("ok %v, %d installs:\n%s", ok, *installs, buf.String())
	}
}

// setup --runtime on a Mac whose runtime is colima: the colima setting is
// written before the upstream installer runs, so the installer's own
// gateway start finds a driver instead of waiting 30 s and failing, as it
// did on a clean Mac on 19 October 2026.
func TestSetupRuntimeFinishesTheColimaGateway(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("setup writes the colima setting before the install on macOS only")
	}
	fake, _, _ := upgradeFake(t, openshell.InstallVersion, errors.New("the OpenShell installer failed: exit status 1"))
	ready := false
	fake.Replies = map[string]openshell.Reply{
		"sandbox list --selector fenzi=1": {Out: "NAME                 CREATED              PHASE\n"},
	}
	fake.Answer = func(args []string) (string, bool) {
		switch strings.Join(args, " ") {
		case "--version":
			return "openshell " + openshell.InstallVersion + "\n", true
		case "status --output json", "status -o json":
			if ready {
				return `{"status":"connected","authentication":{"status":"authenticated"},"version":"0.1.4"}`, true
			}
			return `{"status":"disconnected"}`, true
		}
		return "", false
	}
	installed := false
	written := ""
	oldInstalled, oldSocket, oldDue, oldWrite, oldClient := runtimeInstalled, colimaSocket, colimaConfigDue, writeColima, newClient
	t.Cleanup(func() {
		runtimeInstalled, colimaSocket, colimaConfigDue, writeColima, newClient = oldInstalled, oldSocket, oldDue, oldWrite, oldClient
	})
	runtimeInstalled = func() bool { return installed }
	colimaSocket = func() string { return "/Users/ana/.colima/default/docker.sock" }
	colimaConfigDue = func() bool { return written == "" }
	writeColima = func(sock string) error {
		written = sock
		// The setting is written before the installer runs, so the
		// installer's own gateway start finds a driver.
		if installed {
			t.Error("the colima setting was written after the install")
		}
		return nil
	}
	newClient = func() openshell.Client { return openshell.Client{R: fake} }
	oldDiagnose := diagnoseRuntime
	t.Cleanup(func() { diagnoseRuntime = oldDiagnose })
	diagnoseRuntime = func() openshell.Diagnosis {
		return openshell.Diagnosis{Running: []openshell.Runtime{{Name: "colima", Running: true}}}
	}
	oldInstall := installOpenShell
	installOpenShell = func(ctx context.Context, in io.Reader, out, errw io.Writer) error {
		installed = true
		if written != "" {
			// With the setting in place the installer's own start works.
			ready = true
			return nil
		}
		return oldInstall(ctx, in, out, errw)
	}
	oldRestart := restartGateway
	restartGateway = func(ctx context.Context) error { ready = true; return oldRestart(ctx) }

	var out bytes.Buffer
	code, err := setupRuntime(env{ctx: context.Background(), stdout: &out, stderr: &out})
	if err != nil || code != 0 {
		t.Fatalf("code %d, %v:\n%s", code, err, out.String())
	}
	text := strings.Join(strings.Fields(out.String()), " ")
	if !installed || written != "/Users/ana/.colima/default/docker.sock" {
		t.Fatalf("installed %v, config for %q:\n%s", installed, written, out.String())
	}
	for _, want := range []string{"before the install", "Gateway connected"} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q:\n%s", want, out.String())
		}
	}
}

func TestUpdateRefusesTheAppsOwnCopy(t *testing.T) {
	if !inAppBundle("/Applications/Fenzi.app/Contents/Resources/fenzi") {
		t.Error("the app's copy is not recognised")
	}
	if inAppBundle("/Users/ana/.local/bin/fenzi") || inAppBundle("/usr/local/bin/fenzi") {
		t.Error("an installed copy is taken for the app's")
	}
	// The link the app makes for Terminal resolves to the app's copy.
	dir := t.TempDir()
	app := filepath.Join(dir, "Fenzi.app", "Contents", "Helpers")
	if err := os.MkdirAll(app, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(app, "fenzi"), nil, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "fenzi")
	if err := os.Symlink(filepath.Join(app, "fenzi"), link); err != nil {
		t.Fatal(err)
	}
	if !inAppBundle(resolved(link)) {
		t.Error("the Terminal link is not followed to the app's copy")
	}
}

// A runtime that is installed and stopped is started by setup --runtime,
// colima before Docker Desktop, with no question.
func TestSetupRuntimeStartsAStoppedRuntime(t *testing.T) {
	old, oldStart := diagnoseRuntime, startContainer
	t.Cleanup(func() { diagnoseRuntime, startContainer = old, oldStart })
	diagnoseRuntime = func() openshell.Diagnosis {
		return openshell.Diagnosis{Stopped: []openshell.Runtime{
			{Name: "Docker Desktop", Start: []string{"open", "-a", "Docker"}},
			{Name: "colima", Start: []string{"colima", "start"}},
		}}
	}
	var got string
	startContainer = func(_ context.Context, r openshell.Runtime, _ io.Reader, _, _ io.Writer) error {
		got = r.Name
		return errors.New("colima start: exit status 1")
	}
	var out bytes.Buffer
	code, err := setupRuntime(env{ctx: context.Background(), stdout: &out, stderr: &out})
	if got != "colima" {
		t.Fatalf("started %q:\n%s", got, out.String())
	}
	if code != 3 || err == nil || !strings.Contains(err.Error(), "colima start") {
		t.Fatalf("a failed start ends setup with its error: code %d, %v", code, err)
	}
	if !strings.Contains(out.String(), "colima is not running. Starting it for the sandboxes:") {
		t.Errorf("no note before the start:\n%s", out.String())
	}
}

// A start that asks for a password is left to the person.
func TestSetupRuntimeLeavesASudoStart(t *testing.T) {
	old, oldStart := diagnoseRuntime, startContainer
	t.Cleanup(func() { diagnoseRuntime, startContainer = old, oldStart })
	diagnoseRuntime = func() openshell.Diagnosis {
		return openshell.Diagnosis{Stopped: []openshell.Runtime{{Name: "Docker Engine", Start: []string{"sudo", "systemctl", "start", "docker"}, Attach: true}}}
	}
	startContainer = func(context.Context, openshell.Runtime, io.Reader, io.Writer, io.Writer) error {
		t.Fatal("setup --runtime ran sudo")
		return nil
	}
	var out bytes.Buffer
	code, err := setupRuntime(env{ctx: context.Background(), stdout: &out, stderr: &out})
	if code != 3 || err == nil || !strings.Contains(err.Error(), "Start it with sudo systemctl start docker and try again") {
		t.Fatalf("code %d, %v", code, err)
	}
}

// A Mac with no container runtime gets colima from Homebrew, then starts it.
func TestSetupRuntimeInstallsColima(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("setup installs colima on macOS only")
	}
	old, oldStart, oldCan, oldInstall := diagnoseRuntime, startContainer, canInstallColima, installColima
	t.Cleanup(func() {
		diagnoseRuntime, startContainer, canInstallColima, installColima = old, oldStart, oldCan, oldInstall
	})
	installed, started := false, ""
	diagnoseRuntime = func() openshell.Diagnosis {
		if !installed {
			return openshell.Diagnosis{None: true}
		}
		return openshell.Diagnosis{Stopped: []openshell.Runtime{{Name: "colima", Start: []string{"colima", "start"}}}}
	}
	canInstallColima = func() bool { return true }
	installColima = func(context.Context, io.Reader, io.Writer, io.Writer) error { installed = true; return nil }
	startContainer = func(_ context.Context, r openshell.Runtime, _ io.Reader, _, _ io.Writer) error {
		started = r.Name
		return errors.New("stop here")
	}
	var out bytes.Buffer
	if _, err := setupRuntime(env{ctx: context.Background(), stdout: &out, stderr: &out}); err == nil || !installed || started != "colima" {
		t.Fatalf("installed %v, started %q, %v:\n%s", installed, started, err, out.String())
	}

	// No Homebrew: the error names it, so the app shows its Homebrew step.
	installed = false
	canInstallColima = func() bool { return false }
	installColima = func(context.Context, io.Reader, io.Writer, io.Writer) error {
		t.Fatal("installed with no Homebrew")
		return nil
	}
	if code, err := setupRuntime(env{ctx: context.Background(), stdout: &out, stderr: &out}); code != 3 || err == nil || !strings.Contains(err.Error(), "Homebrew") {
		t.Fatalf("code %d, %v", code, err)
	}
}
