package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"fenzi/cli/internal/config"
	"fenzi/cli/internal/service"
	"fenzi/cli/internal/team"
	"fenzi/cli/internal/tui"
	"fenzi/teamapi"
)

// No test in this package may run launchctl or systemctl, or write to the
// real ~/Library/LaunchAgents: every test gets a fake service manager with
// nothing installed. useFakeManager gives a test one it can look at.
func init() {
	newServiceManager = func() (service.Manager, error) { return &fakeManager{}, nil }
}

type fakeManager struct {
	mu        sync.Mutex
	installed bool
	running   bool
	detail    string
	spec      service.Spec
	installs  int
	removes   int
}

func (f *fakeManager) Kind() string { return "launchd agent" }
func (f *fakeManager) Path() string { return "/fake/LaunchAgents/dev.fenzi.forward.plist" }

func (f *fakeManager) Install(_ context.Context, s service.Spec) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.spec, f.installed, f.running = s, true, true
	f.installs++
	return nil
}

func (f *fakeManager) Remove(context.Context) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	had := f.installed
	f.installed, f.running = false, false
	f.removes++
	return had, nil
}

func (f *fakeManager) Status(context.Context) (service.Status, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return service.Status{Installed: f.installed, Loaded: f.installed, Running: f.running, Detail: f.detail}, nil
}

func useFakeManager(t *testing.T) *fakeManager {
	t.Helper()
	f := &fakeManager{}
	prev := newServiceManager
	newServiceManager = func() (service.Manager, error) { return f, nil }
	t.Cleanup(func() { newServiceManager = prev })
	return f
}

// syncBuffer is standard output for a command that runs in a goroutine.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func signedInMachine(t *testing.T) (*refusingConsole, config.Dirs) {
	t.Helper()
	fakeRuntime(t, nil, "")
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	console := &refusingConsole{bundle: teamapi.ToWire(signed(key, 2))}
	srv := httptest.NewServer(console)
	t.Cleanup(srv.Close)
	return console, enrollCached(t, srv.URL, key)
}

func TestForwardInstallNeedsASignIn(t *testing.T) {
	fakeRuntime(t, nil, "")
	f := useFakeManager(t)
	out, code := runCLI(t, "", "forward", "--install")
	if code != 1 || !strings.Contains(out, "sign in first (fenzi login)") || f.installs != 0 {
		t.Fatalf("exit %d installs %d\n%s", code, f.installs, out)
	}
}

func TestForwardInstallRunsThisBinaryInTheBackground(t *testing.T) {
	_, dirs := signedInMachine(t)
	f := useFakeManager(t)
	out, code := runCLI(t, "", "forward", "--install")
	if code != 0 || !strings.Contains(out, "runs in the background as a launchd agent") || !strings.Contains(out, "fenzi forward --uninstall") {
		t.Fatalf("exit %d\n%s", code, out)
	}
	exe, _ := os.Executable()
	exe, _ = filepath.Abs(exe)
	if f.spec.Binary != exe || !reflect.DeepEqual(f.spec.Args, []string{"forward", "--service"}) {
		t.Fatalf("spec %+v, want %s forward --service", f.spec, exe)
	}
	if f.spec.Log != filepath.Join(dirs.Cache, "forward.log") {
		t.Fatalf("log %s", f.spec.Log)
	}
	// The service reads the same sign-in and finds the same openshell.
	env := strings.Join(f.spec.Env, "\n")
	for _, want := range []string{"PATH=" + os.Getenv("PATH"), "XDG_CONFIG_HOME=" + os.Getenv("XDG_CONFIG_HOME"), "XDG_CACHE_HOME=" + os.Getenv("XDG_CACHE_HOME")} {
		if !strings.Contains(env, want) {
			t.Errorf("service environment lacks %s:\n%s", want, env)
		}
	}

	out, code = runCLI(t, "", "forward", "--uninstall")
	if code != 0 || !strings.Contains(out, "stopped and removed") || f.installed {
		t.Fatalf("uninstall: exit %d installed %v\n%s", code, f.installed, out)
	}
	if out, _ := runCLI(t, "", "forward", "--uninstall"); !strings.Contains(out, "was not installed") {
		t.Fatalf("second uninstall:\n%s", out)
	}
	if out, code := runCLI(t, "", "forward", "--install", "--uninstall"); code != 1 || !strings.Contains(out, "choose --install or --uninstall") {
		t.Fatalf("both: exit %d\n%s", code, out)
	}
}

func TestStatusAndDoctorReportTheForwarder(t *testing.T) {
	_, _ = signedInMachine(t)
	f := useFakeManager(t)

	out, _ := runCLI(t, "", "status")
	if !strings.Contains(out, "only while fenzi run or fenzi forward runs. fenzi forward --install keeps it running") {
		t.Fatalf("not installed:\n%s", out)
	}
	f.installed, f.running = true, true
	out, _ = runCLI(t, "", "status")
	if !strings.Contains(out, "Forwarder") || !strings.Contains(out, "in the background, launchd agent, running") {
		t.Fatalf("running:\n%s", out)
	}
	var doc jsonStatus
	if stderr, code := runJSON(t, &doc, "status", "--json"); code != 0 || doc.Forwarder == nil ||
		!doc.Forwarder.Installed || !doc.Forwarder.Running || doc.Forwarder.Manager != "launchd agent" {
		t.Fatalf("json: exit %d stderr %q %+v", code, stderr, doc.Forwarder)
	}

	f.running, f.detail = false, "last exit code 1"
	out, _ = runCLI(t, "", "status")
	if !strings.Contains(out, "installed, not running: last exit code 1. Log: ") || !strings.Contains(out, "forward.log") {
		t.Fatalf("stopped:\n%s", out)
	}
	out, _ = runCLI(t, "", "doctor")
	if !strings.Contains(out, "installed, not running: last exit code 1") {
		t.Fatalf("doctor:\n%s", out)
	}
	var dd jsonDoctor
	runJSON(t, &dd, "doctor", "--json")
	found := false
	for _, c := range dd.Checks {
		if c.Name == "Forwarder" {
			found = c.Status == "fail"
		}
	}
	if !found {
		t.Fatalf("doctor --json has no failed Forwarder check: %+v", dd.Checks)
	}
}

// On Free there is nothing to forward, and doctor says nothing about it.
func TestDoctorOnFreeLeavesTheForwarderOut(t *testing.T) {
	fakeRuntime(t, nil, "")
	out, _ := runCLI(t, "", "doctor")
	if strings.Contains(out, "Forwarder") {
		t.Fatalf("Free doctor mentions the forwarder:\n%s", out)
	}
}

// Signing in without a terminal (the Mac app, a script) does not ask; it
// names the command.
func TestOfferForwarderWithoutATerminalOnlyNamesTheCommand(t *testing.T) {
	_, dirs := signedInMachine(t)
	f := useFakeManager(t)
	var out bytes.Buffer
	e := env{ctx: context.Background(), stdin: strings.NewReader("y\n"), stdout: &out, stderr: &out}
	offerForwarder(e, newUI(e), dirs)
	if f.installs != 0 || !strings.Contains(out.String(), "fenzi forward --install") {
		t.Fatalf("installs %d\n%s", f.installs, out.String())
	}
	// Already installed: nothing to offer.
	f.installed = true
	out.Reset()
	offerForwarder(e, newUI(e), dirs)
	if out.Len() != 0 {
		t.Fatalf("offered again:\n%s", out.String())
	}
}

func TestLogoutRemovesTheForwarder(t *testing.T) {
	_, dirs := signedInMachine(t)
	f := useFakeManager(t)
	f.installed, f.running = true, true
	out, code := runCLI(t, "", "logout")
	if code != 0 || !strings.Contains(out, "the background forwarder is stopped and removed") || f.installed {
		t.Fatalf("exit %d installed %v\n%s", code, f.installed, out)
	}
	if _, err := team.Load(dirs); !errors.Is(err, team.ErrNotEnrolled) {
		t.Fatalf("still signed in: %v", err)
	}
}

// A pass in flight saves the sign-in back when it ends. Logout waits for it.
func TestLogoutWaitsForAPassInFlight(t *testing.T) {
	_, dirs := signedInMachine(t)
	unlock, err := lockRelay(context.Background(), dirs, 0)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan int)
	go func() {
		_, code := runCLI(t, "", "logout")
		done <- code
	}()
	time.Sleep(150 * time.Millisecond)
	if _, err := team.Load(dirs); err != nil {
		t.Fatalf("logout did not wait for the pass: %v", err)
	}
	unlock()
	if code := <-done; code != 0 {
		t.Fatalf("logout exit %d", code)
	}
	if _, err := team.Load(dirs); !errors.Is(err, team.ErrNotEnrolled) {
		t.Fatalf("still signed in: %v", err)
	}
}

// A pass that read the sign-in, then waited while fenzi logout ran, must not
// save the sign-in back.
func TestAPassAfterLogoutDoesNotSignBackIn(t *testing.T) {
	console, dirs := signedInMachine(t)
	unlock, err := lockRelay(context.Background(), dirs, 0)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error)
	go func() {
		_, err := relayOnceWait(context.Background(), quietEnv(), 5*time.Second)
		done <- err
	}()
	time.Sleep(150 * time.Millisecond)
	if err := team.Clear(dirs); err != nil {
		t.Fatal(err)
	}
	unlock()
	if err := <-done; !errors.Is(err, errSignIn) {
		t.Fatalf("pass after logout: %v", err)
	}
	if _, err := team.Load(dirs); !errors.Is(err, team.ErrNotEnrolled) {
		t.Fatalf("the pass signed the machine back in: %v", err)
	}
	if n := console.beatCount(); n != 0 {
		t.Fatalf("%d heartbeats after logout", n)
	}
}

func TestOneForwarderAtATime(t *testing.T) {
	poll := forwarderPoll
	forwarderPoll = 10 * time.Millisecond
	t.Cleanup(func() { forwarderPoll = poll })
	dirs := config.Dirs{Config: t.TempDir()}

	if _, running := forwarderHolder(dirs); running {
		t.Fatal("a forwarder runs before any started")
	}
	first, ok, err := tryForwarder(dirs, holderService)
	if err != nil || !ok {
		t.Fatalf("first: ok %v err %v", ok, err)
	}
	if _, ok, err := tryForwarder(dirs, holderRun); err != nil || ok {
		t.Fatalf("second while the first runs: ok %v err %v", ok, err)
	}
	if who, running := forwarderHolder(dirs); !running || who != holderService {
		t.Fatalf("holder %q running %v", who, running)
	}

	// A forwarder that waits is told who forwards, once, and takes over.
	var told []string
	go func() {
		time.Sleep(100 * time.Millisecond)
		first()
	}()
	second, err := holdForwarder(context.Background(), dirs, holderForward, func(other string) { told = append(told, other) })
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(told, []string{holderService}) {
		t.Fatalf("told %q", told)
	}
	if who, _ := forwarderHolder(dirs); who != holderForward {
		t.Fatalf("holder %q after the takeover", who)
	}
	second()
	if _, running := forwarderHolder(dirs); running {
		t.Fatal("still running after release")
	}

	// A wait ends with its context.
	third, _, _ := tryForwarder(dirs, holderService)
	defer third()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := holdForwarder(ctx, dirs, holderForward, nil); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err %v", err)
	}
}

// fenzi forward in a terminal (or the Mac app's) waits while the background
// forwarder runs, and takes over when it stops.
func TestForwardWaitsWhileTheServiceForwards(t *testing.T) {
	console, dirs := signedInMachine(t)
	poll := forwarderPoll
	forwarderPoll = 10 * time.Millisecond
	t.Cleanup(func() { forwarderPoll = poll })
	release, ok, err := tryForwarder(dirs, holderService)
	if err != nil || !ok {
		t.Fatal(ok, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	out := &syncBuffer{}
	done := make(chan int)
	go func() {
		code, _ := cmdForward(env{ctx: ctx, stdin: strings.NewReader(""), stdout: out, stderr: out}, []string{"--every", "20ms"})
		done <- code
	}()
	time.Sleep(150 * time.Millisecond)
	if n := console.beatCount(); n != 0 {
		t.Fatalf("%d passes while the service forwarded", n)
	}
	if !strings.Contains(strings.Join(strings.Fields(out.String()), " "), "The background forwarder is already forwarding on this machine. This one waits and takes over when it stops.") {
		t.Fatalf("no word about the wait:\n%s", out.String())
	}
	release()
	deadline := time.Now().Add(5 * time.Second)
	for console.beatCount() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if console.beatCount() == 0 {
		t.Fatal("no takeover after the service stopped")
	}
	cancel()
	if code := <-done; code != 0 {
		t.Fatalf("exit %d", code)
	}
}

// While the background forwarder runs, fenzi run leaves the loop to it, and
// still makes the last pass when the agent exits.
func TestForwardWhileLeavesTheLoopToTheService(t *testing.T) {
	fastForward(t)
	console, dirs := signedInMachine(t)
	release, _, _ := tryForwarder(dirs, holderService)
	stop := forwardWhile(quietEnv(), 2)
	time.Sleep(120 * time.Millisecond)
	if n := console.beatCount(); n != 0 {
		t.Fatalf("%d passes while the service forwarded", n)
	}
	if !stop() {
		t.Fatal("the last pass did not reach the console")
	}
	if console.beatCount() == 0 {
		t.Fatal("no last pass")
	}
	release()

	// With no other forwarder, the run holds the lock while the agent runs.
	stop = forwardWhile(quietEnv(), 2)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if who, _ := forwarderHolder(dirs); who == holderRun {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if who, running := forwarderHolder(dirs); !running || who != holderRun {
		t.Fatalf("holder %q running %v during the run", who, running)
	}
	stop()
	if _, running := forwarderHolder(dirs); running {
		t.Fatal("the run kept the lock after the agent exited")
	}
}

// The service exits cleanly on a signed-out machine, so neither launchd nor
// systemd starts it again.
func TestServiceStopsWhenSignedOut(t *testing.T) {
	fakeRuntime(t, nil, "")
	out := &syncBuffer{}
	code, err := cmdForward(env{ctx: context.Background(), stdin: strings.NewReader(""), stdout: out, stderr: out}, []string{"--service"})
	if code != 0 || err != nil || !strings.Contains(out.String(), "this machine is signed out; the background forwarder stops") {
		t.Fatalf("exit %d err %v\n%s", code, err, out.String())
	}
}

// A failed pass does not end the service: the gateway may not be up yet
// after a login. It says so once, not on every pass.
func TestServiceKeepsGoingAfterAFailedPass(t *testing.T) {
	_, dirs := signedInMachine(t)
	fakeRuntime(t, map[string]reply{"sandbox list": {out: "gateway down", exit: 1}}, "")
	// fakeRuntime moved the folders; sign in again there.
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	srv := httptest.NewServer(&refusingConsole{bundle: teamapi.ToWire(signed(key, 2))})
	t.Cleanup(srv.Close)
	dirs = enrollCached(t, srv.URL, key)

	ctx, cancel := context.WithCancel(context.Background())
	out := &syncBuffer{}
	done := make(chan int)
	go func() {
		code, _ := cmdForward(env{ctx: ctx, stdin: strings.NewReader(""), stdout: out, stderr: out}, []string{"--service", "--every", "20ms"})
		done <- code
	}()
	deadline := time.Now().Add(10 * time.Second)
	for out.String() == "" && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	// Several more passes, each failing the same way.
	time.Sleep(300 * time.Millisecond)
	if who, running := forwarderHolder(dirs); !running || who != holderService {
		t.Fatalf("holder %q running %v", who, running)
	}
	cancel()
	if code := <-done; code != 0 {
		t.Fatalf("exit %d\n%s", code, out.String())
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 1 || !strings.Contains(lines[0], "sandbox list") {
		t.Fatalf("want the failure once, got:\n%s", out.String())
	}
	if _, err := time.Parse(time.RFC3339, strings.Fields(lines[0])[0]); err != nil {
		t.Fatalf("log line without a time: %q", lines[0])
	}
}

func TestServiceLogTrims(t *testing.T) {
	max := serviceLogMax
	serviceLogMax = 100
	t.Cleanup(func() { serviceLogMax = max })
	path := filepath.Join(t.TempDir(), "forward.log")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	l := &serviceLog{w: f, path: path}
	for i := 0; i < 5; i++ {
		l.say(strings.Repeat("x", 30) + string(rune('a'+i)))
	}
	b, _ := os.ReadFile(path)
	old, _ := os.ReadFile(path + ".1")
	if int64(len(b)) >= serviceLogMax+60 || len(old) == 0 {
		t.Fatalf("log %d bytes, forward.log.1 %d bytes", len(b), len(old))
	}
}

func newUI(e env) *tui.UI { return tui.New(e.stdin, e.stdout) }
