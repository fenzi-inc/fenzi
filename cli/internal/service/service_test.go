package service

import (
	"context"
	"encoding/xml"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// fakeRunner answers launchctl and systemctl from a table and records each
// call. Nothing is run.
type fakeRunner struct {
	calls []string
	// replies maps a command line to its output and whether it fails. A
	// line not in the table succeeds with no output.
	replies map[string]reply
	// seq answers the same line differently on each call, in order.
	seq map[string][]reply
}

type reply struct {
	out  string
	fail bool
}

func (f *fakeRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	line := strings.Join(append([]string{name}, args...), " ")
	f.calls = append(f.calls, line)
	r, ok := f.replies[line]
	if s := f.seq[line]; len(s) > 0 {
		r, ok, f.seq[line] = s[0], true, s[1:]
	}
	if !ok {
		return "", nil
	}
	if r.fail {
		return r.out, errors.New("exit status 1")
	}
	return r.out, nil
}

func spec() Spec {
	return Spec{
		Binary: "/Users/dana/.local/bin/fenzi",
		Args:   []string{"forward", "--service"},
		Env:    []string{"PATH=/opt/homebrew/bin:/usr/bin:/bin", "XDG_CONFIG_HOME=/Users/dana/.config"},
		Log:    "/Users/dana/.cache/fenzi/forward.log",
	}
}

// Recorded with launchctl print on macOS 26.5, cut to the top-level lines and
// one nested block, which has a state line of its own.
const printRunning = `gui/501/dev.fenzi.forward = {
	active count = 1
	path = /Users/dana/Library/LaunchAgents/dev.fenzi.forward.plist
	type = LaunchAgent
	state = running

	program = /Users/dana/.local/bin/fenzi
	domain = gui/501 [100002]
	runs = 1
	pid = 526
	last exit code = (never exited)

	endpoints = {
		"dev.fenzi.forward" = {
			port = 0x85c0f
			state = active
		}
	}
}
`

const printExited = `gui/501/dev.fenzi.forward = {
	state = not running
	runs = 128
	last exit code = 1
}
`

const printNeverRan = `gui/501/dev.fenzi.forward = {
	state = not running
	runs = 0
	last exit code = (never exited)
}
`

const printMissing = "Bad request.\nCould not find service \"dev.fenzi.forward\" in domain for user gui: 501\n"

func TestForPicksTheManager(t *testing.T) {
	r := &fakeRunner{}
	if m, err := For("darwin", "/Users/dana", "", 501, r); err != nil || m.Path() != "/Users/dana/Library/LaunchAgents/dev.fenzi.forward.plist" {
		t.Fatalf("darwin: %v %v", m, err)
	}
	if m, err := For("linux", "/home/dana", "", 1000, r); err != nil || m.Path() != "/home/dana/.config/systemd/user/fenzi-forward.service" {
		t.Fatalf("linux: %v %v", m, err)
	}
	if m, err := For("linux", "/home/dana", "/xdg", 1000, r); err != nil || m.Path() != "/xdg/systemd/user/fenzi-forward.service" {
		t.Fatalf("linux with XDG_CONFIG_HOME: %v %v", m, err)
	}
	if _, err := For("windows", `C:\Users\dana`, "", 0, r); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("windows: %v", err)
	}
	if len(r.calls) != 0 {
		t.Fatalf("picking a manager ran %v", r.calls)
	}
}

func TestPlistIsAValidUserAgent(t *testing.T) {
	s := spec()
	s.Binary = "/Users/dana/My & <Tools>/fenzi"
	b := Plist(s)
	// Well-formed XML, with the odd path escaped.
	dec := xml.NewDecoder(strings.NewReader(string(b)))
	dec.Strict = true
	var strs []string
	for {
		tok, err := dec.Token()
		if err != nil {
			if err.Error() == "EOF" {
				break
			}
			t.Fatalf("not well-formed: %v\n%s", err, b)
		}
		if cd, ok := tok.(xml.CharData); ok {
			if v := strings.TrimSpace(string(cd)); v != "" {
				strs = append(strs, v)
			}
		}
	}
	text := strings.Join(strs, "\n")
	for _, want := range []string{
		"Label\ndev.fenzi.forward",
		"ProgramArguments\n/Users/dana/My & <Tools>/fenzi\nforward\n--service",
		"PATH\n/opt/homebrew/bin:/usr/bin:/bin",
		"XDG_CONFIG_HOME\n/Users/dana/.config",
		"StandardOutPath\n/Users/dana/.cache/fenzi/forward.log",
		"StandardErrorPath\n/Users/dana/.cache/fenzi/forward.log",
		"ThrottleInterval\n10",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("plist lacks %q:\n%s", want, b)
		}
	}
	for _, want := range []string{"<key>RunAtLoad</key>\n\t<true/>", "<key>SuccessfulExit</key>\n\t\t<false/>"} {
		if !strings.Contains(string(b), want) {
			t.Errorf("plist lacks %q:\n%s", want, b)
		}
	}
}

func TestLaunchdInstallWritesTheAgentAndBootstrapsIt(t *testing.T) {
	home := t.TempDir()
	r := &fakeRunner{replies: map[string]reply{
		"launchctl print gui/501/dev.fenzi.forward": {out: printMissing, fail: true},
	}}
	l := &Launchd{Home: home, UID: 501, R: r, Sleep: func(time.Duration) {}}
	if err := l.Install(context.Background(), spec()); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(home, "Library", "LaunchAgents", "dev.fenzi.forward.plist")
	b, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(b), "<string>--service</string>") {
		t.Fatalf("plist: %v\n%s", err, b)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm()&0o022 != 0 {
		t.Fatalf("plist mode %v: launchd refuses one others can write", fi.Mode())
	}
	want := []string{
		"launchctl print gui/501/dev.fenzi.forward",
		"launchctl enable gui/501/dev.fenzi.forward",
		"launchctl bootstrap gui/501 " + path,
	}
	if !reflect.DeepEqual(r.calls, want) {
		t.Fatalf("calls\n%q\nwant\n%q", r.calls, want)
	}
}

// Installing again replaces the loaded copy, and waits out bootstrap's
// "Input/output error" while the old process is still going away.
func TestLaunchdInstallReplacesALoadedCopy(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, "Library", "LaunchAgents", "dev.fenzi.forward.plist")
	boot := "launchctl bootstrap gui/501 " + path
	r := &fakeRunner{
		replies: map[string]reply{"launchctl print gui/501/dev.fenzi.forward": {out: printRunning}},
		seq: map[string][]reply{boot: {
			{out: "Bootstrap failed: 5: Input/output error\n", fail: true},
			{out: "Bootstrap failed: 5: Input/output error\n", fail: true},
			{},
		}},
	}
	l := &Launchd{Home: home, UID: 501, R: r, Sleep: func(time.Duration) {}}
	if err := l.Install(context.Background(), spec()); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"launchctl print gui/501/dev.fenzi.forward",
		"launchctl bootout gui/501/dev.fenzi.forward",
		"launchctl enable gui/501/dev.fenzi.forward",
		boot, boot, boot,
	}
	if !reflect.DeepEqual(r.calls, want) {
		t.Fatalf("calls\n%q\nwant\n%q", r.calls, want)
	}

	// A bootstrap that never works says what launchctl said.
	r = &fakeRunner{replies: map[string]reply{
		"launchctl print gui/501/dev.fenzi.forward": {out: printMissing, fail: true},
		boot: {out: "Bootstrap failed: 125: Domain does not support specified action\n", fail: true},
	}}
	l.R = r
	if err := l.Install(context.Background(), spec()); err == nil || !strings.Contains(err.Error(), "Domain does not support") {
		t.Fatalf("err %v", err)
	}
}

func TestLaunchdStatusReadsPrint(t *testing.T) {
	for _, c := range []struct {
		name, out    string
		fail         bool
		loaded, runs bool
		detail       string
	}{
		{"running", printRunning, false, true, true, ""},
		{"exited", printExited, false, true, false, "last exit code 1"},
		{"never ran", printNeverRan, false, true, false, ""},
		{"not loaded", printMissing, true, false, false, ""},
	} {
		home := t.TempDir()
		l := &Launchd{Home: home, UID: 501, R: &fakeRunner{replies: map[string]reply{
			"launchctl print gui/501/dev.fenzi.forward": {out: c.out, fail: c.fail},
		}}}
		st, err := l.Status(context.Background())
		if err != nil || st.Installed || st.Loaded != c.loaded || st.Running != c.runs || st.Detail != c.detail {
			t.Errorf("%s: %+v %v", c.name, st, err)
		}
	}
}

func TestLaunchdRemove(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, "Library", "LaunchAgents", "dev.fenzi.forward.plist")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, Plist(spec()), 0o644); err != nil {
		t.Fatal(err)
	}
	r := &fakeRunner{seq: map[string][]reply{
		"launchctl print gui/501/dev.fenzi.forward": {{out: printRunning}, {out: printMissing, fail: true}},
	}}
	l := &Launchd{Home: home, UID: 501, R: r}
	removed, err := l.Remove(context.Background())
	if err != nil || !removed {
		t.Fatalf("removed %v err %v", removed, err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("plist still there: %v", err)
	}
	if !reflect.DeepEqual(r.calls, []string{"launchctl print gui/501/dev.fenzi.forward", "launchctl bootout gui/501/dev.fenzi.forward"}) {
		t.Fatalf("calls %q", r.calls)
	}

	// Nothing installed, nothing loaded: nothing to do, and only a look.
	r = &fakeRunner{replies: map[string]reply{"launchctl print gui/501/dev.fenzi.forward": {out: printMissing, fail: true}}}
	l.R = r
	if removed, err := l.Remove(context.Background()); err != nil || removed {
		t.Fatalf("removed %v err %v", removed, err)
	}
	if len(r.calls) != 1 {
		t.Fatalf("calls %q", r.calls)
	}
}

func TestUnitQuotesWhatSystemdWouldExpand(t *testing.T) {
	s := spec()
	s.Binary = "/home/dana/my tools/fenzi"
	s.Env = []string{"PATH=/home/dana/100%/bin:/usr/bin", `XDG_CONFIG_HOME=/home/dana/$cfg`}
	s.Log = "/home/dana/.cache/fenzi/forward.log"
	got := string(Unit(s))
	for _, want := range []string{
		`ExecStart="/home/dana/my tools/fenzi" "forward" "--service"` + "\n",
		`Environment="PATH=/home/dana/100%%/bin:/usr/bin"` + "\n",
		`Environment="XDG_CONFIG_HOME=/home/dana/$cfg"` + "\n",
		"Restart=on-failure\nRestartSec=10\n",
		"StandardOutput=append:/home/dana/.cache/fenzi/forward.log\n",
		"StandardError=append:/home/dana/.cache/fenzi/forward.log\n",
		"[Install]\nWantedBy=default.target\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("unit lacks %q:\n%s", want, got)
		}
	}
	if !strings.Contains(string(Unit(Spec{Binary: "/opt/$x/fenzi", Log: "/l"})), `ExecStart="/opt/$$x/fenzi"`) {
		t.Error("a $ in ExecStart is not doubled")
	}
}

func TestSystemdInstallEnablesAndRestarts(t *testing.T) {
	cfg := t.TempDir()
	r := &fakeRunner{}
	d := &Systemd{ConfigHome: cfg, R: r}
	if err := d.Install(context.Background(), spec()); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(filepath.Join(cfg, "systemd", "user", "fenzi-forward.service")); err != nil || !strings.Contains(string(b), `"--service"`) {
		t.Fatalf("unit: %v\n%s", err, b)
	}
	want := []string{
		"systemctl --user daemon-reload",
		"systemctl --user enable fenzi-forward.service",
		"systemctl --user restart fenzi-forward.service",
	}
	if !reflect.DeepEqual(r.calls, want) {
		t.Fatalf("calls %q", r.calls)
	}
}

// With no user manager (a container, WSL without systemd) the install fails
// with systemctl's words and leaves no unit behind.
func TestSystemdInstallWithoutAUserManager(t *testing.T) {
	cfg := t.TempDir()
	d := &Systemd{ConfigHome: cfg, R: &fakeRunner{replies: map[string]reply{
		"systemctl --user daemon-reload": {out: "Failed to connect to bus: No medium found\n", fail: true},
	}}}
	err := d.Install(context.Background(), spec())
	if err == nil || !strings.Contains(err.Error(), "No medium found") {
		t.Fatalf("err %v", err)
	}
	if _, err := os.Stat(d.Path()); !os.IsNotExist(err) {
		t.Fatalf("unit left behind: %v", err)
	}
	st, err := d.Status(context.Background())
	if err != nil || st.Installed || st.Running {
		t.Fatalf("status %+v %v", st, err)
	}
}

func TestSystemdStatusAndRemove(t *testing.T) {
	cfg := t.TempDir()
	active := "systemctl --user is-active fenzi-forward.service"
	r := &fakeRunner{replies: map[string]reply{active: {out: "active\n"}}}
	d := &Systemd{ConfigHome: cfg, R: r}
	if err := writeFile(d.Path(), Unit(spec())); err != nil {
		t.Fatal(err)
	}
	if st, err := d.Status(context.Background()); err != nil || !st.Installed || !st.Loaded || !st.Running || st.Detail != "" {
		t.Fatalf("active: %+v %v", st, err)
	}
	// is-active exits non-zero for every other state; the word decides.
	r.replies[active] = reply{out: "failed\n", fail: true}
	if st, err := d.Status(context.Background()); err != nil || !st.Installed || st.Running || st.Detail != "failed" {
		t.Fatalf("failed: %+v %v", st, err)
	}
	r.calls = nil
	removed, err := d.Remove(context.Background())
	if err != nil || !removed {
		t.Fatalf("removed %v err %v", removed, err)
	}
	if _, err := os.Stat(d.Path()); !os.IsNotExist(err) {
		t.Fatalf("unit still there: %v", err)
	}
	want := []string{
		active,
		"systemctl --user disable --now fenzi-forward.service",
		"systemctl --user daemon-reload",
		"systemctl --user reset-failed fenzi-forward.service",
	}
	if !reflect.DeepEqual(r.calls, want) {
		t.Fatalf("calls %q", r.calls)
	}

	// Nothing there: only the look.
	r.calls = nil
	r.replies[active] = reply{out: "inactive\n", fail: true}
	if removed, err := d.Remove(context.Background()); err != nil || removed || len(r.calls) != 1 {
		t.Fatalf("removed %v err %v calls %q", removed, err, r.calls)
	}
}
