// Package service keeps fenzi forward running for one user after the terminal
// closes: a launchd agent in ~/Library/LaunchAgents on macOS, a systemd user
// unit in ~/.config/systemd/user on Linux. Nothing here needs root or writes a
// system-wide unit.
package service

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Spec is what the service runs.
type Spec struct {
	// Binary is the absolute path of the installed fenzi.
	Binary string
	Args   []string
	// Env is KEY=VALUE pairs the service needs and the service manager does
	// not pass on its own: PATH, so OpenShell and the container runtime are
	// found, and the XDG folders, so the service reads the same sign-in.
	Env []string
	// Log receives the service's standard output and standard error.
	Log string
}

// Status is what the service manager says about the service.
type Status struct {
	// Installed means the unit file is in place.
	Installed bool
	// Loaded means the service manager knows the service.
	Loaded bool
	// Running means it has a live process.
	Running bool
	// Detail is the manager's own words when the service is not running: a
	// state or the last exit code. Empty when there is nothing to add.
	Detail string
}

// Manager installs, removes, and reports one per-user service.
type Manager interface {
	// Kind names the manager's object: "launchd agent", "systemd user unit".
	Kind() string
	// Path is the unit file.
	Path() string
	// Install writes the unit file and starts the service, replacing a copy
	// that is already installed.
	Install(ctx context.Context, s Spec) error
	// Remove stops the service and deletes the unit file. It reports whether
	// there was anything to remove.
	Remove(ctx context.Context) (bool, error)
	Status(ctx context.Context) (Status, error)
}

// ErrUnsupported is returned on a system with neither launchd nor systemd.
var ErrUnsupported = errors.New("a background forwarder needs launchd (macOS) or systemd (Linux)")

// Runner runs launchctl or systemctl. It returns standard output and
// standard error together, also when the command fails: both managers say
// what is wrong there.
type Runner interface {
	Run(ctx context.Context, name string, args ...string) (string, error)
}

// Exec runs the real commands.
type Exec struct{}

func (Exec) Run(ctx context.Context, name string, args ...string) (string, error) {
	var out bytes.Buffer
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	return out.String(), err
}

// For returns the manager for goos. home is the user's home folder and
// configHome the XDG config folder (~/.config when unset); uid is the user's
// id, which names the launchd domain.
func For(goos, home, configHome string, uid int, r Runner) (Manager, error) {
	switch goos {
	case "darwin":
		return &Launchd{Home: home, UID: uid, R: r}, nil
	case "linux":
		if configHome == "" {
			configHome = filepath.Join(home, ".config")
		}
		return &Systemd{ConfigHome: configHome, R: r}, nil
	default:
		return nil, ErrUnsupported
	}
}

// writeFile replaces path in one step, so a manager never reads half a unit.
func writeFile(path string, b []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	// launchd refuses a plist that others can write.
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func removeFile(path string) error {
	err := os.Remove(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// failed wraps a manager's error with what it printed.
func failed(cmd string, out string, err error) error {
	if out = strings.TrimSpace(out); out != "" {
		return fmt.Errorf("%s: %s", cmd, out)
	}
	return fmt.Errorf("%s: %w", cmd, err)
}

// Label is the launchd label and the systemd unit's name without .service.
const Label = "dev.fenzi.forward"

// Launchd is a per-user launchd agent in the gui/<uid> domain.
type Launchd struct {
	Home string
	UID  int
	R    Runner
	// Sleep waits between bootstrap attempts. Nil means time.Sleep.
	Sleep func(time.Duration)
}

func (l *Launchd) Kind() string { return "launchd agent" }

func (l *Launchd) Path() string {
	return filepath.Join(l.Home, "Library", "LaunchAgents", Label+".plist")
}

func (l *Launchd) domain() string { return fmt.Sprintf("gui/%d", l.UID) }
func (l *Launchd) target() string { return l.domain() + "/" + Label }

func (l *Launchd) Install(ctx context.Context, s Spec) error {
	if err := writeFile(l.Path(), Plist(s)); err != nil {
		return err
	}
	// An older copy may be loaded, from another binary path or flags.
	if l.loaded(ctx) {
		_, _ = l.R.Run(ctx, "launchctl", "bootout", l.target())
	}
	// A label disabled with launchctl disable refuses to bootstrap.
	if out, err := l.R.Run(ctx, "launchctl", "enable", l.target()); err != nil {
		return failed("launchctl enable", out, err)
	}
	// bootout returns before the old process is gone, and bootstrap fails
	// until it is. Try a few times.
	var out string
	var err error
	for i := 0; i < 5; i++ {
		if out, err = l.R.Run(ctx, "launchctl", "bootstrap", l.domain(), l.Path()); err == nil {
			return nil
		}
		l.sleep(500 * time.Millisecond)
	}
	return failed("launchctl bootstrap", out, err)
}

func (l *Launchd) sleep(d time.Duration) {
	if l.Sleep != nil {
		l.Sleep(d)
		return
	}
	time.Sleep(d)
}

func (l *Launchd) loaded(ctx context.Context) bool {
	_, err := l.R.Run(ctx, "launchctl", "print", l.target())
	return err == nil
}

func (l *Launchd) Remove(ctx context.Context) (bool, error) {
	had := exists(l.Path())
	if l.loaded(ctx) {
		had = true
		if out, err := l.R.Run(ctx, "launchctl", "bootout", l.target()); err != nil && l.loaded(ctx) {
			return true, failed("launchctl bootout", out, err)
		}
	}
	return had, removeFile(l.Path())
}

func (l *Launchd) Status(ctx context.Context) (Status, error) {
	st := Status{Installed: exists(l.Path())}
	out, err := l.R.Run(ctx, "launchctl", "print", l.target())
	if err != nil {
		// "Could not find service": not loaded.
		return st, nil
	}
	st.Loaded = true
	st.Running, st.Detail = launchdState(out)
	return st, nil
}

// launchdState reads launchctl print. Only the service's own top-level lines
// count: a nested block (endpoints, sockets) has state lines of its own.
// The shape was recorded from launchctl on macOS 26.5.
func launchdState(out string) (running bool, detail string) {
	state, exit := "", ""
	for _, line := range strings.Split(out, "\n") {
		if !strings.HasPrefix(line, "\t") || strings.HasPrefix(line, "\t\t") {
			continue
		}
		k, v, ok := strings.Cut(strings.TrimSpace(line), " = ")
		if !ok {
			continue
		}
		switch k {
		case "state":
			state = v
		case "last exit code":
			exit = v
		}
	}
	if state == "running" {
		return true, ""
	}
	if exit != "" && exit != "(never exited)" {
		return false, "last exit code " + exit
	}
	if state == "not running" {
		return false, ""
	}
	return false, state
}

// Plist is the launchd agent for s. It starts at login, and launchd starts it
// again when it exits with an error, at most every ten seconds.
func Plist(s Spec) []byte {
	var b strings.Builder
	str := func(v string) string { return "<string>" + xmlEscape(v) + "</string>" }
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	` + str(Label) + `
	<key>ProgramArguments</key>
	<array>
`)
	for _, a := range append([]string{s.Binary}, s.Args...) {
		b.WriteString("\t\t" + str(a) + "\n")
	}
	b.WriteString("\t</array>\n")
	if len(s.Env) > 0 {
		b.WriteString("\t<key>EnvironmentVariables</key>\n\t<dict>\n")
		for _, kv := range s.Env {
			k, v, _ := strings.Cut(kv, "=")
			b.WriteString("\t\t<key>" + xmlEscape(k) + "</key>\n\t\t" + str(v) + "\n")
		}
		b.WriteString("\t</dict>\n")
	}
	b.WriteString(`	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<dict>
		<key>SuccessfulExit</key>
		<false/>
	</dict>
	<key>ThrottleInterval</key>
	<integer>10</integer>
	<key>ProcessType</key>
	<string>Background</string>
	<key>StandardOutPath</key>
	` + str(s.Log) + `
	<key>StandardErrorPath</key>
	` + str(s.Log) + `
</dict>
</plist>
`)
	return []byte(b.String())
}

func xmlEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&apos;").Replace(s)
}

// Systemd is a systemd user unit, run by the user's own service manager.
type Systemd struct {
	ConfigHome string
	R          Runner
}

// UnitName is the systemd unit.
const UnitName = "fenzi-forward.service"

func (d *Systemd) Kind() string { return "systemd user unit" }

func (d *Systemd) Path() string {
	return filepath.Join(d.ConfigHome, "systemd", "user", UnitName)
}

func (d *Systemd) systemctl(ctx context.Context, args ...string) (string, error) {
	return d.R.Run(ctx, "systemctl", append([]string{"--user"}, args...)...)
}

func (d *Systemd) Install(ctx context.Context, s Spec) error {
	if err := writeFile(d.Path(), Unit(s)); err != nil {
		return err
	}
	if out, err := d.systemctl(ctx, "daemon-reload"); err != nil {
		// No user manager (a container, WSL without systemd). Leave nothing
		// behind that status would report as installed.
		_ = removeFile(d.Path())
		return failed("systemctl --user daemon-reload", out, err)
	}
	if out, err := d.systemctl(ctx, "enable", UnitName); err != nil {
		return failed("systemctl --user enable", out, err)
	}
	// restart, not start: an installed copy picks up the new unit.
	if out, err := d.systemctl(ctx, "restart", UnitName); err != nil {
		return failed("systemctl --user restart", out, err)
	}
	return nil
}

func (d *Systemd) Remove(ctx context.Context) (bool, error) {
	had := exists(d.Path())
	st, _ := d.state(ctx)
	if st == "active" || st == "activating" || st == "failed" || st == "deactivating" {
		had = true
	}
	if !had {
		return false, nil
	}
	if out, err := d.systemctl(ctx, "disable", "--now", UnitName); err != nil && exists(d.Path()) {
		if s, _ := d.state(ctx); s == "active" {
			return true, failed("systemctl --user disable", out, err)
		}
	}
	if err := removeFile(d.Path()); err != nil {
		return true, err
	}
	_, _ = d.systemctl(ctx, "daemon-reload")
	_, _ = d.systemctl(ctx, "reset-failed", UnitName)
	return true, nil
}

// state is systemctl is-active's one word. It exits non-zero for every
// state but active, so only the word counts.
func (d *Systemd) state(ctx context.Context) (string, error) {
	out, err := d.systemctl(ctx, "is-active", UnitName)
	word := strings.TrimSpace(out)
	if strings.ContainsAny(word, " \n") {
		// Not one word: no user manager to ask.
		return "", failed("systemctl --user is-active", out, err)
	}
	return word, nil
}

func (d *Systemd) Status(ctx context.Context) (Status, error) {
	st := Status{Installed: exists(d.Path())}
	word, err := d.state(ctx)
	if err != nil {
		if st.Installed {
			st.Detail = err.Error()
		}
		return st, nil
	}
	st.Loaded = word != "" && word != "inactive" && word != "unknown"
	st.Running = word == "active"
	if !st.Running {
		st.Detail = word
	}
	return st, nil
}

// Unit is the systemd user unit for s. systemd starts it again ten seconds
// after it fails; a clean exit (signed out) stays stopped.
func Unit(s Spec) []byte {
	var b strings.Builder
	b.WriteString(`[Unit]
Description=Fenzi forwarder: decision records and approvals for the team console

[Service]
Type=simple
`)
	words := make([]string, 0, len(s.Args)+1)
	for _, a := range append([]string{s.Binary}, s.Args...) {
		words = append(words, systemdQuote(a, true))
	}
	b.WriteString("ExecStart=" + strings.Join(words, " ") + "\n")
	for _, kv := range s.Env {
		b.WriteString("Environment=" + systemdQuote(kv, false) + "\n")
	}
	b.WriteString(`Restart=on-failure
RestartSec=10
StandardOutput=append:` + systemdPath(s.Log) + `
StandardError=append:` + systemdPath(s.Log) + `

[Install]
WantedBy=default.target
`)
	return []byte(b.String())
}

// systemdQuote quotes one word for ExecStart or Environment: backslash and
// double quote escaped, % doubled so systemd does not read a specifier, and $
// doubled in ExecStart, the only one of the two that expands variables.
func systemdQuote(s string, exec bool) string {
	r := []string{`\`, `\\`, `"`, `\"`, "%", "%%"}
	if exec {
		r = append(r, "$", "$$")
	}
	return `"` + strings.NewReplacer(r...).Replace(s) + `"`
}

// systemdPath is a path in a setting that takes no quotes. Only % is special.
func systemdPath(s string) string { return strings.ReplaceAll(s, "%", "%%") }
