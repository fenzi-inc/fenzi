package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"fenzi/cli/internal/config"
	"fenzi/cli/internal/relay"
	"fenzi/cli/internal/service"
	"fenzi/cli/internal/team"
	"fenzi/cli/internal/tui"
)

// One forwarder that repeats runs on a machine at a time: the background
// service, fenzi forward in a terminal or in the Mac app, or fenzi run while
// its agent runs. It holds forwarder.lock for as long as it runs. Another one
// waits, and takes over when the first stops, so a closed terminal does not
// stop the records while the service is installed.
//
// relay.lock still makes single passes take turns (fenzi sync, fenzi forward
// --once, the last pass after a run): it is what keeps the spool and the
// cursors safe. forwarder.lock only keeps two loops from doubling the work.

func forwarderLockPath(dirs config.Dirs) string { return filepath.Join(dirs.Config, "forwarder.lock") }

// tryForwarder takes forwarder.lock without waiting. ok is false when another
// forwarder holds it. who is written into the file for fenzi status.
func tryForwarder(dirs config.Dirs, who string) (release func(), ok bool, err error) {
	if err := os.MkdirAll(dirs.Config, 0o700); err != nil {
		return nil, false, err
	}
	f, err := os.OpenFile(forwarderLockPath(dirs), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, false, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, false, nil
		}
		return nil, false, err
	}
	_ = f.Truncate(0)
	_, _ = f.WriteAt([]byte(fmt.Sprintf("%d %s\n", os.Getpid(), who)), 0)
	return func() {
		_ = f.Truncate(0)
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		f.Close()
	}, true, nil
}

// forwarderPoll is how often a waiting forwarder looks for the lock.
var forwarderPoll = 500 * time.Millisecond

// holdForwarder takes forwarder.lock, waiting while another forwarder holds
// it. waiting is called once, with the other forwarder's name, when it has to
// wait. It returns when it has the lock or ctx ends.
func holdForwarder(ctx context.Context, dirs config.Dirs, who string, waiting func(other string)) (release func(), err error) {
	told := false
	for {
		release, ok, err := tryForwarder(dirs, who)
		if err != nil || ok {
			return release, err
		}
		if !told && waiting != nil {
			other, _ := forwarderHolder(dirs)
			waiting(other)
			told = true
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(forwarderPoll):
		}
	}
}

// forwarderHolder says which forwarder runs now, if one does.
func forwarderHolder(dirs config.Dirs) (who string, running bool) {
	f, err := os.Open(forwarderLockPath(dirs))
	if err != nil {
		return "", false
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_SH|syscall.LOCK_NB); err == nil {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		return "", false
	}
	b, _ := io.ReadAll(io.LimitReader(f, 256))
	_, name, _ := strings.Cut(strings.TrimSpace(string(b)), " ")
	if name == "" {
		name = "another fenzi"
	}
	return name, true
}

// Names a forwarder writes into forwarder.lock.
const (
	holderService = "the background forwarder"
	holderForward = "fenzi forward"
	holderRun     = "fenzi run"
)

// newServiceManager is this machine's service manager. Tests replace it: no
// test may run launchctl or systemctl.
var newServiceManager = func() (service.Manager, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	return service.For(runtime.GOOS, home, os.Getenv("XDG_CONFIG_HOME"), os.Getuid(), service.Exec{})
}

// serviceEnv is what the service needs from the shell that installs it. A
// launchd agent starts with PATH=/usr/bin:/bin:/usr/sbin:/sbin and a systemd
// user unit with the manager's PATH, neither of which may hold openshell or
// the container runtime; the XDG folders decide where the sign-in is read.
var serviceEnv = []string{"PATH", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "DOCKER_HOST"}

func forwardLogPath(dirs config.Dirs) string { return filepath.Join(dirs.Cache, "forward.log") }

// forwarderSpec runs this fenzi binary as the background forwarder.
func forwarderSpec(dirs config.Dirs) (service.Spec, error) {
	exe, err := os.Executable()
	if err != nil {
		return service.Spec{}, err
	}
	if exe, err = filepath.Abs(exe); err != nil {
		return service.Spec{}, err
	}
	if err := os.MkdirAll(dirs.Cache, 0o700); err != nil {
		return service.Spec{}, err
	}
	s := service.Spec{Binary: exe, Args: []string{"forward", "--service"}, Log: forwardLogPath(dirs)}
	for _, k := range serviceEnv {
		if v := os.Getenv(k); v != "" {
			s.Env = append(s.Env, k+"="+v)
		}
	}
	return s, nil
}

// installForwarder installs and starts the background forwarder. It needs a
// signed-in machine: the service has nothing to forward to otherwise.
func installForwarder(e env, u *tui.UI, dirs config.Dirs) error {
	if _, err := team.Load(dirs); errors.Is(err, team.ErrNotEnrolled) {
		return errSignIn
	} else if err != nil {
		return err
	}
	m, err := newServiceManager()
	if err != nil {
		return err
	}
	spec, err := forwarderSpec(dirs)
	if err != nil {
		return err
	}
	if err := m.Install(e.ctx, spec); err != nil {
		return err
	}
	u.Done("Forwarder", "runs in the background as a "+m.Kind()+", and again at each login")
	u.Note("Records keep reaching the console after this terminal closes. Log: " + tilde(spec.Log, homeDir()))
	return nil
}

func cmdForwardInstall(e env) (int, error) {
	dirs, err := config.Default()
	if err != nil {
		return 1, err
	}
	u := tui.New(e.stdin, e.stdout)
	u.Title("Background forwarder", "")
	if err := installForwarder(e, u, dirs); err != nil {
		return 1, err
	}
	u.Command("fenzi forward --uninstall", "stop it and remove it")
	u.Blank()
	return 0, nil
}

func cmdForwardUninstall(e env) (int, error) {
	u := tui.New(e.stdin, e.stdout)
	u.Title("Background forwarder", "")
	removed, err := removeForwarder(e)
	if err != nil {
		return 1, err
	}
	if removed {
		u.Done("Forwarder", "stopped and removed. Records reach the console while fenzi run or fenzi forward runs")
	} else {
		u.Skip("Forwarder", "was not installed")
	}
	u.Blank()
	return 0, nil
}

// removeForwarder stops and removes the background forwarder. A system with
// no service manager has none to remove.
func removeForwarder(e env) (bool, error) {
	m, err := newServiceManager()
	if errors.Is(err, service.ErrUnsupported) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return m.Remove(e.ctx)
}

// forwarderState is what status and doctor say about forwarding.
type forwarderState struct {
	Kind      string
	Installed bool
	Running   bool
	Detail    string
	// Holder is the forwarder that runs now, from forwarder.lock.
	Holder string
}

func readForwarder(ctx context.Context, dirs config.Dirs) forwarderState {
	var st forwarderState
	st.Holder, _ = forwarderHolder(dirs)
	m, err := newServiceManager()
	if err != nil {
		return st
	}
	st.Kind = m.Kind()
	s, err := m.Status(ctx)
	if err != nil {
		st.Detail = err.Error()
		return st
	}
	st.Installed, st.Running, st.Detail = s.Installed, s.Running, s.Detail
	if s.Installed && !s.Loaded && s.Detail == "" {
		st.Detail = "not loaded"
	}
	return st
}

// forwarderLine is one status or doctor line: ok, -- (nothing wrong, nothing
// installed), or FAIL.
func forwarderLine(st forwarderState, dirs config.Dirs) (status, detail string) {
	log := tilde(forwardLogPath(dirs), homeDir())
	switch {
	case st.Installed && st.Running:
		return "ok", "in the background, " + st.Kind + ", running"
	case st.Installed:
		why := "not running"
		if st.Detail != "" {
			why += ": " + st.Detail
		}
		return "FAIL", fmt.Sprintf("installed, %s. Log: %s. fenzi forward --install starts it again", why, log)
	case st.Holder != "":
		return "--", st.Holder + " forwards until it exits. fenzi forward --install keeps forwarding after the terminal closes"
	default:
		return "--", "only while fenzi run or fenzi forward runs. fenzi forward --install keeps it running"
	}
}

// offerForwarder asks, after fenzi login, whether to install the background
// forwarder. Without a terminal it only names the command: the Mac app and
// scripts sign in that way, and must not be asked.
func offerForwarder(e env, u *tui.UI, dirs config.Dirs) {
	m, err := newServiceManager()
	if err != nil {
		return
	}
	if st, err := m.Status(e.ctx); err == nil && st.Installed {
		return
	}
	if !u.Interactive() {
		u.Command("fenzi forward --install", "keep sending records after the terminal closes")
		u.Blank()
		return
	}
	yes, err := u.Confirm("Keep sending records to the console after this terminal closes?",
		"Yes, run the forwarder in the background", "No, only while fenzi run runs")
	if err != nil || !yes {
		u.Command("fenzi forward --install", "does it later")
		u.Blank()
		return
	}
	if err := installForwarder(e, u, dirs); err != nil {
		u.Problem("Forwarder", err.Error())
	}
	u.Blank()
}

// serviceLog writes the background forwarder's log: one line per pass that
// did something, with the time. A line the same as the one before is left
// out, so a console that stays away for a day writes one line, not one every
// five seconds.
type serviceLog struct {
	w    io.Writer
	path string
	last string
}

// serviceLogMax is the log size at which the older half moves to forward.log.1.
var serviceLogMax int64 = 1 << 20

func (l *serviceLog) say(msg string) {
	if msg == l.last {
		return
	}
	l.last = msg
	l.trim()
	fmt.Fprintf(l.w, "%s %s\n", time.Now().UTC().Format(time.RFC3339), msg)
}

func (l *serviceLog) report(rep relay.Report) {
	if rep.Decisions == 0 && rep.Requests == 0 && rep.Applied == 0 && len(rep.Notes) == 0 {
		l.say("forwarding")
		return
	}
	msg := fmt.Sprintf("%d decisions, %d requests, %d applied", rep.Decisions, rep.Requests, rep.Applied)
	if len(rep.Notes) > 0 {
		msg += ". " + strings.Join(rep.Notes, ". ")
	}
	l.say(msg)
}

// trim keeps the log under serviceLogMax. The service manager holds the file
// open for appending, so it is copied to forward.log.1 and cut, not renamed.
func (l *serviceLog) trim() {
	if l.path == "" {
		return
	}
	fi, err := os.Stat(l.path)
	if err != nil || fi.Size() < serviceLogMax {
		return
	}
	b, err := os.ReadFile(l.path)
	if err != nil {
		return
	}
	if os.WriteFile(l.path+".1", b, 0o600) == nil {
		_ = os.Truncate(l.path, 0)
	}
}
