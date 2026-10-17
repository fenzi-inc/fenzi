package run

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"fenzi/cli/internal/openshell"
)

// gatewayRunner plays one sandbox on the fake gateway: the agent's terminal
// (sandbox exec --tty) stays open until the sandbox is deleted, and every
// later call that names the sandbox fails, as it does once the gateway no
// longer knows it. The failure text is the fake's own; nothing here depends
// on what OpenShell prints.
type gatewayRunner struct {
	*openshell.Fake
	name     string
	attached chan struct{}
	gone     chan struct{}
	once     sync.Once
	mu       sync.Mutex
	deleted  bool
}

func newGatewayRunner(f *openshell.Fake, name string) *gatewayRunner {
	return &gatewayRunner{Fake: f, name: name, attached: make(chan struct{}), gone: make(chan struct{})}
}

func (g *gatewayRunner) names(args []string) bool {
	for _, a := range args {
		if a == g.name {
			return true
		}
	}
	return false
}

func (g *gatewayRunner) Output(ctx context.Context, args ...string) ([]byte, error) {
	g.mu.Lock()
	gone := g.deleted
	g.mu.Unlock()
	if gone && g.names(args) {
		g.Fake.Output(ctx, args...)
		return nil, &openshell.Error{Bin: "fake", Args: args, ExitCode: 1, Stderr: "fake: no sandbox " + g.name}
	}
	out, err := g.Fake.Output(ctx, args...)
	if err == nil && len(args) >= 3 && args[0] == "sandbox" && args[1] == "delete" && args[2] == g.name {
		g.mu.Lock()
		g.deleted = true
		g.mu.Unlock()
		g.once.Do(func() { close(g.gone) })
	}
	return out, err
}

func (g *gatewayRunner) Attach(ctx context.Context, args ...string) error {
	if _, err := g.Fake.Output(ctx, args...); err != nil {
		return err
	}
	close(g.attached)
	<-g.gone
	return &openshell.Error{Bin: "fake", Args: args, ExitCode: 255, Stderr: "fake: exec relay closed"}
}

func (g *gatewayRunner) downloads() int {
	n := 0
	for _, c := range g.Fake.Calls {
		if strings.HasPrefix(c, "sandbox download") {
			n++
		}
	}
	return n
}

// The bug from 18 October 2026: the Mac app stopped a sandbox while its
// session window still ran fenzi run. Stop staged the changes and deleted
// the sandbox, which closed the agent's terminal; run then removed the
// staged copy before its own download failed. Now the run waits for the
// stop, finds the sandbox stopped, and leaves the copy alone.
func TestStopWhileRunIsAttached(t *testing.T) {
	h := setup(t)
	gw := newGatewayRunner(h.os, "fenzi-test-0001")
	h.deps.OpenShell = openshell.Client{R: gw}
	// The CLI keeps the sandbox after the agent exits.
	h.opts.OnExit = func(string) (bool, error) {
		t.Error("the run asked about a sandbox that another command stopped")
		return true, nil
	}

	type ran struct {
		res Result
		err error
	}
	done := make(chan ran, 1)
	go func() {
		res, err := Run(context.Background(), h.deps, h.opts)
		done <- ran{res, err}
	}()
	select {
	case <-gw.attached:
	case <-time.After(5 * time.Second):
		t.Fatal("the agent never started")
	}

	s, err := h.deps.Dirs.LoadState()
	if err != nil {
		t.Fatal(err)
	}
	sb, ok := s.Find("fenzi-test-0001")
	if !ok || !sb.Running {
		t.Fatalf("attached sandbox not recorded as running: %+v", s)
	}
	stopOut := &bytes.Buffer{}
	stopDeps := h.deps
	stopDeps.Out = stopOut
	changes, err := Stop(context.Background(), stopDeps, sb)
	if err != nil {
		t.Fatalf("stop: %v\n%s", err, stopOut)
	}
	if len(changes) != 3 {
		t.Fatalf("stop staged %v", changes)
	}

	var r ran
	select {
	case r = <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("fenzi run did not end after the stop")
	}
	if r.err != nil {
		t.Fatalf("run: %v\n%s", r.err, h.out)
	}
	if !r.res.StoppedElsewhere || r.res.ExitCode != 0 || len(r.res.Changes) != 3 {
		t.Errorf("result = %+v", r.res)
	}
	out := h.out.String()
	for _, bad := range []string{"could not be saved", "copying changes out", "fake:", "kept"} {
		if strings.Contains(out, bad) {
			t.Errorf("run printed %q:\n%s", bad, out)
		}
	}
	if !strings.Contains(out, "stopped by fenzi stop outside this window") || !strings.Contains(out, "3 files staged, not applied") {
		t.Errorf("run output:\n%s", out)
	}
	if n := gw.downloads(); n != 1 {
		t.Errorf("%d downloads, want only the stop's", n)
	}
	staged := filepath.Join(h.deps.Dirs.Staging("fenzi-test-0001"), StagedFiles)
	if b, err := os.ReadFile(filepath.Join(staged, "main.go")); err != nil || string(b) != "package main // edited" {
		t.Fatalf("staged copy lost: %q, %v", b, err)
	}
}

// The other order: the agent exits first and the run is copying out when
// the stop arrives. The stop waits, then copies the sandbox again and
// deletes it.
func TestStopWaitsForRunCopy(t *testing.T) {
	h := setup(t)
	release := make(chan struct{})
	downloading := make(chan struct{})
	var once sync.Once
	hook := h.os.Hook
	h.os.Hook = func(args []string) {
		hook(args)
		if len(args) >= 2 && args[0] == "sandbox" && args[1] == "download" {
			once.Do(func() {
				close(downloading)
				<-release
			})
		}
	}
	h.opts.OnExit = func(string) (bool, error) { return true, nil }
	done := make(chan error, 1)
	go func() {
		_, err := Run(context.Background(), h.deps, h.opts)
		done <- err
	}()
	<-downloading

	s, _ := h.deps.Dirs.LoadState()
	sb, _ := s.Find("fenzi-test-0001")
	stopped := make(chan error, 1)
	stopDeps := h.deps
	stopDeps.Out = &bytes.Buffer{}
	// The fake holds its own lock while the hook waits, so the stop is
	// started here and released only after it had time to reach the lock.
	go func() {
		_, err := Stop(context.Background(), stopDeps, sb)
		stopped <- err
	}()
	time.Sleep(3 * lockPoll)
	select {
	case err := <-stopped:
		t.Fatalf("stop finished while the run was copying: %v", err)
	default:
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatalf("run: %v\n%s", err, h.out)
	}
	if err := <-stopped; err != nil {
		t.Fatalf("stop: %v", err)
	}
	if !h.called("sandbox delete fenzi-test-0001") {
		t.Error("the stop did not delete the sandbox")
	}
	staged := filepath.Join(h.deps.Dirs.Staging("fenzi-test-0001"), StagedFiles)
	if _, err := os.Stat(filepath.Join(staged, "new.go")); err != nil {
		t.Fatalf("staged copy lost: %v", err)
	}
}

// A stop from elsewhere while the run asks what to do with the sandbox:
// the run must not try to delete or keep a sandbox that is gone.
func TestStopDuringExitQuestion(t *testing.T) {
	h := setup(t)
	gw := newGatewayRunner(h.os, "fenzi-test-0001")
	gw.once.Do(func() { close(gw.gone) })
	h.deps.OpenShell = openshell.Client{R: gw}
	h.opts.OnExit = func(name string) (bool, error) {
		s, _ := h.deps.Dirs.LoadState()
		sb, _ := s.Find(name)
		d := h.deps
		d.Out = &bytes.Buffer{}
		if _, err := Stop(context.Background(), d, sb); err != nil {
			t.Fatalf("stop: %v", err)
		}
		return false, nil
	}
	res, err := Run(context.Background(), h.deps, h.opts)
	if err != nil {
		t.Fatalf("run: %v\n%s", err, h.out)
	}
	if !res.StoppedElsewhere {
		t.Errorf("result = %+v", res)
	}
	deletes := 0
	for _, c := range h.os.Calls {
		if strings.HasPrefix(c, "sandbox delete") {
			deletes++
		}
	}
	if deletes != 1 {
		t.Errorf("%d deletes, want the stop's only: %v", deletes, h.os.Calls)
	}
}

// A failed download never removes a copy staged before it.
func TestFailedCopyKeepsStagedCopy(t *testing.T) {
	h := setup(t)
	h.opts.Keep = true
	if _, err := Run(context.Background(), h.deps, h.opts); err != nil {
		t.Fatal(err)
	}
	s, _ := h.deps.Dirs.LoadState()
	sb, _ := s.Find("fenzi-test-0001")
	h.os.Replies["sandbox download"] = openshell.Reply{Exit: 1}
	if _, err := Stop(context.Background(), h.deps, sb); err == nil {
		t.Fatal("want an error when the copy fails")
	}
	staging := h.deps.Dirs.Staging("fenzi-test-0001")
	if b, err := os.ReadFile(filepath.Join(staging, StagedFiles, "main.go")); err != nil || string(b) != "package main // edited" {
		t.Fatalf("the earlier copy is gone: %q, %v", b, err)
	}
	entries, _ := os.ReadDir(staging)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".download-") {
			t.Errorf("left %s behind", e.Name())
		}
	}
}

// A new copy replaces the old one whole and clears the applied mark.
func TestNewCopyReplacesOld(t *testing.T) {
	h := setup(t)
	h.opts.Keep = true
	if _, err := Run(context.Background(), h.deps, h.opts); err != nil {
		t.Fatal(err)
	}
	staging := h.deps.Dirs.Staging("fenzi-test-0001")
	os.WriteFile(filepath.Join(staging, StagedFiles, "stale.go"), []byte("x"), 0o644)
	MarkApplied(staging, time.Unix(0, 0))
	s, _ := h.deps.Dirs.LoadState()
	sb, _ := s.Find("fenzi-test-0001")
	if _, err := Stop(context.Background(), h.deps, sb); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(staging, StagedFiles, "stale.go")); err == nil {
		t.Error("a file from the old copy is still staged")
	}
	if _, err := os.Stat(filepath.Join(staging, AppliedMark)); err == nil {
		t.Error("the applied mark survived a new copy")
	}
}
