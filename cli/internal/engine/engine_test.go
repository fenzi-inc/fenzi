package engine

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func stubPath(t *testing.T, installed ...string) {
	t.Helper()
	old := lookPath
	t.Cleanup(func() { lookPath = old })
	lookPath = func(bin string) (string, error) {
		for _, b := range installed {
			if b == bin {
				return "/usr/bin/" + bin, nil
			}
		}
		return "", errors.New("not found")
	}
}

func TestDetectForFollowsTheGateway(t *testing.T) {
	cases := []struct {
		installed []string
		driver    string
		want      string
	}{
		{[]string{"docker", "podman"}, "", "docker"},
		{[]string{"docker", "podman"}, "docker", "docker"},
		{[]string{"docker", "podman"}, "podman", "podman"},
		{[]string{"docker", "podman"}, "vm", "docker"},
		{[]string{"docker"}, "podman", "docker"},
		{[]string{"podman"}, "docker", "podman"},
		{[]string{"podman"}, "", "podman"},
	}
	for _, c := range cases {
		stubPath(t, c.installed...)
		b, err := DetectFor(nil, c.driver)
		if err != nil || b.Bin != c.want {
			t.Errorf("installed %v, driver %q: got %q, %v; want %q", c.installed, c.driver, b.Bin, err, c.want)
		}
	}
	stubPath(t)
	if _, err := DetectFor(nil, "podman"); err == nil {
		t.Error("no builder installed, and no error")
	}
}

func TestDriver(t *testing.T) {
	cases := map[string][]string{
		"docker": {"docker"},
		"podman": {"podman"},
		"":       {"vm"},
	}
	for want, names := range cases {
		if got := Driver(names); got != want {
			t.Errorf("Driver(%v) = %q, want %q", names, got, want)
		}
	}
	if got := Driver([]string{"docker", "podman"}); got != "" {
		t.Errorf("both named: %q", got)
	}
	if got := Driver(nil); got != "" {
		t.Errorf("none: %q", got)
	}
}

// docker builds on the gateway's socket, whatever its own context or the
// environment says; podman and a builder with no socket run as they are.
func TestCommandUsesTheGatewaysSocket(t *testing.T) {
	t.Setenv("DOCKER_HOST", "unix:///somewhere/else.sock")
	t.Setenv("DOCKER_CONTEXT", "desktop-linux")
	t.Setenv("FENZI_TEST_KEPT", "1")
	b := Builder{Bin: "docker", Socket: "/Users/you/.colima/default/docker.sock"}
	cmd := b.Command(context.Background(), "image", "inspect", "fenzi/claude:1")
	if got := strings.Join(cmd.Args, " "); got != "docker image inspect fenzi/claude:1" {
		t.Errorf("args %q", got)
	}
	var hosts, kept int
	for _, kv := range cmd.Env {
		switch {
		case kv == "DOCKER_HOST=unix:///Users/you/.colima/default/docker.sock":
			hosts++
		case strings.HasPrefix(kv, "DOCKER_HOST="), strings.HasPrefix(kv, "DOCKER_CONTEXT="):
			t.Errorf("left in the environment: %s", kv)
		case kv == "FENZI_TEST_KEPT=1":
			kept++
		}
	}
	if hosts != 1 || kept != 1 {
		t.Errorf("DOCKER_HOST set %d times, the rest of the environment kept %d times", hosts, kept)
	}
	for _, b := range []Builder{{Bin: "docker"}, {Bin: "podman", Socket: "/run/user/1000/podman/podman.sock"}} {
		if cmd := b.Command(context.Background(), "version"); cmd.Env != nil {
			t.Errorf("%+v: the environment was changed", b)
		}
	}
	if err := (Builder{Bin: "podman"}).Ping(context.Background()); err != nil {
		t.Errorf("podman is not asked: %v", err)
	}
}

// Ping runs the builder and reads its first line. The stand-ins print what
// docker 29.2.1 printed on 15 November 2026.
func TestPingReadsDockersOwnWords(t *testing.T) {
	dir := t.TempDir()
	docker := filepath.Join(dir, "docker")
	write := func(script string) {
		t.Helper()
		if err := os.WriteFile(docker, []byte("#!/bin/sh\n"+script+"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	b := Builder{Bin: docker}
	// The real name decides whether a builder is asked at all.
	ping := func() error {
		cmd := b
		cmd.Bin = "docker"
		t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
		return cmd.Ping(context.Background())
	}

	write(`[ "$*" = "image ls -q fenzi/claude" ] || { echo "unexpected: $*"; exit 2; }; echo 4fb21d43549b`)
	if err := ping(); err != nil {
		t.Errorf("a runtime that answers: %v", err)
	}
	write(`echo; echo "failed to connect to the docker API at unix:///tmp/no-such.sock; check if the path is correct and if the daemon is running: dial unix /tmp/no-such.sock: connect: no such file or directory" >&2; exit 1`)
	if err := ping(); err == nil || !strings.HasPrefix(err.Error(), "failed to connect to the docker API at unix:///tmp/no-such.sock") {
		t.Errorf("no socket: %v", err)
	}
	write(`exit 1`)
	if err := ping(); err == nil || err.Error() != "exit status 1" {
		t.Errorf("nothing printed: %v", err)
	}
	old := pingWait
	pingWait = 200 * time.Millisecond
	t.Cleanup(func() { pingWait = old })
	write(`exec sleep 5`)
	if err := ping(); err == nil || err.Error() != "no answer in 200ms" {
		t.Errorf("a socket with nobody behind it: %v", err)
	}
}
