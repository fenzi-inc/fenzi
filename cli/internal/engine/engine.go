// Package engine builds agent images with Docker or Podman on the developer's
// machine. We publish Dockerfiles, not agent binaries.
package engine

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"
)

type Builder struct {
	Bin string
	Out io.Writer
	// Socket is the Docker socket the gateway starts sandboxes from, when its
	// config names one. docker is then run with DOCKER_HOST set to it, so an
	// image lands where the gateway looks for it, whatever context the
	// docker CLI is on. Recorded on 12 and 15 November 2026 with docker
	// 29.2.1: the CLI's context pointed at a runtime that was not running,
	// the gateway's config named colima's socket, and with DOCKER_HOST set
	// to that socket the build landed where the gateway started the sandbox
	// from it. With DOCKER_CONTEXT set as well, DOCKER_HOST still won there;
	// Docker's reference says the opposite, so the variable is taken out.
	// Podman's way to name a socket was not recorded, so podman keeps its
	// own default.
	Socket string
}

// Command is the builder's CLI with args, pointed at Socket when there is one.
func (b Builder) Command(ctx context.Context, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, b.Bin, args...)
	if b.Socket == "" || b.Bin != "docker" {
		return cmd
	}
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "DOCKER_HOST=") && !strings.HasPrefix(kv, "DOCKER_CONTEXT=") {
			cmd.Env = append(cmd.Env, kv)
		}
	}
	cmd.Env = append(cmd.Env, "DOCKER_HOST=unix://"+b.Socket)
	return cmd
}

// pingWait bounds Ping: a docker CLI whose socket has nobody behind it can
// wait for a minute and more (seen on 15 November 2026).
var pingWait = 5 * time.Second

// Ping reports whether docker's daemon answers where the builder will
// build, with docker's own words when it does not. It lists the images of
// one name, which needs the daemon and changes nothing. Recorded on 15
// November 2026 with docker 29.2.1: exit 0 on a running runtime; exit 1 and
// "failed to connect to the docker API at unix://…; check if the path is
// correct and if the daemon is running: …" for a socket that is not there;
// exit 1 and "request returned 500 Internal Server Error for API route and
// version …" for Docker Desktop's socket with Docker Desktop stopped.
// `docker version --format` was not used: with a socket path too long for a
// unix socket it crashed instead of answering. Podman is not asked: what it
// prints with no service was not recorded.
func (b Builder) Ping(ctx context.Context) error {
	if b.Bin != "docker" {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, pingWait)
	defer cancel()
	out, err := b.Command(ctx, "image", "ls", "-q", "fenzi/claude").CombinedOutput()
	switch {
	case ctx.Err() != nil:
		return fmt.Errorf("no answer in %s", pingWait)
	case err != nil:
		return errors.New(firstLine(string(out), err.Error()))
	}
	return nil
}

// firstLine is the first line of s that says something, or fallback.
func firstLine(s, fallback string) string {
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			return l
		}
	}
	return fallback
}

// lookPath finds a builder on PATH; tests replace it.
var lookPath = exec.LookPath

// Detect picks docker, then podman: the first one on PATH wins.
func Detect(out io.Writer) (Builder, error) { return DetectFor(out, "") }

// DetectFor prefers the builder that matches the gateway's compute driver,
// so the image lands in the store the gateway starts sandboxes from. A
// driver of "podman" tries podman first; any other value, including "",
// keeps docker first. When the preferred one is not installed, the other is
// used, as before.
//
// The caller sets Socket when the gateway's config names one.
func DetectFor(out io.Writer, driver string) (Builder, error) {
	order := []string{"docker", "podman"}
	if driver == "podman" {
		order = []string{"podman", "docker"}
	}
	for _, bin := range order {
		if _, err := lookPath(bin); err == nil {
			return Builder{Bin: bin, Out: out}, nil
		}
	}
	return Builder{}, errors.New("neither docker nor podman is installed; one is needed to build agent images")
}

// Driver picks the container driver from the names the gateway reports in
// compute_drivers[].name. OpenShell 0.1.2 on colima reported "docker";
// "podman" is the other value the gateway config accepts for compute_driver.
// It returns "" when the gateway names neither, or both, so the caller keeps
// the default order.
func Driver(names []string) string {
	found := ""
	for _, n := range names {
		n = strings.ToLower(strings.TrimSpace(n))
		if n != "docker" && n != "podman" {
			continue
		}
		if found != "" && found != n {
			return ""
		}
		found = n
	}
	return found
}

func (b Builder) Exists(ctx context.Context, tag string) bool {
	return b.Command(ctx, "image", "inspect", tag).Run() == nil
}

// Build builds from a Dockerfile on stdin, with no build context. Our
// Dockerfiles copy nothing from the host.
func (b Builder) Build(ctx context.Context, tag string, dockerfile []byte) error {
	cmd := b.Command(ctx, "build", "-t", tag, "-")
	cmd.Stdin = bytes.NewReader(dockerfile)
	cmd.Stdout = b.Out
	cmd.Stderr = b.Out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s build %s: %w", b.Bin, tag, err)
	}
	return nil
}
