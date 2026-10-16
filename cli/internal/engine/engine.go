// Package engine builds agent images with Docker or Podman on the developer's
// machine. We publish Dockerfiles, not agent binaries.
package engine

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
)

type Builder struct {
	Bin string
	Out io.Writer
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
// Pointing the builder at the socket the gateway uses (for example colima's,
// from socket_path) is not done: how docker and podman would be pointed at it
// has not been recorded against a gateway, so the builder uses its own
// default context.
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
	return exec.CommandContext(ctx, b.Bin, "image", "inspect", tag).Run() == nil
}

// Build builds from a Dockerfile on stdin, with no build context. Our
// Dockerfiles copy nothing from the host.
func (b Builder) Build(ctx context.Context, tag string, dockerfile []byte) error {
	cmd := exec.CommandContext(ctx, b.Bin, "build", "-t", tag, "-")
	cmd.Stdin = bytes.NewReader(dockerfile)
	cmd.Stdout = b.Out
	cmd.Stderr = b.Out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s build %s: %w", b.Bin, tag, err)
	}
	return nil
}
