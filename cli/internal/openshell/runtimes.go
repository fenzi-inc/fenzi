package openshell

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Runtime is a container runtime the gateway's Docker or Podman driver can
// start sandboxes in. Boundlane starts it with the runtime's own command; it
// never configures the runtime itself.
type Runtime struct {
	Name    string
	Socket  string
	Start   []string
	Running bool
	// Attach means Start may prompt, for example sudo for a password.
	Attach bool
	// Tested means a gateway on this runtime has run with Boundlane (colima),
	// or it is the upstream docs' path on a Mac (Docker Desktop). Docker
	// Engine and Podman on Linux are named upstream but have not been run
	// with Boundlane, so setup says so.
	Tested bool
}

// StartLine is the command as setup shows it.
func (r Runtime) StartLine() string { return strings.Join(r.Start, " ") }

type probe struct {
	goos    string
	home    string
	xdg     string
	has     func(bin string) bool
	exists  func(path string) bool
	answers func(socket string) bool
}

// Runtimes lists the container runtimes installed on this machine.
func Runtimes() []Runtime {
	home, _ := os.UserHomeDir()
	return detect(probe{
		goos: runtime.GOOS,
		home: home,
		xdg:  os.Getenv("XDG_RUNTIME_DIR"),
		has: func(bin string) bool {
			_, err := exec.LookPath(bin)
			return err == nil
		},
		exists: func(path string) bool {
			_, err := os.Stat(path)
			return err == nil
		},
		answers: socketAnswers,
	})
}

func detect(p probe) []Runtime {
	var out []Runtime
	add := func(r Runtime) {
		r.Running = r.Socket != "" && p.answers(r.Socket)
		out = append(out, r)
	}
	switch p.goos {
	case "darwin":
		if p.exists("/Applications/Docker.app") {
			add(Runtime{Name: "Docker Desktop", Socket: filepath.Join(p.home, ".docker", "run", "docker.sock"), Start: []string{"open", "-a", "Docker"}, Tested: true})
		}
		if p.has("colima") {
			add(Runtime{Name: "colima", Socket: filepath.Join(p.home, ".colima", "default", "docker.sock"), Start: []string{"colima", "start"}, Tested: true})
		}
		if p.exists("/Applications/OrbStack.app") {
			add(Runtime{Name: "OrbStack", Socket: filepath.Join(p.home, ".orbstack", "run", "docker.sock"), Start: []string{"open", "-a", "OrbStack"}})
		}
		if p.exists("/Applications/Rancher Desktop.app") {
			add(Runtime{Name: "Rancher Desktop", Socket: filepath.Join(p.home, ".rd", "docker.sock"), Start: []string{"open", "-a", "Rancher Desktop"}})
		}
	case "linux":
		if p.has("docker") {
			r := Runtime{Name: "Docker Engine", Socket: "/var/run/docker.sock", Start: []string{"sudo", "systemctl", "start", "docker"}, Attach: true}
			if rootless := filepath.Join(p.xdg, "docker.sock"); p.xdg != "" && p.exists(rootless) {
				r.Socket, r.Start, r.Attach = rootless, []string{"systemctl", "--user", "start", "docker"}, false
			}
			add(r)
		}
		if p.has("podman") && p.xdg != "" {
			add(Runtime{Name: "Podman", Socket: filepath.Join(p.xdg, "podman", "podman.sock"), Start: []string{"systemctl", "--user", "start", "podman.socket"}})
		}
	}
	return out
}

func socketAnswers(socket string) bool {
	c, err := net.DialTimeout("unix", socket, time.Second)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

// Diagnosis is what setup and doctor say when the gateway is not connected.
type Diagnosis struct {
	// Configured is socket_path from the gateway config, when it sets one.
	Configured string
	// Stopped are installed runtimes the gateway could use that are not running.
	// When the config names a socket, only the runtime that serves it.
	Stopped []Runtime
	Running []Runtime
	// Orphan means the config names a socket no known runtime serves.
	Orphan bool
	// None means no container runtime is installed.
	None bool
	// OtherDriver means the config picks a driver that needs no container runtime.
	OtherDriver string
}

// Diagnose reads the gateway config and the installed runtimes.
func Diagnose() Diagnosis {
	return diagnose(Runtimes(), readGatewayConfig(GatewayConfig()))
}

func diagnose(rts []Runtime, cfg gatewayConfig) Diagnosis {
	d := Diagnosis{Configured: cfg.socket}
	if cfg.driver != "" && cfg.driver != "docker" && cfg.driver != "podman" {
		d.OtherDriver = cfg.driver
		return d
	}
	if len(rts) == 0 {
		d.None = true
		return d
	}
	for _, r := range rts {
		if cfg.socket != "" && r.Socket != cfg.socket {
			continue
		}
		if r.Running {
			d.Running = append(d.Running, r)
		} else {
			d.Stopped = append(d.Stopped, r)
		}
	}
	d.Orphan = cfg.socket != "" && len(d.Running) == 0 && len(d.Stopped) == 0
	return d
}

// Summary is one line for doctor and for the note above setup's choices.
func (d Diagnosis) Summary() string {
	switch {
	case d.OtherDriver != "":
		return fmt.Sprintf("The gateway uses the %s driver.", d.OtherDriver)
	case d.None:
		return "No container runtime is installed, so the gateway has nothing to start sandboxes in."
	case d.Orphan:
		return "The gateway config points at " + d.Configured + ", and nothing is serving it."
	case len(d.Running) == 0 && len(d.Stopped) > 0:
		return names(d.Stopped) + notRunning(len(d.Stopped)) + ", so the gateway has nothing to start sandboxes in. This is normal after a restart."
	case len(d.Running) > 0:
		return names(d.Running) + " is running."
	}
	return ""
}

func names(rts []Runtime) string {
	n := make([]string, len(rts))
	for i, r := range rts {
		n[i] = r.Name
	}
	if len(n) <= 1 {
		return strings.Join(n, "")
	}
	return strings.Join(n[:len(n)-1], ", ") + " and " + n[len(n)-1]
}

func notRunning(n int) string {
	if n == 1 {
		return " is installed but not running"
	}
	return " are installed but none is running"
}

type gatewayConfig struct{ driver, socket string }

// ConfiguredDriver is compute_driver from the local gateway config, or "".
func ConfiguredDriver() string { return readGatewayConfig(GatewayConfig()).driver }

// readGatewayConfig reads the two keys setup cares about from gateway.toml.
// It is not a TOML parser; it only reads `key = "value"` lines.
func readGatewayConfig(path string) gatewayConfig {
	b, err := os.ReadFile(path)
	if err != nil {
		return gatewayConfig{}
	}
	var c gatewayConfig
	for _, line := range strings.Split(string(b), "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		v = strings.Trim(strings.TrimSpace(v), `"`)
		switch strings.TrimSpace(k) {
		case "compute_driver":
			c.driver = v
		case "socket_path":
			c.socket = v
		}
	}
	return c
}

// StartRuntime runs the runtime's start command, then waits for its socket.
// Apps opened with `open -a` return at once, so the wait is what matters.
func StartRuntime(ctx context.Context, r Runtime, stdin io.Reader, stdout, stderr io.Writer) error {
	if len(r.Start) == 0 {
		return errors.New("no start command known for " + r.Name)
	}
	cmd := exec.CommandContext(ctx, r.Start[0], r.Start[1:]...)
	if r.Attach {
		cmd.Stdin, cmd.Stdout, cmd.Stderr = stdin, stdout, stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("%s: %w", r.StartLine(), err)
		}
	} else if out, err := cmd.CombinedOutput(); err != nil {
		lines := strings.Split(strings.TrimSpace(string(out)), "\n")
		return fmt.Errorf("%s: %s", r.StartLine(), lines[len(lines)-1])
	}
	deadline := time.Now().Add(3 * time.Minute)
	for time.Now().Before(deadline) {
		if socketAnswers(r.Socket) {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	return fmt.Errorf("%s did not answer on %s after 3 minutes", r.Name, r.Socket)
}

// InstallColimaCommand is the runtime setup can install for someone who has
// none. colima is the one Boundlane has run on; the docker CLI builds agent images.
var InstallColimaCommand = []string{"brew", "install", "colima", "docker"}

// CanInstallColima reports whether InstallColimaCommand can run here.
func CanInstallColima() bool {
	return runtime.GOOS == "darwin" && HasHomebrew()
}

// InstallColima runs InstallColimaCommand with the terminal attached.
func InstallColima(ctx context.Context, stdin io.Reader, stdout, stderr io.Writer) error {
	cmd := exec.CommandContext(ctx, InstallColimaCommand[0], InstallColimaCommand[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = stdin, stdout, stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s: %w", strings.Join(InstallColimaCommand, " "), err)
	}
	return nil
}
