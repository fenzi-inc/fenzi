package openshell

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// InstallVersion is the release setup installs. It must stay inside Pinned.
// 0.1.2 is the release the recorded test output comes from.
const InstallVersion = "0.1.2"

// upstreamInstaller is the upstream install script at the release tag for
// InstallVersion, so the script is as fixed as the binaries it installs. On
// macOS it installs the Homebrew formula, which includes openshell-prover.
const upstreamInstaller = "https://raw.githubusercontent.com/NVIDIA/OpenShell/v" + InstallVersion + "/install.sh"

// upstreamInstallerSHA256 is the sha256 of upstreamInstaller. Tags can move,
// so Install refuses a script that does not match. Change it together with
// InstallVersion.
const upstreamInstallerSHA256 = "5c98a86a4b811c471b212219cb2a62d458244220ffa71ac8e3baf3700b17b871"

// InstallCommand is the shell line setup shows before it runs it: download
// the installer, check its sha256, run it for InstallVersion.
func InstallCommand() string {
	check := "sha256sum -c -"
	if runtime.GOOS == "darwin" {
		check = "shasum -a 256 -c -"
	}
	return fmt.Sprintf("curl -LsSf %s -o install.sh && echo '%s  install.sh' | %s && OPENSHELL_VERSION=v%s sh install.sh",
		upstreamInstaller, upstreamInstallerSHA256, check, InstallVersion)
}

// Install downloads the upstream installer, checks it against
// upstreamInstallerSHA256, and runs it for InstallVersion with the terminal
// attached, so a password prompt from a package manager reaches the person.
func Install(ctx context.Context, stdin io.Reader, stdout, stderr io.Writer) error {
	dir, err := os.MkdirTemp("", "fenzi-openshell-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	script := filepath.Join(dir, "install.sh")
	get := exec.CommandContext(ctx, "curl", "-LsSf", upstreamInstaller, "-o", script)
	get.Stderr = stderr
	if err := get.Run(); err != nil {
		return fmt.Errorf("downloading the OpenShell installer: %w", err)
	}
	if err := checkSHA256(script, upstreamInstallerSHA256); err != nil {
		return fmt.Errorf("the OpenShell installer from %s: %w", upstreamInstaller, err)
	}
	cmd := exec.CommandContext(ctx, "sh", script)
	cmd.Env = append(os.Environ(), "OPENSHELL_VERSION=v"+InstallVersion)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = stdin, stdout, stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("the OpenShell installer failed: %w", err)
	}
	FindInstalled()
	return nil
}

// checkSHA256 returns an error unless the file at path hashes to want.
func checkSHA256(path, want string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != want {
		return fmt.Errorf("sha256 is %s, expected %s; it was not run", got, want)
	}
	return nil
}

// FindInstalled adds the usual install folders to this process's PATH when
// openshell is in one of them but not on PATH yet, and returns that folder.
func FindInstalled() string {
	if Installed("openshell") {
		return ""
	}
	home, _ := os.UserHomeDir()
	for _, dir := range []string{"/opt/homebrew/bin", "/usr/local/bin", filepath.Join(home, ".local", "bin")} {
		if _, err := os.Stat(filepath.Join(dir, "openshell")); err == nil {
			os.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
			return dir
		}
	}
	return ""
}

// NeedsHomebrew reports whether the upstream installer will refuse to run:
// on macOS it stops with "Homebrew is required for macOS installs".
func NeedsHomebrew() bool {
	return runtime.GOOS == "darwin" && !HasHomebrew()
}

// HasHomebrew finds brew, also in /opt/homebrew/bin right after Homebrew's
// installer ran, before the shell profile puts it on PATH.
func HasHomebrew() bool {
	if _, err := exec.LookPath("brew"); err == nil {
		return true
	}
	if _, err := os.Stat("/opt/homebrew/bin/brew"); err == nil {
		os.Setenv("PATH", "/opt/homebrew/bin"+string(os.PathListSeparator)+os.Getenv("PATH"))
		return true
	}
	return false
}

// HomebrewInstaller is Homebrew's documented install script (https://brew.sh).
const HomebrewInstaller = "https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh"

// HomebrewInstallCommand is the line setup shows before it runs it.
func HomebrewInstallCommand() string {
	return `/bin/bash -c "$(curl -fsSL ` + HomebrewInstaller + `)"`
}

// InstallHomebrew downloads Homebrew's installer and runs it with the
// terminal attached; it asks for the password and to confirm.
func InstallHomebrew(ctx context.Context, stdin io.Reader, stdout, stderr io.Writer) error {
	dir, err := os.MkdirTemp("", "fenzi-homebrew-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	script := filepath.Join(dir, "install.sh")
	get := exec.CommandContext(ctx, "curl", "-fsSL", HomebrewInstaller, "-o", script)
	get.Stderr = stderr
	if err := get.Run(); err != nil {
		return fmt.Errorf("downloading the Homebrew installer: %w", err)
	}
	cmd := exec.CommandContext(ctx, "/bin/bash", script)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = stdin, stdout, stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("the Homebrew installer failed: %w", err)
	}
	if !HasHomebrew() {
		return errors.New("Homebrew installed, but brew was not found in /opt/homebrew/bin")
	}
	return nil
}

// Service is how setup starts or restarts the gateway, when it knows how.
// On macOS the upstream installer hands the gateway to Homebrew services; on
// Linux it installs the systemd user unit openshell-gateway (upstream
// install.sh). Use "restart" to start it: after the gateway exits with an
// error, launchd keeps the job loaded and "brew services start" fails with
// "Bootstrap failed: 5".
func Service(verb string) []string {
	switch runtime.GOOS {
	case "darwin":
		if HasHomebrew() {
			return []string{"brew", "services", verb, "openshell"}
		}
	case "linux":
		if _, err := exec.LookPath("systemctl"); err == nil {
			return []string{"systemctl", "--user", verb, "openshell-gateway"}
		}
	}
	return nil
}

// RunService runs Service(verb) and returns its output on failure.
func RunService(ctx context.Context, verb string) error {
	argv := Service(verb)
	if argv == nil {
		return fmt.Errorf("no service manager known for %s", runtime.GOOS)
	}
	out, err := exec.CommandContext(ctx, argv[0], argv[1:]...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %s", strings.Join(argv, " "), strings.TrimSpace(string(out)))
	}
	return nil
}

// ColimaSocket returns colima's Docker socket when it exists.
func ColimaSocket() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	sock := filepath.Join(home, ".colima", "default", "docker.sock")
	if _, err := os.Stat(sock); err != nil {
		return ""
	}
	return sock
}

// GatewayConfig is the gateway's config file on a laptop.
func GatewayConfig() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "openshell", "gateway.toml")
}

// ColimaConfig is the gateway.toml colima needs: sandboxes run in colima's
// VM, where loopback is not the Mac, and the gateway certificate already
// covers host.docker.internal.
func ColimaConfig(socket string) string {
	return `[openshell]
version = 2

[openshell.gateway]
compute_driver = "docker"

[openshell.drivers.docker]
socket_path = "` + socket + `"
grpc_endpoint = "https://host.docker.internal:17670"
`
}

// WriteColimaConfig writes ColimaConfig. It never edits an existing file.
func WriteColimaConfig(socket string) error {
	path := GatewayConfig()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if os.IsExist(err) {
			return fmt.Errorf("%s already exists; it was not changed", path)
		}
		return err
	}
	if _, err := f.WriteString(ColimaConfig(socket)); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
