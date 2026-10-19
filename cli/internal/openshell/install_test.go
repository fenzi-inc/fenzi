package openshell

import (
	"os"
	"strings"
	"testing"
)

func TestWriteColimaConfigNeverOverwrites(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	sock := "/Users/you/.colima/default/docker.sock"
	if err := WriteColimaConfig(sock); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(GatewayConfig())
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`compute_driver = "docker"`, `socket_path = "` + sock + `"`, `grpc_endpoint = "https://host.docker.internal:17670"`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("missing %s in:\n%s", want, b)
		}
	}
	if err := WriteColimaConfig("/other.sock"); err == nil {
		t.Fatal("an existing gateway.toml was overwritten")
	}
	if after, _ := os.ReadFile(GatewayConfig()); string(after) != string(b) {
		t.Fatal("an existing gateway.toml was changed")
	}
}

func TestInstallVersionIsPinned(t *testing.T) {
	if _, ok := Pinned.Contains("openshell " + InstallVersion); !ok {
		t.Fatalf("%s is outside %s", InstallVersion, Pinned)
	}
}

func TestInstallerIsPinnedToTheReleaseTag(t *testing.T) {
	if !strings.Contains(upstreamInstaller, "/OpenShell/v"+InstallVersion+"/install.sh") {
		t.Fatalf("installer %s is not at tag v%s", upstreamInstaller, InstallVersion)
	}
	if len(upstreamInstallerSHA256) != 64 {
		t.Fatalf("installer sha256 %q is not a sha256", upstreamInstallerSHA256)
	}
	cmd := InstallCommand()
	for _, want := range []string{upstreamInstaller, upstreamInstallerSHA256, "OPENSHELL_VERSION=v" + InstallVersion} {
		if !strings.Contains(cmd, want) {
			t.Errorf("missing %s in %s", want, cmd)
		}
	}
}

func TestCheckSHA256(t *testing.T) {
	path := t.TempDir() + "/install.sh"
	if err := os.WriteFile(path, []byte("echo hi\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := checkSHA256(path, "ab08508fdf5ca4da5c4995987bc41c56c048aaa5eeb046417ae4049b7d40286e"); err != nil {
		t.Fatal(err)
	}
	if err := checkSHA256(path, upstreamInstallerSHA256); err == nil {
		t.Fatal("a script with another sha256 was accepted")
	}
}

func TestOlder(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want bool
	}{
		{"0.1.2", "0.1.4", true},
		{"0.1.4", "0.1.4", false},
		{"0.1.10", "0.1.4", false},
		{"0.1.4", "0.1.10", true},
		{"0.0.9", "0.1.0", true},
		{"1.0.0", "0.9.9", false},
		{"", "0.1.4", false},
	} {
		if got := older(c.a, c.b); got != c.want {
			t.Errorf("older(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

func TestBehindReadsTheVersionLine(t *testing.T) {
	// The line `openshell --version` printed in 0.1.2 and 0.1.4.
	if v, behind := Behind("openshell " + InstallVersion + "\n"); v != InstallVersion || behind {
		t.Errorf("InstallVersion: %q, %v", v, behind)
	}
	if v, behind := Behind("openshell 0.1.0\n"); v != "0.1.0" || !behind {
		t.Errorf("0.1.0: %q, %v", v, behind)
	}
	if v, behind := Behind("unreadable"); v != "" || behind {
		t.Errorf("no version: %q, %v", v, behind)
	}
}
