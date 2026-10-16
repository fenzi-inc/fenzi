package openshell

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fakeProbe(goos string, bins, paths, live []string) probe {
	in := func(list []string) func(string) bool {
		return func(s string) bool {
			for _, x := range list {
				if x == s {
					return true
				}
			}
			return false
		}
	}
	return probe{goos: goos, home: "/Users/you", xdg: "/run/user/1000", has: in(bins), exists: in(paths), answers: in(live)}
}

func TestDetectMac(t *testing.T) {
	rts := detect(fakeProbe("darwin",
		[]string{"colima"},
		[]string{"/Applications/Docker.app", "/Applications/OrbStack.app"},
		[]string{"/Users/you/.orbstack/run/docker.sock"},
	))
	got := map[string]Runtime{}
	for _, r := range rts {
		got[r.Name] = r
	}
	if len(rts) != 3 {
		t.Fatalf("want Docker Desktop, colima, OrbStack; got %+v", rts)
	}
	if got["colima"].Running || got["colima"].StartLine() != "colima start" || !got["colima"].Tested {
		t.Errorf("colima: %+v", got["colima"])
	}
	if got["Docker Desktop"].StartLine() != "open -a Docker" || got["Docker Desktop"].Running {
		t.Errorf("Docker Desktop: %+v", got["Docker Desktop"])
	}
	if !got["OrbStack"].Running || got["OrbStack"].Tested {
		t.Errorf("OrbStack is running and untested: %+v", got["OrbStack"])
	}
}

func TestDetectLinux(t *testing.T) {
	rts := detect(fakeProbe("linux", []string{"docker", "podman"}, nil, nil))
	if len(rts) != 2 || rts[0].Name != "Docker Engine" || !rts[0].Attach || rts[1].Name != "Podman" {
		t.Fatalf("got %+v", rts)
	}
	if rts[0].Tested || rts[1].Tested {
		t.Errorf("Docker Engine and Podman have not been run with Fenzi: %+v", rts)
	}
	rootless := detect(fakeProbe("linux", []string{"docker"}, []string{"/run/user/1000/docker.sock"}, nil))
	if rootless[0].Socket != "/run/user/1000/docker.sock" || rootless[0].Attach {
		t.Fatalf("rootless Docker should use the user socket without sudo: %+v", rootless[0])
	}
}

func TestDiagnose(t *testing.T) {
	colima := Runtime{Name: "colima", Socket: "/c.sock"}
	desktop := Runtime{Name: "Docker Desktop", Socket: "/d.sock", Running: true}

	d := diagnose([]Runtime{colima, desktop}, gatewayConfig{driver: "docker", socket: "/c.sock"})
	if len(d.Stopped) != 1 || d.Stopped[0].Name != "colima" || len(d.Running) != 0 {
		t.Errorf("a configured socket narrows the choice to its runtime: %+v", d)
	}
	if !strings.HasPrefix(d.Summary(), "colima is installed but not running") {
		t.Errorf("summary: %q", d.Summary())
	}

	d = diagnose([]Runtime{colima, desktop}, gatewayConfig{})
	if len(d.Running) != 1 || len(d.Stopped) != 1 {
		t.Errorf("without a config every runtime counts: %+v", d)
	}

	if d := diagnose(nil, gatewayConfig{}); !d.None {
		t.Errorf("no runtimes: %+v", d)
	}
	if d := diagnose([]Runtime{desktop}, gatewayConfig{socket: "/gone.sock"}); !d.Orphan {
		t.Errorf("a socket nobody serves: %+v", d)
	}
	if d := diagnose(nil, gatewayConfig{driver: "vm"}); d.OtherDriver != "vm" || d.None {
		t.Errorf("another driver needs no container runtime: %+v", d)
	}

	two := diagnose([]Runtime{colima, {Name: "OrbStack", Socket: "/o.sock"}}, gatewayConfig{})
	if got := two.Summary(); !strings.HasPrefix(got, "colima and OrbStack are installed but none is running") {
		t.Errorf("summary: %q", got)
	}
}

func TestReadGatewayConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gateway.toml")
	if err := os.WriteFile(path, []byte(ColimaConfig("/Users/you/.colima/default/docker.sock")), 0o600); err != nil {
		t.Fatal(err)
	}
	c := readGatewayConfig(path)
	if c.driver != "docker" || c.socket != "/Users/you/.colima/default/docker.sock" {
		t.Fatalf("got %+v", c)
	}
	if c := readGatewayConfig(filepath.Join(t.TempDir(), "missing.toml")); c != (gatewayConfig{}) {
		t.Fatalf("missing file: %+v", c)
	}
}
