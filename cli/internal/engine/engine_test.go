package engine

import (
	"errors"
	"testing"
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
