//go:build !team

package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestServerIsNotInThisBuild(t *testing.T) {
	var out, errOut bytes.Buffer
	code := cli([]string{"server"}, strings.NewReader(""), &out, &errOut)
	if code != 1 || !strings.Contains(errOut.String(), "not part of this build") || !strings.Contains(errOut.String(), "The team control plane is hosted") {
		t.Fatalf("exit %d stderr %q", code, errOut.String())
	}
}

func TestHelpListsTeamCommands(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := cli([]string{"help"}, strings.NewReader(""), &out, &errOut); code != 0 {
		t.Fatalf("exit %d stderr %q", code, errOut.String())
	}
	help := out.String()
	for _, cmd := range []string{"login", "logout", "status", "sync", "forward"} {
		if !strings.Contains(help, cmd) {
			t.Errorf("help does not list %s", cmd)
		}
	}
	if strings.Contains(help, "Not in this build") || strings.Contains(help, "Local team server") {
		t.Errorf("help still describes a Free-only build:\n%s", help)
	}
}

func TestStatusBeforeLoginSaysHowToSignIn(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	var out, errOut bytes.Buffer
	cli([]string{"status"}, strings.NewReader(""), &out, &errOut)
	if all := out.String() + errOut.String(); !strings.Contains(all, "boundlane login") {
		t.Fatalf("status before login:\n%s", all)
	}
}
