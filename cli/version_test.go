package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestVersionDisplay(t *testing.T) {
	for _, args := range [][]string{{"version"}, {"--version"}} {
		var out, errOut bytes.Buffer
		if code := cli(args, strings.NewReader(""), &out, &errOut); code != 0 {
			t.Fatalf("%v: exit %d stderr %q", args, code, errOut.String())
		}
		got := out.String()
		if strings.Contains(got, "OpenShell") || strings.Contains(got, "openshell") {
			t.Fatalf("%v names the runtime:\n%s", args, got)
		}
		if !strings.Contains(got, "■ Version") || !strings.Contains(got, "Boundlane") || !strings.Contains(got, Version) {
			t.Fatalf("%v display:\n%s", args, got)
		}
		if strings.Contains(errOut.String(), "unknown command") {
			t.Fatalf("%v treated as unknown: %s", args, errOut.String())
		}
	}
}
