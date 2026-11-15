package main

import (
	"context"
	"errors"
	"fenzi/cli/internal/engine"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"fenzi/cli/internal/config"
	"fenzi/cli/internal/openshell"
	"fenzi/cli/internal/team"
)

// Recorded from OpenShell 0.1.2.
const doctorStatus = `{"authentication":{"provider":"mTLS transport","status":"authenticated"},"gateway":"openshell","server":"https://localhost:17670","status":"connected","version":"0.1.2"}`

func TestDoctorFixSaysWhatItChangesFirst(t *testing.T) {
	// Answers in the shapes recorded from 0.1.2: --version's line, status
	// JSON, gateway info's compute_drivers, and settings get --global --json,
	// with gateway-wide values that weaken Fenzi.
	fakeRuntime(t, map[string]reply{
		"--version":                    {out: "openshell 0.1.2\n"},
		"status":                       {out: doctorStatus},
		"gateway info":                 {out: `{"compute_drivers":[{"name":"docker"}]}`},
		"settings get --global --json": {out: `{"settings":{"ocsf_json_enabled":"<unset>","agent_policy_proposals_enabled":false,"proposal_approval_mode":"auto"}}`},
	}, "")
	out, _ := runCLI(t, "", "doctor", "--fix")
	flat := strings.Join(strings.Fields(out), " ")
	for _, pair := range [][2]string{
		{"Changing: removing the gateway-wide proposal_approval_mode (auto)", "fixed: a person approves each request"},
		{"Changing: removing the gateway-wide agent_policy_proposals_enabled (false)", "fixed: removed the gateway-wide agent_policy_proposals_enabled"},
	} {
		before, after := strings.Index(flat, pair[0]), strings.Index(flat, pair[1])
		if before < 0 || after < 0 || before > after {
			t.Errorf("%q must come before %q:\n%s", pair[0], pair[1], out)
		}
	}
	if _, code := runCLI(t, "", "doctor"); code != 3 {
		t.Errorf("doctor without --fix exit %d", code)
	}
}

func TestPublishByAMemberNamesTheConsole(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	dirs, err := config.Default()
	if err != nil {
		t.Fatal(err)
	}
	if err := (team.Enrollment{Server: "https://fenzi.example", Token: "t", Email: "ana@acme.dev", Tenant: "acme", Machine: "m"}).Save(dirs); err != nil {
		t.Fatal(err)
	}
	file := t.TempDir() + "/org.yaml"
	if err := os.WriteFile(file, []byte("version: 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out, code := runCLI(t, "", "policy", "publish", file)
	if code != 1 || !strings.Contains(out, "ana@acme.dev is a member") || !strings.Contains(out, "https://fenzi.example/console") || strings.Contains(out, "dana@") || strings.Contains(out, "local server") {
		t.Errorf("exit %d:\n%s", code, out)
	}
}

func TestDoctorNotesAnOlderPatch(t *testing.T) {
	runtime := func(version string) jsonCheck {
		t.Helper()
		r := doctorReplies(t, "")
		r["--version"] = reply{out: "openshell " + version + "\n"}
		fakeRuntime(t, r, "")
		var doc jsonDoctor
		runJSON(t, &doc, "doctor", "--json")
		for _, c := range doc.Checks {
			if c.Name == "Runtime" {
				return c
			}
		}
		t.Fatalf("no Runtime check: %+v", doc.Checks)
		return jsonCheck{}
	}
	// 0.1.0 is older than any InstallVersion this pin can have.
	c := runtime("0.1.0")
	if c.Status != "ok" {
		t.Errorf("an older patch is a note, not a failure: %+v", c)
	}
	for _, want := range []string{"0.1.0, older than " + openshell.InstallVersion, "run fenzi setup to upgrade", "restarts the gateway. There is no sandbox on this machine, so nothing is lost."} {
		if !strings.Contains(c.Detail, want) {
			t.Errorf("missing %q in %q", want, c.Detail)
		}
	}
	if strings.Contains(c.Detail, "openshell ") {
		t.Errorf("doctor tells the user to run openshell: %q", c.Detail)
	}
	if c := runtime(openshell.InstallVersion); c.Status != "ok" || c.Detail != openshell.InstallVersion {
		t.Errorf("the installed release is InstallVersion: %+v", c)
	}
}

// A docker on PATH says nothing about the runtime behind it: doctor asks the
// builder where it will build, and fails with docker's own words when
// nothing answers. Seen on 15 November 2026: the docker CLI's context
// pointed at Docker Desktop, which was not running, and doctor said docker
// was available.
func TestDoctorAsksTheImageBuilder(t *testing.T) {
	check := func() jsonCheck {
		t.Helper()
		fakeRuntime(t, doctorReplies(t, ""), "")
		// A docker that is only a name on PATH.
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "docker"), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
		var doc jsonDoctor
		runJSON(t, &doc, "doctor", "--json")
		for _, c := range doc.Checks {
			if c.Name == "Image builds" {
				return c
			}
		}
		t.Fatalf("no Image builds check: %+v", doc.Checks)
		return jsonCheck{}
	}
	oldSocket, oldAnswers := gatewaySocket, builderAnswers
	t.Cleanup(func() { gatewaySocket, builderAnswers = oldSocket, oldAnswers })

	var asked engine.Builder
	gatewaySocket = func() string { return "/Users/you/.colima/default/docker.sock" }
	builderAnswers = func(_ context.Context, b engine.Builder) error { asked = b; return nil }
	if c := check(); c.Status != "ok" || c.Detail != "docker builds on the gateway's socket, /Users/you/.colima/default/docker.sock" {
		t.Errorf("the gateway's socket answers: %+v", c)
	}
	if asked.Bin != "docker" || asked.Socket != "/Users/you/.colima/default/docker.sock" {
		t.Errorf("asked %+v", asked)
	}

	builderAnswers = func(context.Context, engine.Builder) error {
		return errors.New("Cannot connect to the Docker daemon at unix:///Users/you/.colima/default/docker.sock. Is the docker daemon running?")
	}
	c := check()
	if c.Status != "fail" || !strings.Contains(c.Detail, "docker does not answer on the gateway's socket, /Users/you/.colima/default/docker.sock: Cannot connect to the Docker daemon") || !strings.HasSuffix(c.Detail, "The container runtime behind it is not running.") || strings.Contains(c.Detail, "fenzi ") {
		t.Errorf("nothing answers: %+v", c)
	}

	// No socket in the gateway's config: docker's own context, and the old words.
	gatewaySocket = func() string { return "" }
	builderAnswers = func(context.Context, engine.Builder) error { return nil }
	if c := check(); c.Status != "ok" || c.Detail != "docker is available" {
		t.Errorf("no socket named: %+v", c)
	}
}
