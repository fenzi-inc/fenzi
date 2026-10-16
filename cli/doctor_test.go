package main

import (
	"os"
	"strings"
	"testing"

	"fenzi/cli/internal/config"
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
