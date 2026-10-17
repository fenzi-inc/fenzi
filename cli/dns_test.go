package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"fenzi/cli/internal/openshell"
	"fenzi/cli/internal/tui"
)

// Recorded with colima 0.10.1 and dns set in colima.yaml: one answer from
// 192.168.5.1 for registry.npmjs.org, twelve A records with a TTL of 56.
// internal/openshell/colima_test.go has the command that printed it.
const npmAnswer = "464281800001000c00000000087265676973747279056e706d6a73036f72670000010001c00c0001000100000038000468100222c00c0001000100000038000468100022c00c0001000100000038000468100422c00c0001000100000038000468100722c00c0001000100000038000468100622c00c0001000100000038000468100822c00c0001000100000038000468100a22c00c0001000100000038000468100522c00c0001000100000038000468100322c00c0001000100000038000468100122c00c0001000100000038000468100b22c00c0001000100000038000468100922\n"

// zeroAnswer is npmAnswer with each TTL set to 0, as colima's resolver
// answered with dns: null.
var zeroAnswer = strings.ReplaceAll(npmAnswer, "c00c0001000100000038", "c00c0001000100000000")

// fakeColima makes the runtime colima, with a colima.yaml whose dns line is
// dns, and a resolver that answers with answer. It returns the fake colima
// and the number of restarts, which switch the answer to npmAnswer.
func fakeColima(t *testing.T, dns, answer string) (*openshell.Fake, string, *int) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "colima.yaml")
	if err := os.WriteFile(path, []byte("network:\n  mode: shared\n"+dns+"\n  dnsHosts: {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	f := &openshell.Fake{Replies: map[string]openshell.Reply{"ssh -- python3 -c": {Out: answer + answer}}}
	restarts := 0
	oldOn, oldRunner, oldFile, oldRestart := onColima, colimaRunner, colimaFile, restartColima
	onColima = func() bool { return true }
	colimaRunner = f
	colimaFile = func() string { return path }
	restartColima = func(context.Context) error {
		restarts++
		f.Replies["ssh -- python3 -c"] = openshell.Reply{Out: npmAnswer + npmAnswer}
		return nil
	}
	t.Cleanup(func() { onColima, colimaRunner, colimaFile, restartColima = oldOn, oldRunner, oldFile, oldRestart })
	return f, path, &restarts
}

// Built from the 0.1.2 supervisor's answer format, not recorded:
// internal/openshell/dnsprobe_test.go says how.
const (
	sandboxTTL1  = "464281800001000100000000036170690667697468756203636f6d0000010001c00c00010001000000010004c6120002\n"
	sandboxTTL30 = "464281800001000100000000036170690667697468756203636f6d0000010001c00c000100010000001e0004c6120002\n"
)

// doctorReplies are the gateway's answers, with one running sandbox whose
// lookup gives answer, or none when answer is "".
func doctorReplies(t *testing.T, answer string) map[string]reply {
	t.Helper()
	r := map[string]reply{
		"--version":                    {out: "openshell 0.1.2\n"},
		"status":                       {out: doctorStatus},
		"gateway info":                 {out: `{"compute_drivers":[{"name":"docker"}]}`},
		"settings get --global --json": {out: `{"settings":{}}`},
	}
	if answer != "" {
		policy, err := os.ReadFile("../compiler/testdata/golden/signin.policy.yaml")
		if err != nil {
			t.Fatal(err)
		}
		r["sandbox list --selector fenzi=1"] = reply{out: "fenzi-web-1a2b\n"}
		r["sandbox get fenzi-web-1a2b --policy-only"] = reply{out: string(policy)}
		r["sandbox exec -n fenzi-web-1a2b"] = reply{out: answer + answer}
	}
	return r
}

func TestDoctorDNS(t *testing.T) {
	cases := []struct {
		name        string
		colima      bool
		dns, answer string
		sandbox     string
		want, not   []string
	}{
		{"any runtime, ttl 1", false, "", "", sandboxTTL1,
			[]string{"! DNS", "sandbox fenzi-web-1a2b answers api.github.com with a TTL of 1", "transparent_tcp_mapping_denied", "OpenShell has no setting", "troubleshooting#dns"}, []string{"colima"}},
		{"any runtime, ttl 30", false, "", "", sandboxTTL30,
			[]string{"sandbox fenzi-web-1a2b answers api.github.com with a TTL of 30"}, []string{"! DNS"}},
		{"any runtime, no sandbox", false, "", "", "",
			[]string{"not checked: no sandbox is running"}, []string{"! DNS"}},
		{"colima, sandbox ttl 1", true, "  dns: null", zeroAnswer, sandboxTTL1,
			[]string{"sandbox fenzi-web-1a2b answers api.github.com with a TTL of 1", "On colima, fenzi setup can set dns in"}, []string{"colima's resolver answers"}},
		{"colima, no sandbox, ttl 0", true, "  dns: null", zeroAnswer, "",
			[]string{"colima's resolver answers registry.npmjs.org with a TTL of 0", "On colima, fenzi setup can set dns in"}, nil},
		{"colima, dns set, ttl 0", true, "  dns: [10.0.0.2]", zeroAnswer, "",
			[]string{"with a TTL of 0", "On colima: dns is already set in", "then restart colima"}, []string{"fenzi setup can set dns"}},
		{"colima, real ttl", true, "  dns: [1.1.1.1, 8.8.8.8]", npmAnswer, "",
			[]string{"colima's resolver answers registry.npmjs.org with a TTL of 56"}, []string{"! DNS"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fakeRuntime(t, doctorReplies(t, c.sandbox), "")
			f, path, _ := fakeColima(t, c.dns, c.answer)
			if !c.colima {
				onColima = func() bool { return false }
			}
			before, _ := os.ReadFile(path)
			out, _ := runCLI(t, "", "doctor", "--fix")
			flat := strings.Join(strings.Fields(out), " ")
			for _, w := range c.want {
				if !strings.Contains(flat, w) {
					t.Errorf("missing %q in:\n%s", w, out)
				}
			}
			for _, w := range c.not {
				if strings.Contains(flat, w) {
					t.Errorf("%q in:\n%s", w, out)
				}
			}
			// Even --fix leaves colima alone, and colima is asked only when
			// no sandbox answered.
			calls := 0
			if c.colima && c.sandbox == "" {
				calls = 1
			}
			if after, _ := os.ReadFile(path); !bytes.Equal(before, after) || len(f.Calls) != calls {
				t.Errorf("doctor changed or asked colima: calls %v\n%s", f.Calls, after)
			}
		})
	}

	fakeRuntime(t, doctorReplies(t, sandboxTTL1), "")
	onColima = func() bool { return false }
	out, code := runCLI(t, "", "doctor", "--json")
	if code != 3 || !strings.Contains(out, `"name": "DNS"`) || !strings.Contains(out, `"status": "fail"`) {
		t.Errorf("--json exit %d:\n%s", code, out)
	}
}

func TestSetupOffersColimaDNS(t *testing.T) {
	oc := openshell.Client{R: &openshell.Fake{Replies: map[string]openshell.Reply{"status": {Out: doctorStatus}}}}
	setup := func(answer string) string {
		var out bytes.Buffer
		u := tui.New(strings.NewReader(answer), &out)
		if err := setupDNS(env{ctx: context.Background(), stdout: &out, stderr: &out}, u, oc); err != nil {
			t.Fatalf("%v\n%s", err, out.String())
		}
		return strings.Join(strings.Fields(out.String()), " ")
	}

	_, path, restarts := fakeColima(t, "  dns: null", zeroAnswer)
	before, _ := os.ReadFile(path)
	out := setup("2\n")
	for _, w := range []string{"TTL of 0", "On colima, setup can set this line", "dns: [1.1.1.1, 8.8.8.8]", "stops every sandbox running in it", "does not see your company's internal names", "unchanged"} {
		if !strings.Contains(out, w) {
			t.Errorf("missing %q in:\n%s", w, out)
		}
	}
	if after, _ := os.ReadFile(path); !bytes.Equal(before, after) || *restarts != 0 {
		t.Errorf("No changed colima: %d restarts\n%s", *restarts, after)
	}

	out = setup("1\n")
	after, _ := os.ReadFile(path)
	if *restarts != 1 || !strings.Contains(string(after), "\n  dns: [1.1.1.1, 8.8.8.8]\n") || !strings.Contains(out, "registry.npmjs.org with a TTL of 56") {
		t.Errorf("%d restarts, file:\n%s\n%s", *restarts, after, out)
	}

	// With dns already set, setup says what to change and changes nothing.
	_, path, restarts = fakeColima(t, "  dns: [10.0.0.2]", zeroAnswer)
	out = setup("")
	if after, _ := os.ReadFile(path); !strings.Contains(out, "setup cannot change it") || strings.Contains(out, "Set dns and restart colima?") || *restarts != 0 || !strings.Contains(string(after), "dns: [10.0.0.2]") {
		t.Errorf("%d restarts:\n%s", *restarts, out)
	}

	_, _, _ = fakeColima(t, "  dns: null", npmAnswer)
	if out = setup(""); !strings.Contains(out, "TTL of 56") || strings.Contains(out, "?") {
		t.Errorf("a real TTL:\n%s", out)
	}
}

func TestSetupDNSOnOtherRuntimes(t *testing.T) {
	policy, err := os.ReadFile("../compiler/testdata/golden/signin.policy.yaml")
	if err != nil {
		t.Fatal(err)
	}
	f, path, restarts := fakeColima(t, "  dns: null", zeroAnswer)
	onColima = func() bool { return false }
	run := func(replies map[string]openshell.Reply) string {
		var out bytes.Buffer
		oc := openshell.Client{R: &openshell.Fake{Replies: replies}}
		if err := setupDNS(env{ctx: context.Background(), stdout: &out, stderr: &out}, tui.New(strings.NewReader(""), &out), oc); err != nil {
			t.Fatal(err)
		}
		return strings.Join(strings.Fields(out.String()), " ")
	}
	out := run(map[string]openshell.Reply{
		"sandbox list --selector fenzi=1": {Out: "fenzi-web-1a2b\n"},
		"sandbox get":                     {Out: string(policy)},
		"sandbox exec":                    {Out: sandboxTTL1 + sandboxTTL1},
	})
	before, _ := os.ReadFile(path)
	if !strings.Contains(out, "answers api.github.com with a TTL of 1") || !strings.Contains(out, "troubleshooting#dns") || strings.Contains(out, "colima") || strings.Contains(out, "?") || *restarts != 0 || len(f.Calls) != 0 {
		t.Errorf("calls %v:\n%s", f.Calls, out)
	}
	if after, _ := os.ReadFile(path); !bytes.Equal(before, after) {
		t.Error("colima.yaml changed")
	}
	if out = run(map[string]openshell.Reply{}); !strings.Contains(out, "checked by fenzi doctor while a sandbox runs") {
		t.Errorf("no sandbox:\n%s", out)
	}
}
