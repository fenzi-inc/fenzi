package openshell

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestProverResults(t *testing.T) {
	cases := []struct {
		name   string
		reply  Reply
		passed bool
		err    bool
	}{
		{"within, list coverage", Reply{Out: `{"result":"within_boundary","coverage":{"domains":["filesystem","network_l4","network_rest","process","landlock"]}}`}, true, false},
		{"within, string coverage", Reply{Out: `{"result":"within_boundary","coverage":{"domains":"domains=filesystem,network_l4,network_rest,process,landlock"}}`}, true, false},
		{"within, partial coverage", Reply{Out: `{"result":"within_boundary","coverage":{"domains":["filesystem"]}}`}, false, false},
		{"within, no coverage", Reply{Out: `{"result":"within_boundary"}`}, false, false},
		{"exceeds", Reply{Out: `{"result":"exceeds_boundary","counterexample":"filesystem write /tmp"}`, Exit: 1}, false, false},
		{"error", Reply{Out: `{"result":"error","reason_code":"invalid_policy"}`, Exit: 2}, false, false},
		{"unsupported", Reply{Out: `{"result":"unsupported","reason_code":"unsupported_policy_shape"}`, Exit: 3}, false, false},
		{"crash", Reply{Out: "", Exit: 101}, false, true},
		{"garbage", Reply{Out: "result: within_boundary"}, false, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := &Fake{Replies: map[string]Reply{"check": c.reply}}
			r, err := Prover{R: f}.Check(context.Background(), "c.yaml", "b.yaml")
			if (err != nil) != c.err {
				t.Fatalf("err = %v", err)
			}
			if r.Passed() != c.passed {
				t.Errorf("Passed = %v, result %+v", r.Passed(), r)
			}
			if f.Calls[0] != "check c.yaml --boundary b.yaml --output json" {
				t.Errorf("args = %q", f.Calls[0])
			}
		})
	}
}

// Recorded output of openshell-prover 0.1.2.
const (
	proverPass    = `{"schema_version":1,"prover_version":"0.1.2","check":"boundary","coverage":{"domains":["filesystem","network_l4","network_rest","process","landlock"]},"result":"within_boundary","exit_code":0,"inputs":{"candidate":"c.yaml","boundary":"b.yaml"},"counterexample":null,"reason_code":null,"reason":null}`
	proverExceeds = `{"schema_version":1,"prover_version":"0.1.2","check":"boundary","coverage":{"domains":["filesystem","network_l4","network_rest","process","landlock"]},"result":"exceeds_boundary","exit_code":1,"inputs":{"candidate":"c.yaml","boundary":"b.yaml"},"counterexample":{"domain":"network","binary":null,"ancestor_binary":null,"binary_identity_required":false,"host":"paste.example.net","destination_ip":"8.8.8.8","trusted_gateway":false,"port":443,"protocol":"rest","method":"GET","path":"/"},"reason_code":null,"reason":null}`
	proverUnsup   = `{"schema_version":1,"prover_version":"0.1.2","check":"boundary","coverage":{"domains":["filesystem","network_l4","network_rest","process","landlock"]},"result":"unsupported","exit_code":3,"inputs":{"candidate":"c.yaml","boundary":"b.yaml"},"counterexample":null,"reason_code":"unsupported_policy_shape","reason":"boundary policy rule 'registry_npmjs_org' uses authority outside the initial model"}`
)

func TestRecordedProverOutput(t *testing.T) {
	cases := []struct {
		out     string
		exit    int
		passed  bool
		example string
	}{
		{proverPass, 0, true, ""},
		{proverExceeds, 1, false, "any program can GET paste.example.net:443/"},
		{proverUnsup, 3, false, ""},
	}
	for _, c := range cases {
		f := &Fake{Replies: map[string]Reply{"check": {Out: c.out, Exit: c.exit}}}
		r, err := Prover{R: f}.Check(context.Background(), "c.yaml", "b.yaml")
		if err != nil {
			t.Fatal(err)
		}
		if r.Passed() != c.passed || r.Example() != c.example {
			t.Errorf("%s: Passed=%v Example=%q", r.Result, r.Passed(), r.Example())
		}
	}
}

func TestCounterexample(t *testing.T) {
	r := Result{Counterexample: []byte(`"filesystem write /tmp"`)}
	if r.Example() != "filesystem write /tmp" {
		t.Errorf("Example = %q", r.Example())
	}
	r = Result{Counterexample: []byte(`{"domain":"filesystem","path":"/etc","access":"write","binary":null}`)}
	if r.Example() != "access=write domain=filesystem path=/etc" {
		t.Errorf("Example = %q", r.Example())
	}
}

func TestVersionRange(t *testing.T) {
	v := VersionRange{Major: 0, Minor: 1}
	for s, want := range map[string]bool{
		"openshell 0.1.0":         true,
		"openshell version 0.1.7": true,
		"0.2.0":                   false,
		"1.1.0":                   false,
		"dev":                     false,
	} {
		if _, ok := v.Contains(s); ok != want {
			t.Errorf("Contains(%q) = %v", s, ok)
		}
	}
}

func TestCreateArgs(t *testing.T) {
	f := &Fake{}
	_, _ = Client{R: f}.SandboxCreate(context.Background(), CreateOptions{
		Name: "n", From: "img:1", Policy: "p.yaml", Provider: "fenzi-claude",
		Labels: map[string]string{"policy_rev": "r1", "fenzi": "1"},
	})
	want := "sandbox create --name n --from img:1 --policy p.yaml --provider fenzi-claude --label fenzi=1 --label policy_rev=r1 --approval-mode manual --no-auto-providers --detach --output json"
	if f.Calls[0] != want {
		t.Errorf("got  %s\nwant %s", f.Calls[0], want)
	}
}

// MCP server tokens are more providers, one --provider each.
func TestCreateArgsWithMCPProviders(t *testing.T) {
	f := &Fake{}
	_, _ = Client{R: f}.SandboxCreate(context.Background(), CreateOptions{
		Name: "n", From: "img:1", Policy: "p.yaml", Provider: "fenzi-claude", Providers: []string{"fenzi-mcp-a", "fenzi-mcp-b"},
	})
	if !strings.Contains(f.Calls[0], "--provider fenzi-claude --provider fenzi-mcp-a --provider fenzi-mcp-b ") {
		t.Errorf("got %s", f.Calls[0])
	}
}

// Sandboxes created before the rename from Boundlane carry boundlane=1.
func TestSandboxesListsBothLabels(t *testing.T) {
	f := &Fake{Replies: map[string]Reply{
		"sandbox list --selector fenzi=1":     {Out: "fenzi-new-1a2b\n"},
		"sandbox list --selector boundlane=1": {Out: "fenzi-old-3c4d\nfenzi-new-1a2b\n"},
	}}
	got, err := Client{R: f}.Sandboxes(context.Background())
	if err != nil || strings.Join(got, " ") != "fenzi-new-1a2b fenzi-old-3c4d" {
		t.Fatalf("%q %v", got, err)
	}
}

// Recorded from OpenShell 0.1.2 on 17 October 2026, after the container
// runtime restarted under a running sandbox: the list is a table with the
// phase last, and a label with no sandbox prints one line.
func TestListPhases(t *testing.T) {
	f := &Fake{Replies: map[string]Reply{
		"sandbox list --selector fenzi=1":     {Out: "NAME                 CREATED              PHASE\nfenzi-rs-brain-8a52  2026-10-17 19:20:02  Error\nfenzi-web-1a2b       2026-10-17 19:32:52  Ready\n"},
		"sandbox list --selector boundlane=1": {Out: "No sandboxes found.\n"},
	}}
	c := Client{R: f}
	list, err := c.List(context.Background())
	if err != nil || len(list) != 2 || list[0] != (Listed{"fenzi-rs-brain-8a52", PhaseError}) || list[1].Phase != "Ready" {
		t.Fatalf("%+v %v", list, err)
	}
	running, _ := c.Sandboxes(context.Background())
	lost, _ := c.Lost(context.Background())
	if strings.Join(running, " ") != "fenzi-web-1a2b" || strings.Join(lost, " ") != "fenzi-rs-brain-8a52" {
		t.Errorf("running %v, lost %v", running, lost)
	}
}

// The error as the runner returns it: the command, then OpenShell's framed
// message on stderr (0.1.2, `sandbox start` on a sandbox lost in a runtime
// restart).
func TestErrorMessage(t *testing.T) {
	err := errors.New("openshell sandbox start fenzi-rs-brain-8a52: Error:   × code: 'The system is not in a state required for the operation's\n  │ execution', message: \"sandbox must be Stopped, Completed, or a failed\n  │ main-process Error to start (current phase: Error)\"\n")
	if got := ErrorMessage(err); got != "sandbox must be Stopped, Completed, or a failed main-process Error to start (current phase: Error)" {
		t.Errorf("%q", got)
	}
	if got := ErrorMessage(errors.New("exit status 1")); got != "exit status 1" {
		t.Errorf("%q", got)
	}
}
