package openshell

import (
	"context"
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
		Name: "n", From: "img:1", Policy: "p.yaml", Provider: "bl-claude",
		Labels: map[string]string{"policy_rev": "r1", "fenzi": "1"},
	})
	want := "sandbox create --name n --from img:1 --policy p.yaml --provider bl-claude --label fenzi=1 --label policy_rev=r1 --approval-mode manual --no-auto-providers --detach --output json"
	if f.Calls[0] != want {
		t.Errorf("got  %s\nwant %s", f.Calls[0], want)
	}
}

// Sandboxes created before the rename from Boundlane carry boundlane=1.
func TestSandboxesListsBothLabels(t *testing.T) {
	f := &Fake{Replies: map[string]Reply{
		"sandbox list --names --selector fenzi=1":     {Out: "bl-new-1a2b\n"},
		"sandbox list --names --selector boundlane=1": {Out: "bl-old-3c4d\nbl-new-1a2b\n"},
	}}
	got, err := Client{R: f}.Sandboxes(context.Background())
	if err != nil || strings.Join(got, " ") != "bl-new-1a2b bl-old-3c4d" {
		t.Fatalf("%q %v", got, err)
	}
}
