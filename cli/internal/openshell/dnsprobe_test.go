package openshell

import (
	"context"
	"os"
	"slices"
	"strings"
	"testing"
)

// Not recorded: no sandbox was asked. These are the answers the 0.1.2
// supervisor builds for an allowed name (policy_dns/wire.rs): one A record
// with a placeholder address and the mapping's TTL, which is the resolver's
// TTL clamped to 1 to 30 seconds. ttl1 is what a TTL of 0 from the resolver
// becomes; ttl30 is a resolver TTL of 30 or more.
const (
	sandboxTTL1  = "464281800001000100000000036170690667697468756203636f6d0000010001c00c00010001000000010004c6120002\n"
	sandboxTTL30 = "464281800001000100000000036170690667697468756203636f6d0000010001c00c000100010000001e0004c6120002\n"
)

func TestSandboxTTLs(t *testing.T) {
	cases := []struct {
		name  string
		reply Reply
		want  []uint32
		short bool
		err   string
	}{
		{"ttl 1", Reply{Out: sandboxTTL1 + sandboxTTL1}, []uint32{1, 1}, true, ""},
		{"ttl 30", Reply{Out: sandboxTTL30 + sandboxTTL30}, []uint32{30, 30}, false, ""},
		{"one of two expiring", Reply{Out: sandboxTTL1 + sandboxTTL30}, []uint32{1, 30}, false, ""},
		{"refused", Reply{Out: "464281850001000000000000036170690667697468756203636f6d0000010001\n"}, nil, false, "DNS error code 5"},
		{"exec failed", Reply{Exit: 1, Stderr: "TimeoutError: timed out\n"}, nil, false, "TimeoutError: timed out"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := &Fake{Replies: map[string]Reply{"sandbox exec": c.reply}}
			got, err := Client{R: f}.SandboxTTLs(context.Background(), "fenzi-web-1a2b", "api.github.com")
			if c.err != "" {
				if err == nil || !strings.Contains(err.Error(), c.err) {
					t.Fatalf("err %v, want %q", err, c.err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(got, c.want) || ShortTTL(got) != c.short {
				t.Errorf("got %v, short %v", got, ShortTTL(got))
			}
			// The query asks the sandbox's own resolver: no address given.
			if want := "sandbox exec -n fenzi-web-1a2b --no-login-shell -- python3 -c " + dnsQuery + " api.github.com "; f.Calls[0] != want {
				t.Errorf("call %q", f.Calls[0])
			}
		})
	}
}

func TestPolicyHost(t *testing.T) {
	golden, err := os.ReadFile("../../../compiler/testdata/golden/signin.policy.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if got := PolicyHost(golden); got != "api.github.com" {
		t.Errorf("golden: %q", got)
	}
	wild := []byte("network_policies:\n  a_any:\n    endpoints:\n      - host: '*.example.com'\n  b_one:\n    endpoints:\n      - host: '*.x.org'\n      - host: pypi.org\n")
	if got := PolicyHost(wild); got != "pypi.org" {
		t.Errorf("wildcards: %q", got)
	}
	if got := PolicyHost([]byte("network_policies: {}\n")); got != "" {
		t.Errorf("empty: %q", got)
	}
}
