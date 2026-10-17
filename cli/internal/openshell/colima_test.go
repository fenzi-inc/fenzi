package openshell

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// Recorded on 17 October 2026 with colima 0.10.1 (Lima 2.1.1, Ubuntu 24.04)
// and dns set in colima.yaml: `colima ssh -- python3 -c <dnsQuery>
// registry.npmjs.org 192.168.5.1` printed two answers, twelve A records
// each, all with a TTL of 56.
const recordedNPM = "464281800001000c00000000087265676973747279056e706d6a73036f72670000010001c00c0001000100000038000468100222c00c0001000100000038000468100022c00c0001000100000038000468100422c00c0001000100000038000468100722c00c0001000100000038000468100622c00c0001000100000038000468100822c00c0001000100000038000468100a22c00c0001000100000038000468100522c00c0001000100000038000468100322c00c0001000100000038000468100122c00c0001000100000038000468100b22c00c0001000100000038000468100922\n"

// The same query for api.anthropic.com, one A record with a TTL of 43.
const recordedAnthropic = "4642818000010001000000000361706909616e7468726f70696303636f6d0000010001c00c000100010000002b0004a04f680a\n"

// The same query sent to an address with no resolver.
const recordedTimeout = `Traceback (most recent call last):
  File "<string>", line 8, in <module>
TimeoutError: timed out
time="2026-10-17T22:04:02+02:00" level=fatal msg="exit status 1"
`

func TestResolverTTLs(t *testing.T) {
	// With dns: null the resolver answered with a TTL of 0. That was seen
	// with another script, which kept no raw answer, so this is the recorded
	// answer with each TTL set to 0.
	zero := strings.ReplaceAll(recordedNPM, "c00c0001000100000038", "c00c0001000100000000")
	cases := []struct {
		name  string
		reply Reply
		want  []uint32
		zero  bool
		err   string
	}{
		{"npm", Reply{Out: recordedNPM + recordedNPM}, slices.Repeat([]uint32{56}, 24), false, ""},
		{"anthropic", Reply{Out: recordedAnthropic + recordedAnthropic}, []uint32{43, 43}, false, ""},
		{"ttl 0", Reply{Out: zero + zero}, make([]uint32, 24), true, ""},
		{"timeout", Reply{Exit: 1, Stderr: recordedTimeout}, nil, false, "TimeoutError: timed out"},
		{"garbage", Reply{Out: "python3: not found\n"}, nil, false, "unexpected answer"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := &Fake{Replies: map[string]Reply{"ssh -- python3 -c": c.reply}}
			got, err := Colima{R: f}.ResolverTTLs(context.Background(), DNSProbeName)
			if c.err != "" {
				if err == nil || !strings.Contains(err.Error(), c.err) || strings.Contains(err.Error(), "level=fatal") {
					t.Fatalf("err %v, want %q", err, c.err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(got, c.want) || ShortTTL(got) != c.zero {
				t.Errorf("got %v", got)
			}
			if want := "ssh -- python3 -c " + dnsQuery + " registry.npmjs.org 192.168.5.1"; f.Calls[0] != want {
				t.Errorf("call %q", f.Calls[0])
			}
		})
	}
}

func TestAnswerWithAnErrorCode(t *testing.T) {
	// NXDOMAIN: the recorded header with rcode 3 and no answers.
	if _, err := answerTTLs([]byte{0x46, 0x42, 0x81, 0x83, 0, 1, 0, 0, 0, 0, 0, 0}); err == nil || !strings.Contains(err.Error(), "code 3") {
		t.Errorf("err %v", err)
	}
	if _, err := answerTTLs([]byte{0x46, 0x42, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0, 3, 'a'}); err == nil {
		t.Error("a cut answer was read")
	}
}

func TestOnColima(t *testing.T) {
	colima := Runtime{Name: "colima", Socket: "/Users/you/.colima/default/docker.sock", Running: true}
	docker := Runtime{Name: "Docker Desktop", Socket: "/Users/you/.docker/run/docker.sock", Running: true}
	cases := []struct {
		name string
		d    Diagnosis
		want bool
	}{
		{"config names colima", diagnose([]Runtime{docker, colima}, gatewayConfig{socket: colima.Socket}), true},
		{"only colima runs", diagnose([]Runtime{colima}, gatewayConfig{}), true},
		{"config names docker", diagnose([]Runtime{docker, colima}, gatewayConfig{socket: docker.Socket}), false},
		{"two run, none named", diagnose([]Runtime{docker, colima}, gatewayConfig{}), false},
		{"microvm", diagnose([]Runtime{colima}, gatewayConfig{driver: "vm"}), false},
		{"colima stopped", diagnose([]Runtime{{Name: "colima", Socket: colima.Socket}}, gatewayConfig{}), false},
	}
	for _, c := range cases {
		if got := c.d.OnColima(); got != c.want {
			t.Errorf("%s: %v", c.name, got)
		}
	}
}

// colimaYAML is the network section of colima 0.10.1's colima.yaml, with
// the dns value replaced.
func colimaYAML(dns string) string {
	return `network:
  # Custom DNS resolvers for the virtual machine.
  #
  # EXAMPLE
  # dns: [8.8.8.8, 1.1.1.1]
  #
  # Default: []
` + dns + `
  # DNS hostnames to resolve to custom targets using the internal resolver.
  dnsHosts: {}
`
}

func TestSetColimaDNS(t *testing.T) {
	cases := []struct {
		name, dns, want, err string
	}{
		{"null", "  dns: null", "  dns: [1.1.1.1, 8.8.8.8]", ""},
		{"empty list", "  dns: []", "  dns: [1.1.1.1, 8.8.8.8]", ""},
		{"no value", "  dns:", "  dns: [1.1.1.1, 8.8.8.8]", ""},
		{"block list", "  dns:\n    - 10.0.0.2", "", "already set"},
		{"flow list", "  dns: [10.0.0.2]", "", "already set"},
		{"no line", "", "", "no dns line"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "colima.yaml")
			before := colimaYAML(c.dns)
			if err := os.WriteFile(path, []byte(before), 0o644); err != nil {
				t.Fatal(err)
			}
			err := SetColimaDNS(path, ColimaPublicDNS)
			after, _ := os.ReadFile(path)
			if c.err != "" {
				if err == nil || !strings.Contains(err.Error(), c.err) || string(after) != before {
					t.Errorf("err %v, file:\n%s", err, after)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if want := colimaYAML(c.want); string(after) != want {
				t.Errorf("got:\n%s\nwant:\n%s", after, want)
			}
		})
	}
}
