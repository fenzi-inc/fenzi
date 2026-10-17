package openshell

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"
)

// How long the sandbox keeps an allowed name's address. In 0.1.2 the
// supervisor asks the first nameserver in its own /etc/resolv.conf, keeps the
// answer for its TTL clamped to 1 to 30 seconds, and answers the sandbox with
// that clamped TTL (policy_dns/mod.rs MIN_MAPPING_TTL, MAX_MAPPING_TTL,
// clamp_mapping_ttl; wire.rs). Neither the resolver nor the floor is a
// setting. A connection made after the mapping expires is refused with
// transparent_tcp_mapping_denied.
const (
	MinMappingTTL = 1
	MaxMappingTTL = 30
)

// dnsQuery sends one A query for argv[1] twice and prints each raw answer as
// hex. It asks argv[2], or the first nameserver in /etc/resolv.conf when
// argv[2] is empty, as a program in the sandbox does. Agent images and
// colima's VM have python3; neither has dig, nslookup or host.
const dnsQuery = `import socket,struct,sys
n,r=sys.argv[1],sys.argv[2]
if not r:
    r=[l.split()[1] for l in open("/etc/resolv.conf") if l.split()[:1]==["nameserver"]][0]
q=struct.pack(">HHHHHH",0x4642,0x0100,1,0,0,0)+b"".join(bytes([len(p)])+p.encode() for p in n.split("."))+b"\0"+struct.pack(">HH",1,1)
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.settimeout(3)
for _ in range(2):
    s.sendto(q,(r,53))
    print(s.recvfrom(4096)[0].hex())
`

// SandboxTTLs looks up host from inside a running sandbox, through the
// sandbox's own resolver, and returns the TTL of each A record. This is the
// TTL the agent sees, on any runtime: 1 means the supervisor keeps the
// address for 1 second.
func (c Client) SandboxTTLs(ctx context.Context, sandbox, host string) ([]uint32, error) {
	out, err := c.ExecOutput(ctx, sandbox, "python3", "-c", dnsQuery, host, "")
	if err != nil {
		return nil, errors.New(lastLine(err))
	}
	return parseAnswers(out, host)
}

// ShortTTL reports whether every TTL leaves the sandbox 1 second or less.
func ShortTTL(ttls []uint32) bool {
	for _, t := range ttls {
		if t > MinMappingTTL {
			return false
		}
	}
	return len(ttls) > 0
}

// PolicyHost returns the first exact host, by rule name, in a policy as
// `sandbox get --policy-only` prints it, or "" when there is none. A
// wildcard host is skipped: the lookup must be for a name the policy allows.
func PolicyHost(policy []byte) string {
	var p struct {
		Network map[string]struct {
			Endpoints []struct {
				Host string `yaml:"host"`
			} `yaml:"endpoints"`
		} `yaml:"network_policies"`
	}
	if yaml.Unmarshal(policy, &p) != nil {
		return ""
	}
	names := make([]string, 0, len(p.Network))
	for n := range p.Network {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		for _, e := range p.Network[n].Endpoints {
			if e.Host != "" && !strings.Contains(e.Host, "*") {
				return e.Host
			}
		}
	}
	return ""
}

// parseAnswers reads dnsQuery's output.
func parseAnswers(out []byte, name string) ([]uint32, error) {
	var ttls []uint32
	for _, line := range strings.Fields(string(out)) {
		msg, err := hex.DecodeString(line)
		if err != nil {
			return nil, fmt.Errorf("unexpected answer %q", line)
		}
		t, err := answerTTLs(msg)
		if err != nil {
			return nil, err
		}
		ttls = append(ttls, t...)
	}
	if len(ttls) == 0 {
		return nil, fmt.Errorf("no address for %s", name)
	}
	return ttls, nil
}

// lastLine is the reason a failed probe gives, without colima's own
// "level=fatal msg=exit status 1" line.
func lastLine(err error) string {
	var e *Error
	if !errors.As(err, &e) {
		return err.Error()
	}
	lines := strings.Split(strings.TrimSpace(e.Stderr), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if l := strings.TrimSpace(lines[i]); l != "" && !strings.HasPrefix(l, "time=") {
			return l
		}
	}
	return fmt.Sprintf("exit status %d", e.ExitCode)
}

// answerTTLs reads the TTL of each A record in a DNS answer.
func answerTTLs(m []byte) ([]uint32, error) {
	bad := errors.New("the resolver's answer could not be read")
	if len(m) < 12 {
		return nil, bad
	}
	if rcode := m[3] & 0x0f; rcode != 0 {
		return nil, fmt.Errorf("the resolver answered with DNS error code %d", rcode)
	}
	qd, an := binary.BigEndian.Uint16(m[4:6]), binary.BigEndian.Uint16(m[6:8])
	i := 12
	skipName := func() bool {
		for i < len(m) {
			switch l := int(m[i]); {
			case l == 0:
				i++
				return true
			case l&0xc0 == 0xc0:
				i += 2
				return i <= len(m)
			default:
				i += l + 1
			}
		}
		return false
	}
	for range qd {
		if !skipName() || i+4 > len(m) {
			return nil, bad
		}
		i += 4
	}
	var ttls []uint32
	for range an {
		if !skipName() || i+10 > len(m) {
			return nil, bad
		}
		typ, ttl, l := binary.BigEndian.Uint16(m[i:]), binary.BigEndian.Uint32(m[i+4:]), int(binary.BigEndian.Uint16(m[i+8:]))
		i += 10 + l
		if i > len(m) {
			return nil, bad
		}
		if typ == 1 {
			ttls = append(ttls, ttl)
		}
	}
	return ttls, nil
}
