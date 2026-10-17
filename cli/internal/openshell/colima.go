package openshell

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// ColimaResolver is the resolver colima's VM sends every lookup to: the only
// nameserver in the VM's /etc/resolv.conf, with or without colima's dns
// setting (colima 0.10.1, Lima 2.1.1, Ubuntu 24.04).
const ColimaResolver = "192.168.5.1"

// DNSProbeName is the name the check asks colima's resolver for when no
// sandbox is running. developer-default allows it.
const DNSProbeName = "registry.npmjs.org"

// ColimaPublicDNS is what setup offers for colima's dns setting.
var ColimaPublicDNS = []string{"1.1.1.1", "8.8.8.8"}

// Colima runs the colima binary.
type Colima struct{ R Runner }

// ResolverTTLs asks the VM's resolver for name and returns the TTL of every
// A record in its answers. It is the check when no sandbox is running: on
// colima the supervisor's resolver is this one, so a TTL of 0 here lasts 1
// second in the sandbox.
func (c Colima) ResolverTTLs(ctx context.Context, name string) ([]uint32, error) {
	out, err := c.R.Output(ctx, "ssh", "--", "python3", "-c", dnsQuery, name, ColimaResolver)
	if err != nil {
		return nil, errors.New(lastLine(err))
	}
	return parseAnswers(out, name)
}

// OnColima reports whether the gateway's sandboxes run in colima: colima
// serves the socket the config names, or the config names none and colima
// is the only runtime running.
func (d Diagnosis) OnColima() bool {
	if d.OtherDriver != "" || len(d.Running) != 1 || d.Running[0].Name != "colima" {
		return false
	}
	return d.Configured == "" || d.Configured == d.Running[0].Socket
}

// ColimaFile is colima's config for the default profile.
func ColimaFile() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".colima", "default", "colima.yaml")
}

var dnsLine = regexp.MustCompile(`^(\s*)dns:\s*([^#]*?)\s*(#.*)?$`)

// findDNS returns the index of the dns line and whether it sets no
// resolvers: empty, [], null or ~, with no list under it.
func findDNS(lines []string) (int, bool) {
	for i, l := range lines {
		m := dnsLine.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		switch m[2] {
		case "[]", "null", "~":
			return i, true
		case "":
			for _, next := range lines[i+1:] {
				t := strings.TrimSpace(next)
				if t == "" || strings.HasPrefix(t, "#") {
					continue
				}
				return i, !strings.HasPrefix(t, "- ")
			}
			return i, true
		}
		return i, false
	}
	return -1, false
}

// CanSetColimaDNS says why SetColimaDNS would refuse, or nil.
func CanSetColimaDNS(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	switch i, empty := findDNS(strings.Split(string(b), "\n")); {
	case i < 0:
		return fmt.Errorf("%s has no dns line", path)
	case !empty:
		return fmt.Errorf("dns is already set in %s", path)
	}
	return nil
}

// SetColimaDNS replaces colima's empty dns line with servers. It changes
// only that line, and refuses a file where dns already names a resolver.
func SetColimaDNS(path string, servers []string) error {
	if err := CanSetColimaDNS(path); err != nil {
		return err
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	lines := strings.Split(string(b), "\n")
	i, _ := findDNS(lines)
	lines[i] = dnsLine.FindStringSubmatch(lines[i])[1] + ColimaDNSLine(servers)
	return os.WriteFile(path, []byte(strings.Join(lines, "\n")), info.Mode().Perm())
}

// ColimaDNSLine is the line SetColimaDNS writes, without its indent.
func ColimaDNSLine(servers []string) string {
	return "dns: [" + strings.Join(servers, ", ") + "]"
}
