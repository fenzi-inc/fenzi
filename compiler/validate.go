package compiler

import (
	"errors"
	"fmt"
	"net"
	"path"
	"regexp"
	"strings"
)

// Limits from the OpenShell policy schema reference.
const (
	maxPathBytes = 4096
	maxPaths     = 256
)

var (
	agentName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)
	dnsLabel  = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)
	methods   = map[string]bool{"GET": true, "HEAD": true, "OPTIONS": true, "POST": true, "PUT": true, "PATCH": true, "DELETE": true}

	// Ports OpenShell blocks on exact-host endpoints (Kubernetes and etcd control planes).
	blockedPorts = map[int]bool{2379: true, 2380: true, 6443: true, 10250: true, 10255: true}

	// Paths that hold a user's home directory on Linux or a Mac.
	homeRoots = []string{"/root", "/home", "/Users"}
)

// ValidationError lists every problem found, with the field it belongs to.
type ValidationError struct {
	Problems []string
}

func (e *ValidationError) Error() string {
	return "invalid policy document:\n  " + strings.Join(e.Problems, "\n  ")
}

// Validate checks a document after defaults are applied. It rejects anything
// OpenShell would refuse and anything the prover cannot check.
func (d *Document) Validate() error {
	var p []string
	add := func(format string, args ...any) { p = append(p, fmt.Sprintf(format, args...)) }

	if d.Version != 1 {
		add("version: must be 1, got %d", d.Version)
	}
	for i, a := range d.Agents {
		if !agentName.MatchString(a) {
			add("agents[%d]: %q is not an agent name", i, a)
		}
	}
	switch d.Workspace {
	case "", WorkspaceReadWrite, WorkspaceReadOnly:
	default:
		add("workspace: must be %q or %q, got %q", WorkspaceReadWrite, WorkspaceReadOnly, d.Workspace)
	}
	switch d.Approvals {
	case "", ApprovalsPerson:
	default:
		add("approvals: the only accepted value is %q; there is no automatic approval", ApprovalsPerson)
	}

	seenPath := map[string]string{}
	checkPaths := func(field string, list []string, writable bool) {
		for i, raw := range list {
			f := fmt.Sprintf("paths.%s[%d]", field, i)
			if err := checkPath(raw, writable); err != nil {
				add("%s: %v", f, err)
				continue
			}
			if prev, ok := seenPath[raw]; ok {
				add("%s: %s is already listed in %s", f, raw, prev)
				continue
			}
			seenPath[raw] = f
		}
	}
	checkPaths("read_only", d.Paths.ReadOnly, false)
	checkPaths("read_write", d.Paths.ReadWrite, true)

	seenHost := map[string]int{}
	for i, h := range d.Hosts {
		// Named by host: the document is merged over developer-default, so
		// an index would not match the line in the person's file.
		f := fmt.Sprintf("hosts[%d]", i)
		if h.Host != "" {
			f = "hosts[" + h.Host + "]"
		}
		if err := checkHost(h.Host); err != nil {
			add("%s.host: %v", f, err)
		}
		port := h.Port
		if port == 0 {
			port = 443
		}
		if port < 1 || port > 65535 {
			add("%s.port: %d is not a TCP port", f, h.Port)
		} else if blockedPorts[port] {
			add("%s.port: %d is a cluster control-plane port that OpenShell blocks", f, port)
		}
		key := fmt.Sprintf("%s:%d", h.Host, port)
		if _, ok := seenHost[key]; ok {
			add("%s: %s is listed twice", f, key)
		}
		seenHost[key] = i

		switch h.Access {
		case AccessReadOnly:
			if len(h.Allow) > 0 {
				add("%s.allow: only used with access %q", f, AccessReadWrite)
			}
		case AccessReadWrite:
			if len(h.Allow) == 0 {
				add("%s.allow: access %q needs at least one \"METHOD /path\" line", f, AccessReadWrite)
			}
			for j, line := range h.Allow {
				if _, _, err := parseAllow(line); err != nil {
					add("%s.allow[%d]: %v", f, j, err)
				}
			}
		default:
			add("%s.access: must be %q or %q, got %q", f, AccessReadOnly, AccessReadWrite, h.Access)
		}
	}
	p = append(p, d.validateMCP(seenHost)...)

	if len(p) == 0 {
		return nil
	}
	return &ValidationError{Problems: p}
}

func checkPath(p string, writable bool) error {
	switch {
	case p == "":
		return errors.New("empty path")
	case !isASCII(p):
		return errors.New("non-ASCII paths cannot be checked by the prover")
	case len(p) > maxPathBytes:
		return fmt.Errorf("longer than %d bytes", maxPathBytes)
	case !strings.HasPrefix(p, "/"):
		return fmt.Errorf("%s is not absolute", p)
	case strings.Contains(p, ".."):
		return fmt.Errorf("%s contains ..", p)
	case path.Clean(p) != p:
		return fmt.Errorf("%s is not clean; write %s", p, path.Clean(p))
	case writable && p == "/":
		return errors.New("/ cannot be writable")
	}
	for _, h := range homeRoots {
		if p == h || strings.HasPrefix(p, h+"/") {
			return fmt.Errorf("%s is under a home directory; home directories are never in the sandbox", p)
		}
	}
	return nil
}

func checkHost(h string) error {
	switch {
	case h == "":
		return errors.New("empty host")
	case strings.Contains(h, "*"):
		return errors.New("wildcard hosts are not accepted in the MVP")
	case strings.Contains(h, "://") || strings.ContainsAny(h, "/:"):
		return fmt.Errorf("%q must be a bare host name, without scheme, port, or path", h)
	case net.ParseIP(h) != nil:
		return errors.New("IP addresses are not accepted; use a host name")
	case h != strings.ToLower(h):
		return fmt.Errorf("%q must be lowercase", h)
	case h == "localhost" || strings.HasSuffix(h, ".localhost"):
		return errors.New("loopback hosts are never reachable through network policy")
	case h == "host.openshell.internal":
		return errors.New("host.openshell.internal reaches the gateway host and is not accepted")
	}
	labels := strings.Split(h, ".")
	if len(labels) < 2 {
		return fmt.Errorf("%q is not a fully qualified host name", h)
	}
	for _, l := range labels {
		if !dnsLabel.MatchString(l) || len(l) > 63 {
			return fmt.Errorf("%q is not a valid host name", h)
		}
	}
	return nil
}

// parseAllow reads one "METHOD /path" line.
func parseAllow(line string) (method, p string, err error) {
	fields := strings.Fields(line)
	if len(fields) != 2 {
		return "", "", fmt.Errorf("%q must be \"METHOD /path\"", line)
	}
	method, p = fields[0], fields[1]
	if !methods[method] {
		return "", "", fmt.Errorf("%q is not an accepted method; list each method explicitly", method)
	}
	switch {
	case !strings.HasPrefix(p, "/"):
		return "", "", fmt.Errorf("path %q must start with /", p)
	case !isASCII(p):
		return "", "", errors.New("non-ASCII paths cannot be checked by the prover")
	case strings.ContainsAny(p, "?[]"):
		return "", "", fmt.Errorf("path %q uses ?, [ or ], which the prover cannot check", p)
	}
	return method, p, nil
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] > 0x7e || s[i] < 0x20 {
			return false
		}
	}
	return true
}

// countPaths is used to enforce the schema's 256-path limit on compiled output.
func countPaths(fs *FilesystemPolicy) int {
	return len(fs.ReadOnly) + len(fs.ReadWrite)
}
