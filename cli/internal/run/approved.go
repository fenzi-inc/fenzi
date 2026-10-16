package run

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"

	"go.yaml.in/yaml/v3"

	"fenzi/compiler"
)

// ApprovedFile, in a sandbox's run folder, lists the hosts approved for that
// sandbox while it ran. They are loaded with its network policy, so a call of
// the same kind does not file another request, and fenzi policy apply keeps
// them when it loads a change to fenzi.yaml.
const ApprovedFile = "approved-hosts.yaml"

// LoadApproved reads the hosts approved for the sandbox whose run folder is dir.
func LoadApproved(dir string) ([]compiler.Host, error) {
	b, err := os.ReadFile(filepath.Join(dir, ApprovedFile))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var hosts []compiler.Host
	if err := yaml.Unmarshal(b, &hosts); err != nil {
		return nil, fmt.Errorf("%s: %w", filepath.Join(dir, ApprovedFile), err)
	}
	return hosts, nil
}

// SaveApproved adds h to the sandbox's approved hosts.
func SaveApproved(dir string, h compiler.Host) error {
	hosts, err := LoadApproved(dir)
	if err != nil {
		return err
	}
	hosts = append(hosts, h)
	b, err := yaml.Marshal(hosts)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, ApprovedFile), b, 0o600)
}

// ErrNarrower is returned when a host is already in the document with less
// access than the approval needs. Widening it is a change to fenzi.yaml.
var ErrNarrower = errors.New("already in the policy with less access")

// WithHost returns doc with h added at host level, and whether that changed
// anything. A host already allowed at the same level, or a read-only request
// to a read-write host, leaves doc as it is.
func WithHost(doc *compiler.Document, h compiler.Host) (*compiler.Document, bool, error) {
	out := *doc
	out.Hosts = slices.Clone(doc.Hosts)
	port := func(p int) int {
		if p == 0 {
			return 443
		}
		return p
	}
	for i, e := range out.Hosts {
		if e.Host != h.Host || port(e.Port) != port(h.Port) {
			continue
		}
		switch {
		case e.Access == h.Access && h.Access == compiler.AccessReadOnly,
			e.Access == compiler.AccessReadWrite && h.Access == compiler.AccessReadOnly:
			return doc, false, nil
		case e.Access == compiler.AccessReadWrite && h.Access == compiler.AccessReadWrite:
			if len(e.Allow) == 0 {
				return doc, false, nil
			}
			missing := false
			for _, a := range h.Allow {
				if !slices.Contains(e.Allow, a) {
					missing = true
				}
			}
			if !missing {
				return doc, false, nil
			}
			e.Allow = append(slices.Clone(e.Allow), h.Allow...)
			out.Hosts[i] = e
			return &out, true, nil
		default:
			return doc, false, ErrNarrower
		}
	}
	out.Hosts = append(out.Hosts, h)
	return &out, true, nil
}
