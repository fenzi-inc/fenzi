package relay

// Fakes shared by the relay tests: a gateway that answers with output
// recorded from OpenShell 0.1.2, and errors shaped like its refusals.

import (
	"context"
	"net/http"
	"os"
)

var errStale = staleError("proposal inputs changed; evaluation refreshed, refetch and review again")

type staleError string

func (e staleError) Error() string { return string(e) }

type errStatus int

func (e errStatus) Error() string { return http.StatusText(int(e)) }

type allow struct{}

func (allow) Check(context.Context, []byte, []byte) (bool, string, error) { return true, "", nil }

type fakeGW struct {
	logs         []byte
	logErr       error
	rules        []byte
	list         []byte
	set          bool
	policy       []byte
	approved     string
	approveCalls int
	approveErr   error
	pendingCalls int
	mode         string
	modeErr      error
}

// Version and ComputeDrivers return what OpenShell 0.1.2 gave on the test machine.
func (g *fakeGW) Version(context.Context) (string, error) { return "openshell 0.1.2\n", nil }
func (g *fakeGW) ComputeDrivers(context.Context) ([]string, error) {
	return []string{"docker"}, nil
}
func (g *fakeGW) GlobalSetting(context.Context, string) (string, error) {
	if g.mode == "" {
		return "<unset>", g.modeErr
	}
	return g.mode, g.modeErr
}
func (g *fakeGW) Sandboxes(context.Context) ([]string, error) { return []string{"bl-1"}, nil }
func (g *fakeGW) LogLines(context.Context, string, int) ([]byte, error) {
	return g.logs, g.logErr
}
func (g *fakeGW) PendingRules(context.Context, string) ([]byte, error) {
	g.pendingCalls++
	return g.rules, nil
}
func (g *fakeGW) RuleApprove(_ context.Context, _, chunk string) error {
	g.approveCalls++
	g.approved = chunk
	return g.approveErr
}
func (g *fakeGW) RuleReject(context.Context, string, string, string) error { return nil }
func (g *fakeGW) PolicySet(_ context.Context, _, file string) error {
	g.set = true
	b, err := os.ReadFile(file)
	g.policy = b
	return err
}
func (g *fakeGW) PolicyList(context.Context, string) ([]byte, error) { return g.list, nil }

const baseDoc = `version: 1
name: acme
agents: [claude]
workspace: read-write
hosts:
  - host: example.com
    access: read-only
approvals: person
`

const hostDoc = `version: 1
name: acme
agents: [claude]
workspace: read-write
hosts:
  - host: example.com
    access: read-only
  - host: pypi.org
    access: read-only
approvals: person
`

const wallDoc = `version: 1
name: acme
agents: [claude]
workspace: read-write
paths:
  read_only: [/etc]
hosts:
  - host: example.com
    access: read-only
approvals: person
`
