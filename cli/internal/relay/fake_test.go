package relay

// Fakes shared by the relay tests: a gateway that answers with output
// recorded from OpenShell 0.1.2, and errors shaped like its refusals.

import (
	"context"
	"errors"
	"net/http"
	"os"

	"fenzi/cli/internal/openshell"
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
	listed       []string
	logCalls     int
	// effective is what sandbox get --policy-only prints; nil fails the
	// read, so a test that sets nothing compares nothing.
	effective      []byte
	effectiveCalls int
	listCalls      int
}

// Recorded output of openshell-prover 0.1.2.
const (
	proverPass    = `{"schema_version":1,"prover_version":"0.1.2","check":"boundary","coverage":{"domains":["filesystem","network_l4","network_rest","process","landlock"]},"result":"within_boundary","exit_code":0,"inputs":{"candidate":"c.yaml","boundary":"b.yaml"},"counterexample":null,"reason_code":null,"reason":null}`
	proverExceeds = `{"schema_version":1,"prover_version":"0.1.2","check":"boundary","coverage":{"domains":["filesystem","network_l4","network_rest","process","landlock"]},"result":"exceeds_boundary","exit_code":1,"inputs":{"candidate":"c.yaml","boundary":"b.yaml"},"counterexample":{"domain":"network","binary":null,"ancestor_binary":null,"binary_identity_required":false,"host":"paste.example.net","destination_ip":"8.8.8.8","trusted_gateway":false,"port":443,"protocol":"rest","method":"GET","path":"/"},"reason_code":null,"reason":null}`
)

// fakeProver answers every check with out and exit, as openshell-prover does.
func fakeProver(out string, exit int) (openshell.Prover, *openshell.Fake) {
	f := &openshell.Fake{Replies: map[string]openshell.Reply{"check": {Out: out, Exit: exit}}}
	return openshell.Prover{R: f}, f
}

func passing() openshell.Prover {
	p, _ := fakeProver(proverPass, 0)
	return p
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

// Sandboxes lists bl-1 unless the test set listed; an empty list is a
// gateway with no sandbox left.
func (g *fakeGW) Sandboxes(context.Context) ([]string, error) {
	if g.listed != nil {
		return g.listed, nil
	}
	return []string{"bl-1"}, nil
}
func (g *fakeGW) LogLines(context.Context, string, int) ([]byte, error) {
	g.logCalls++
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
func (g *fakeGW) PolicyList(context.Context, string) ([]byte, error) {
	g.listCalls++
	return g.list, nil
}
func (g *fakeGW) EffectivePolicy(context.Context, string) ([]byte, error) {
	g.effectiveCalls++
	if g.effective == nil {
		return nil, errors.New("no effective policy in this test")
	}
	return g.effective, nil
}

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
