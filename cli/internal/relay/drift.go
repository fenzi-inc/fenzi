package relay

// The policy compare: whether the policy the runtime holds for a running
// sandbox is the policy compiled from the team revision the sandbox runs.
//
// `openshell sandbox get <name> --policy-only` on OpenShell 0.1.2 printed the
// compiled policy with three differences: no leading comment line, no
// trailing newline, and one added network_policies entry per provider, named
// _provider_<provider name>. Key order and number types were unchanged. So
// both documents are parsed and compared section by section, with the
// provider entries left out.

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"

	"fenzi/cli/internal/config"
	"fenzi/cli/internal/run"
	"fenzi/compiler"
	"fenzi/teamapi"
)

// providerRule starts the name of a rule the runtime adds for a provider.
const providerRule = "_provider_"

// policyCheck is how one sandbox compared on a pass.
type policyCheck struct {
	// revision is the team revision the sandbox was compared against.
	revision int
	result   string
	differs  []string
}

// compare reads the policy each running sandbox holds, for each sandbox that
// was started from or last loaded a team revision, and compares it with the
// policy compiled from that revision for its agent. A sandbox that cannot be
// compared on this pass, because the gateway, the server, or the revision
// does not answer, gets no result; the server keeps the last one it had.
//
// Nothing of either policy is printed. A mismatch note names the sandbox, the
// revision, and the top-level sections that differ.
func (p *pass) compare(ctx context.Context) error {
	p.checks = map[string]policyCheck{}
	state, err := p.Dirs.LoadState()
	if err != nil {
		return err
	}
	var todo []int
	for i, sb := range state.Sandboxes {
		if sb.Running && sb.TeamRevision > 0 {
			todo = append(todo, i)
		}
	}
	if len(todo) == 0 {
		return nil
	}
	names, err := p.Gateway.Sandboxes(ctx)
	if err != nil {
		// ship lists the sandboxes again and reports the error.
		return nil
	}
	live := map[string]bool{}
	for _, n := range names {
		live[n] = true
	}
	docs := map[int]*compiler.Document{}
	changed := false
	for _, i := range todo {
		sb := &state.Sandboxes[i]
		if !live[sb.Name] {
			continue
		}
		if sb.PendingLoad != 0 {
			// Whether --policy-only shows the Loaded or the Pending revision
			// after policy set was not recorded on OpenShell 0.1.2. So a
			// sandbox with a load policy list has not shown Loaded is not
			// compared: it may still hold the revision before.
			list, err := p.Gateway.PolicyList(ctx, sb.Name)
			if err != nil || run.ListState(list) != run.LoadLoaded {
				p.checks[sb.Name] = policyCheck{revision: sb.TeamRevision, result: teamapi.PolicyPending}
				continue
			}
			sb.PendingLoad = 0
			changed = true
		}
		doc := p.revisionDocument(ctx, sb.TeamRevision, docs)
		if doc == nil {
			continue
		}
		c, ok := p.compareOne(ctx, *sb, doc)
		if !ok {
			continue
		}
		c.revision = sb.TeamRevision
		p.checks[sb.Name] = c
		if c.result == teamapi.PolicyMismatch {
			p.note(fmt.Sprintf("%s: the policy the runtime holds differs from r%d in %s", sb.Name, sb.TeamRevision, strings.Join(c.differs, ", ")))
		}
	}
	if changed {
		return p.Dirs.SaveState(state)
	}
	return nil
}

// revisionDocument is the org document of a team revision: the signed one
// this machine holds, or the one the server returns for an older revision.
// Nil means it is not available on this pass.
func (p *pass) revisionDocument(ctx context.Context, n int, docs map[int]*compiler.Document) *compiler.Document {
	if d, ok := docs[n]; ok {
		return d
	}
	var raw []byte
	switch {
	case n == p.Revision && len(p.Document) > 0:
		raw = p.Document
	case p.up():
		b, err := p.Client.Revision(ctx, p.Token, n)
		if err != nil {
			// Not compared on this pass. The heartbeat and the upload
			// report a server that does not answer.
			docs[n] = nil
			return nil
		}
		raw = b.Document
	default:
		return nil
	}
	d, err := compiler.Parse(raw)
	if err != nil {
		d = nil
	}
	docs[n] = d
	return d
}

// compareOne compiles doc for the agent and compares it with the policy the
// runtime holds for the sandbox. ok is false when either could not be had.
func (p *pass) compareOne(ctx context.Context, sb config.Sandbox, doc *compiler.Document) (policyCheck, bool) {
	name := sb.Name
	entry, err := run.AgentFor(sb)
	if err != nil {
		return policyCheck{}, false
	}
	compiled, err := compiler.Compile(doc, compiler.Target{Agent: entry.CompilerAgent(), Workdir: compiler.DefaultWorkdir})
	if err != nil {
		return policyCheck{}, false
	}
	want, err := compiled.YAML("")
	if err != nil {
		return policyCheck{}, false
	}
	got, err := p.Gateway.EffectivePolicy(ctx, name)
	if err != nil {
		return policyCheck{}, false
	}
	differs, err := policyDiff(want, got)
	if err != nil {
		return policyCheck{}, false
	}
	if len(differs) > 0 {
		return policyCheck{result: teamapi.PolicyMismatch, differs: differs}, true
	}
	return policyCheck{result: teamapi.PolicyMatch}, true
}

// policyDiff parses a compiled policy and the policy the runtime holds and
// returns the top-level sections that differ, sorted. Entries under
// network_policies whose name starts with _provider_ are left out of both.
func policyDiff(compiled, effective []byte) ([]string, error) {
	var want, got map[string]any
	if err := yaml.Unmarshal(compiled, &want); err != nil {
		return nil, fmt.Errorf("compiled policy: %w", err)
	}
	if err := yaml.Unmarshal(effective, &got); err != nil {
		return nil, fmt.Errorf("effective policy: %w", err)
	}
	if len(got) == 0 {
		return nil, errors.New("effective policy: empty")
	}
	dropProviderRules(want)
	dropProviderRules(got)
	keys := map[string]bool{}
	for k := range want {
		keys[k] = true
	}
	for k := range got {
		keys[k] = true
	}
	var out []string
	for k := range keys {
		if !reflect.DeepEqual(want[k], got[k]) {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out, nil
}

func dropProviderRules(doc map[string]any) {
	rules, ok := doc["network_policies"].(map[string]any)
	if !ok {
		return
	}
	for k := range rules {
		if strings.HasPrefix(k, providerRule) {
			delete(rules, k)
		}
	}
	if len(rules) == 0 {
		delete(doc, "network_policies")
	}
}
