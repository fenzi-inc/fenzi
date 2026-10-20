package main

// After an approval on the Free plan, the request's host is added to that
// sandbox's running network policy at host level: read-only for a read
// request, or the method and path for a write. A call of the same kind to
// that host then passes without another request, for the rest of the
// sandbox. A signed-in machine runs the team's signed policy, so there the
// approval stays exactly as the request asked.

import (
	"errors"
	"fmt"
	"path/filepath"
	"slices"

	"fenzi/agents"

	"fenzi/cli/internal/config"
	"fenzi/cli/internal/openshell"
	"fenzi/cli/internal/run"
	"fenzi/cli/internal/team"
	"fenzi/compiler"
)

// sameKindResult says what the widening did, for people and for --json.
type sameKindResult struct {
	// Loaded names the host rule the sandbox now has, empty when nothing
	// was added.
	Loaded string
	// Also lists the other pending requests the rule covers, approved too.
	Also []string
	// Skipped says why the approval stayed as the request asked.
	Skipped string
}

func sameKind(e env, dirs config.Dirs, sb config.Sandbox, p openshell.Proposal) sameKindResult {
	if _, err := team.Load(dirs); err == nil {
		return sameKindResult{}
	} else if !errors.Is(err, team.ErrNotEnrolled) {
		return sameKindResult{Skipped: err.Error()}
	}
	// The host rule is compiled for the agent's own programs. A request
	// from another program (curl run by the agent's shell, git) would be
	// replaced by a rule that does not name it, and that program refused
	// again after its approval (run of 19 October 2026), so it stays as
	// the request asked.
	own := agentPrograms(sb.Agent)
	if p.Binary != "" && own != nil && !slices.Contains(own, p.Binary) {
		return sameKindResult{Skipped: "only this request was approved: it is for " + filepath.Base(p.Binary) + ", and host rules cover the agent's own program"}
	}
	h, err := requestHost(p.Endpoints)
	if err != nil {
		return sameKindResult{Skipped: "only this request was approved: " + err.Error()}
	}
	dir := dirs.Run(sb.Name)
	prev, err := run.LoadResolved(dir)
	if err != nil {
		return sameKindResult{Skipped: "only this request was approved: the policy this sandbox runs was not saved"}
	}
	host := compiler.Host{Host: h.Host, Port: h.Port, Access: h.Access, Allow: h.Allow}
	next, changed, err := run.WithHost(prev, host)
	switch {
	case errors.Is(err, run.ErrNarrower):
		return sameKindResult{Skipped: fmt.Sprintf("only this request was approved: %s is already allowed with less access, and widening it to %s is a change to %s", h.key(), describe(h), run.ProjectFile)}
	case err != nil:
		return sameKindResult{Skipped: err.Error()}
	case !changed:
		return sameKindResult{}
	}
	if _, _, err := loadHosts(e, dirs, sb, run.Resolved{Doc: next, Sources: "this sandbox's policy and its approvals"}); err != nil {
		return sameKindResult{Skipped: "only this request was approved; the host rule was not loaded: " + err.Error()}
	}
	if err := run.SaveApproved(dir, host); err != nil {
		return sameKindResult{Skipped: err.Error()}
	}
	res := sameKindResult{Loaded: describe(h)}
	// Requests already filed for the same host and the same kind of call are
	// covered by the rule now; answering them clears the pending list.
	if out, err := client().PendingRules(e.ctx, sb.Name); err == nil {
		for _, q := range openshell.ParseRules(out) {
			if q.Chunk == p.Chunk || q.MCP() || (q.Binary != "" && own != nil && !slices.Contains(own, q.Binary)) {
				continue
			}
			qh, err := requestHost(q.Endpoints)
			if err != nil || qh.key() != h.key() {
				continue
			}
			if _, covered, err := run.WithHost(next, compiler.Host{Host: qh.Host, Port: qh.Port, Access: qh.Access, Allow: qh.Allow}); err != nil || covered {
				continue
			}
			if client().RuleApprove(e.ctx, sb.Name, q.Chunk) == nil {
				res.Also = append(res.Also, shortID(q.Chunk))
			}
		}
	}
	return res
}

// line is the sentence shown after the approval.
func (r sameKindResult) line(host string) string {
	if r.Loaded == "" {
		return ""
	}
	s := "Calls of the same kind to " + host + " pass for the rest of this sandbox: " + r.Loaded + "."
	if len(r.Also) > 0 {
		s += fmt.Sprintf(" Also approved %d other pending request(s) it covers.", len(r.Also))
	}
	return s
}

// agentPrograms is the agent's binaries from the catalog, nil when the agent
// is not in it (then nothing is compared).
func agentPrograms(name string) []string {
	a, err := agents.Get(name)
	if err != nil || len(a.Binaries) == 0 {
		return nil
	}
	return a.Binaries
}
