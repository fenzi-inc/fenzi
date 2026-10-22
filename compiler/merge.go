package compiler

import (
	"fmt"
	"strings"
)

// Merge layers a project file over a base document, such as developer-default
// on the Free plan. A project may add hosts and paths and change workspace
// access. A host the project lists on the same port replaces the base entry.
// A project may add MCP servers and narrow one the base has.
// Name, agents, and approvals belong to the base and cannot be set by a project.
func Merge(base, project *Document) (*Document, error) {
	if project == nil {
		return base.clone(), nil
	}
	var p []string
	if project.Version != 1 {
		p = append(p, fmt.Sprintf("version: must be 1, got %d", project.Version))
	}
	if project.Name != "" {
		p = append(p, "name: set in the base policy, not in a project file")
	}
	if len(project.Agents) > 0 {
		p = append(p, "agents: set in the base policy, not in a project file")
	}
	if project.MemberMCP != "" {
		p = append(p, "member_mcp: set in a team's policy, not in a project file")
	}
	if project.Approvals != "" && project.Approvals != ApprovalsPerson {
		p = append(p, fmt.Sprintf("approvals: the only accepted value is %q", ApprovalsPerson))
	}
	if len(p) > 0 {
		return nil, &ValidationError{Problems: prefix("project file: ", p)}
	}

	out := base.clone()
	if project.Workspace != "" {
		out.Workspace = project.Workspace
	}
	out.Paths.ReadOnly = appendNew(out.Paths.ReadOnly, project.Paths.ReadOnly)
	out.Paths.ReadWrite = appendNew(out.Paths.ReadWrite, project.Paths.ReadWrite)

	key := func(h Host) string {
		port := h.Port
		if port == 0 {
			port = 443
		}
		return fmt.Sprintf("%s:%d", h.Host, port)
	}
	index := map[string]int{}
	for i, h := range out.Hosts {
		index[key(h)] = i
	}
	for _, h := range project.Hosts {
		h.Allow = append([]string(nil), h.Allow...)
		if i, ok := index[key(h)]; ok {
			out.Hosts[i] = h
			continue
		}
		index[key(h)] = len(out.Hosts)
		out.Hosts = append(out.Hosts, h)
	}
	if p := mergeMCP(out, project); len(p) > 0 {
		return nil, &ValidationError{Problems: prefix("project file: ", p)}
	}
	return out, nil
}

func appendNew(list, more []string) []string {
	seen := map[string]bool{}
	for _, s := range list {
		seen[s] = true
	}
	for _, s := range more {
		if !seen[s] {
			list = append(list, s)
			seen[s] = true
		}
	}
	return list
}

func prefix(pre string, list []string) []string {
	out := make([]string, len(list))
	for i, s := range list {
		out[i] = pre + strings.TrimSpace(s)
	}
	return out
}
