package compiler

import "sort"

const (
	// EffectSame means the running sandbox already matches the new document.
	EffectSame = "same"
	// EffectNetwork means only hosts changed. OpenShell can load that on a running sandbox.
	EffectNetwork = "network"
	// EffectWall means workspace, paths, agents, approvals, or MCP servers
	// changed. Those are fixed when the sandbox is created: the agent reads
	// its MCP servers when it starts.
	EffectWall = "wall"
)

// Effect compares two org documents after defaults are filled in.
// A wall change wins when both hosts and the sandbox shape changed,
// because a running sandbox cannot pick up the shape.
func Effect(prev, next *Document) string {
	if prev == nil || next == nil {
		return EffectWall
	}
	a, b := prev.WithDefaults(), next.WithDefaults()
	wall := a.Version != b.Version ||
		a.Workspace != b.Workspace ||
		a.Approvals != b.Approvals ||
		!sameStrings(a.Agents, b.Agents) ||
		!sameStrings(a.Paths.ReadOnly, b.Paths.ReadOnly) ||
		!sameStrings(a.Paths.ReadWrite, b.Paths.ReadWrite) ||
		!sameMCP(a.MCP, b.MCP)
	network := !sameHosts(a.Hosts, b.Hosts)
	switch {
	case wall:
		return EffectWall
	case network:
		return EffectNetwork
	default:
		return EffectSame
	}
}

// EffectNote is the sentence the console and the CLI show for a kind.
func EffectNote(kind string) string {
	switch kind {
	case EffectNetwork:
		return "Applies to running agents."
	case EffectWall:
		return "Takes effect on the next run. Running agents keep the old paths."
	default:
		return "No change to what running agents can do."
	}
}

func sameStrings(a, b []string) bool {
	aa, bb := append([]string(nil), a...), append([]string(nil), b...)
	sort.Strings(aa)
	sort.Strings(bb)
	if len(aa) != len(bb) {
		return false
	}
	for i := range aa {
		if aa[i] != bb[i] {
			return false
		}
	}
	return true
}

func sameHosts(a, b []Host) bool {
	if len(a) != len(b) {
		return false
	}
	aa, bb := append([]Host(nil), a...), append([]Host(nil), b...)
	sort.Slice(aa, func(i, j int) bool { return hostKey(aa[i]) < hostKey(aa[j]) })
	sort.Slice(bb, func(i, j int) bool { return hostKey(bb[i]) < hostKey(bb[j]) })
	for i := range aa {
		if aa[i].Host != bb[i].Host || aa[i].Port != bb[i].Port || aa[i].Access != bb[i].Access || !sameStrings(aa[i].Allow, bb[i].Allow) {
			return false
		}
	}
	return true
}

func hostKey(h Host) string {
	return h.Host + "\n" + h.Access
}
