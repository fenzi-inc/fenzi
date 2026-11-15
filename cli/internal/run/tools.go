package run

import (
	"context"
	"fmt"
	"strings"

	"fenzi/agents"
	"fenzi/policies"
)

// ToolsImage returns the image for the toolchains Fenzi adds, its
// Dockerfile, and those toolchains; the agent's own tag and nil when none
// of them adds anything.
func ToolsImage(a agents.Entry, chains []policies.Toolchain) (string, []byte, []policies.Toolchain) {
	var added []policies.Toolchain
	var names, packages, backports []string
	for _, t := range chains {
		if t.Adds() {
			added = append(added, t)
			names = append(names, t.Name)
			packages = append(packages, t.Packages...)
			backports = append(backports, t.Backports...)
		}
	}
	if len(added) == 0 {
		return a.Tag(), nil, nil
	}
	tag, df := a.ToolsImage(names, packages, backports)
	return tag, df, added
}

// toolsImage returns the image the sandbox starts from: the agent's own,
// or a copy with the packages of the project's toolchains, built on this
// machine the first time. A build that fails leaves the agent's own image;
// the check after the start then names what is missing.
func toolsImage(ctx context.Context, d Deps, a agents.Entry, chains []policies.Toolchain, say func(label, format string, args ...any)) string {
	tag, df, added := ToolsImage(a, chains)
	if len(added) == 0 {
		return tag
	}
	list := policies.ToolchainNames(added)
	if !d.Images.Exists(ctx, tag) {
		say("tools", "adding %s to the image, building on this machine", list)
		if err := d.Images.Build(ctx, tag, df); err != nil {
			say("tools", "%s could not be added (%v); the agent starts without them", list, err)
			return a.Tag()
		}
	}
	say("image", "%s, with %s", tag, list)
	return tag
}

// whichScript prints each argument that names a command on the sandbox's
// PATH, one per line, and always exits 0.
const whichScript = `import shutil, sys
print("\n".join(c for c in sys.argv[1:] if shutil.which(c)))`

// checkTools asks the sandbox which of the toolchains' commands it has,
// says so, and returns the agent's entry with a note about any that are
// missing, so it says so instead of looking for a way to install them.
func checkTools(ctx context.Context, d Deps, sandbox string, a agents.Entry, chains []policies.Toolchain, say func(label, format string, args ...any)) agents.Entry {
	if len(chains) == 0 {
		return a
	}
	var cmds []string
	for _, t := range chains {
		cmds = append(cmds, t.Commands...)
	}
	out, err := d.OpenShell.ExecOutput(ctx, sandbox, append([]string{"python3", "-c", whichScript}, cmds...)...)
	if err != nil {
		say("tools", "not checked: %v", err)
		return a
	}
	found := map[string]bool{}
	for _, line := range strings.Split(string(out), "\n") {
		if c := strings.TrimSpace(line); c != "" {
			found[c] = true
		}
	}
	var ready, missing []string
	for _, t := range chains {
		var gone []string
		for _, c := range t.Commands {
			if found[c] {
				ready = append(ready, c)
			} else {
				gone = append(gone, c)
			}
		}
		if len(gone) == 0 {
			continue
		}
		why := t.Missing
		if why == "" {
			why = "the image was not built with them"
		}
		say("tools", "%s missing for %s: %s", andList(gone), t.Name, why)
		missing = append(missing, gone...)
	}
	if len(ready) > 0 {
		say("tools", "%s ready", strings.Join(ready, ", "))
	}
	if len(missing) == 0 {
		return a
	}
	return a.WithNote(fmt.Sprintf("This sandbox has no %s, and cannot add them: installing packages needs root, which the sandbox does not give. When the task needs them, tell the developer, rather than looking for a way around it.", orList(missing)))
}

func andList(items []string) string { return joinList(items, "and") }
func orList(items []string) string  { return joinList(items, "or") }

func joinList(items []string, word string) string {
	switch len(items) {
	case 0:
		return ""
	case 1:
		return items[0]
	}
	return strings.Join(items[:len(items)-1], ", ") + " " + word + " " + items[len(items)-1]
}
