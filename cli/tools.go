package main

import (
	"errors"
	"strings"

	"fenzi/agents"
	"fenzi/cli/internal/run"
	"fenzi/cli/internal/tui"
	"fenzi/policies"
)

// jsonTools is fenzi tools --json: the languages the folder's files call
// for, and where the commands each needs come from in the agent's sandbox.
type jsonTools struct {
	Agent string `json:"agent"`
	// Image is the image fenzi run starts the sandbox from.
	Image string `json:"image"`
	// Built is whether Image is on this machine already; absent when no
	// image builder answered. When false, the first start builds it.
	Built      *bool           `json:"built,omitempty"`
	Toolchains []jsonToolchain `json:"toolchains"`
}

type jsonToolchain struct {
	Name     string   `json:"name"`
	Commands []string `json:"commands"`
	// Source is "image" when the agent's image carries the commands,
	// "added" when fenzi run adds them to a copy of it, and "missing" when
	// Fenzi does not add them; Note then says why.
	Source string `json:"source"`
	Note   string `json:"note,omitempty"`
}

// cmdTools shows what the folder's languages need in the sandbox, before a
// start: fenzi run adds the packages to a copy of the agent's image and
// checks the commands once the sandbox runs.
//
//	fenzi tools [agent]          for the agent setup chose, or the one named
//	fenzi tools --json [agent]   the same, for a program
//	fenzi tools --build [agent]  build the image fenzi run would start from, ahead of time
func cmdTools(e env, args []string) (int, error) {
	fs := newFlags("tools", e.stderr)
	asJSON := jsonFlag(fs)
	build := fs.Bool("build", false, "build the agent's image with the folder's tools added, so the first start does not wait for it")
	pos, err := parse(fs, args)
	if err != nil {
		return 1, err
	}
	if len(pos) > 1 {
		return 1, errors.New("fenzi tools takes one agent name")
	}
	name := defaultAgent()
	if len(pos) == 1 {
		name = pos[0]
	}
	entry, err := agents.Get(name)
	if err != nil {
		return 1, err
	}
	repo, err := cwd()
	if err != nil {
		return 1, err
	}
	chains := policies.DetectToolchains(repo)
	if *build {
		if *asJSON {
			return 1, errors.New("--build prints the build, not JSON; run fenzi tools --json after it")
		}
		return buildTools(e, entry, chains)
	}
	image, _, added := run.ToolsImage(entry, chains)
	doc := jsonTools{Agent: entry.Name, Image: image, Toolchains: []jsonToolchain{}}
	for _, t := range chains {
		row := jsonToolchain{Name: t.Name, Commands: t.Commands, Source: "image"}
		switch {
		case t.Adds():
			row.Source = "added"
		case t.Missing != "":
			row.Source, row.Note = "missing", t.Missing
		}
		doc.Toolchains = append(doc.Toolchains, row)
	}
	if len(added) > 0 {
		if b, err := imageBuilder(e, e.stderr); err == nil {
			built := b.Exists(e.ctx, doc.Image)
			doc.Built = &built
		}
	}
	if *asJSON {
		return 0, writeJSON(e.stdout, doc)
	}

	u := tui.New(e.stdin, e.stdout)
	if len(chains) == 0 {
		u.Done("Tools", "no language files here that Fenzi knows; the sandbox has git, node and python3")
		return 0, nil
	}
	for _, t := range doc.Toolchains {
		cmds := strings.Join(t.Commands, ", ")
		switch t.Source {
		case "image":
			u.Done(t.Name, cmds+", in the "+entry.Display+" image")
		case "added":
			detail := cmds + ", added to a copy of the " + entry.Display + " image"
			if doc.Built != nil && !*doc.Built {
				detail += ", built at the first start"
			}
			u.Done(t.Name, detail)
		default:
			u.Problem(t.Name, cmds+" missing: "+t.Note)
		}
	}
	u.Note("fenzi run checks these commands once the sandbox runs, and tells the agent about any that are missing.")
	return 0, nil
}

// buildTools is fenzi tools --build: the agent's image when it is missing,
// then the copy with the folder's tools, as fenzi run would build them.
// Unlike run, a failed build is an error: nothing else is waiting on it.
func buildTools(e env, entry agents.Entry, chains []policies.Toolchain) (int, error) {
	u := tui.New(e.stdin, e.stdout)
	tag, df, added := run.ToolsImage(entry, chains)
	if len(added) == 0 {
		u.Done("Tools", "nothing to add here; the "+entry.Display+" image has what this folder needs")
		return 0, nil
	}
	b, err := imageBuilder(e, e.stdout)
	if err != nil {
		return 1, err
	}
	list := policies.ToolchainNames(added)
	if b.Exists(e.ctx, tag) {
		u.Done("Tools", list+", built already: "+tag)
		return 0, nil
	}
	if !b.Exists(e.ctx, entry.Tag()) {
		base, err := entry.Dockerfile()
		if err != nil {
			return 1, err
		}
		u.Title("Building "+entry.Display, entry.Tag())
		if err := b.Build(e.ctx, entry.Tag(), base); err != nil {
			return 1, err
		}
	}
	u.Title("Adding "+list, tag)
	if err := b.Build(e.ctx, tag, df); err != nil {
		return 1, err
	}
	u.Done("Tools", list+", built: fenzi run starts from "+tag)
	return 0, nil
}
