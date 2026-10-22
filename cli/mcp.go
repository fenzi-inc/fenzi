package main

// fenzi mcp: the MCP servers every agent gets in this folder. Servers live in
// the mcp section of ./fenzi.yaml, or of ~/.config/fenzi/mcp.yaml for the
// ones used in every project, or of the team's policy on a signed-in
// machine. A remote server gets a rule the sandbox checks per tool; its
// token is stored on this machine and never written to a file. A local
// server lists the secrets it reads and the hosts it sends them to; each
// secret is stored the same way, and the sandbox puts it on those hosts only.

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"

	"fenzi/cli/internal/config"
	"fenzi/cli/internal/run"
	"fenzi/cli/internal/team"
	"fenzi/cli/internal/tui"
	"fenzi/compiler"
	"fenzi/policies"
)

func machineMCPFile() string {
	dirs, err := config.Default()
	if err != nil {
		return ""
	}
	return filepath.Join(dirs.Config, "mcp.yaml")
}

func cmdMCP(e env, args []string) (int, error) {
	if len(args) == 0 {
		return mcpList(e, nil)
	}
	switch args[0] {
	case "-h", "--help", "help":
		subHelp(e, "mcp", "The MCP servers every agent gets in this folder, from the mcp section of ./fenzi.yaml and of ~/.config/fenzi/mcp.yaml. The sandbox checks each call to a remote server against the tools listed for it, and a server's token stays outside the sandbox.", [][2]string{
			{"mcp list", "The servers agents get here, and where each comes from"},
			{"mcp add <name> <url> --tool <tool>", "Add a remote server and the tools agents may call; --all-tools for every tool"},
			{"mcp add <name> --claude-account --tool <tool>", "Let Claude Code use the connectors of the Claude account it is signed in with, and the tools it may call there"},
			{"mcp add <name> -- <command>", "Add a local server, which runs inside the sandbox; --secret <VAR> --host <host> for one that needs a secret"},
			{"mcp allow <name> <tool>...", "Let agents call more tools on a server already listed, in the file it comes from"},
			{"mcp remove <name>", "Remove a server"},
			{"mcp token <name>", "Store or replace a server's token, or a local server's secret; it is hidden as you type"},
			{"mcp token <name> --env <VAR>", "Store the secret a local server reads from VAR; every server that lists VAR shares it"},
			{"mcp import", "Copy the servers in .mcp.json or .cursor/mcp.json into fenzi.yaml"},
			{"mcp import --dry-run", "Show the servers an import would add, and write nothing; --json for a program"},
		}, "--machine on add and remove edits ~/.config/fenzi/mcp.yaml instead of ./fenzi.yaml. On a machine signed in to a team, agents get the team's servers and, unless the team's policy says team-only, the ones in ~/.config/fenzi/mcp.yaml within the team's limits; ./fenzi.yaml is not used. A change applies to the next fenzi run: agents read their servers when they start.")
		return 0, nil
	case "list":
		return mcpList(e, args[1:])
	case "add":
		return mcpAdd(e, args[1:])
	case "allow":
		return mcpAllow(e, args[1:])
	case "remove", "rm":
		return mcpRemove(e, args[1:])
	case "token":
		return mcpToken(e, args[1:])
	case "import":
		return mcpImport(e, args[1:])
	}
	return 1, fmt.Errorf("%q is not an mcp command; try fenzi mcp list, add, allow, remove, token, or import", args[0])
}

// jsonMCP is one server in fenzi mcp list --json.
type jsonMCP struct {
	Name string `json:"name"`
	URL  string `json:"url,omitempty"`
	// Account is "claude" for Claude's account connectors.
	Account string   `json:"account,omitempty"`
	Command []string `json:"command,omitempty"`
	Allow   []string `json:"allow"`
	Deny    []string `json:"deny"`
	Token   bool     `json:"token"`
	// TokenHeader is set when the token goes in a header other than
	// Authorization: Bearer.
	TokenHeader string `json:"token_header,omitempty"`
	// TokenStored is nil when the runtime could not be asked.
	TokenStored *bool `json:"token_stored,omitempty"`
	// Source is project, machine, project over machine, or team. On a team,
	// machine is a server of this machine's own, and team a server of the
	// team's policy, narrowed or not by this machine's file.
	Source string `json:"source"`
	// Refused says why a team's policy leaves this machine's server out; it
	// is then not given to agents. Empty when it is used.
	Refused string `json:"refused,omitempty"`
	// Secrets and Hosts are a local server's; see compiler.MCPServer.
	Secrets []jsonMCPSecret `json:"secrets,omitempty"`
	Hosts   []string        `json:"hosts,omitempty"`
}

// jsonMCPSecret is one secret a local server reads.
type jsonMCPSecret struct {
	Variable string `json:"variable"`
	// Stored is nil when the runtime could not be asked.
	Stored *bool `json:"stored,omitempty"`
}

func mcpList(e env, args []string) (int, error) {
	fs := newFlags("mcp list", e.stderr)
	asJSON := jsonFlag(fs)
	if _, err := parse(fs, args); err != nil {
		return 1, err
	}
	repo, err := cwd()
	if err != nil {
		return 1, err
	}
	dirs, err := config.Default()
	if err != nil {
		return 1, err
	}
	resolved, err := resolvePolicy(e, dirs, repo, "")
	if err != nil {
		return 1, err
	}
	// The same check run does, so a problem shows here and not first at run.
	if err := resolved.Doc.WithDefaults().Validate(); err != nil {
		return 1, err
	}
	teamDoc, _, onTeam, err := teamMCPLimits()
	if err != nil {
		return 1, err
	}
	machine, _ := run.LoadMachineMCP()
	project, _ := readProjectDoc(repo)

	oc := client()
	docs := []jsonMCP{}
	for _, n := range resolved.Doc.MCPNames() {
		s := resolved.Doc.MCP[n]
		d := jsonMCP{Name: n, URL: s.URL, Account: s.Account, Command: s.Command, Allow: nonNilStrings(s.Tools.Allow), Deny: nonNilStrings(s.Tools.Deny), Token: s.Token, TokenHeader: s.TokenHeader}
		_, inMachine := mcpOf(machine)[n]
		_, inProject := mcpOf(project)[n]
		_, inTeam := mcpOf(teamDoc)[n]
		switch {
		case onTeam && inTeam:
			d.Source = "team"
		case onTeam:
			d.Source = "machine"
		case inMachine && inProject:
			d.Source = "project over machine"
		case inProject:
			d.Source = "project"
		default:
			d.Source = "machine"
		}
		if s.Token {
			if ok, err := oc.ProviderExists(e.ctx, compiler.MCPProvider(n)); err == nil {
				d.TokenStored = &ok
			}
		}
		for _, v := range s.Secrets {
			sec := jsonMCPSecret{Variable: v}
			if ok, err := oc.ProviderExists(e.ctx, compiler.SecretProvider(v)); err == nil {
				sec.Stored = &ok
			}
			d.Secrets = append(d.Secrets, sec)
		}
		d.Hosts = s.Hosts
		docs = append(docs, d)
	}
	for _, n := range sortedKeys(resolved.MemberRefused) {
		s := machine.MCP[n]
		docs = append(docs, jsonMCP{Name: n, URL: s.URL, Account: s.Account, Command: s.Command, Allow: nonNilStrings(s.Tools.Allow), Deny: nonNilStrings(s.Tools.Deny),
			Token: s.Token, TokenHeader: s.TokenHeader, Source: "machine", Refused: resolved.MemberRefused[n], Hosts: s.Hosts})
	}
	if *asJSON {
		return 0, writeJSON(e.stdout, docs)
	}
	u := tui.New(e.stdin, e.stdout)
	u.Title("MCP servers", tilde(repo, homeDir()))
	if len(docs) == 0 {
		u.Skip("None", "agents here get no MCP servers")
		u.Note("fenzi mcp add <name> <url> --tool <tool> adds one to ./fenzi.yaml; --machine adds it for every project.")
		u.Blank()
		return 0, nil
	}
	for _, d := range docs {
		where := d.URL
		switch {
		case d.Account != "":
			where = "the connectors of Claude's account, for Claude Code"
		case where == "":
			where = strings.Join(d.Command, " ")
		}
		if d.Refused != "" {
			u.Skip(d.Name, where)
			u.Println("    " + u.Deny("not used: "+d.Refused))
			continue
		}
		u.Done(d.Name, where)
		u.Println("    " + u.Dim(mcpToolsLine(d)+", from "+mcpSourceLabel(d.Source, onTeam)))
		if d.Token {
			switch {
			case d.TokenStored == nil:
				u.Println("    " + u.Dim("token: the runtime did not answer"))
			case *d.TokenStored:
				u.Println("    " + u.Dim("token stored on this machine; the agent sees a placeholder"))
			default:
				u.Println("    " + u.Deny("no token stored. fenzi mcp token "+d.Name))
			}
		}
		if len(d.Hosts) > 0 {
			u.Println("    " + u.Dim("calls "+strings.Join(d.Hosts, ", ")))
		}
		for _, sec := range d.Secrets {
			switch {
			case sec.Stored == nil:
				u.Println("    " + u.Dim(sec.Variable+": the runtime did not answer"))
			case *sec.Stored:
				u.Println("    " + u.Dim(sec.Variable+" stored on this machine; the server sees a placeholder, filled on "+strings.Join(d.Hosts, ", ")+" only"))
			default:
				u.Println("    " + u.Deny("no "+sec.Variable+" stored. fenzi mcp token "+d.Name+" --env "+sec.Variable))
			}
		}
	}
	u.Blank()
	if onTeam && !teamDoc.MembersMayAddMCP() {
		u.Note("The team's policy gives agents the team's servers only; " + run.MachineMCPSource + " is not used.")
	}
	if remoteMCP(resolved.Doc) > 0 {
		u.Note("Each remote server's calls are checked per tool by the sandbox, and recorded in fenzi log. Its rules are checked by Fenzi, not by the policy prover.")
	}
	if len(resolved.Doc.Secrets()) > 0 {
		u.Note("A local server's secret is a placeholder inside the sandbox. Any program the agent starts can send it to the hosts listed with it, and nowhere else.")
	}
	u.Blank()
	return 0, nil
}

func mcpToolsLine(d jsonMCP) string {
	if d.URL == "" && d.Account == "" {
		return "runs inside the sandbox; not checked per tool"
	}
	allow := "tools: " + strings.Join(d.Allow, ", ")
	if len(d.Allow) == 1 && d.Allow[0] == compiler.AllTools {
		allow = "every tool"
	}
	if len(d.Deny) > 0 {
		allow += "; denied: " + strings.Join(d.Deny, ", ")
	}
	return allow
}

// mcpSourceLabel says where a server comes from, for people.
func mcpSourceLabel(source string, onTeam bool) string {
	switch {
	case source == "team":
		return "the team's policy"
	case onTeam && source == "machine":
		return "this machine (" + run.MachineMCPSource + ")"
	}
	return source
}

// teamMCPLimits reads the team's policy and boundary from the signed
// revision this machine holds, without asking the server. onTeam is false,
// with no error, on a machine that is not signed in; team is nil before the
// first revision.
func teamMCPLimits() (teamDoc, boundary *compiler.Document, onTeam bool, err error) {
	dirs, err := config.Default()
	if err != nil {
		return nil, nil, false, err
	}
	en, err := team.Load(dirs)
	if errors.Is(err, team.ErrNotEnrolled) {
		return nil, nil, false, nil
	}
	if err != nil {
		return nil, nil, false, err
	}
	if en.Revision == 0 {
		return nil, nil, true, nil
	}
	b, err := en.Bundle()
	if err != nil {
		return nil, nil, true, err
	}
	if teamDoc, err = compiler.Parse(b.Document); err != nil {
		return nil, nil, true, err
	}
	if len(b.Boundary) > 0 {
		if boundary, err = compiler.Parse(b.Boundary); err != nil {
			return nil, nil, true, fmt.Errorf("team boundary: %w", err)
		}
	}
	return teamDoc, boundary, true, nil
}

// checkMemberServer refuses, on a team, a server this machine is about to
// write: anywhere but the machine file, or outside the team's limits. Off
// a team it says nothing.
func checkMemberServer(name string, s compiler.MCPServer, machine bool) error {
	teamDoc, boundary, onTeam, err := teamMCPLimits()
	if err != nil || !onTeam {
		return err
	}
	if !machine {
		return fmt.Errorf("this machine is signed in to a team, so ./%s is not used. Add it for this machine with --machine", run.ProjectFile)
	}
	if teamDoc == nil {
		return errors.New("the team has no policy yet; an admin publishes one in the console, then this machine can add its own servers")
	}
	_, refused := compiler.MergeMemberMCP(teamDoc, &compiler.Document{Version: 1, MCP: map[string]compiler.MCPServer{name: s}}, boundary)
	if why := refused[name]; why != "" {
		return fmt.Errorf("the team would not give agents %s: %s. An admin changes the team's servers in the team console", name, why)
	}
	return nil
}

func mcpOf(d *compiler.Document) map[string]compiler.MCPServer {
	if d == nil {
		return nil
	}
	return d.MCP
}

func nonNilStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func readProjectDoc(repo string) (*compiler.Document, error) {
	raw, err := os.ReadFile(filepath.Join(repo, run.ProjectFile))
	if err != nil {
		return nil, err
	}
	return compiler.Parse(raw)
}

// stringList is a repeatable flag.
type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

func mcpAdd(e env, args []string) (int, error) {
	fs := newFlags("mcp add", e.stderr)
	var tools, deny stringList
	fs.Var(&tools, "tool", "a tool agents may call; repeat for more")
	fs.Var(&deny, "deny", "a tool agents may never call; repeat for more")
	all := fs.Bool("all-tools", false, "allow every tool the server has, except --deny")
	token := fs.Bool("token", false, "the server needs a token; store it with fenzi mcp token <name>")
	tokenHeader := fs.String("token-header", "", "the header the server reads its token from, when it is not Authorization: Bearer; implies --token")
	machine := fs.Bool("machine", false, "add it to ~/.config/fenzi/mcp.yaml, for every project")
	account := fs.Bool("claude-account", false, "the connectors of the Claude account Claude Code is signed in with")
	var secrets, hosts stringList
	fs.Var(&secrets, "secret", "a variable a local server reads that holds a secret; repeat for more")
	fs.Var(&hosts, "host", "a host a local server calls, over HTTPS; repeat for more")
	pos, err := parse(fs, args)
	if err != nil {
		return 1, err
	}
	local := false
	for _, a := range args {
		if a == "--" {
			local = true
			break
		}
	}
	if *account {
		return mcpAddAccount(e, pos, local, *all, tools, deny, *token || *tokenHeader != "" || len(secrets) > 0 || len(hosts) > 0, *machine)
	}
	if len(pos) < 2 {
		return 1, errors.New("name the server and its URL: fenzi mcp add linear https://mcp.linear.app/mcp --tool list_issues, or a local one: fenzi mcp add files -- npx -y @modelcontextprotocol/server-filesystem /sandbox")
	}
	name := pos[0]
	s := compiler.MCPServer{Token: *token || *tokenHeader != "", TokenHeader: *tokenHeader}
	if local {
		s.Command = pos[1:]
		if len(tools) > 0 || len(deny) > 0 || *all {
			return 1, errors.New("a local server is not checked per tool; drop --tool, --deny and --all-tools")
		}
		if s.Token {
			return 1, errors.New("--token and --token-header are for a remote server; a local server's secret is --secret <VAR> --host <host>")
		}
		s.Secrets, s.Hosts = secrets, hosts
	} else {
		if len(pos) != 2 {
			return 1, errors.New("a remote server takes one URL; put a local server's command after --")
		}
		if len(secrets) > 0 || len(hosts) > 0 {
			return 1, errors.New("--secret and --host are for a local server; a remote server's token is --token")
		}
		s.URL = pos[1]
		if *all {
			s.Tools.Allow = []string{compiler.AllTools}
		}
		s.Tools.Allow = append(s.Tools.Allow, tools...)
		s.Tools.Deny = deny
		if len(s.Tools.Allow) == 0 {
			return 1, fmt.Errorf("say which tools agents may call: --tool <name> for each, or --all-tools. fenzi checks every call to %s against that list", name)
		}
	}
	if err := checkMemberServer(name, s, *machine); err != nil {
		return 1, err
	}
	file, label := mcpFile(*machine)
	if file == "" {
		return 1, errors.New("no config folder on this machine")
	}
	f, err := loadMCPFile(file)
	if err != nil {
		return 1, err
	}
	replaced := f.put(name, s)
	if err := f.writeMCP(*machine); err != nil {
		return 1, err
	}
	u := tui.New(e.stdin, e.stdout)
	u.Blank()
	verb := "Added"
	if replaced {
		verb = "Replaced"
	}
	u.Done(verb, name+" in "+label)
	if s.Remote() {
		u.Note("The sandbox lets agents call " + mcpToolsLine(jsonMCP{URL: s.URL, Allow: s.Tools.Allow, Deny: s.Tools.Deny}) + " on " + s.URL + ", and nothing else there.")
	} else {
		u.Note("It runs inside the sandbox as a child of the agent, with the agent's limits.")
		if len(s.Hosts) > 0 {
			u.Note("The sandbox lets it call " + strings.Join(s.Hosts, ", ") + ". Other hosts it calls need to be in the policy's hosts.")
		} else {
			u.Note("Hosts it calls need --host, or the policy's hosts.")
		}
		for _, v := range s.Secrets {
			u.Note("Store " + v + " with fenzi mcp token " + name + " --env " + v + ". The server sees a placeholder; the sandbox puts the value only on requests to " + strings.Join(s.Hosts, ", ") + ".")
		}
	}
	if s.Token {
		u.Note("Store its token with fenzi mcp token " + name + ". The agent sees a placeholder.")
	}
	u.Note("The next fenzi run gives it to the agent.")
	u.Blank()
	return 0, nil
}

// mcpAddAccount adds Claude's account connectors with the tools Claude Code
// may call there.
func mcpAddAccount(e env, pos []string, local, all bool, tools, deny []string, extra, machine bool) (int, error) {
	if len(pos) != 1 || local {
		return 1, errors.New("name the entry and nothing else: fenzi mcp add claude-ai --claude-account --tool list_issues. Claude Code finds the connectors itself")
	}
	if extra {
		return 1, errors.New("--claude-account takes --tool, --deny and --all-tools only; Claude Code sends its own sign-in to its connectors")
	}
	s := compiler.MCPServer{Account: compiler.AccountClaude}
	if all {
		s.Tools.Allow = []string{compiler.AllTools}
	}
	s.Tools.Allow = append(s.Tools.Allow, tools...)
	s.Tools.Deny = deny
	if len(s.Tools.Allow) == 0 {
		return 1, errors.New("say which tools Claude Code may call on its connectors: --tool <name> for each, as the connector names it (list_issues, not mcp__claude_ai_Linear__list_issues), or --all-tools")
	}
	name := pos[0]
	if err := checkMemberServer(name, s, machine); err != nil {
		return 1, err
	}
	file, label := mcpFile(machine)
	if file == "" {
		return 1, errors.New("no config folder on this machine")
	}
	f, err := loadMCPFile(file)
	if err != nil {
		return 1, err
	}
	replaced := f.put(name, s)
	if err := f.writeMCP(machine); err != nil {
		return 1, err
	}
	u := tui.New(e.stdin, e.stdout)
	u.Blank()
	verb := "Added"
	if replaced {
		verb = "Replaced"
	}
	u.Done(verb, name+" in "+label)
	u.Note("On the connectors of its Claude account, the sandbox lets Claude Code call " + mcpToolsLine(jsonMCP{Account: s.Account, Allow: s.Tools.Allow, Deny: s.Tools.Deny}) + ". Each call is recorded in fenzi log. Other agents get nothing from it.")
	u.Note("Connectors come with a Claude subscription sign-in (fenzi run --sign-in claude); with an API key Claude Code has none.")
	u.Note("The next fenzi run gives them to Claude Code.")
	u.Blank()
	return 0, nil
}

// mcpAllow adds tools to a remote server's allow list, in the file the
// entry comes from: this folder's fenzi.yaml when it has the entry, else
// the machine file. It is how a refused MCP tool is let through: an agent
// cannot ask for one through the sandbox, and fenzi does not approve MCP
// requests, because the runtime stores an approved one for every tool.
func mcpAllow(e env, args []string) (int, error) {
	fs := newFlags("mcp allow", e.stderr)
	machine := fs.Bool("machine", false, "edit the entry in ~/.config/fenzi/mcp.yaml even when this folder's fenzi.yaml has one")
	pos, err := parse(fs, args)
	if err != nil {
		return 1, err
	}
	if len(pos) < 2 {
		return 1, errors.New("name the server and the tools: fenzi mcp allow claude-ai api_request")
	}
	name, tools := pos[0], pos[1:]
	_, _, onTeam, err := teamMCPLimits()
	if err != nil {
		return 1, err
	}
	// This folder's entry first: it is the one that applies here. On a
	// team only the machine file is used.
	useMachine := *machine || onTeam
	if !useMachine {
		file, _ := mcpFile(false)
		f, err := loadMCPFile(file)
		useMachine = file == "" || err != nil || !f.has(name)
	}
	file, label := mcpFile(useMachine)
	if file == "" {
		return 1, errors.New("no config folder on this machine")
	}
	f, err := loadMCPFile(file)
	if err != nil {
		return 1, err
	}
	node := value(f.mcpNode(), name)
	if node == nil {
		if onTeam {
			return 1, fmt.Errorf("%s is not in %s. A team server's tools are changed by an admin in the team console", name, run.MachineMCPSource)
		}
		return 1, fmt.Errorf("%s is not in ./%s or %s; fenzi mcp list shows the servers agents get here", name, run.ProjectFile, run.MachineMCPSource)
	}
	var s compiler.MCPServer
	if err := node.Decode(&s); err != nil {
		return 1, fmt.Errorf("%s in %s: %w", name, label, err)
	}
	if !s.Remote() {
		return 1, fmt.Errorf("%s is a local server: it runs inside the sandbox and is not checked per tool", name)
	}
	u := tui.New(e.stdin, e.stdout)
	if slices.Contains(s.Tools.Allow, compiler.AllTools) {
		u.Blank()
		u.Skip("Nothing to change", name+" already allows every tool in "+label)
		u.Blank()
		return 0, nil
	}
	var added []string
	for _, t := range tools {
		if slices.Contains(s.Tools.Deny, t) {
			return 1, fmt.Errorf("%s denies %s in %s. A denied tool stays refused; to allow it, replace the entry with fenzi mcp add", name, t, label)
		}
		if !slices.Contains(s.Tools.Allow, t) && !slices.Contains(added, t) {
			added = append(added, t)
		}
	}
	u.Blank()
	if len(added) == 0 {
		u.Skip("Nothing to change", name+" already allows "+strings.Join(tools, ", ")+" in "+label)
		u.Blank()
		return 0, nil
	}
	s.Tools.Allow = append(s.Tools.Allow, added...)
	if err := checkMemberServer(name, s, useMachine); err != nil {
		return 1, err
	}
	f.put(name, s)
	if err := f.writeMCP(useMachine); err != nil {
		return 1, err
	}
	u.Done("Allowed", strings.Join(added, ", ")+" on "+name+" in "+label)
	u.Note("Agents may now call " + strings.Join(s.Tools.Allow, ", ") + " there. The next fenzi run gets it; a sandbox already running keeps the tools it started with.")
	u.Blank()
	return 0, nil
}

func mcpRemove(e env, args []string) (int, error) {
	fs := newFlags("mcp remove", e.stderr)
	machine := fs.Bool("machine", false, "remove it from ~/.config/fenzi/mcp.yaml")
	pos, err := parse(fs, args)
	if err != nil {
		return 1, err
	}
	if len(pos) != 1 {
		return 1, errors.New("name the server: fenzi mcp remove <name>")
	}
	// On a team only the machine file is used.
	_, _, onTeam, err := teamMCPLimits()
	if err != nil {
		return 1, err
	}
	useMachine := *machine || onTeam
	file, label := mcpFile(useMachine)
	f, err := loadMCPFile(file)
	if err != nil {
		return 1, err
	}
	u := tui.New(e.stdin, e.stdout)
	u.Blank()
	if !f.remove(pos[0]) {
		u.Skip("Nothing to remove", pos[0]+" is not in "+label)
		if onTeam {
			u.Note("A team server is removed by an admin in the team console.")
		}
		u.Blank()
		return 0, nil
	}
	if err := f.writeMCP(useMachine); err != nil {
		return 1, err
	}
	u.Done("Removed", pos[0]+" from "+label)
	u.Note("Its token, if one is stored, stays until fenzi mcp token " + pos[0] + " --remove.")
	u.Blank()
	return 0, nil
}

func mcpToken(e env, args []string) (int, error) {
	fs := newFlags("mcp token", e.stderr)
	remove := fs.Bool("remove", false, "forget the token")
	variable := fs.String("env", "", "the variable a local server reads the secret from")
	pos, err := parse(fs, args)
	if err != nil {
		return 1, err
	}
	if len(pos) != 1 {
		return 1, errors.New("name the server: fenzi mcp token <name>")
	}
	name := pos[0]
	if err := (&compiler.Document{Version: 1, MCP: map[string]compiler.MCPServer{name: {Command: []string{"x"}}}}).Validate(); err != nil {
		return 1, fmt.Errorf("%q is not a server name", name)
	}
	here := mcpHere(e)
	if s, ok := here[name]; ok && s.Connectors() {
		return 1, fmt.Errorf("%s is Claude's account connectors; Claude Code sends its own sign-in there, so there is no token to store", name)
	}
	if *variable == "" {
		if s, ok := here[name]; ok && !s.Remote() {
			switch len(s.Secrets) {
			case 0:
				return 1, fmt.Errorf("%s is a local server and lists no secrets; add the variable it reads: fenzi mcp add %s --secret <VAR> --host <host> -- %s", name, name, strings.Join(s.Command, " "))
			case 1:
				*variable = s.Secrets[0]
			default:
				return 1, fmt.Errorf("%s reads %s; say which with --env", name, strings.Join(s.Secrets, " and "))
			}
		}
	}
	if *variable != "" {
		return mcpSecret(e, here, name, *variable, *remove)
	}
	oc := client()
	u := tui.New(e.stdin, e.stdout)
	if *remove {
		dirs, err := config.Default()
		if err != nil {
			return 1, err
		}
		removed, err := run.RemoveMCPToken(e.ctx, oc, dirs, name)
		if err != nil {
			return 1, err
		}
		u.Blank()
		if removed {
			u.Done("Removed", "the "+name+" token")
		} else {
			u.Skip("Nothing to remove", "no "+name+" token was stored")
		}
		u.Blank()
		return 0, nil
	}
	var value string
	if u.Interactive() {
		u.Blank()
		value, err = u.Secret("Paste the " + name + " token")
		if errors.Is(err, tui.ErrCancelled) {
			return 130, nil
		}
	} else {
		value, err = readLine(e)
	}
	if err != nil {
		return 1, err
	}
	replaced, err := run.SetMCPToken(e.ctx, oc, name, value)
	if err != nil {
		return 1, err
	}
	u.Blank()
	if replaced {
		u.Done("Replaced", "the "+name+" token")
	} else {
		u.Done("Stored", "the "+name+" token, on this machine")
	}
	u.Note("The agent sees a placeholder. The sandbox puts the token only on requests to " + name + ", which needs token: true in its entry (fenzi mcp add --token).")
	u.Blank()
	return 0, nil
}

// mcpHere is the servers agents get in this folder, or none when the policy
// here cannot be read.
func mcpHere(e env) map[string]compiler.MCPServer {
	repo, err := cwd()
	if err != nil {
		return nil
	}
	dirs, err := config.Default()
	if err != nil {
		return nil
	}
	resolved, err := resolvePolicy(e, dirs, repo, "")
	if err != nil || resolved.Doc == nil {
		return nil
	}
	return resolved.Doc.MCP
}

// mcpSecret stores, replaces, or removes the value of a local server's
// secret. It is stored once per variable: every server that lists the
// variable shares it.
func mcpSecret(e env, here map[string]compiler.MCPServer, name, variable string, remove bool) (int, error) {
	if err := compiler.CheckSecretName(variable); err != nil {
		return 1, err
	}
	if s, ok := here[name]; ok && !slices.Contains(s.Secrets, variable) {
		return 1, fmt.Errorf("%s does not list %s under secrets; add it with fenzi mcp add %s --secret %s --host <host> -- <command>", name, variable, name, variable)
	}
	var users, hosts []string
	for _, n := range sortedMCP(here) {
		s := here[n]
		if slices.Contains(s.Secrets, variable) {
			users = append(users, n)
			for _, h := range s.Hosts {
				if !slices.Contains(hosts, h) {
					hosts = append(hosts, h)
				}
			}
		}
	}
	slices.Sort(hosts)
	oc := client()
	u := tui.New(e.stdin, e.stdout)
	if remove {
		dirs, err := config.Default()
		if err != nil {
			return 1, err
		}
		removed, err := run.RemoveMCPSecret(e.ctx, oc, dirs, variable)
		if err != nil {
			return 1, err
		}
		u.Blank()
		if removed {
			u.Done("Removed", variable)
		} else {
			u.Skip("Nothing to remove", "no "+variable+" was stored")
		}
		u.Blank()
		return 0, nil
	}
	var value string
	var err error
	if u.Interactive() {
		u.Blank()
		value, err = u.Secret("Paste the value of " + variable)
		if errors.Is(err, tui.ErrCancelled) {
			return 130, nil
		}
	} else {
		value, err = readLine(e)
	}
	if err != nil {
		return 1, err
	}
	replaced, err := run.SetMCPSecret(e.ctx, oc, variable, value)
	if err != nil {
		return 1, err
	}
	u.Blank()
	if replaced {
		u.Done("Replaced", variable)
	} else {
		u.Done("Stored", variable+", on this machine")
	}
	switch {
	case len(users) == 0:
		u.Note("No server here lists " + variable + " yet. A local server that lists it under secrets gets a placeholder, and the sandbox puts the value only on requests to the hosts that server lists.")
	case len(users) <= 3:
		u.Note("Used here by " + strings.Join(users, ", ") + ". The server sees a placeholder; the sandbox puts the value only on requests to " + strings.Join(hosts, ", ") + ".")
	default:
		u.Note(fmt.Sprintf("Used here by %s and %d other servers. Each sees a placeholder; the sandbox puts the value only on requests to %s.", users[0], len(users)-1, strings.Join(hosts, ", ")))
	}
	u.Blank()
	return 0, nil
}

// jsonMCPImport is what mcp import --json prints, with or without --dry-run.
type jsonMCPImport struct {
	Sources []string          `json:"sources"`
	Added   []jsonMCPImported `json:"added"`
	Skipped []jsonMCPSkipped  `json:"skipped"`
	// Tokens are the servers whose token header was not copied.
	Tokens []string `json:"tokens"`
	// Secrets are the variables imported local servers read, whose values
	// were not copied, with the servers that read each.
	Secrets []jsonMCPImportSecret `json:"secrets"`
}

type jsonMCPImported struct {
	Name    string   `json:"name"`
	URL     string   `json:"url,omitempty"`
	Command []string `json:"command,omitempty"`
	Allow   []string `json:"allow"`
	Token   bool     `json:"token"`
	Secrets []string `json:"secrets,omitempty"`
	Hosts   []string `json:"hosts,omitempty"`
}

type jsonMCPImportSecret struct {
	Variable string   `json:"variable"`
	Servers  []string `json:"servers"`
	Hosts    []string `json:"hosts"`
}

type jsonMCPSkipped struct {
	Name   string `json:"name"`
	Reason string `json:"reason"`
}

// mcpImport copies servers from the agents' own project files into
// fenzi.yaml. A remote server comes in with every tool allowed and a note to
// narrow it; a header that looks like a token is not copied. --dry-run works
// out the same result and writes nothing.
func mcpImport(e env, args []string) (int, error) {
	fs := newFlags("mcp import", e.stderr)
	dryRun := fs.Bool("dry-run", false, "show the servers an import would add; write nothing")
	asJSON := jsonFlag(fs)
	pos, err := parse(fs, args)
	if err != nil {
		return 1, err
	}
	repo, err := cwd()
	if err != nil {
		return 1, err
	}
	if _, _, onTeam, err := teamMCPLimits(); err != nil {
		return 1, err
	} else if onTeam && !*dryRun {
		return 1, fmt.Errorf("this machine is signed in to a team, so ./%s is not used. Add each server for this machine with fenzi mcp add --machine", run.ProjectFile)
	}
	sources := pos
	if len(sources) == 0 {
		for _, c := range []string{".mcp.json", ".cursor/mcp.json"} {
			if _, err := os.Stat(filepath.Join(repo, c)); err == nil {
				sources = append(sources, c)
			}
		}
	}
	res := jsonMCPImport{Sources: nonNilStrings(sources), Added: []jsonMCPImported{}, Skipped: []jsonMCPSkipped{}, Tokens: []string{}, Secrets: []jsonMCPImportSecret{}}
	u := tui.New(e.stdin, e.stdout)
	if len(sources) == 0 {
		if *asJSON {
			return 0, writeJSON(e.stdout, res)
		}
		u.Blank()
		u.Skip("Nothing to import", "no .mcp.json or .cursor/mcp.json here")
		u.Blank()
		return 0, nil
	}
	f, err := loadMCPFile(filepath.Join(repo, run.ProjectFile))
	if err != nil {
		return 1, err
	}
	from := map[string]string{}
	for _, src := range sources {
		raw, err := os.ReadFile(filepath.Join(repo, src))
		if err != nil {
			return 1, err
		}
		servers, refused, needsToken, err := parseAgentMCP(raw)
		if err != nil {
			return 1, fmt.Errorf("%s: %w", src, err)
		}
		res.Skipped = append(res.Skipped, refused...)
		for _, n := range sortedMCP(servers) {
			if f.has(n) {
				reason := "already in fenzi.yaml; left as it is"
				if first, ok := from[n]; ok {
					reason = "also in " + first + "; the entry from there is kept"
				}
				res.Skipped = append(res.Skipped, jsonMCPSkipped{Name: n, Reason: reason})
				continue
			}
			s := servers[n]
			f.put(n, s)
			// Each server is checked on its own, so one the policy refuses
			// is left out with the reason and the rest still come in.
			if _, err := f.checkMCP(false); err != nil {
				f.remove(n)
				res.Skipped = append(res.Skipped, jsonMCPSkipped{Name: n, Reason: importProblem(n, err)})
				continue
			}
			from[n] = src
			res.Added = append(res.Added, jsonMCPImported{Name: n, URL: s.URL, Command: s.Command, Allow: nonNilStrings(s.Tools.Allow), Token: s.Token, Secrets: s.Secrets, Hosts: s.Hosts})
		}
		res.Tokens = append(res.Tokens, needsToken...)
	}
	res.Secrets = importSecrets(res.Added)
	if len(res.Added) > 0 {
		if *dryRun {
			_, err = f.checkMCP(false)
		} else {
			err = f.writeMCP(false)
		}
		if err != nil {
			return 1, err
		}
	}
	if *asJSON {
		return 0, writeJSON(e.stdout, res)
	}
	if *dryRun {
		u.Title("Import preview", "from "+strings.Join(sources, ", ")+"; nothing is written")
	} else {
		u.Blank()
	}
	for _, s := range res.Skipped {
		u.Skip(s.Name, s.Reason)
	}
	if len(res.Added) == 0 {
		u.Skip("Nothing new", "no server here can be added to fenzi.yaml")
		u.Blank()
		return 0, nil
	}
	names := make([]string, len(res.Added))
	for i, a := range res.Added {
		names[i] = a.Name
	}
	if *dryRun {
		for _, a := range res.Added {
			where := a.URL
			if where == "" {
				where = strings.Join(a.Command, " ")
			}
			u.Done(a.Name, where)
			u.Println("    " + u.Dim(mcpToolsLine(jsonMCP{URL: a.URL, Allow: a.Allow})))
		}
		if remoteAdded(res.Added) {
			u.Note("fenzi mcp import adds these to fenzi.yaml, with every tool allowed on a remote server. Narrow each one afterwards: fenzi mcp add <name> <url> --tool <tool>.")
		}
		for _, n := range res.Tokens {
			u.Note("The " + n + " entry sends a token in a header. It would not be copied; store the token with fenzi mcp token " + n + ".")
		}
		for _, sec := range res.Secrets {
			u.Note(importSecretNote(sec, "would not be copied"))
		}
		u.Blank()
		return 0, nil
	}
	u.Done("Imported", strings.Join(names, ", ")+" into fenzi.yaml")
	if remoteAdded(res.Added) {
		u.Note("Remote servers came in with every tool allowed. Narrow each one to the tools agents need: fenzi mcp add <name> <url> --tool <tool>.")
	}
	for _, n := range res.Tokens {
		u.Note("The " + n + " entry sent a token in a header. It was not copied; store the token with fenzi mcp token " + n + ".")
	}
	for _, sec := range res.Secrets {
		u.Note(importSecretNote(sec, "was not copied"))
	}
	u.Blank()
	return 0, nil
}

func remoteAdded(added []jsonMCPImported) bool {
	for _, a := range added {
		if a.URL != "" {
			return true
		}
	}
	return false
}

// importSecrets groups the imported local servers by the secrets they read.
func importSecrets(added []jsonMCPImported) []jsonMCPImportSecret {
	byVar := map[string]*jsonMCPImportSecret{}
	var order []string
	for _, a := range added {
		for _, v := range a.Secrets {
			s, ok := byVar[v]
			if !ok {
				s = &jsonMCPImportSecret{Variable: v, Servers: []string{}, Hosts: []string{}}
				byVar[v] = s
				order = append(order, v)
			}
			s.Servers = append(s.Servers, a.Name)
			for _, h := range a.Hosts {
				if !slices.Contains(s.Hosts, h) {
					s.Hosts = append(s.Hosts, h)
				}
			}
		}
	}
	slices.Sort(order)
	out := []jsonMCPImportSecret{}
	for _, v := range order {
		out = append(out, *byVar[v])
	}
	return out
}

func importSecretNote(s jsonMCPImportSecret, copied string) string {
	who := s.Servers[0] + " reads"
	if len(s.Servers) > 1 {
		who = fmt.Sprintf("%s and %d other servers read", s.Servers[0], len(s.Servers)-1)
	}
	return fmt.Sprintf("%s %s. Its value %s; store it once with fenzi mcp token %s --env %s. The sandbox puts it only on %s.", who, s.Variable, copied, s.Servers[0], s.Variable, strings.Join(s.Hosts, ", "))
}

// parseAgentMCP reads the mcpServers object Claude Code (.mcp.json) and
// Cursor (.cursor/mcp.json) use.
func parseAgentMCP(raw []byte) (map[string]compiler.MCPServer, []jsonMCPSkipped, []string, error) {
	var doc struct {
		MCPServers map[string]struct {
			Type    string            `json:"type"`
			URL     string            `json:"url"`
			Command string            `json:"command"`
			Args    []string          `json:"args"`
			Env     map[string]string `json:"env"`
			Headers map[string]string `json:"headers"`
		} `json:"mcpServers"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, nil, nil, err
	}
	out := map[string]compiler.MCPServer{}
	var skipped []jsonMCPSkipped
	var tokens []string
	for name, s := range doc.MCPServers {
		n := importName(name)
		var m compiler.MCPServer
		switch {
		case s.URL != "":
			m.URL = s.URL
			m.Tools.Allow = []string{compiler.AllTools}
			// A token goes in Authorization, or in another header whose name
			// or value looks like a secret. One per server.
			var carry []string
			for _, k := range sortedKeys(s.Headers) {
				if strings.EqualFold(k, "authorization") || compiler.SecretEnv(strings.ToUpper(strings.ReplaceAll(k, "-", "_")), s.Headers[k]) {
					carry = append(carry, k)
				}
			}
			if len(carry) > 1 {
				skipped = append(skipped, jsonMCPSkipped{Name: n, Reason: "sends a secret in " + strings.Join(carry, " and ") + "; fenzi puts a server's token in one header"})
				continue
			}
			if len(carry) == 1 {
				m.Token = true
				if !strings.EqualFold(carry[0], "authorization") {
					m.TokenHeader = carry[0]
				}
				tokens = append(tokens, n)
			}
		case s.Command != "":
			m.Command = append([]string{s.Command}, s.Args...)
			var secrets []string
			for k, v := range s.Env {
				if compiler.SecretEnv(k, v) {
					secrets = append(secrets, k)
					continue
				}
				if m.Env == nil {
					m.Env = map[string]string{}
				}
				m.Env[k] = v
			}
			if len(secrets) > 0 {
				sort.Strings(secrets)
				var unknown []string
				for _, v := range secrets {
					hosts, ok := knownSecretHosts[v]
					if !ok {
						unknown = append(unknown, v)
					}
					for _, h := range hosts {
						if !slices.Contains(m.Hosts, h) {
							m.Hosts = append(m.Hosts, h)
						}
					}
				}
				if len(unknown) > 0 {
					skipped = append(skipped, jsonMCPSkipped{Name: n, Reason: "Needs " + strings.Join(unknown, ", ") + ", a secret, and fenzi does not know which hosts the server sends it to. Add it with fenzi mcp add " + n + " --secret " + unknown[0] + " --host <host> -- " + strings.Join(m.Command, " ") + "."})
					continue
				}
				m.Secrets = secrets
			}
		default:
			skipped = append(skipped, jsonMCPSkipped{Name: n, Reason: "has neither a url nor a command"})
			continue
		}
		if _, dup := out[n]; dup {
			skipped = append(skipped, jsonMCPSkipped{Name: n, Reason: "another entry in the same file has this name"})
			continue
		}
		out[n] = m
	}
	sort.Strings(tokens)
	sort.Slice(skipped, func(i, j int) bool { return skipped[i].Name < skipped[j].Name })
	return out, skipped, tokens, nil
}

// knownSecretHosts are the hosts an imported server's secret is sent to,
// for variables whose server was run through the sandbox. The value is
// never copied; the host list fills the entry's hosts. DigitalOcean's
// server (@digitalocean/mcp 1.5.1, --services droplets) called only
// api.digitalocean.com through the sandbox on OpenShell 0.1.2. Its other
// services may call more hosts; the sandbox refuses those, and fenzi log
// shows them.
var knownSecretHosts = map[string][]string{
	"DIGITALOCEAN_API_TOKEN": {"api.digitalocean.com"},
}

// importName turns an agent's server name into one fenzi.yaml takes:
// lowercase, with underscores, spaces, and dots as dashes.
func importName(name string) string {
	n := strings.ToLower(strings.TrimSpace(name))
	n = strings.NewReplacer("_", "-", " ", "-", ".", "-").Replace(n)
	return strings.Trim(n, "-")
}

// importProblem is the first reason the policy gives for refusing a server,
// without the field path in front.
func importProblem(name string, err error) string {
	var ve *compiler.ValidationError
	if !errors.As(err, &ve) || len(ve.Problems) == 0 {
		return err.Error()
	}
	p := strings.TrimPrefix(ve.Problems[0], "project file: ")
	if i := strings.Index(p, ": "); i >= 0 && strings.HasPrefix(p, "mcp."+name) {
		p = p[i+2:]
	}
	return p
}

func sortedMCP(m map[string]compiler.MCPServer) []string {
	names := make([]string, 0, len(m))
	for n := range m {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

func mcpFile(machine bool) (string, string) {
	if machine {
		return machineMCPFile(), run.MachineMCPSource
	}
	repo, err := cwd()
	if err != nil {
		return "", ""
	}
	return filepath.Join(repo, run.ProjectFile), "./" + run.ProjectFile
}

// loadMCPFile reads fenzi.yaml or the machine file as YAML nodes, like
// approve --save, so comments and order survive.
func loadMCPFile(path string) (*projectFile, error) {
	if _, err := os.Stat(path); errors.Is(err, fs.ErrNotExist) {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return nil, err
		}
	}
	return loadProject(path)
}

// mcpNode returns the mcp mapping, creating it when missing.
func (p *projectFile) mcpNode() *yaml.Node {
	root := p.doc.Content[0]
	if v := value(root, "mcp"); v != nil {
		if v.Kind != yaml.MappingNode {
			*v = yaml.Node{Kind: yaml.MappingNode, Tag: "!!map", HeadComment: v.HeadComment}
		}
		return v
	}
	m := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	root.Content = append(root.Content, scalar("mcp"), m)
	return m
}

func (p *projectFile) has(name string) bool {
	return value(p.mcpNode(), name) != nil
}

// put sets one server, replacing an entry of the same name, and reports
// whether it replaced one.
func (p *projectFile) put(name string, s compiler.MCPServer) bool {
	var n yaml.Node
	if err := n.Encode(s); err != nil {
		return false
	}
	m := p.mcpNode()
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == name {
			m.Content[i+1] = &n
			return true
		}
	}
	m.Content = append(m.Content, scalar(name), &n)
	return false
}

func (p *projectFile) remove(name string) bool {
	root := p.doc.Content[0]
	m := value(root, "mcp")
	if m == nil {
		return false
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == name {
			m.Content = append(m.Content[:i], m.Content[i+2:]...)
			return true
		}
	}
	return false
}

// remoteMCP counts a document's remote servers.
func remoteMCP(d *compiler.Document) int {
	n := 0
	if d != nil {
		for _, s := range d.MCP {
			if s.Remote() {
				n++
			}
		}
	}
	return n
}

// checkMCP checks the edited file the way run will read it and returns its
// bytes: a project file over developer-default and the machine's servers.
func (p *projectFile) checkMCP(machine bool) ([]byte, error) {
	out, err := p.bytes()
	if err != nil {
		return nil, err
	}
	doc, err := compiler.Parse(out)
	if err != nil {
		return nil, err
	}
	if machine {
		if err := doc.WithDefaults().Validate(); err != nil {
			return nil, err
		}
		return out, nil
	}
	base := policies.DeveloperDefault()
	if m, err := run.LoadMachineMCP(); err != nil {
		return nil, err
	} else if m != nil {
		if base, err = compiler.Merge(base, m); err != nil {
			return nil, err
		}
	}
	merged, err := compiler.Merge(base, doc)
	if err != nil {
		return nil, err
	}
	if err := merged.WithDefaults().Validate(); err != nil {
		return nil, err
	}
	if err := checkProject(out); err != nil {
		return nil, err
	}
	return out, nil
}

// writeMCP checks the edited file with checkMCP, then writes it.
func (p *projectFile) writeMCP(machine bool) error {
	out, err := p.checkMCP(machine)
	if err != nil {
		return err
	}
	if machine {
		return os.WriteFile(p.path, out, 0o600)
	}
	return os.WriteFile(p.path, out, p.mode)
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
