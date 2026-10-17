package main

// fenzi mcp: the MCP servers every agent gets in this folder. Servers live in
// the mcp section of ./fenzi.yaml, or of ~/.config/fenzi/mcp.yaml for the
// ones used in every project, or of the team's policy on a signed-in
// machine. A remote server gets a rule the sandbox checks per tool; its
// token is stored on this machine and never written to a file.

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
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
			{"mcp add <name> -- <command>", "Add a local server, which runs inside the sandbox"},
			{"mcp remove <name>", "Remove a server"},
			{"mcp token <name>", "Store or replace a server's token; it is hidden as you type"},
			{"mcp import", "Copy the servers in .mcp.json or .cursor/mcp.json into fenzi.yaml"},
			{"mcp import --dry-run", "Show the servers an import would add, and write nothing; --json for a program"},
		}, "--machine on add and remove edits ~/.config/fenzi/mcp.yaml instead of ./fenzi.yaml. A change applies to the next fenzi run: agents read their servers when they start.")
		return 0, nil
	case "list":
		return mcpList(e, args[1:])
	case "add":
		return mcpAdd(e, args[1:])
	case "remove", "rm":
		return mcpRemove(e, args[1:])
	case "token":
		return mcpToken(e, args[1:])
	case "import":
		return mcpImport(e, args[1:])
	}
	return 1, fmt.Errorf("%q is not an mcp command; try fenzi mcp list, add, remove, token, or import", args[0])
}

// jsonMCP is one server in fenzi mcp list --json.
type jsonMCP struct {
	Name    string   `json:"name"`
	URL     string   `json:"url,omitempty"`
	Command []string `json:"command,omitempty"`
	Allow   []string `json:"allow"`
	Deny    []string `json:"deny"`
	Token   bool     `json:"token"`
	// TokenStored is nil when the runtime could not be asked.
	TokenStored *bool `json:"token_stored,omitempty"`
	// Source is project, machine, project over machine, or team.
	Source string `json:"source"`
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
	_, enrolledErr := team.Load(dirs)
	onTeam := enrolledErr == nil
	machine, _ := run.LoadMachineMCP()
	project, _ := readProjectDoc(repo)

	oc := client()
	docs := []jsonMCP{}
	for _, n := range resolved.Doc.MCPNames() {
		s := resolved.Doc.MCP[n]
		d := jsonMCP{Name: n, URL: s.URL, Command: s.Command, Allow: nonNilStrings(s.Tools.Allow), Deny: nonNilStrings(s.Tools.Deny), Token: s.Token}
		_, inMachine := mcpOf(machine)[n]
		_, inProject := mcpOf(project)[n]
		switch {
		case onTeam:
			d.Source = "team"
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
		docs = append(docs, d)
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
		if where == "" {
			where = strings.Join(d.Command, " ")
		}
		u.Done(d.Name, where)
		u.Println("    " + u.Dim(mcpToolsLine(d)+", from "+d.Source))
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
	}
	u.Blank()
	u.Note("Each remote server's calls are checked per tool by the sandbox, and recorded in fenzi log. Its rules are checked by Fenzi, not by the policy prover.")
	u.Blank()
	return 0, nil
}

func mcpToolsLine(d jsonMCP) string {
	if d.URL == "" {
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
	machine := fs.Bool("machine", false, "add it to ~/.config/fenzi/mcp.yaml, for every project")
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
	if len(pos) < 2 {
		return 1, errors.New("name the server and its URL: fenzi mcp add linear https://mcp.linear.app/mcp --tool list_issues, or a local one: fenzi mcp add files -- npx -y @modelcontextprotocol/server-filesystem /sandbox")
	}
	name := pos[0]
	s := compiler.MCPServer{Token: *token}
	if local {
		s.Command = pos[1:]
		if len(tools) > 0 || len(deny) > 0 || *all {
			return 1, errors.New("a local server is not checked per tool; drop --tool, --deny and --all-tools")
		}
	} else {
		if len(pos) != 2 {
			return 1, errors.New("a remote server takes one URL; put a local server's command after --")
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
		u.Note("It runs inside the sandbox as a child of the agent, with the agent's limits. Hosts it calls need to be in the policy's hosts.")
	}
	if s.Token {
		u.Note("Store its token with fenzi mcp token " + name + ". The agent sees a placeholder.")
	}
	u.Note("The next fenzi run gives it to the agent.")
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
	file, label := mcpFile(*machine)
	f, err := loadMCPFile(file)
	if err != nil {
		return 1, err
	}
	u := tui.New(e.stdin, e.stdout)
	u.Blank()
	if !f.remove(pos[0]) {
		u.Skip("Nothing to remove", pos[0]+" is not in "+label)
		u.Blank()
		return 0, nil
	}
	if err := f.writeMCP(*machine); err != nil {
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

// jsonMCPImport is what mcp import --json prints, with or without --dry-run.
type jsonMCPImport struct {
	Sources []string          `json:"sources"`
	Added   []jsonMCPImported `json:"added"`
	Skipped []jsonMCPSkipped  `json:"skipped"`
	// Tokens are the servers whose Authorization header was not copied.
	Tokens []string `json:"tokens"`
}

type jsonMCPImported struct {
	Name    string   `json:"name"`
	URL     string   `json:"url,omitempty"`
	Command []string `json:"command,omitempty"`
	Allow   []string `json:"allow"`
	Token   bool     `json:"token"`
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
	sources := pos
	if len(sources) == 0 {
		for _, c := range []string{".mcp.json", ".cursor/mcp.json"} {
			if _, err := os.Stat(filepath.Join(repo, c)); err == nil {
				sources = append(sources, c)
			}
		}
	}
	res := jsonMCPImport{Sources: nonNilStrings(sources), Added: []jsonMCPImported{}, Skipped: []jsonMCPSkipped{}, Tokens: []string{}}
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
			res.Added = append(res.Added, jsonMCPImported{Name: n, URL: s.URL, Command: s.Command, Allow: nonNilStrings(s.Tools.Allow), Token: s.Token})
		}
		res.Tokens = append(res.Tokens, needsToken...)
	}
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
		u.Note("fenzi mcp import adds these to fenzi.yaml, with every tool allowed on a remote server. Narrow each one afterwards: fenzi mcp add <name> <url> --tool <tool>.")
		for _, n := range res.Tokens {
			u.Note("The " + n + " entry sends an Authorization header. It would not be copied; store the token with fenzi mcp token " + n + ".")
		}
		u.Blank()
		return 0, nil
	}
	u.Done("Imported", strings.Join(names, ", ")+" into fenzi.yaml")
	u.Note("Remote servers came in with every tool allowed. Narrow each one to the tools agents need: fenzi mcp add <name> <url> --tool <tool>.")
	for _, n := range res.Tokens {
		u.Note("The " + n + " entry sent an Authorization header. It was not copied; store the token with fenzi mcp token " + n + ".")
	}
	u.Blank()
	return 0, nil
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
			for k := range s.Headers {
				if strings.EqualFold(k, "authorization") {
					m.Token = true
					tokens = append(tokens, n)
				}
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
				skipped = append(skipped, jsonMCPSkipped{Name: n, Reason: "Needs " + strings.Join(secrets, ", ") + ", a secret. A local server with a secret is not supported yet, and fenzi.yaml never holds one."})
				continue
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
