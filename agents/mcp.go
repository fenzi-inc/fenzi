package agents

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"fenzi/compiler"
)

// MCP config formats, one per way an agent reads its MCP servers. Each was
// read from the agent's own help and the config it writes (Claude Code
// 2.1.288, Codex 0.160.1, OpenCode 1.18.34, Grok 1.0.46), and each agent put
// an environment variable into the Authorization header of a test server.
const (
	// MCPClaudeJSON is a file passed with --mcp-config and
	// --strict-mcp-config, so Claude Code loads these servers and no others.
	MCPClaudeJSON = "claude-json"
	// MCPCodexConfig is -c mcp_servers.<name>.<key>=<TOML value> flags.
	MCPCodexConfig = "codex-config"
	// MCPOpenCodeEnv is an "mcp" key in OPENCODE_CONFIG_CONTENT.
	MCPOpenCodeEnv = "opencode-env"
	// MCPGrokTOML is [mcp_servers.<name>] in ~/.grok/config.toml.
	MCPGrokTOML = "grok-toml"
)

// File is a file run writes into the sandbox before the agent starts. Paths
// are under the sandbox workdir and outside the project copy.
type File struct {
	Path    string
	Content string
}

const (
	claudeMCPFile = compiler.DefaultWorkdir + "/.fenzi/mcp.json"
	grokConfig    = compiler.DefaultWorkdir + "/.grok/config.toml"
)

// WithMCP returns the entry set up to load the document's MCP servers, and
// the files to write first. A remote server's token is referred to by its
// placeholder variable, which the sandbox fills only on that server. A local
// server's secrets are passed to it under their own names; the values are
// placeholders, which the sandbox fills only on the hosts the server lists.
func (e Entry) WithMCP(d *compiler.Document) (Entry, []File, error) {
	if d == nil || len(d.MCP) == 0 {
		return e, nil, nil
	}
	names := d.MCPNames()
	if err := e.checkSecrets(d); err != nil {
		return e, nil, err
	}
	switch e.MCPFormat {
	case MCPClaudeJSON:
		servers := map[string]any{}
		for _, n := range names {
			s := d.MCP[n]
			if s.Remote() {
				v := map[string]any{"type": "http", "url": s.URL}
				if s.Token {
					v["headers"] = tokenHeader(s, n, "${", "}")
				}
				servers[n] = v
				continue
			}
			v := map[string]any{"type": "stdio", "command": s.Command[0], "args": nonNil(s.Command[1:])}
			// Claude Code 2.1.288 expands ${VAR} in env. In a sandbox, a
			// stdio server it started saw the placeholder this way and without it.
			if env := secretEnv(s, "${", "}"); len(env) > 0 {
				v["env"] = env
			}
			servers[n] = v
		}
		b, err := json.MarshalIndent(map[string]any{"mcpServers": servers}, "", "  ")
		if err != nil {
			return e, nil, err
		}
		e.Args = append(append([]string(nil), e.Args...), "--mcp-config", claudeMCPFile, "--strict-mcp-config")
		return e, []File{{Path: claudeMCPFile, Content: string(b) + "\n"}}, nil

	case MCPCodexConfig:
		args := append([]string(nil), e.Args...)
		set := func(n, key, value string) {
			args = append(args, "-c", "mcp_servers."+n+"."+key+"="+value)
		}
		for _, n := range names {
			s := d.MCP[n]
			if s.Remote() {
				set(n, "url", tomlString(s.URL))
				// Codex 0.160.1: env_http_headers maps a header to a variable
				// (plain Docker, a custom header reached the server).
				switch {
				case s.Token && s.TokenHeader != "":
					set(n, "env_http_headers", "{"+tomlString(s.TokenHeader)+" = "+tomlString(compiler.MCPTokenEnv(n))+"}")
				case s.Token:
					set(n, "bearer_token_env_var", tomlString(compiler.MCPTokenEnv(n)))
				}
				continue
			}
			set(n, "command", tomlString(s.Command[0]))
			set(n, "args", tomlArray(s.Command[1:]))
			if len(s.Env) > 0 {
				set(n, "env", tomlInline(s.Env))
			}
			// Codex 0.160.1 starts a stdio server with a short list of its
			// own variables, not its whole environment, and does not expand
			// ${VAR} in env; env_vars passes the named ones (seen in plain
			// Docker, not yet in a sandbox).
			if len(s.Secrets) > 0 {
				set(n, "env_vars", tomlArray(s.Secrets))
			}
		}
		e.Args = args
		return e, nil, nil

	case MCPOpenCodeEnv:
		const key = "OPENCODE_CONFIG_CONTENT"
		cfg := map[string]any{}
		if raw := e.Env[key]; raw != "" {
			if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
				return e, nil, fmt.Errorf("%s: %s in the catalog is not JSON: %w", e.Name, key, err)
			}
		}
		servers := map[string]any{}
		for _, n := range names {
			s := d.MCP[n]
			if s.Remote() {
				v := map[string]any{"type": "remote", "url": s.URL}
				if s.Token {
					v["headers"] = tokenHeader(s, n, "{env:", "}")
				}
				servers[n] = v
				continue
			}
			v := map[string]any{"type": "local", "command": s.Command}
			// OpenCode 1.18.34 passes its environment to a local server and
			// fills {env:VAR} in environment; ${VAR} stays literal (plain
			// Docker, opencode mcp list).
			if env := secretEnv(s, "{env:", "}"); len(env) > 0 {
				v["environment"] = env
			}
			servers[n] = v
		}
		cfg["mcp"] = servers
		b, err := json.Marshal(cfg)
		if err != nil {
			return e, nil, err
		}
		env := make(map[string]string, len(e.Env)+1)
		for k, v := range e.Env {
			env[k] = v
		}
		env[key] = string(b)
		e.Env = env
		return e, nil, nil

	case MCPGrokTOML:
		var b strings.Builder
		b.WriteString("# Written by fenzi run from the policy's mcp section. Do not edit.\n")
		for _, n := range names {
			s := d.MCP[n]
			fmt.Fprintf(&b, "\n[mcp_servers.%s]\n", n)
			if s.Remote() {
				fmt.Fprintf(&b, "url = %s\nenabled = true\n", tomlString(s.URL))
				if s.Token {
					// A header name is a bare TOML key: letters, digits, dashes.
					for k, v := range tokenHeader(s, n, "${", "}") {
						fmt.Fprintf(&b, "\n[mcp_servers.%s.headers]\n%s = %s\n", n, k, tomlString(v))
					}
				}
				continue
			}
			fmt.Fprintf(&b, "command = %s\nargs = %s\nenabled = true\n", tomlString(s.Command[0]), tomlArray(s.Command[1:]))
			// Grok 1.0.46 passes its environment to a local server and fills
			// ${VAR} in env (plain Docker, grok mcp doctor).
			if env := secretEnv(s, "${", "}"); len(env) > 0 {
				fmt.Fprintf(&b, "\n[mcp_servers.%s.env]\n", n)
				for _, k := range sortedKeys(env) {
					fmt.Fprintf(&b, "%s = %s\n", k, tomlString(env[k]))
				}
			}
		}
		return e, []File{{Path: grokConfig, Content: b.String()}}, nil
	}
	return e, nil, fmt.Errorf("%s does not take MCP servers from Fenzi yet; remove the mcp section or run another agent", e.Display)
}

// secretsChecked are the formats whose agents were seen passing a secret's
// placeholder to a local server. Another format refuses such a server until
// that is recorded.
var secretsChecked = map[string]bool{MCPClaudeJSON: true, MCPCodexConfig: true, MCPOpenCodeEnv: true, MCPGrokTOML: true}

// checkSecrets refuses local servers with secrets for an agent not checked
// with them, and a secret named like a variable the agent itself is given.
func (e Entry) checkSecrets(d *compiler.Document) error {
	secrets := d.Secrets()
	if len(secrets) == 0 {
		return nil
	}
	if !secretsChecked[e.MCPFormat] {
		var with []string
		for _, n := range d.MCPNames() {
			if len(d.MCP[n].Secrets) > 0 {
				with = append(with, n)
			}
		}
		return fmt.Errorf("%s is not checked yet with local MCP servers that read a secret (%s); run claude or codex, or leave those servers out of this project", e.Display, strings.Join(with, ", "))
	}
	for _, v := range secrets {
		if v == e.Key.Env {
			return fmt.Errorf("%s is the %s key; a local MCP server's secret needs a name of its own", v, e.Display)
		}
		if _, ok := e.Env[v]; ok {
			return fmt.Errorf("%s is set by Fenzi for %s; a local MCP server's secret needs a name of its own", v, e.Display)
		}
	}
	return nil
}

// tokenHeader is the header that carries a remote server's token: the
// placeholder variable as Authorization: Bearer, or as it is in the server's
// token_header. The four agents put a variable in a custom header the same
// way they do in Authorization (plain Docker, a header-logging server).
func tokenHeader(s compiler.MCPServer, name, open, close string) map[string]string {
	ref := open + compiler.MCPTokenEnv(name) + close
	if s.TokenHeader != "" {
		return map[string]string{s.TokenHeader: ref}
	}
	return map[string]string{"Authorization": "Bearer " + ref}
}

// secretEnv is a local server's env with each secret added as a reference
// to the variable of the same name, in the agent's syntax.
func secretEnv(s compiler.MCPServer, open, close string) map[string]string {
	if len(s.Env) == 0 && len(s.Secrets) == 0 {
		return nil
	}
	env := make(map[string]string, len(s.Env)+len(s.Secrets))
	for k, v := range s.Env {
		env[k] = v
	}
	for _, v := range s.Secrets {
		env[v] = open + v + close
	}
	return env
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func tomlArray(list []string) string {
	q := make([]string, len(list))
	for i, s := range list {
		q[i] = tomlString(s)
	}
	return "[" + strings.Join(q, ", ") + "]"
}

func tomlInline(m map[string]string) string {
	parts := make([]string, 0, len(m))
	for _, k := range sortedKeys(m) {
		parts = append(parts, k+" = "+tomlString(m[k]))
	}
	return "{" + strings.Join(parts, ", ") + "}"
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
