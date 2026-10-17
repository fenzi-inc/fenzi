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
// placeholder variable, which the sandbox fills only on that server.
func (e Entry) WithMCP(d *compiler.Document) (Entry, []File, error) {
	if d == nil || len(d.MCP) == 0 {
		return e, nil, nil
	}
	names := d.MCPNames()
	switch e.MCPFormat {
	case MCPClaudeJSON:
		servers := map[string]any{}
		for _, n := range names {
			s := d.MCP[n]
			if s.Remote() {
				v := map[string]any{"type": "http", "url": s.URL}
				if s.Token {
					v["headers"] = map[string]string{"Authorization": "Bearer ${" + compiler.MCPTokenEnv(n) + "}"}
				}
				servers[n] = v
				continue
			}
			v := map[string]any{"type": "stdio", "command": s.Command[0], "args": nonNil(s.Command[1:])}
			if len(s.Env) > 0 {
				v["env"] = s.Env
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
				if s.Token {
					set(n, "bearer_token_env_var", tomlString(compiler.MCPTokenEnv(n)))
				}
				continue
			}
			set(n, "command", tomlString(s.Command[0]))
			set(n, "args", tomlArray(s.Command[1:]))
			if len(s.Env) > 0 {
				set(n, "env", tomlInline(s.Env))
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
					v["headers"] = map[string]string{"Authorization": "Bearer {env:" + compiler.MCPTokenEnv(n) + "}"}
				}
				servers[n] = v
				continue
			}
			v := map[string]any{"type": "local", "command": s.Command}
			if len(s.Env) > 0 {
				v["environment"] = s.Env
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
					fmt.Fprintf(&b, "\n[mcp_servers.%s.headers]\nAuthorization = %s\n", n, tomlString("Bearer ${"+compiler.MCPTokenEnv(n)+"}"))
				}
				continue
			}
			fmt.Fprintf(&b, "command = %s\nargs = %s\nenabled = true\n", tomlString(s.Command[0]), tomlArray(s.Command[1:]))
			if len(s.Env) > 0 {
				fmt.Fprintf(&b, "\n[mcp_servers.%s.env]\n", n)
				for _, k := range sortedKeys(s.Env) {
					fmt.Fprintf(&b, "%s = %s\n", k, tomlString(s.Env[k]))
				}
			}
		}
		return e, []File{{Path: grokConfig, Content: b.String()}}, nil
	}
	return e, nil, fmt.Errorf("%s does not take MCP servers from Fenzi yet; remove the mcp section or run another agent", e.Display)
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
