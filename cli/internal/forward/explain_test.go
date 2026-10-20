package forward

import "testing"

// The reasons recorded from OpenShell 0.1.2 and 0.1.4, and the plain words for each.
func TestExplained(t *testing.T) {
	lines := map[string]string{
		"[1791085.948] [sandbox] [OCSF ] [ocsf] NET:REFUSE [MED] DENIED paste.example.net [reason:policy_dns_ineligible]":                                                                                                                                                                                                                                       "not in the policy",
		"[1791085.939] [sandbox] [OCSF ] [ocsf] NET:OPEN [MED] DENIED /usr/bin/curl(0) -> api.github.com:443 [reason:transparent_tcp_policy_denied]":                                                                                                                                                                                                            "not in the policy",
		"[1791085.939] [sandbox] [OCSF ] [ocsf] NET:OPEN [MED] DENIED /usr/local/bin/node(0) -> 198.18.0.2:443 [reason:transparent_tcp_mapping_denied]":                                                                                                                                                                                                         "the DNS answer expired before the connection",
		"[1791150.996] [sandbox] [OCSF ] [ocsf] HTTP:POST [MED] DENIED POST http://api.github.com:443/markdown [policy:allow_api_github_com_443 engine:l7] [reason:L7_REQUEST deny POST api.github.com:443/markdown reason=POST /markdown not permitted by policy]":                                                                                             "method not allowed on this host",
		"[1791242.945] [sandbox] [OCSF ] [ocsf] NET:OPEN [MED] DENIED platform.claude.com:443 [reason:L7 tunnel closed before inspection because policy changed: policy generation is stale [captured_generation:1 current_generation:2]]":                                                                                                                      "reset by a policy change",
		"[1792229821.710] [sandbox] [OCSF ] [ocsf] HTTP:POST [MED] DENIED POST http://mcp.deepwiki.com:443/mcp [policy:mcp_deepwiki_com engine:l7-mcp] [reason:JSONRPC_L7_REQUEST decision=deny rule_methods=tools/call tools=read_wiki_contents http_method=POST endpoint=mcp.deepwiki.com:443/mcp policy_version=2 reason=POST /mcp not permitted by policy]": "tool not in the server's list",
		"[1792229823.832] [sandbox] [OCSF ] [ocsf] HTTP:POST [MED] DENIED POST http://mcp.deepwiki.com:443/mcp [policy:mcp_deepwiki_com engine:l7-mcp] [reason:L7_REQUEST deny POST mcp.deepwiki.com:443/mcp rule_methods=tools/list tools=- reason=MCP protocol version 2025-06-18 is not allowed by endpoint policy]":                                         "protocol version not allowed on this server",
		"[1791126.330] [sandbox] [OCSF ] [ocsf] HTTP:GET [HIGH] DENIED GET http://postman-echo.com:443/get [policy:x engine:credential-binding] [reason:credential_endpoint_mismatch]":                                                                                                                                                                          "the credential is bound to another host",
		"[1791126.330] [sandbox] [OCSF ] [ocsf] NET:OPEN [INFO] ALLOWED /usr/bin/curl(0) -> api.github.com:443 [policy:allow_api_github_com_443 engine:opa]":                                                                                                                                                                                                    "",
		// OpenShell 0.1.4, 19 October 2026: a connector tool not in the rule.
		"[1792410634.010] [sandbox] [OCSF ] [ocsf] HTTP:POST [MED] DENIED POST http://mcp-proxy.anthropic.com:443/v1/mcp/mcpsrv_01NXbt6n5Hhyz7zFREQtXmcQ [policy:mcp_claude_ai engine:l7-mcp] [reason:JSONRPC_L7_REQUEST decision=deny rule_methods=tools/call tools=api_request http_method=POST endpoint=mcp-proxy.anthropic.com:443/v1/mcp/mcpsrv_01NXbt6n5Hhyz7zFREQtXmcQ policy_version=1 reason=MCP tool call has no matching allow rule; ask the policy owner t...]": "tool not in the server's list",
		"[1791126.330] [sandbox] [OCSF ] [ocsf] NET:OPEN [MED] DENIED /usr/bin/curl(0) -> api.github.com:443 [reason:something_new]": "",
	}
	for line, want := range lines {
		r, ok := FromShorthand(line, "s")
		if !ok {
			t.Fatalf("not a decision: %s", line)
		}
		if got := r.Explained(); got != want {
			t.Errorf("%s\n  explained = %q, want %q", line, got, want)
		}
	}
}
