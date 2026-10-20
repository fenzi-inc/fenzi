package forward

import "strings"

// Explained is a deny's reason in plain words, for the places that show a
// person why a call was refused. Every phrase maps a reason recorded from
// OpenShell 0.1.2 or 0.1.4; a reason that has not been recorded gets no phrase, and
// the caller shows the runtime's own words instead. Allows have no reason.
func (r Record) Explained() string {
	if !r.Denied() {
		return ""
	}
	switch {
	case r.Reset():
		return "reset by a policy change"
	case r.Reason == "policy_dns_ineligible", r.Reason == "transparent_tcp_policy_denied":
		// Refused at DNS, or at connect: the host is not in the policy.
		return "not in the policy"
	case r.Reason == "transparent_tcp_mapping_denied":
		// The supervisor's DNS mapping ran out before the program connected.
		return "the DNS answer expired before the connection"
	case r.Reason == "credential_endpoint_mismatch":
		return "the credential is bound to another host"
	case strings.HasSuffix(r.Reason, "not permitted by policy"):
		if r.MCPTool != "" {
			return "tool not in the server's list"
		}
		if r.MCPMethod != "" {
			return "method not allowed on this server"
		}
		return "method not allowed on this host"
	case strings.HasPrefix(r.Reason, "MCP tool call has no matching allow rule") && r.MCPTool != "":
		// 0.1.4's wording for a tool not in the rule; the runtime cuts
		// the rest of it off in its own log.
		return "tool not in the server's list"
	case strings.Contains(r.Reason, "is not allowed by endpoint policy"):
		return "protocol version not allowed on this server"
	}
	return ""
}
