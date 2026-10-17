// Package forward turns OpenShell's OCSF events into decision records, the
// only data that leaves a machine on the Team plan.
package forward

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Record is the decision record the forwarder ships. It never holds
// bodies, headers, terminal output, or file contents.
type Record struct {
	Time           time.Time `json:"time"`
	Sandbox        string    `json:"sandbox"`
	Machine        string    `json:"machine,omitempty"`
	PolicyRevision string    `json:"policy_revision,omitempty"`
	Class          string    `json:"class"`
	Action         string    `json:"action"`
	Destination    string    `json:"destination"`
	Process        string    `json:"process,omitempty"`
	Rule           string    `json:"rule,omitempty"`
	// Reason is OpenShell's reason for a deny, such as policy_dns_ineligible.
	Reason string `json:"reason,omitempty"`
	// Gap is a hole in the log stream. The events inside it are gone.
	Gap bool `json:"gap,omitempty"`
	// Chunk is the OpenShell proposal an approval record is about.
	Chunk string `json:"chunk,omitempty"`
	// MCPMethod and MCPTool are set on a request to an MCP server: the
	// JSON-RPC method and, for tools/call, the tool.
	MCPMethod string `json:"mcp_method,omitempty"`
	MCPTool   string `json:"mcp_tool,omitempty"`
}

// What is the destination as people read it: for an MCP request, with the
// method and the tool.
func (r Record) What() string {
	switch {
	case r.MCPTool != "":
		return r.Destination + " " + r.MCPMethod + " " + r.MCPTool
	case r.MCPMethod != "":
		return r.Destination + " " + r.MCPMethod
	}
	return r.Destination
}

// ocsf holds the OCSF fields the contract reads. Which of them OpenShell
// fills is not documented; missing fields stay empty.
type ocsf struct {
	Time      json.Number `json:"time"`
	ClassName string      `json:"class_name"`
	Action    string      `json:"action"`
	Container struct {
		UID string `json:"uid"`
	} `json:"container"`
	DstEndpoint struct {
		Domain   string      `json:"domain"`
		Hostname string      `json:"hostname"`
		IP       string      `json:"ip"`
		Port     json.Number `json:"port"`
	} `json:"dst_endpoint"`
	HTTPRequest struct {
		Method string `json:"http_method"`
		URL    struct {
			Path      string `json:"path"`
			Hostname  string `json:"hostname"`
			URLString string `json:"url_string"`
		} `json:"url"`
	} `json:"http_request"`
	Actor struct {
		Process struct {
			Name string `json:"name"`
		} `json:"process"`
	} `json:"actor"`
	FirewallRule struct {
		Name string `json:"name"`
	} `json:"firewall_rule"`
}

// FromOCSF maps one OCSF JSON event. The query string is always dropped.
func FromOCSF(line []byte, sandbox string) (Record, error) {
	var e ocsf
	if err := json.Unmarshal(line, &e); err != nil {
		return Record{}, err
	}
	r := Record{
		Sandbox: firstNonEmpty(sandbox, e.Container.UID),
		Class:   e.ClassName,
		Action:  e.Action,
		Process: e.Actor.Process.Name,
		Rule:    e.FirewallRule.Name,
	}
	if ms, err := e.Time.Int64(); err == nil {
		r.Time = time.UnixMilli(ms).UTC()
	}
	host := firstNonEmpty(e.DstEndpoint.Domain, e.DstEndpoint.Hostname, e.HTTPRequest.URL.Hostname, e.DstEndpoint.IP)
	path := e.HTTPRequest.URL.Path
	if path == "" && e.HTTPRequest.URL.URLString != "" {
		if u, err := url.Parse(e.HTTPRequest.URL.URLString); err == nil {
			path = u.Path
			host = firstNonEmpty(host, u.Hostname())
		}
	}
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	switch {
	case e.HTTPRequest.Method != "":
		r.Destination = strings.TrimSpace(fmt.Sprintf("%s %s%s", e.HTTPRequest.Method, host, path))
	case host != "":
		r.Destination = host
		if p := e.DstEndpoint.Port.String(); p != "" {
			if _, err := strconv.Atoi(p); err == nil {
				r.Destination += ":" + p
			}
		}
	}
	return r, nil
}

// ReadJSONL maps every event in an OCSF JSONL stream, skipping lines that do
// not parse and counting them.
func ReadJSONL(r io.Reader, sandbox string) (records []Record, skipped int, err error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if len(strings.TrimSpace(string(line))) == 0 {
			continue
		}
		rec, err := FromOCSF(line, sandbox)
		if err != nil {
			skipped++
			continue
		}
		records = append(records, rec)
	}
	return records, skipped, sc.Err()
}

// Denied reports whether a record is a deny.
func (r Record) Denied() bool { return strings.EqualFold(r.Action, "denied") }

// Reset reports a connection the supervisor closed because the policy changed
// under it, which OpenShell 0.1.2 logs as a deny. The client reconnects under
// the new policy; nothing was refused.
func (r Record) Reset() bool {
	return r.Denied() && strings.HasPrefix(r.Reason, "L7 tunnel closed before inspection because policy changed")
}

func firstNonEmpty(s ...string) string {
	for _, v := range s {
		if v != "" {
			return v
		}
	}
	return ""
}
