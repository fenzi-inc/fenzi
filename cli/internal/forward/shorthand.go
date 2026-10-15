package forward

import (
	"bufio"
	"bytes"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Shorthand lines from `openshell logs --source sandbox`, as recorded from
// OpenShell 0.1.2:
//
//	[1791059126.330] [sandbox] [OCSF ] [ocsf] NET:OPEN [INFO] ALLOWED /usr/bin/curl(0) -> api.github.com:443 [policy:allow_api_github_com_443 engine:opa]
//	[1791059150.996] [sandbox] [OCSF ] [ocsf] HTTP:POST [MED] DENIED POST http://api.github.com:443/markdown [policy:allow_api_github_com_443 engine:l7] [reason:...]
//	[1791059085.948] [sandbox] [OCSF ] [ocsf] NET:REFUSE [MED] DENIED paste.example.net [reason:policy_dns_ineligible]
var (
	shortLine = regexp.MustCompile(`^\[(\d+(?:\.\d+)?)\] \[sandbox\] \[OCSF\s*\] \[ocsf\] (.*)$`)
	decision  = regexp.MustCompile(`^(NET|HTTP):(\S+) \[\w+\] (ALLOWED|DENIED) (.*)$`)
	shortNet  = regexp.MustCompile(`^(\S+?)\(\d+\) -> (\S+)`)
	shortHTTP = regexp.MustCompile(`^([A-Z]+) (\S+)`)
	shortRule = regexp.MustCompile(`\[policy:(\S+)`)
	// The reason runs to the line's last bracket; it can hold nested ones:
	// [reason:L7 tunnel closed before inspection because policy changed: policy generation is stale [captured_generation:1 current_generation:2]]
	shortReason = regexp.MustCompile(`\[reason:(.*)\]\s*$`)
	// HTTP reasons repeat the request path; records never keep a query string.
	query = regexp.MustCompile(`\?[^\s\]]*`)
	// The one approval event recorded from OpenShell 0.1.2:
	//
	//	CONFIG:APPROVED [INFO] chunk:fad7c2ed-3aca-4fb7-bb37-495820dd7562 approved on example.com:443 HEAD / by /usr/bin/curl
	//
	// CONFIG:REJECTED and the other CONFIG events have not been recorded, so
	// they are not mapped.
	approval = regexp.MustCompile(`^CONFIG:APPROVED \[\w+\] chunk:(\S+) approved on (.+) by (\S+)$`)
	// lineTime is the time prefix every line of `openshell logs` carries.
	lineTime = regexp.MustCompile(`^\[(\d+(?:\.\d+)?)\] `)
)

// FromShorthand maps one shorthand log line. ok is false for lines that are
// not network or HTTP decisions.
func FromShorthand(line, sandbox string) (Record, bool) {
	m := shortLine.FindStringSubmatch(strings.TrimSpace(line))
	if m == nil {
		return Record{}, false
	}
	return FromStream(epoch(m[1]), "OCSF", m[2], sandbox)
}

// epoch parses "1791063979.337" without going through a float, which would
// turn .337 into .336999.
func epoch(s string) time.Time {
	whole, frac, _ := strings.Cut(s, ".")
	secs, err := strconv.ParseInt(whole, 10, 64)
	if err != nil {
		return time.Time{}
	}
	frac = (frac + "000000000")[:9]
	nanos, _ := strconv.ParseInt(frac, 10, 64)
	return time.Unix(secs, nanos)
}

// FromStream maps one log line from the gateway's watch stream, the gRPC
// stream behind `openshell logs`. OCSF lines arrive with level "OCSF", no
// structured fields, and the shorthand text without its time and source
// prefix:
//
//	NET:OPEN [INFO] ALLOWED /usr/local/lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe(0) -> api.anthropic.com:443 [policy:_provider_bl_claude engine:opa]
func FromStream(t time.Time, level, message, sandbox string) (Record, bool) {
	if level != "OCSF" {
		return Record{}, false
	}
	m := decision.FindStringSubmatch(strings.TrimSpace(message))
	if m == nil {
		return Record{}, false
	}
	r := Record{Sandbox: sandbox, Action: titleCase(m[3]), Time: t.UTC().Truncate(time.Millisecond)}
	rest := m[4]
	if rm := shortRule.FindStringSubmatch(rest); rm != nil && rm[1] != "-" {
		r.Rule = rm[1]
	}
	if rm := shortReason.FindStringSubmatch(rest); rm != nil {
		r.Reason = query.ReplaceAllString(rm[1], "")
	}
	switch m[1] {
	case "NET":
		r.Class = "Network Activity"
		if nm := shortNet.FindStringSubmatch(rest); nm != nil {
			r.Process, r.Destination = nm[1], nm[2]
		} else if f := strings.Fields(rest); len(f) > 0 {
			r.Destination = f[0]
		}
	case "HTTP":
		r.Class = "HTTP Activity"
		if hm := shortHTTP.FindStringSubmatch(rest); hm != nil {
			r.Destination = hm[1] + " " + hostPath(hm[2])
		}
	}
	return r, r.Destination != ""
}

// ReadShorthand maps every decision line in a shorthand log.
func ReadShorthand(rd io.Reader, sandbox string) ([]Record, error) {
	return read(rd, sandbox, FromShorthand)
}

// AuditFromStream maps a decision or an approval. The forwarder ships both so
// the control plane can match OpenShell's approvals to console reviews.
// `boundlane log` reads decisions only.
func AuditFromStream(t time.Time, level, message, sandbox string) (Record, bool) {
	if r, ok := FromStream(t, level, message, sandbox); ok {
		return r, true
	}
	if level != "OCSF" {
		return Record{}, false
	}
	m := approval.FindStringSubmatch(strings.TrimSpace(message))
	if m == nil {
		return Record{}, false
	}
	return Record{
		Time: t.UTC().Truncate(time.Millisecond), Sandbox: sandbox, Class: "Config", Action: "Approved",
		Destination: m[2], Process: m[3], Chunk: m[1],
	}, true
}

// AuditFromShorthand is AuditFromStream for one shorthand log line.
func AuditFromShorthand(line, sandbox string) (Record, bool) {
	m := shortLine.FindStringSubmatch(strings.TrimSpace(line))
	if m == nil {
		return Record{}, false
	}
	return AuditFromStream(epoch(m[1]), "OCSF", m[2], sandbox)
}

// ReadAudit maps every decision and approval line in a shorthand log.
func ReadAudit(rd io.Reader, sandbox string) ([]Record, error) {
	return read(rd, sandbox, AuditFromShorthand)
}

func read(rd io.Reader, sandbox string, from func(string, string) (Record, bool)) ([]Record, error) {
	var out []Record
	sc := bufio.NewScanner(rd)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		if r, ok := from(sc.Text(), sandbox); ok {
			out = append(out, r)
		}
	}
	return out, sc.Err()
}

// Span counts the lines of a shorthand log and returns the times of the
// oldest and newest ones, whatever their kind. Lines without a time prefix
// are counted and have no time.
func Span(raw []byte) (lines int, oldest, newest time.Time) {
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		lines++
		m := lineTime.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		t := epoch(m[1]).UTC()
		if oldest.IsZero() || t.Before(oldest) {
			oldest = t
		}
		if t.After(newest) {
			newest = t
		}
	}
	return lines, oldest, newest
}

// hostPath turns http://host:443/path?q into host/path. The query is dropped.
func hostPath(u string) string {
	u = strings.TrimPrefix(strings.TrimPrefix(u, "http://"), "https://")
	if i := strings.IndexByte(u, '?'); i >= 0 {
		u = u[:i]
	}
	host, path, _ := strings.Cut(u, "/")
	host = strings.TrimSuffix(host, ":443")
	return host + "/" + path
}

func titleCase(s string) string {
	if s == "" {
		return s
	}
	return s[:1] + strings.ToLower(s[1:])
}
