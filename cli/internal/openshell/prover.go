package openshell

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strings"
)

// Prover results, from the upstream Policy prover page.
const (
	WithinBoundary  = "within_boundary"
	ExceedsBoundary = "exceeds_boundary"
	ProverError     = "error"
	Unsupported     = "unsupported"
	Inconclusive    = "inconclusive"
)

// RequiredDomains are the parts of a policy Fenzi relies on. A result whose
// coverage omits any of them does not count as a pass.
var RequiredDomains = []string{"filesystem", "network_l4", "network_rest", "process", "landlock"}

// Prover wraps openshell-prover. It needs no gateway.
type Prover struct {
	R Runner
}

// Result is the prover's JSON output. Only result and reason_code are
// documented as stable; the other fields are kept as given.
type Result struct {
	Result         string          `json:"result"`
	ReasonCode     string          `json:"reason_code,omitempty"`
	Reason         string          `json:"reason,omitempty"`
	Counterexample json.RawMessage `json:"counterexample,omitempty"`
	Coverage       struct {
		Domains json.RawMessage `json:"domains,omitempty"`
	} `json:"coverage"`
}

// Passed is true only for within_boundary with full coverage.
func (r Result) Passed() bool {
	return r.Result == WithinBoundary && len(r.MissingDomains()) == 0
}

// Domains reads coverage.domains as a list or a comma-separated string.
func (r Result) Domains() []string {
	var list []string
	if json.Unmarshal(r.Coverage.Domains, &list) == nil {
		return list
	}
	var s string
	if json.Unmarshal(r.Coverage.Domains, &s) == nil {
		s = strings.TrimPrefix(s, "domains=")
		for _, d := range strings.Split(s, ",") {
			if d = strings.TrimSpace(d); d != "" {
				list = append(list, d)
			}
		}
	}
	return list
}

func (r Result) MissingDomains() []string {
	have := r.Domains()
	var missing []string
	for _, d := range RequiredDomains {
		if !slices.Contains(have, d) {
			missing = append(missing, d)
		}
	}
	sort.Strings(missing)
	return missing
}

// Example renders the counterexample for people. Prover 0.1.2 and 0.1.4
// give an object with domain, binary, host, port, protocol, method, and path for
// network results.
func (r Result) Example() string {
	raw := strings.TrimSpace(string(r.Counterexample))
	if raw == "" || raw == "null" {
		return ""
	}
	var s string
	if json.Unmarshal(r.Counterexample, &s) == nil {
		return s
	}
	var ce map[string]any
	if json.Unmarshal(r.Counterexample, &ce) != nil {
		return raw
	}
	str := func(k string) string {
		switch v := ce[k].(type) {
		case string:
			return v
		case float64:
			return fmt.Sprint(int64(v))
		}
		return ""
	}
	if str("domain") == "network" && str("host") != "" {
		who := str("binary")
		if who == "" {
			who = "any program"
		}
		dest := str("host")
		if p := str("port"); p != "" {
			dest += ":" + p
		}
		if m := str("method"); m != "" {
			return fmt.Sprintf("%s can %s %s%s", who, m, dest, str("path"))
		}
		return fmt.Sprintf("%s can connect to %s", who, dest)
	}
	keys := make([]string, 0, len(ce))
	for k := range ce {
		if str(k) != "" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+str(k))
	}
	return strings.Join(parts, " ")
}

// Check runs `openshell-prover check <candidate> --boundary <boundary> --output json`.
// Exit codes 0 to 3 are results, not failures of the command.
func (p Prover) Check(ctx context.Context, candidate, boundary string) (Result, error) {
	out, err := p.R.Output(ctx, "check", candidate, "--boundary", boundary, "--output", "json")
	if code := ExitCode(err); err != nil && (code < 0 || code > 3) {
		return Result{}, err
	}
	var r Result
	if jerr := json.Unmarshal(out, &r); jerr != nil || r.Result == "" {
		if err != nil {
			return Result{}, err
		}
		return Result{}, fmt.Errorf("openshell-prover: unreadable output: %q", strings.TrimSpace(string(out)))
	}
	return r, nil
}
