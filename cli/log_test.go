package main

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"

	"fenzi/cli/internal/config"
	"fenzi/cli/internal/forward"
)

// recentLine is the recorded NET:OPEN line from decisionLines with its time
// moved to now, so --since has something newer than the cut.
func recentLine() string {
	return fmt.Sprintf("[%d.000] [sandbox] [OCSF ] [ocsf] NET:OPEN [INFO] ALLOWED /usr/bin/node(0) -> pypi.org:443 [policy:allow_pypi_org_443 engine:opa]\n", time.Now().Unix())
}

func TestLogSinceAppliesToRunningSandboxes(t *testing.T) {
	fakeRuntime(t, map[string]reply{"logs bl-web-1a2b --source sandbox -n": {out: decisionLines + recentLine()}}, "")
	seedState(t, config.Sandbox{Name: "bl-web-1a2b", Agent: "claude", Repo: "/Users/ana/web", Created: time.Now(), Running: true})
	var recs []forward.Record
	if stderr, code := runJSON(t, &recs, "log", "--sandbox", "bl-web-1a2b", "--json"); code != 0 || stderr != "" || len(recs) != 4 {
		t.Fatalf("exit %d stderr %q records %d", code, stderr, len(recs))
	}
	if stderr, code := runJSON(t, &recs, "log", "--since", "1h", "--sandbox", "bl-web-1a2b", "--json"); code != 0 || stderr != "" {
		t.Fatalf("exit %d stderr %q", code, stderr)
	}
	if len(recs) != 1 || recs[0].Destination != "pypi.org:443" {
		t.Errorf("--since 1h on a running sandbox = %+v", recs)
	}
	out, code := runCLI(t, "", "log", "--since", "1h", "--sandbox", "bl-web-1a2b")
	if code != 0 || !strings.Contains(out, "1 decision") || strings.Contains(out, "api.github.com") {
		t.Errorf("text, exit %d:\n%s", code, out)
	}
	if out, code := runCLI(t, "", "log", "--since", "soon", "--sandbox", "bl-web-1a2b"); code != 1 || !strings.Contains(out, "--since") {
		t.Errorf("a bad --since: exit %d:\n%s", code, out)
	}
}

// runFollow runs the CLI with standard output and standard error apart: the
// runtime's standard error is copied by a goroutine of its own, which must
// not share a buffer with the command's output.
func runFollow(t *testing.T, args ...string) (string, int) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := cli(args, strings.NewReader(""), &out, &errOut)
	return out.String() + errOut.String(), code
}

func TestLogFollowPrintsDecisionRows(t *testing.T) {
	fakeRuntime(t, map[string]reply{
		"logs bl-web-1a2b --source sandbox --tail":             {out: decisionLines},
		"logs bl-web-1a2b --source sandbox --since 10m --tail": {out: recentLine()},
	}, "")
	seedState(t, config.Sandbox{Name: "bl-web-1a2b", Agent: "claude", Repo: "/Users/ana/web", Created: time.Now(), Running: true})

	out, code := runFollow(t, "log", "--follow", "--sandbox", "bl-web-1a2b")
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 4 || !strings.Contains(lines[0], "action") {
		t.Fatalf("want a header and 3 rows:\n%s", out)
	}
	for _, want := range []string{"allowed", "curl", "api.github.com:443", "allow_api_github_com_443", "POST api.github.com/markdown", "paste.example.net"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "[sandbox]") || strings.Contains(out, "CONFIG:LOADED") {
		t.Errorf("raw runtime lines were printed:\n%s", out)
	}

	out, _ = runFollow(t, "log", "--follow", "--deny", "--sandbox", "bl-web-1a2b")
	lines = strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 3 || !strings.Contains(lines[0], "reason") || strings.Contains(out, "allowed") || !strings.Contains(out, "policy_dns_ineligible") {
		t.Errorf("--deny:\n%s", out)
	}

	out, _ = runFollow(t, "log", "--follow", "--since", "10m", "--sandbox", "bl-web-1a2b")
	if !strings.Contains(out, "pypi.org:443") || strings.Contains(out, "api.github.com") {
		t.Errorf("--since is passed to the runtime's follow:\n%s", out)
	}
}
