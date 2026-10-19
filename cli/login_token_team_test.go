//go:build team

package main

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"fenzi/cli/internal/config"
	"fenzi/cli/internal/team"
	"fenzi/controlplane"
)

// acmeServer is a local team server that has published teamOrg as r1.
func acmeServer(t *testing.T) string {
	t.Helper()
	s, err := controlplane.Open(filepath.Join(t.TempDir(), "team.db"), allowProver{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	if _, err := s.Publish(context.Background(), "acme", []byte(teamOrg)); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(controlplane.Handler(s))
	t.Cleanup(srv.Close)
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	return srv.URL
}

func approve(t *testing.T, server, code, email string) {
	t.Helper()
	res, err := http.PostForm(server+"/device", url.Values{"code": {code}, "email": {email}})
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
}

// fenzi login --token-for makes a token for another machine, approved by
// the member who owns it, prints it on standard output only, and stores
// nothing here. fenzi login --token-stdin then signs a runner in with it.
func TestLoginWithATeamToken(t *testing.T) {
	server := acmeServer(t)

	pr, pw := io.Pipe()
	var stdout bytes.Buffer
	done := make(chan int)
	go func() {
		code := cli([]string{"login", "--server", server, "--token-for", "github-actions"}, strings.NewReader(""), &stdout, pw)
		pw.Close()
		done <- code
	}()
	var stderr strings.Builder
	sc := bufio.NewScanner(pr)
	codeLine := regexp.MustCompile(`Code\s+(\S+)`)
	approved := false
	for sc.Scan() {
		stderr.WriteString(sc.Text() + "\n")
		if m := codeLine.FindStringSubmatch(sc.Text()); m != nil && !approved {
			approve(t, server, m[1], "li@acme.dev")
			approved = true
		}
	}
	if code := <-done; code != 0 {
		t.Fatalf("token-for: exit %d\n%s", code, stderr.String())
	}
	token := strings.TrimSpace(stdout.String())
	if token == "" || strings.Contains(token, "\n") || strings.Contains(stderr.String(), token) {
		t.Fatalf("stdout %q, the token must be on stdout alone", stdout.String())
	}
	if !strings.Contains(stderr.String(), "Runs with it count against li@acme.dev") {
		t.Errorf("stderr:\n%s", stderr.String())
	}
	dirs, _ := config.Default()
	if _, err := team.Load(dirs); err != team.ErrNotEnrolled {
		t.Fatalf("--token-for signed this machine in: %v", err)
	}

	out, code := runCLI(t, token+"\n", "login", "--server", server, "--token-stdin")
	if code != 0 {
		t.Fatalf("token-stdin: exit %d\n%s", code, out)
	}
	if strings.Contains(out, token) {
		t.Error("the token was printed")
	}
	for _, want := range []string{"li@acme.dev, a developer of team acme", "github-actions, runs count against this member", "acme r1, verified and cached"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	en, err := team.Load(dirs)
	if err != nil || en.Token != token || en.Machine != "github-actions" || en.Revision != 1 {
		t.Fatalf("enrollment %+v, %v", en, err)
	}
	resolved, err := resolvePolicy(env{ctx: context.Background(), stdout: io.Discard}, dirs, t.TempDir(), "")
	if err != nil || resolved.Sources != "acme r1 (signed)" {
		t.Fatalf("resolved %q, %v", resolved.Sources, err)
	}
}

func TestLoginTokenStdinRefusals(t *testing.T) {
	server := acmeServer(t)
	for _, tc := range []struct{ in, want string }{
		{"", "no token on standard input"},
		{"a b\n", "more than one token"},
		{"not-a-token\n", "the team server refused the token"},
	} {
		out, code := runCLI(t, tc.in, "login", "--server", server, "--token-stdin")
		if code != 1 || !strings.Contains(out, tc.want) {
			t.Errorf("%q: exit %d\n%s", tc.in, code, out)
		}
	}
	if out, code := runCLI(t, "", "login", "--token-stdin", "--token-for", "ci"); code != 1 || !strings.Contains(out, "Use one") {
		t.Errorf("both: exit %d\n%s", code, out)
	}
}
