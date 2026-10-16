//go:build team

package main

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"boundlane/cli/internal/config"
	"boundlane/cli/internal/team"
	"boundlane/controlplane"
)

func TestServerRejectsAPublicAddress(t *testing.T) {
	var out, errOut bytes.Buffer
	code, err := cmdServer(env{ctx: context.Background(), stdout: &out, stderr: &errOut}, []string{"--addr", "0.0.0.0:8787"})
	if code == 0 || err == nil || !strings.Contains(err.Error(), "localhost") {
		t.Fatalf("code %d err %v", code, err)
	}
}

// enrollAcme signs this test's config folder in to a local team server that
// has published teamOrg as r1.
func enrollAcme(t *testing.T) config.Dirs {
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
	c := team.Client{Base: srv.URL}
	start, err := c.StartDevice(context.Background(), "test-host")
	if err != nil {
		t.Fatal(err)
	}
	res, err := http.PostForm(srv.URL+"/device", url.Values{"code": {start.UserCode}, "email": {"dana@acme.dev"}})
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	en, err := c.Exchange(context.Background(), start.DeviceCode)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	dirs, err := config.Default()
	if err != nil {
		t.Fatal(err)
	}
	if err := en.Save(dirs); err != nil {
		t.Fatal(err)
	}
	return dirs
}

func TestRunUsesTheSignedTeamPolicy(t *testing.T) {
	dirs := enrollAcme(t)
	repo := t.TempDir()
	if err := os.WriteFile(filepath.Join(repo, "boundlane.yaml"), []byte("version: 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	resolved, err := resolvePolicy(env{ctx: context.Background(), stdout: &out}, dirs, repo, "")
	if err != nil {
		t.Fatal(err)
	}
	if resolved.Sources != "acme r1 (signed)" || resolved.Doc.Name != "acme" {
		t.Fatalf("resolved %q name %q", resolved.Sources, resolved.Doc.Name)
	}
	if !strings.Contains(out.String(), "project file not used") {
		t.Fatalf("stdout %q", out.String())
	}
	if _, err := resolvePolicy(env{ctx: context.Background(), stdout: &out}, dirs, repo, "other.yaml"); err == nil {
		t.Fatal("--policy must not override a team policy")
	}
}

func TestPolicyCheckUsesTheSignedTeamPolicy(t *testing.T) {
	// The prover from the runtime fake; the config folder from the enrollment.
	fakeRuntime(t, nil, proverWithin)
	enrollAcme(t)
	repo := t.TempDir()
	if err := os.WriteFile(filepath.Join(repo, "boundlane.yaml"), []byte("version: 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Chdir(repo)
	var doc jsonPolicyCheck
	stderr, code := runJSON(t, &doc, "policy", "check", "--json")
	if code != 0 || doc.Checked != "acme r1 (signed)" || !doc.Passed {
		t.Fatalf("exit %d stderr %q check %+v", code, stderr, doc)
	}
	if !strings.Contains(stderr, "project file not used") {
		t.Errorf("stderr %q; want the label run prints", stderr)
	}
	var out, errOut bytes.Buffer
	if code := cli([]string{"policy", "compile"}, strings.NewReader(""), &out, &errOut); code != 0 || strings.Contains(out.String(), "project file not used") || !strings.Contains(out.String(), "network_policies") {
		t.Fatalf("compile: exit %d stdout %q stderr %q", code, out.String(), errOut.String())
	}
}

type allowProver struct{}

func (allowProver) Check(context.Context, []byte, []byte) (bool, string, error) {
	return true, "", nil
}

const teamOrg = `version: 1
name: acme
agents: [claude]
workspace: read-write
hosts:
  - host: example.com
    access: read-only
approvals: person
`
