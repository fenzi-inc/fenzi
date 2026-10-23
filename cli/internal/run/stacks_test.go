package run

import (
	"os"
	"path/filepath"
	"testing"
)

// A folder with a go.mod gets the go stack between developer-default and
// its fenzi.yaml, and the project's entry for a stack host wins.
func TestResolveFreeAddsTheFolderStacks(t *testing.T) {
	repo := t.TempDir()
	os.WriteFile(filepath.Join(repo, "go.mod"), []byte("module x\n"), 0o644)
	res, err := ResolveFree(repo, "")
	if err != nil {
		t.Fatal(err)
	}
	if res.Sources != "developer-default (built in) + stacks go" || len(res.Stacks) != 1 {
		t.Fatalf("sources %q stacks %v", res.Sources, res.Stacks)
	}
	hosts := map[string]string{}
	for _, h := range res.Doc.Hosts {
		hosts[h.Host] = h.Access
	}
	if hosts["proxy.golang.org"] != "read-only" || hosts["sum.golang.org"] != "read-only" || hosts["crates.io"] != "" {
		t.Errorf("hosts = %v", hosts)
	}

	os.WriteFile(filepath.Join(repo, ProjectFile), []byte("version: 1\nhosts:\n  - host: proxy.golang.org\n    access: read-write\n    allow: [GET /golang.org/**]\n"), 0o644)
	res, err = ResolveFree(repo, "")
	if err != nil {
		t.Fatal(err)
	}
	if res.Sources != "developer-default (built in) + stacks go + ./fenzi.yaml" {
		t.Errorf("sources %q", res.Sources)
	}
	for _, h := range res.Doc.Hosts {
		if h.Host == "proxy.golang.org" && (h.Access != "read-write" || len(h.Allow) != 1) {
			t.Errorf("the project's entry did not win: %+v", h)
		}
	}

	// A preview elsewhere resolves with the project folder's stacks.
	other := t.TempDir()
	if res, err = ResolveFreeAs(other, "", repo); err != nil || len(res.Stacks) != 1 {
		t.Errorf("ResolveFreeAs: %v, %v", res.Stacks, err)
	}
}
