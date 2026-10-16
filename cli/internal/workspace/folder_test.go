package workspace

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestCheckFolder(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "Users", "ana")
	project := filepath.Join(home, "web")
	if err := os.MkdirAll(project, 0o755); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	file := filepath.Join(home, "notes.txt")
	if err := os.WriteFile(file, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(outside, "home-link")
	if err := os.Symlink(home, link); err != nil {
		t.Fatal(err)
	}
	for _, ok := range []string{project, outside} {
		if err := CheckFolder(ok, home); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	cases := map[string]string{
		home:                         "that is your home folder",
		home + "/":                   "that is your home folder",
		link:                         "that is your home folder",
		filepath.Join(root, "Users"): "that folder holds your home folder",
		root:                         "that folder holds your home folder",
		"/":                          "that is the whole disk",
		file:                         "that is a file, not a folder",
		filepath.Join(home, "gone"):  "that folder does not exist",
	}
	for dir, want := range cases {
		err := CheckFolder(dir, home)
		if err == nil || err.Error() != want {
			t.Errorf("%s: got %v, want %q", dir, err, want)
		}
	}
	if ContainsHome(filepath.Join(root, "Users", "anabel"), home) {
		t.Error("a sibling with a longer name was taken for a parent")
	}
}

func TestLooksSecret(t *testing.T) {
	secret := []string{
		".env", "app/.env", ".env.local", ".env.production", "certs/server.pem", "tls.key",
		"id_rsa", "deploy/id_ed25519", "id_ecdsa_sk", "store.p12", "store.PFX",
		".npmrc", "sub/.pypirc", ".netrc", "credentials.json", "credentials-prod.json",
		"prod.tfvars", "service-account.json", "gcp/service-account-ci.json",
	}
	plain := []string{
		".env.example", ".env.sample", ".env.template", "config/.env.local.example",
		"env.go", "README.md", "keys.go", "credentials.yaml", "service.json", "main.tf",
		"pem.go", "monkey.txt", ".environment", "id.go", "id_rsa.pub", "deploy/id_ed25519.pub",
	}
	for _, p := range secret {
		if !LooksSecret(p) {
			t.Errorf("%s was not flagged", p)
		}
	}
	for _, p := range plain {
		if LooksSecret(p) {
			t.Errorf("%s was flagged", p)
		}
	}
	m := Manifest{"main.go": "a", ".env": "b", "deploy/key.pem": "c", ".env.example": "d"}
	if got := m.Secrets(); !reflect.DeepEqual(got, []string{".env", "deploy/key.pem"}) {
		t.Errorf("Secrets() = %v", got)
	}
}
