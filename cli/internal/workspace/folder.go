package workspace

import (
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// CheckFolder refuses a folder that is not one project: a path that does not
// exist, a file, the whole disk, the home folder, or a folder that holds the
// home folder. The sandbox gets a copy of the folder, so any of those would
// copy the user's credentials and everything else in their home folder.
// The message says what the folder is; callers add what to do instead.
func CheckFolder(dir, home string) error {
	info, err := os.Stat(dir)
	if err != nil {
		return errors.New("that folder does not exist")
	}
	if !info.IsDir() {
		return errors.New("that is a file, not a folder")
	}
	for _, d := range forms(dir) {
		if d == string(filepath.Separator) {
			return errors.New("that is the whole disk")
		}
	}
	if home == "" {
		return nil
	}
	for _, d := range forms(dir) {
		for _, h := range forms(home) {
			if d == h {
				return errors.New("that is your home folder")
			}
		}
	}
	if ContainsHome(dir, home) {
		return errors.New("that folder holds your home folder")
	}
	return nil
}

// ContainsHome reports whether dir is the home folder or holds it. Both are
// compared as written and with symbolic links resolved.
func ContainsHome(dir, home string) bool {
	if home == "" {
		return false
	}
	for _, d := range forms(dir) {
		for _, h := range forms(home) {
			rel, err := filepath.Rel(d, h)
			if err != nil {
				continue
			}
			if rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))) {
				return true
			}
		}
	}
	return false
}

// forms is the cleaned path, and the path with symbolic links resolved when
// that differs.
func forms(p string) []string {
	clean := filepath.Clean(p)
	if abs, err := filepath.Abs(clean); err == nil {
		clean = abs
	}
	out := []string{clean}
	if real, err := filepath.EvalSymlinks(clean); err == nil && real != clean {
		out = append(out, real)
	}
	return out
}

// secretNames are exact file names that usually hold credentials.
var secretNames = map[string]bool{
	".env":    true,
	".npmrc":  true,
	".pypirc": true,
	".netrc":  true,
}

// secretSuffixes are extensions of key and certificate stores, and of
// Terraform variable files, which often carry cloud credentials.
var secretSuffixes = []string{".pem", ".key", ".p12", ".pfx", ".tfvars"}

// secretPrefixes are SSH private key names.
var secretPrefixes = []string{"id_rsa", "id_ed25519", "id_ecdsa"}

// exampleSuffixes mark a .env.* file as a template, not a secret.
var exampleSuffixes = []string{".example", ".sample", ".template"}

// LooksSecret reports whether a file name is one that usually holds a
// secret: .env and .env.* (but not .env.example, .sample, or .template),
// private keys and certificate stores, SSH keys, package registry and netrc
// credentials, cloud credential JSON files, and Terraform variable files.
// It reads the name only, never the content.
func LooksSecret(rel string) bool {
	name := strings.ToLower(filepath.Base(filepath.FromSlash(rel)))
	if secretNames[name] {
		return true
	}
	if strings.HasPrefix(name, ".env.") {
		for _, s := range exampleSuffixes {
			if strings.HasSuffix(name, s) {
				return false
			}
		}
		return true
	}
	for _, s := range secretSuffixes {
		if strings.HasSuffix(name, s) {
			return true
		}
	}
	for _, p := range secretPrefixes {
		// The .pub half of an SSH key pair is public and safe to copy.
		if strings.HasPrefix(name, p) && !strings.HasSuffix(name, ".pub") {
			return true
		}
	}
	if strings.HasSuffix(name, ".json") && (strings.HasPrefix(name, "credentials") || strings.HasPrefix(name, "service-account")) {
		return true
	}
	return false
}

// Secrets lists the files in a snapshot whose names look like secrets,
// sorted. The snapshot already leaves out what .gitignore excludes, so these
// are files that would be copied into the sandbox.
func (m Manifest) Secrets() []string {
	var out []string
	for rel := range m {
		if LooksSecret(rel) {
			out = append(out, rel)
		}
	}
	sort.Strings(out)
	return out
}
