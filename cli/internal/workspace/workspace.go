// Package workspace snapshots a project before it is copied into a sandbox,
// compares the copy that comes back, and applies the changes on confirmation.
package workspace

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Manifest maps a slash-separated relative path to the SHA-256 of a regular file.
type Manifest map[string]string

// Filter returns the relative paths that belong to the project. Ignored files
// are never uploaded, so they are never compared or applied.
type Filter func(rels []string) ([]string, error)

// All keeps every file except git internals: a .git folder or file at any
// depth, in any case.
func All(rels []string) ([]string, error) {
	kept := make([]string, 0, len(rels))
	for _, r := range rels {
		if !isGitPath(r) {
			kept = append(kept, r)
		}
	}
	return kept, nil
}

// isGitPath reports whether any component of a slash-separated path is a
// .git folder or file. Git runs what it finds there: a nested sub/.git with
// core.fsmonitor runs on the next git status in sub/, and on a
// case-insensitive disk .GIT/hooks/pre-commit is the real hook. A .git file
// is a gitlink, which points git at another folder. The sandbox is Linux and
// case-sensitive, so it can hand back any of these as ordinary files.
func isGitPath(rel string) bool {
	for _, part := range strings.Split(rel, "/") {
		if isDotGit(part) {
			return true
		}
	}
	return false
}

// isDotGit compares one name with .git the way the disks a project may land
// on do, after git's own checks (verify_dotfile, is_hfs_dotgit,
// is_ntfs_dotgit): any case, code points HFS+ ignores removed, and the
// trailing dots and spaces and the GIT~1 short name that NTFS accepts.
func isDotGit(name string) bool {
	name = strings.Map(func(r rune) rune {
		if hfsIgnored(r) {
			return -1
		}
		return r
	}, name)
	name = strings.TrimRight(name, ". ")
	return strings.EqualFold(name, ".git") || strings.EqualFold(name, "git~1")
}

func hfsIgnored(r rune) bool {
	return r >= 0x200c && r <= 0x200f || r >= 0x202a && r <= 0x202e || r >= 0x206a && r <= 0x206f || r == 0xfeff
}

type Kind string

const (
	Added    Kind = "A"
	Modified Kind = "M"
	Deleted  Kind = "D"
)

type Change struct {
	Path string
	Kind Kind
}

// Snapshot hashes every included regular file under root.
func Snapshot(root string, include Filter) (Manifest, error) {
	rels, err := files(root)
	if err != nil {
		return nil, err
	}
	if rels, err = include(rels); err != nil {
		return nil, err
	}
	m := Manifest{}
	for _, rel := range rels {
		sum, err := hashFile(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			return nil, err
		}
		m[rel] = sum
	}
	return m, nil
}

// Changes compares a staged copy against the snapshot taken before upload.
func Changes(base Manifest, staged string, include Filter) ([]Change, error) {
	now, err := Snapshot(staged, include)
	if err != nil {
		return nil, err
	}
	var out []Change
	for rel, sum := range now {
		switch old, ok := base[rel]; {
		case !ok:
			out = append(out, Change{rel, Added})
		case old != sum:
			out = append(out, Change{rel, Modified})
		}
	}
	for rel := range base {
		// A snapshot taken before git internals were skipped at every
		// depth may list them; they are not the project's to delete.
		if isGitPath(rel) {
			continue
		}
		if _, ok := now[rel]; !ok {
			out = append(out, Change{rel, Deleted})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

// Conflicts lists files that changed in root since the snapshot, where
// applying a change would overwrite someone's work.
func Conflicts(root string, base Manifest, changes []Change) ([]string, error) {
	var out []string
	for _, c := range changes {
		abs := filepath.Join(root, filepath.FromSlash(c.Path))
		sum, err := hashFile(abs)
		exists := err == nil
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
		switch c.Kind {
		case Added:
			if exists {
				out = append(out, c.Path)
			}
		case Modified, Deleted:
			if !exists || sum != base[c.Path] {
				out = append(out, c.Path)
			}
		}
	}
	return out, nil
}

// Apply copies added and modified files from staged into root and removes
// deleted ones. Call Conflicts first. It refuses the whole set, before
// writing anything, if one path leaves the project or touches git
// internals. Changes already leaves those out; this is the second check.
func Apply(root, staged string, changes []Change) error {
	for _, c := range changes {
		if isGitPath(c.Path) {
			return fmt.Errorf("refusing to write git internals: %s", c.Path)
		}
		if !within(root, filepath.Join(root, filepath.FromSlash(c.Path))) {
			return fmt.Errorf("refusing to write outside the project: %s", c.Path)
		}
	}
	for _, c := range changes {
		dst := filepath.Join(root, filepath.FromSlash(c.Path))
		switch c.Kind {
		case Deleted:
			if err := os.Remove(dst); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return err
			}
		case Added, Modified:
			if err := copyFile(filepath.Join(staged, filepath.FromSlash(c.Path)), dst); err != nil {
				return err
			}
		}
	}
	return nil
}

// Applied is base with changes taken from staged: what the sandbox and root
// both hold once Apply has run. It becomes the snapshot for a sandbox that
// keeps running, so its next copy is compared against what was applied.
func Applied(base Manifest, staged string, changes []Change) (Manifest, error) {
	next := make(Manifest, len(base))
	for rel, sum := range base {
		if !isGitPath(rel) {
			next[rel] = sum
		}
	}
	for _, c := range changes {
		if c.Kind == Deleted {
			delete(next, c.Path)
			continue
		}
		sum, err := hashFile(filepath.Join(staged, filepath.FromSlash(c.Path)))
		if err != nil {
			return nil, err
		}
		next[c.Path] = sum
	}
	return next, nil
}

// Save and Load keep the snapshot next to the staged copy between runs.
func (m Manifest) Save(path string) error {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

func Load(path string) (Manifest, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m Manifest
	return m, json.Unmarshal(b, &m)
}

// files lists regular files under root, skipping git internals whatever
// the filter, so no Filter can let them into a snapshot.
func files(root string) ([]string, error) {
	var out []string
	err := filepath.WalkDir(root, func(abs string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, abs)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if rel == "." {
			return nil
		}
		if isGitPath(rel) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			return nil
		}
		// Symlinks and special files are not compared; a symlink could point
		// outside the project when applied.
		if d.Type().IsRegular() {
			out = append(out, rel)
		}
		return nil
	})
	return out, err
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func copyFile(src, dst string) error {
	info, err := os.Lstat(src)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", src)
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp, err := os.CreateTemp(filepath.Dir(dst), ".fenzi-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := io.Copy(tmp, in); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(info.Mode().Perm()); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), dst)
}

func within(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
