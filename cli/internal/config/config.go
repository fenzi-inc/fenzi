// Package config holds the CLI's local folders and state.
package config

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Dirs are the CLI's folders: ~/.config/fenzi and ~/.cache/fenzi,
// or the XDG equivalents. Model keys are never stored here.
type Dirs struct {
	Config string
	Cache  string
}

func Default() (Dirs, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return Dirs{}, err
	}
	cfg := os.Getenv("XDG_CONFIG_HOME")
	if cfg == "" {
		cfg = filepath.Join(home, ".config")
	}
	cache := os.Getenv("XDG_CACHE_HOME")
	if cache == "" {
		cache = filepath.Join(home, ".cache")
	}
	d := Dirs{Config: filepath.Join(cfg, "fenzi"), Cache: filepath.Join(cache, "fenzi")}
	// Machines set up before the rename from Boundlane keep their sign-in,
	// state and cache: the old folders move once, when the new ones are missing.
	moveLegacy(filepath.Join(cfg, "boundlane"), d.Config)
	moveLegacy(filepath.Join(cache, "boundlane"), d.Cache)
	return d, nil
}

func moveLegacy(old, cur string) {
	if _, err := os.Stat(cur); err == nil {
		return
	}
	if _, err := os.Stat(old); err != nil {
		return
	}
	_ = os.Rename(old, cur)
}

// Run holds the compiled policy, boundary, and effective policy for one sandbox.
func (d Dirs) Run(sandbox string) string { return filepath.Join(d.Cache, "runs", sandbox) }

// Staging holds the copy downloaded from a sandbox and the snapshot taken before upload.
func (d Dirs) Staging(sandbox string) string { return filepath.Join(d.Cache, "staging", sandbox) }

func (d Dirs) statePath() string { return filepath.Join(d.Config, "state.json") }

// State remembers which sandboxes Fenzi started. Profiles and providers
// are looked up on the gateway instead.
type State struct {
	Sandboxes []Sandbox `json:"sandboxes"`
}

type Sandbox struct {
	Name         string `json:"name"`
	Agent        string `json:"agent"`
	Repo         string `json:"repo"`
	Revision     string `json:"policy_revision"`
	TeamRevision int    `json:"team_revision,omitempty"`
	Notified     int    `json:"notified_revision,omitempty"`
	// PendingLoad is the team revision the forwarder loaded with policy set
	// whose load policy list has not shown Loaded yet, 0 when there is none.
	// Until it is confirmed, the policy the sandbox holds is not compared.
	PendingLoad int       `json:"pending_load,omitempty"`
	Created     time.Time `json:"created"`
	Running     bool      `json:"running"`
}

func (d Dirs) LoadState() (*State, error) {
	s := &State{}
	b, err := os.ReadFile(d.statePath())
	if errors.Is(err, fs.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, s); err != nil {
		return nil, err
	}
	return s, nil
}

func (d Dirs) SaveState(s *State) error {
	if err := os.MkdirAll(d.Config, 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := d.statePath() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, d.statePath())
}

// Put adds or replaces a sandbox record.
func (s *State) Put(sb Sandbox) {
	for i := range s.Sandboxes {
		if s.Sandboxes[i].Name == sb.Name {
			s.Sandboxes[i] = sb
			return
		}
	}
	s.Sandboxes = append(s.Sandboxes, sb)
}

// Latest returns the most recently created sandbox, optionally only running ones.
func (s *State) Latest(runningOnly bool) (Sandbox, bool) {
	list := append([]Sandbox(nil), s.Sandboxes...)
	sort.Slice(list, func(i, j int) bool { return list[i].Created.After(list[j].Created) })
	for _, sb := range list {
		if !runningOnly || sb.Running {
			return sb, true
		}
	}
	return Sandbox{}, false
}

// LatestIn is Latest limited to sandboxes started for dir or a folder that
// contains it.
func (s *State) LatestIn(dir string, runningOnly bool) (Sandbox, bool) {
	dir = filepath.Clean(dir)
	in := &State{}
	for _, sb := range s.Sandboxes {
		repo := filepath.Clean(sb.Repo)
		if sb.Repo != "" && (dir == repo || strings.HasPrefix(dir, repo+string(filepath.Separator))) {
			in.Sandboxes = append(in.Sandboxes, sb)
		}
	}
	return in.Latest(runningOnly)
}

// Setup records the answers from fenzi setup.
type Setup struct {
	Agent    string    `json:"agent"`
	Project  string    `json:"project"`
	Finished time.Time `json:"finished"`
}

func (d Dirs) setupPath() string { return filepath.Join(d.Config, "setup.json") }

// LoadSetup returns the saved answers, or false when setup never finished.
func (d Dirs) LoadSetup() (Setup, bool) {
	var s Setup
	b, err := os.ReadFile(d.setupPath())
	if err != nil || json.Unmarshal(b, &s) != nil || s.Finished.IsZero() {
		return Setup{}, false
	}
	return s, true
}

func (d Dirs) SaveSetup(s Setup) error {
	if err := os.MkdirAll(d.Config, 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(d.setupPath(), b, 0o600)
}

func (s *State) Find(name string) (Sandbox, bool) {
	for _, sb := range s.Sandboxes {
		if sb.Name == name {
			return sb, true
		}
	}
	return Sandbox{}, false
}
