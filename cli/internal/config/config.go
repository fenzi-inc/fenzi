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
	return d, nil
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
	Name  string `json:"name"`
	Agent string `json:"agent"`
	// SignIn means the sandbox was started without a provider: the agent
	// signs in itself, and its policy holds the model endpoints.
	SignIn       bool   `json:"sign_in,omitempty"`
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
	// Ended is when fenzi saw the agent exit or stopped the sandbox. Zero
	// while it runs, and for a sandbox that ended some other way.
	Ended time.Time `json:"ended,omitzero"`
	// Git is the repository state of the folder when the sandbox started,
	// and what the agent's commits became on this machine. Nil when the
	// folder is not a git repository.
	Git *Git `json:"git,omitempty"`
}

// Git records one sandbox's round trip through the developer's repository.
// The repository on this machine is the only history: the sandbox gets a
// copy of it, the agent works on a branch of its own, and its commits come
// back as git objects with the same ids.
type Git struct {
	// Branch is the branch checked out when the sandbox started, "" when
	// HEAD was detached. Head is the commit checked out then.
	Branch string `json:"branch,omitempty"`
	Head   string `json:"head,omitempty"`
	// Dirty is whether the folder had uncommitted edits at start.
	Dirty bool `json:"dirty,omitempty"`
	// History is whether the sandbox was given the repository's history.
	// When it was not, only files come back, as before, and FilesOnly says
	// why.
	History   bool   `json:"history,omitempty"`
	FilesOnly string `json:"files_only,omitempty"`
	// Start is the commit the agent's branch began at: Head, or the start
	// commit built from the uncommitted edits when the folder was dirty.
	// AgentBranch is the branch the agent was started on in the sandbox.
	Start       string `json:"start,omitempty"`
	AgentBranch string `json:"agent_branch,omitempty"`
	// Landed is the branch in the repository that holds the agent's
	// commits, set when the sandbox was collected at exit. Tip is its
	// commit, Commits how many commits it has since Start, and Checkpoint
	// whether the last of them holds what the agent left uncommitted.
	Landed     string `json:"landed,omitempty"`
	Tip        string `json:"tip,omitempty"`
	Commits    int    `json:"commits,omitempty"`
	Checkpoint bool   `json:"checkpoint,omitempty"`
	// Merged is the commit fenzi apply moved Branch to, "" until then.
	Merged string `json:"merged,omitempty"`
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
