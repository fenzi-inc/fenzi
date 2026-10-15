package team

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"boundlane/cli/internal/config"
)

func path(dirs config.Dirs) string { return filepath.Join(dirs.Config, "enrollment.json") }

// Load reads the cached sign-in. The signature is checked.
func Load(dirs config.Dirs) (Enrollment, error) {
	b, err := os.ReadFile(path(dirs))
	if errors.Is(err, os.ErrNotExist) {
		return Enrollment{}, ErrNotEnrolled
	}
	if err != nil {
		return Enrollment{}, err
	}
	var e Enrollment
	if err := json.Unmarshal(b, &e); err != nil {
		return Enrollment{}, err
	}
	if e.Revision > 0 {
		if _, err := e.Bundle(); err != nil {
			return Enrollment{}, err
		}
	}
	return e, nil
}

// Save writes the sign-in. The file is readable only by this user.
func (e Enrollment) Save(dirs config.Dirs) error {
	if err := os.MkdirAll(dirs.Config, 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		return err
	}
	tmp := path(dirs) + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path(dirs))
}

// Clear removes the sign-in. A sandbox that is already running keeps its policy.
func Clear(dirs config.Dirs) error {
	err := os.Remove(path(dirs))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}
