package run

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"fenzi/agents"
	"fenzi/cli/internal/config"
	"fenzi/cli/internal/openshell"
)

// ProviderName is the OpenShell provider that holds an agent's key.
func ProviderName(a agents.Entry) string { return "bl-" + a.Name }

// KeyStored reports whether the gateway holds a key for the agent.
func KeyStored(ctx context.Context, oc openshell.Client, a agents.Entry) (bool, error) {
	return oc.ProviderExists(ctx, ProviderName(a))
}

// SetKey stores or replaces the agent's key in the gateway on this machine.
// It reports whether the key replaced an existing one.
func SetKey(ctx context.Context, oc openshell.Client, a agents.Entry, value string) (replaced bool, err error) {
	if value == "" {
		return false, errors.New("empty key; nothing stored")
	}
	profile, err := a.Profile()
	if err != nil {
		return false, err
	}
	dir, err := os.MkdirTemp("", "fenzi-profile-")
	if err != nil {
		return false, err
	}
	defer os.RemoveAll(dir)
	pf := filepath.Join(dir, "profile.yaml")
	if err := os.WriteFile(pf, profile, 0o600); err != nil {
		return false, err
	}
	if err := oc.EnsureProfile(ctx, a.Key.ProfileType, pf); err != nil {
		return false, err
	}
	exists, err := KeyStored(ctx, oc, a)
	if err != nil {
		return false, err
	}
	return exists, oc.ProviderSetKey(ctx, ProviderName(a), a.Key.ProfileType, a.Key.Env, value, exists)
}

// RemoveKey deletes the agent's key from the gateway. It refuses while a
// sandbox that was started for this agent is still running, because what a
// running sandbox does when its provider disappears is not documented. The
// running sandboxes come from the gateway; which agent each one runs comes
// from the state Fenzi kept when it started them.
func RemoveKey(ctx context.Context, oc openshell.Client, dirs config.Dirs, a agents.Entry) (bool, error) {
	exists, err := KeyStored(ctx, oc, a)
	if err != nil || !exists {
		return false, err
	}
	running, err := oc.Sandboxes(ctx)
	if err != nil {
		return false, err
	}
	if name := RunningWith(dirs, a, running); name != "" {
		return false, fmt.Errorf("%s is running with the %s key; stop it first (fenzi stop %s)", name, a.Display, name)
	}
	return true, oc.ProviderDelete(ctx, ProviderName(a))
}

// RunningWith names the first of the running sandboxes that the state says
// was started for the agent, or "" when none was.
func RunningWith(dirs config.Dirs, a agents.Entry, running []string) string {
	s, err := dirs.LoadState()
	if err != nil {
		return ""
	}
	for _, name := range running {
		if sb, ok := s.Find(name); ok && sb.Agent == a.Name {
			return name
		}
	}
	return ""
}
