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

// ProviderName is the OpenShell provider that holds an agent's key:
// fenzi-<agent>. Keys stored before the rename from Boundlane live under
// LegacyProviderName and keep working until they are replaced.
func ProviderName(a agents.Entry) string { return "fenzi-" + a.Name }

// LegacyProviderName is bl-<agent>, the name before the rename. OpenShell
// cannot rename a provider or read its value back, so Fenzi keeps using one
// it finds and moves the key to the new name the next time it is set.
func LegacyProviderName(a agents.Entry) string { return "bl-" + a.Name }

// StoredProvider names the provider that holds the agent's key on this
// gateway: the new name, else the old one, else "".
func StoredProvider(ctx context.Context, oc openshell.Client, a agents.Entry) (string, error) {
	for _, name := range []string{ProviderName(a), LegacyProviderName(a)} {
		ok, err := oc.ProviderExists(ctx, name)
		if err != nil {
			return "", err
		}
		if ok {
			return name, nil
		}
	}
	return "", nil
}

// KeyStored reports whether the gateway holds a key for the agent.
func KeyStored(ctx context.Context, oc openshell.Client, a agents.Entry) (bool, error) {
	name, err := StoredProvider(ctx, oc, a)
	return name != "", err
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
	stored, err := StoredProvider(ctx, oc, a)
	if err != nil {
		return false, err
	}
	// The key goes under the new name. A key under the old one is replaced:
	// the old provider is deleted once nothing running uses it.
	exists := stored == ProviderName(a)
	if err := oc.ProviderSetKey(ctx, ProviderName(a), a.Key.ProfileType, a.Key.Env, value, exists); err != nil {
		return false, err
	}
	if stored == LegacyProviderName(a) {
		if running, err := oc.Sandboxes(ctx); err == nil && len(running) == 0 {
			_ = oc.ProviderDelete(ctx, LegacyProviderName(a))
		}
	}
	return stored != "", nil
}

// RemoveKey deletes the agent's key from the gateway. It refuses while a
// sandbox that was started for this agent is still running, because what a
// running sandbox does when its provider disappears is not documented. The
// running sandboxes come from the gateway; which agent each one runs comes
// from the state Fenzi kept when it started them.
func RemoveKey(ctx context.Context, oc openshell.Client, dirs config.Dirs, a agents.Entry) (bool, error) {
	stored, err := StoredProvider(ctx, oc, a)
	if err != nil || stored == "" {
		return false, err
	}
	running, err := oc.Sandboxes(ctx)
	if err != nil {
		return false, err
	}
	if name := RunningWith(dirs, a, running); name != "" {
		return false, fmt.Errorf("%s is running with the %s key; stop it first (fenzi stop %s)", name, a.Display, name)
	}
	// Both names, so a key under the old one does not come back.
	for _, name := range []string{ProviderName(a), LegacyProviderName(a)} {
		if ok, err := oc.ProviderExists(ctx, name); err == nil && ok {
			if err := oc.ProviderDelete(ctx, name); err != nil {
				return false, err
			}
		}
	}
	return true, nil
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
