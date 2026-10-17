package run

import (
	"context"
	"strings"
	"testing"

	"fenzi/agents"
	"fenzi/cli/internal/config"
	"fenzi/cli/internal/openshell"
)

func keyFake(t *testing.T, providerExists bool, sandboxes string) (*openshell.Fake, agents.Entry) {
	t.Helper()
	a, err := agents.Get("claude")
	if err != nil {
		t.Fatal(err)
	}
	f := &openshell.Fake{Replies: map[string]openshell.Reply{
		"sandbox list": {Out: sandboxes},
	}}
	if !providerExists {
		f.Replies["provider get"] = openshell.Reply{Exit: 1}
	}
	return f, a
}

func TestSetKeyCreatesThroughEnvironment(t *testing.T) {
	f, a := keyFake(t, false, "")
	replaced, err := SetKey(context.Background(), openshell.Client{R: f}, a, "sk-secret-value")
	if err != nil || replaced {
		t.Fatalf("replaced %v, err %v", replaced, err)
	}
	if !strings.HasPrefix(f.Calls[len(f.Calls)-1], "provider create --name fenzi-claude --type fenzi-claude-code --from-existing") {
		t.Errorf("calls: %v", f.Calls)
	}
	for _, c := range f.Calls {
		if strings.Contains(c, "sk-secret-value") {
			t.Fatalf("the key appeared in a command line: %s", c)
		}
	}
	if len(f.Env) != 1 || f.Env[0] != "ANTHROPIC_API_KEY=sk-secret-value" {
		t.Errorf("env = %v", f.Env)
	}
}

func TestSetKeyReplaces(t *testing.T) {
	f, a := keyFake(t, true, "")
	replaced, err := SetKey(context.Background(), openshell.Client{R: f}, a, "sk-new")
	if err != nil || !replaced {
		t.Fatalf("replaced %v, err %v", replaced, err)
	}
	if last := f.Calls[len(f.Calls)-1]; last != "provider update fenzi-claude --from-existing" {
		t.Errorf("last call %q", last)
	}
}

func TestSetKeyRejectsEmpty(t *testing.T) {
	f, a := keyFake(t, false, "")
	if _, err := SetKey(context.Background(), openshell.Client{R: f}, a, ""); err == nil || len(f.Calls) != 0 {
		t.Errorf("err %v, calls %v", err, f.Calls)
	}
}

// stateWith writes a state in a temporary config folder: one sandbox per
// name=agent pair, all running.
func stateWith(t *testing.T, pairs ...string) config.Dirs {
	t.Helper()
	dirs := config.Dirs{Config: t.TempDir(), Cache: t.TempDir()}
	s := &config.State{}
	for _, p := range pairs {
		name, agent, _ := strings.Cut(p, "=")
		s.Put(config.Sandbox{Name: name, Agent: agent, Running: true})
	}
	if err := dirs.SaveState(s); err != nil {
		t.Fatal(err)
	}
	return dirs
}

func TestRemoveKeyRefusesWhileThatAgentRuns(t *testing.T) {
	f, a := keyFake(t, true, "bl-web-4f2a\nbl-api-90cc\n")
	dirs := stateWith(t, "bl-web-4f2a=codex", "bl-api-90cc=claude")
	_, err := RemoveKey(context.Background(), openshell.Client{R: f}, dirs, a)
	if err == nil {
		t.Fatal("want a refusal while a Claude Code sandbox runs")
	}
	if want := "bl-api-90cc is running with the Claude Code key; stop it first (fenzi stop bl-api-90cc)"; err.Error() != want {
		t.Errorf("err = %q, want %q", err, want)
	}
	for _, c := range f.Calls {
		if strings.HasPrefix(c, "provider delete") {
			t.Fatal("the provider was deleted anyway")
		}
	}
}

func TestRemoveKeyIgnoresOtherAgentsSandboxes(t *testing.T) {
	// Only a Codex sandbox runs: the Claude Code key is not in use.
	f, a := keyFake(t, true, "bl-web-4f2a\n")
	dirs := stateWith(t, "bl-web-4f2a=codex", "bl-old-0000=claude")
	removed, err := RemoveKey(context.Background(), openshell.Client{R: f}, dirs, a)
	if err != nil || !removed || !hasCall(f.Calls, "provider delete fenzi-claude") || !hasCall(f.Calls, "provider delete bl-claude") {
		t.Errorf("removed %v, err %v, calls %v", removed, err, f.Calls)
	}

	// No sandbox at all.
	f, a = keyFake(t, true, "")
	removed, err = RemoveKey(context.Background(), openshell.Client{R: f}, stateWith(t), a)
	if err != nil || !removed || !hasCall(f.Calls, "provider delete fenzi-claude") {
		t.Errorf("removed %v, err %v, calls %v", removed, err, f.Calls)
	}

	// No key stored: nothing to remove, and the gateway is not asked for sandboxes.
	f, a = keyFake(t, false, "bl-web-4f2a\n")
	removed, err = RemoveKey(context.Background(), openshell.Client{R: f}, stateWith(t, "bl-web-4f2a=claude"), a)
	if err != nil || removed || len(f.Calls) != 2 {
		t.Errorf("removed %v, err %v, calls %v", removed, err, f.Calls)
	}
}

// A local server's secret is stored like a key: through openshell's
// environment, as a provider of an endpointless profile named for the
// variable, which exposes the variable under its own name.
func TestSetMCPSecretCreatesThroughEnvironment(t *testing.T) {
	f, _ := keyFake(t, false, "")
	replaced, err := SetMCPSecret(context.Background(), openshell.Client{R: f}, "DIGITALOCEAN_API_TOKEN", "dop_v1_not_a_real_one")
	if err != nil || replaced {
		t.Fatalf("replaced %v, err %v", replaced, err)
	}
	if !strings.HasPrefix(f.Calls[len(f.Calls)-1], "provider create --name fenzi-secret-digitalocean-api-token --type fenzi-secret-digitalocean-api-token --from-existing") {
		t.Errorf("calls: %v", f.Calls)
	}
	for _, c := range f.Calls {
		if strings.Contains(c, "dop_v1_") {
			t.Fatalf("the value appeared in a command line: %s", c)
		}
	}
	if len(f.Env) != 1 || f.Env[0] != "DIGITALOCEAN_API_TOKEN=dop_v1_not_a_real_one" {
		t.Errorf("env = %v", f.Env)
	}
	prof := string(SecretProfile("DIGITALOCEAN_API_TOKEN"))
	if !strings.Contains(prof, "id: fenzi-secret-digitalocean-api-token\n") || !strings.Contains(prof, "env_vars: [DIGITALOCEAN_API_TOKEN]") || strings.Contains(prof, "endpoints") {
		t.Errorf("profile:\n%s", prof)
	}
	if _, err := SetMCPSecret(context.Background(), openshell.Client{R: f}, "DIGITALOCEAN_API_TOKEN", " "); err == nil {
		t.Error("an empty value must be refused")
	}
}

func hasCall(calls []string, want string) bool {
	for _, c := range calls {
		if c == want {
			return true
		}
	}
	return false
}

// Setting the key again moves one stored under the old name, bl-claude, to
// fenzi-claude, and removes the old provider when no sandbox is running.
func TestSetKeyMovesAKeyFromTheOldName(t *testing.T) {
	a, err := agents.Get("claude")
	if err != nil {
		t.Fatal(err)
	}
	f := &openshell.Fake{Replies: map[string]openshell.Reply{
		"provider get fenzi-claude": {Exit: 1},
		"provider get bl-claude":    {},
		"sandbox list":              {},
	}}
	replaced, err := SetKey(context.Background(), openshell.Client{R: f}, a, "sk-test")
	if err != nil || !replaced {
		t.Fatalf("replaced %v err %v", replaced, err)
	}
	if !hasCall(f.Calls, "provider create --name fenzi-claude --type fenzi-claude-code --from-existing") || !hasCall(f.Calls, "provider delete bl-claude") {
		t.Errorf("calls %v", f.Calls)
	}

	f.Replies["sandbox list"] = openshell.Reply{Out: "bl-web-4f2a\n"}
	f.Calls = nil
	if _, err := SetKey(context.Background(), openshell.Client{R: f}, a, "sk-test"); err != nil {
		t.Fatal(err)
	}
	if hasCall(f.Calls, "provider delete bl-claude") {
		t.Error("the old provider must stay while a sandbox runs")
	}
}
