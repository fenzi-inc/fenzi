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
	if !strings.HasPrefix(f.Calls[len(f.Calls)-1], "provider create --name bl-claude --type fenzi-claude-code --from-existing") {
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
	if last := f.Calls[len(f.Calls)-1]; last != "provider update bl-claude --from-existing" {
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
	if err != nil || !removed || f.Calls[len(f.Calls)-1] != "provider delete bl-claude" {
		t.Errorf("removed %v, err %v, calls %v", removed, err, f.Calls)
	}

	// No sandbox at all.
	f, a = keyFake(t, true, "")
	removed, err = RemoveKey(context.Background(), openshell.Client{R: f}, stateWith(t), a)
	if err != nil || !removed || f.Calls[len(f.Calls)-1] != "provider delete bl-claude" {
		t.Errorf("removed %v, err %v, calls %v", removed, err, f.Calls)
	}

	// No key stored: nothing to remove, and the gateway is not asked for sandboxes.
	f, a = keyFake(t, false, "bl-web-4f2a\n")
	removed, err = RemoveKey(context.Background(), openshell.Client{R: f}, stateWith(t, "bl-web-4f2a=claude"), a)
	if err != nil || removed || len(f.Calls) != 1 {
		t.Errorf("removed %v, err %v, calls %v", removed, err, f.Calls)
	}
}
