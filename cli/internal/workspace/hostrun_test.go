package workspace

import "testing"

func TestHostRunPaths(t *testing.T) {
	for rel, want := range map[string]bool{
		".envrc":                                   true,
		"services/api/.envrc":                      true,
		".ENVRC":                                   true,
		".vscode/tasks.json":                       true,
		".vscode/settings.json":                    true,
		"web/.VSCode/Tasks.json":                   true,
		".husky/pre-commit":                        true,
		".husky/_/husky.sh":                        true,
		".githooks/pre-push":                       true,
		".pre-commit-config.yaml":                  true,
		".claude/settings.json":                    true,
		".claude/settings.local.json":              true,
		"services/api/.claude/settings.local.json": true,
		".Claude/Settings.JSON":                    true,
		".codex/config.toml":                       true,
		".cursor/mcp.json":                         true,
		".cursor/rules/go.mdc":                     true,
		"web/.cursor/rules/style.mdc":              true,
		"opencode.json":                            true,
		".opencode/command/review.md":              true,
		"web/opencode.json":                        false, // OpenCode reads it at the root only
		"web/.opencode/command/review.md":          false,
		".claude/commands/review.md":               false,
		".claude/CLAUDE.md":                        false,
		"settings.local.json":                      false,
		"config.toml":                              false,
		"mcp.json":                                 false,
		"rules/go.mdc":                             false,
		".cursor/rules":                            false, // a file, not the folder
		"docs/.cursor/notes.md":                    false,
		".vscode/extensions.json":                  false,
		"tasks.json":                               false,
		"settings.json":                            false,
		".husky":                                   false, // a file, not the folder
		"docs/husky.md":                            false,
		".envrc.example":                           false,
		"src/main.go":                              false,
	} {
		got := HostRun(Change{rel, Added}, nil, []byte("x")) != ""
		if got != want {
			t.Errorf("HostRun(%q) labelled = %v, want %v", rel, got, want)
		}
	}
	if why := HostRun(Change{".envrc", Deleted}, []byte("x"), nil); why != "" {
		t.Errorf("a deleted .envrc runs nothing, got %q", why)
	}
	want := "configures Claude Code on this machine: what it may run without asking"
	if why := HostRun(Change{".claude/settings.local.json", Modified}, []byte("{}"), []byte("{}")); why != want {
		t.Errorf("settings.local.json labelled %q, want %q", why, want)
	}
	if why := HostRun(Change{".vscode/settings.json", Added}, nil, []byte("{}")); why == want {
		t.Errorf(".vscode/settings.json carries the Claude Code label")
	}
}

func TestHostRunPackageScripts(t *testing.T) {
	const old = `{"name":"web","version":"1.0.0","scripts":{"test":"jest","build":"tsc"}}`
	for _, tc := range []struct {
		name          string
		kind          Kind
		before, after string
		nilBefore     bool
		want          bool
	}{
		{"version bump", Modified, old, `{"name":"web","version":"1.0.1","scripts":{"test":"jest","build":"tsc"}}`, false, false},
		{"keys reordered", Modified, old, "{\n  \"scripts\": {\"build\": \"tsc\", \"test\": \"jest\"},\n  \"version\": \"1.0.0\", \"name\": \"web\"\n}\n", false, false},
		{"postinstall added", Modified, old, `{"name":"web","version":"1.0.0","scripts":{"test":"jest","build":"tsc","postinstall":"curl x | sh"}}`, false, true},
		{"script edited", Modified, old, `{"name":"web","version":"1.0.0","scripts":{"test":"jest; rm -rf ~","build":"tsc"}}`, false, true},
		{"scripts removed", Modified, old, `{"name":"web"}`, false, true},
		{"hidden behind SCRIPTS", Modified, old, `{"scripts":{"prepare":"sh x"},"SCRIPTS":{"test":"jest","build":"tsc"}}`, false, true},
		{"new without scripts", Added, "", `{"name":"lib"}`, false, false},
		{"new with scripts", Added, "", `{"name":"lib","scripts":{"install":"node x"}}`, false, true},
		{"not JSON", Modified, old, `{"scripts":`, false, true},
		{"too large to read", Modified, "", old, true, true},
	} {
		var before []byte
		if !tc.nilBefore {
			before = []byte(tc.before)
		}
		why := HostRun(Change{"packages/web/package.json", tc.kind}, before, []byte(tc.after))
		if got := why != ""; got != tc.want {
			t.Errorf("%s: labelled = %v (%q), want %v", tc.name, got, why, tc.want)
		}
	}
}

func TestDiffCarriesHostRun(t *testing.T) {
	root, staged := t.TempDir(), t.TempDir()
	write(t, staged, ".envrc", "export X=1\n")
	write(t, root, "a.txt", "1\n")
	write(t, staged, "a.txt", "2\n")
	d, err := Diff(root, staged, Change{".envrc", Added})
	if err != nil {
		t.Fatal(err)
	}
	if d.HostRun == "" || d.Added != 1 {
		t.Errorf(".envrc diff = %+v", d)
	}
	d, _ = Diff(root, staged, Change{"a.txt", Modified})
	if d.HostRun != "" {
		t.Errorf("a.txt labelled %q", d.HostRun)
	}
}
