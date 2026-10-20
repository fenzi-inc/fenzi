package main

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"fenzi/cli/internal/config"
)

// fakeUninstallMachine gives uninstall a temporary home, no real images and
// no real runtime. It returns the home.
func fakeUninstallMachine(t *testing.T) (home string, imagesRemoved, runtimeRemoved *bool) {
	t.Helper()
	home = t.TempDir()
	images, rt := false, false
	oldHome, oldImages, oldRuntime, oldPaths := uninstallHome, removeImages, removeRuntime, commandPaths
	t.Cleanup(func() { uninstallHome, removeImages, removeRuntime, commandPaths = oldHome, oldImages, oldRuntime, oldPaths })
	uninstallHome = func() (string, error) { return home, nil }
	// Never the machine's own /usr/local/bin.
	commandPaths = func(h string) []string { return []string{filepath.Join(h, ".local", "bin", "fenzi")} }
	removeImages = func(context.Context) ([]string, error) { images = true; return []string{"fenzi/claude:2.1.288"}, nil }
	removeRuntime = func(context.Context, string) (string, error) {
		rt = true
		return "OpenShell, its gateway and its data", nil
	}
	t.Setenv("ZDOTDIR", "")
	return home, &images, &rt
}

func TestUninstallDryRunSaysWhatAndKeepsTheRest(t *testing.T) {
	fakeRuntime(t, map[string]reply{"sandbox list": {out: "fenzi-web-1a2b\n"}}, "")
	fakeUninstallMachine(t)
	var out jsonUninstall
	if stderr, code := runJSON(t, &out, "uninstall", "--keys", "--dry-run", "--json"); code != 0 {
		t.Fatalf("exit %d %s", code, stderr)
	}
	if len(out.Removed) != 4 || !strings.Contains(out.Removed[0].What, "fenzi-web-1a2b") {
		t.Fatalf("plan %+v", out.Removed)
	}
	if !slices.Equal(out.Kept, []string{"the fenzi command", "agent images", "the sandbox runtime"}) {
		t.Fatalf("kept %v", out.Kept)
	}
	for _, c := range runtimeCalls(t) {
		if strings.Contains(c, "delete") {
			t.Fatalf("a dry run called %q", c)
		}
	}
}

func TestUninstallAllRemovesEverythingFenziLeft(t *testing.T) {
	fakeRuntime(t, map[string]reply{
		"sandbox list":    {out: "fenzi-web-1a2b\nsomeone-else\n"},
		"provider list":   {out: "fenzi-claude\nfenzi-mcp-github\nanother-tool\n"},
		"sandbox delete":  {},
		"provider delete": {},
	}, "")
	home, images, rt := fakeUninstallMachine(t)
	mgr := useFakeManager(t)
	mgr.installed = true
	dirs := seedState(t, config.Sandbox{Name: "fenzi-web-1a2b", Agent: "claude", Repo: t.TempDir(), Created: time.Now(), Running: true})

	// The Terminal link and the installer's PATH line, among the person's own lines.
	bin := filepath.Join(home, ".local", "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/Applications/Fenzi.app/Contents/Helpers/fenzi", filepath.Join(bin, "fenzi")); err != nil {
		t.Fatal(err)
	}
	zshrc := filepath.Join(home, ".zshrc")
	mine := "alias ll='ls -l'\n\nexport PATH=\"$HOME/.local/bin:$PATH\" " + pathMarker + "\nexport EDITOR=vim\n"
	if err := os.WriteFile(zshrc, []byte(mine), 0o600); err != nil {
		t.Fatal(err)
	}

	var out jsonUninstall
	if stderr, code := runJSON(t, &out, "uninstall", "--all", "--yes", "--json"); code != 0 {
		t.Fatalf("exit %d %s\n%+v", code, stderr, out)
	}
	if len(out.Failed) != 0 {
		t.Fatalf("failed %+v", out.Failed)
	}
	// With everything chosen, kept is an empty list, never null: the app's
	// decoder refused null on 20 October and showed a finished uninstall
	// as failed.
	if out.Kept == nil || len(out.Kept) != 0 {
		t.Fatalf("kept %#v", out.Kept)
	}
	calls := strings.Join(runtimeCalls(t), "\n")
	for _, want := range []string{"sandbox delete fenzi-web-1a2b", "provider delete fenzi-claude", "provider delete fenzi-mcp-github"} {
		if !strings.Contains(calls, want) {
			t.Errorf("no %q in\n%s", want, calls)
		}
	}
	for _, never := range []string{"sandbox delete someone-else", "provider delete another-tool"} {
		if strings.Contains(calls, never) {
			t.Errorf("deleted what is not Fenzi's: %q", never)
		}
	}
	if mgr.installed || mgr.removes != 1 {
		t.Errorf("the forwarder service was not removed")
	}
	for _, d := range []string{dirs.Config, dirs.Cache, filepath.Join(bin, "fenzi")} {
		if _, err := os.Lstat(d); err == nil {
			t.Errorf("%s is still there", d)
		}
	}
	raw, _ := os.ReadFile(zshrc)
	if string(raw) != "alias ll='ls -l'\nexport EDITOR=vim\n" {
		t.Errorf(".zshrc is now %q", raw)
	}
	if mode, _ := os.Stat(zshrc); mode.Mode().Perm() != 0o600 {
		t.Errorf(".zshrc mode is %v", mode.Mode().Perm())
	}
	if !*images || !*rt {
		t.Errorf("images %v, runtime %v", *images, *rt)
	}
}

func TestUninstallWithoutAPersonNeedsYes(t *testing.T) {
	fakeRuntime(t, map[string]reply{"sandbox list": {out: ""}}, "")
	fakeUninstallMachine(t)
	out, code := runCLI(t, "", "uninstall")
	if code == 0 || !strings.Contains(out, "--yes") {
		t.Fatalf("exit %d\n%s", code, out)
	}
}
