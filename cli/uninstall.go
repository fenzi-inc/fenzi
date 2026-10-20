package main

// fenzi uninstall: take Fenzi off this machine. Moving the Mac app to the
// Trash, or deleting the binary, leaves everything else behind: sandboxes,
// stored keys, the background forwarder, the records in ~/.config/fenzi and
// ~/.cache/fenzi, the Terminal command and its PATH line, agent images and
// the sandbox runtime. This removes them, the optional parts on request.

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	"fenzi/cli/internal/config"
	"fenzi/cli/internal/engine"
	"fenzi/cli/internal/tui"
)

// pathMarker ends the PATH line install.sh and the Mac app add to a shell
// profile; uninstall removes the lines that carry it.
const pathMarker = "# added by the fenzi installer"

// What uninstall touches on the machine; tests replace them.
var (
	uninstallHome = os.UserHomeDir
	// removeImages deletes the agent images and returns their tags.
	removeImages = removeAgentImages
	// removeRuntime stops and removes the sandbox runtime and its data.
	removeRuntime = removeOpenShell
	// commandPaths are where install.sh puts the binary, and where the Mac
	// app links its own copy for Terminal.
	commandPaths = func(home string) []string {
		return []string{filepath.Join(home, ".local", "bin", "fenzi"), "/usr/local/bin/fenzi"}
	}
)

// uninstallStep is one thing uninstall did, or could not do.
type uninstallStep struct {
	What   string `json:"what"`
	Detail string `json:"detail"`
	OK     bool   `json:"ok"`
}

type jsonUninstall struct {
	Removed []uninstallStep `json:"removed"`
	Failed  []uninstallStep `json:"failed"`
	// Kept lists what was left on purpose, by the choices made.
	Kept []string `json:"kept"`
}

func cmdUninstall(e env, args []string) (int, error) {
	fs := newFlags("uninstall", e.stderr)
	keys := fs.Bool("keys", false, "also forget the model keys and MCP tokens stored in the runtime")
	command := fs.Bool("command", false, "also remove the fenzi command in Terminal and its PATH line")
	images := fs.Bool("images", false, "also delete the agent images")
	runtimeToo := fs.Bool("runtime", false, "also remove the sandbox runtime (OpenShell) and its data")
	all := fs.Bool("all", false, "all of the above")
	yes := fs.Bool("yes", false, "do not ask")
	dry := fs.Bool("dry-run", false, "say what would be removed and remove nothing")
	asJSON := jsonFlag(fs)
	if _, err := parse(fs, args); err != nil {
		return 1, err
	}
	if *all {
		*keys, *command, *images, *runtimeToo = true, true, true, true
	}
	dirs, err := config.Default()
	if err != nil {
		return 1, err
	}
	home, err := uninstallHome()
	if err != nil {
		return 1, err
	}
	u := tui.New(e.stdin, e.stdout)
	sandboxes := uninstallSandboxes(e, dirs)

	plan := []string{
		describeSandboxes(sandboxes),
		"the background forwarder, if it is installed",
		"Fenzi's records, settings and Team sign-in (" + tilde(dirs.Config, home) + ", " + tilde(dirs.Cache, home) + ")",
	}
	// Never null in --json: an empty list when everything goes.
	kept := []string{}
	choose := func(on bool, what, keptWhat string) {
		if on {
			plan = append(plan, what)
		} else {
			kept = append(kept, keptWhat)
		}
	}
	choose(*keys, "the model keys and MCP tokens stored in the runtime", "model keys and MCP tokens")
	choose(*command, "the fenzi command in Terminal and its PATH line", "the fenzi command")
	choose(*images, "the agent images", "agent images")
	choose(*runtimeToo, "the sandbox runtime (OpenShell), its gateway and its data", "the sandbox runtime")

	if *dry {
		if *asJSON {
			out := jsonUninstall{Removed: []uninstallStep{}, Failed: []uninstallStep{}, Kept: kept}
			for _, p := range plan {
				out.Removed = append(out.Removed, uninstallStep{What: p, Detail: "would be removed"})
			}
			return 0, writeJSON(e.stdout, out)
		}
		u.Blank()
		u.Println("  " + u.Bold("fenzi uninstall would remove:"))
		for _, p := range plan {
			u.Println("    " + p)
		}
		if len(kept) > 0 {
			u.Note("It keeps " + strings.Join(kept, ", ") + ".")
		}
		u.Blank()
		return 0, nil
	}
	if !*yes {
		if !u.Interactive() {
			return 1, errors.New("uninstall removes sandboxes and records; run it in a terminal, or add --yes")
		}
		u.Blank()
		u.Println("  " + u.Bold("This removes:"))
		for _, p := range plan {
			u.Println("    " + p)
		}
		if len(sandboxes) > 0 {
			u.Note("Changes in those sandboxes that you have not applied are lost.")
		}
		ok, err := u.Confirm("Uninstall Fenzi?", "Yes, remove it", "No, keep it")
		if err != nil || !ok {
			return 1, err
		}
	}

	out := jsonUninstall{Removed: []uninstallStep{}, Failed: []uninstallStep{}, Kept: kept}
	// record(what)(detail, err) notes one step's outcome.
	record := func(what string) func(string, error) {
		return func(detail string, err error) {
			if err != nil {
				out.Failed = append(out.Failed, uninstallStep{What: what, Detail: err.Error()})
				return
			}
			if detail != "" {
				out.Removed = append(out.Removed, uninstallStep{What: what, Detail: detail, OK: true})
			}
		}
	}

	// The order matters: the forwarder first, so nothing is sent while the
	// rest goes; sandboxes and keys while the runtime still answers; the
	// records after them; the runtime last.
	record("Forwarder")(uninstallForwarder(e))
	record("Sandboxes")(uninstallDeleteSandboxes(e, sandboxes))
	if *keys {
		record("Keys")(uninstallKeys(e))
	}
	if *images {
		tags, err := removeImages(e.ctx)
		detail := ""
		if len(tags) > 0 {
			detail = strings.Join(tags, ", ")
		}
		record("Images")(detail, err)
	}
	if *command {
		record("Command")(uninstallCommand(home))
	}
	record("Records")(uninstallRecords(dirs, home))
	if *runtimeToo {
		record("Runtime")(removeRuntime(e.ctx, home))
	}

	if *asJSON {
		return 0, writeJSON(e.stdout, out)
	}
	u.Blank()
	for _, s := range out.Removed {
		u.Done(s.What, s.Detail)
	}
	for _, s := range out.Failed {
		u.Problem(s.What, s.Detail)
	}
	if len(kept) > 0 {
		u.Note("Kept: " + strings.Join(kept, ", ") + ".")
	}
	if len(out.Failed) > 0 {
		u.Blank()
		return 1, nil
	}
	u.Note("Fenzi is off this machine. The Mac app goes to the Trash on its own when it ran this.")
	u.Blank()
	return 0, nil
}

func describeSandboxes(names []string) string {
	switch len(names) {
	case 0:
		return "no sandboxes (none found)"
	case 1:
		return "1 sandbox: " + names[0]
	default:
		return fmt.Sprintf("%d sandboxes: %s", len(names), strings.Join(names, ", "))
	}
}

// uninstallSandboxes lists Fenzi's sandboxes: the ones in its records, and
// any fenzi- sandbox the runtime still has.
func uninstallSandboxes(e env, dirs config.Dirs) []string {
	var names []string
	if s, err := dirs.LoadState(); err == nil {
		for _, sb := range s.Sandboxes {
			names = append(names, sb.Name)
		}
	}
	if list, err := client().List(e.ctx); err == nil {
		for _, l := range list {
			if strings.HasPrefix(l.Name, "fenzi-") {
				names = append(names, l.Name)
			}
		}
	}
	slices.Sort(names)
	return slices.Compact(names)
}

func uninstallDeleteSandboxes(e env, names []string) (string, error) {
	if len(names) == 0 {
		return "", nil
	}
	live := map[string]bool{}
	if list, err := client().List(e.ctx); err == nil {
		for _, l := range list {
			live[l.Name] = true
		}
	}
	var deleted, failed []string
	for _, n := range names {
		if !live[n] {
			continue // a finished sandbox: only its records, which go below
		}
		if err := client().Delete(e.ctx, n); err != nil {
			failed = append(failed, n)
			continue
		}
		deleted = append(deleted, n)
	}
	if len(failed) > 0 {
		return "", fmt.Errorf("could not delete %s; the runtime may be stopped", strings.Join(failed, ", "))
	}
	if len(deleted) == 0 {
		// Only finished ones: their records go with the records below.
		return "", nil
	}
	return strings.Join(deleted, ", "), nil
}

func uninstallForwarder(e env) (string, error) {
	m, err := newServiceManager()
	if err != nil {
		// No launchd or systemd: there is no service to remove.
		return "", nil
	}
	removed, err := m.Remove(e.ctx)
	if err != nil || !removed {
		return "", err
	}
	return "the background " + m.Kind(), nil
}

// uninstallKeys deletes every fenzi- provider: the agents' keys and the MCP
// servers' tokens and secrets.
func uninstallKeys(e env) (string, error) {
	names, err := client().ProviderNames(e.ctx)
	if err != nil {
		return "", fmt.Errorf("could not list the stored keys; the runtime may be stopped")
	}
	var gone, failed []string
	for _, n := range names {
		if !strings.HasPrefix(n, "fenzi-") {
			continue
		}
		if err := client().ProviderDelete(e.ctx, n); err != nil {
			failed = append(failed, n)
			continue
		}
		gone = append(gone, n)
	}
	if len(failed) > 0 {
		return "", fmt.Errorf("could not forget %s", strings.Join(failed, ", "))
	}
	if len(gone) == 0 {
		return "", nil
	}
	return plural(len(gone), "stored key or token", "stored keys and tokens"), nil
}

// uninstallCommand removes the fenzi binary or link in the usual places and
// the marked PATH lines in the shell profiles.
func uninstallCommand(home string) (string, error) {
	var removed []string
	for _, p := range commandPaths(home) {
		info, err := os.Lstat(p)
		if err != nil {
			continue
		}
		if info.Mode()&fs.ModeSymlink == 0 && !info.Mode().IsRegular() {
			continue
		}
		if err := os.Remove(p); err != nil {
			return "", fmt.Errorf("%s: %w", tilde(p, home), err)
		}
		removed = append(removed, tilde(p, home))
	}
	for _, profile := range shellProfiles(home) {
		changed, err := dropMarkedLines(profile)
		if err != nil {
			return "", err
		}
		if changed {
			removed = append(removed, "the PATH line in "+tilde(profile, home))
		}
	}
	return strings.Join(removed, ", "), nil
}

// shellProfiles are the files install.sh and the Mac app may write to.
func shellProfiles(home string) []string {
	zdot := os.Getenv("ZDOTDIR")
	if zdot == "" {
		zdot = home
	}
	xdg := os.Getenv("XDG_CONFIG_HOME")
	if xdg == "" {
		xdg = filepath.Join(home, ".config")
	}
	return []string{
		filepath.Join(zdot, ".zshrc"),
		filepath.Join(home, ".bash_profile"),
		filepath.Join(home, ".bashrc"),
		filepath.Join(home, ".profile"),
		filepath.Join(xdg, "fish", "conf.d", "fenzi.fish"),
	}
}

// dropMarkedLines removes the lines that end with pathMarker, and the empty
// line the installer put before each. A fish file left empty is deleted.
func dropMarkedLines(path string) (bool, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return false, nil
	}
	if !strings.Contains(string(raw), pathMarker) {
		return false, nil
	}
	info, _ := os.Stat(path)
	var kept []string
	sc := bufio.NewScanner(strings.NewReader(string(raw)))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if strings.Contains(line, pathMarker) {
			if n := len(kept); n > 0 && strings.TrimSpace(kept[n-1]) == "" {
				kept = kept[:n-1]
			}
			continue
		}
		kept = append(kept, line)
	}
	text := strings.Join(kept, "\n")
	if strings.HasSuffix(string(raw), "\n") && text != "" {
		text += "\n"
	}
	if strings.TrimSpace(text) == "" && filepath.Base(path) == "fenzi.fish" {
		return true, os.Remove(path)
	}
	mode := fs.FileMode(0o644)
	if info != nil {
		mode = info.Mode().Perm()
	}
	return true, os.WriteFile(path, []byte(text), mode)
}

func uninstallRecords(dirs config.Dirs, home string) (string, error) {
	var gone []string
	for _, d := range []string{dirs.Config, dirs.Cache} {
		if _, err := os.Stat(d); err != nil {
			continue
		}
		if err := os.RemoveAll(d); err != nil {
			return "", err
		}
		gone = append(gone, tilde(d, home))
	}
	return strings.Join(gone, ", "), nil
}

// removeAgentImages deletes every fenzi/ image the image builder has.
func removeAgentImages(ctx context.Context) ([]string, error) {
	b, err := engine.Detect(nil)
	if err != nil {
		return nil, nil // no Docker or Podman: no images
	}
	out, err := exec.CommandContext(ctx, b.Bin, "images", "--format", "{{.Repository}}:{{.Tag}}").Output()
	if err != nil {
		return nil, fmt.Errorf("could not list the images: %w", err)
	}
	var tags []string
	for _, l := range strings.Split(string(out), "\n") {
		if l = strings.TrimSpace(l); strings.HasPrefix(l, "fenzi/") {
			tags = append(tags, l)
		}
	}
	if len(tags) == 0 {
		return nil, nil
	}
	if msg, err := exec.CommandContext(ctx, b.Bin, append([]string{"rmi", "--force"}, tags...)...).CombinedOutput(); err != nil {
		return nil, fmt.Errorf("could not delete the images: %s", strings.TrimSpace(string(msg)))
	}
	return tags, nil
}

// removeOpenShell stops the gateway service, removes the Homebrew package
// and the runtime's data: its gateway config, its state and the gateway's
// database. Only for an install from Homebrew on a Mac, the way setup does
// it; elsewhere it says what to remove.
func removeOpenShell(ctx context.Context, home string) (string, error) {
	if runtime.GOOS != "darwin" {
		return "", errors.New("remove the openshell package with your package manager, then ~/.config/openshell")
	}
	brew, err := exec.LookPath("brew")
	if err != nil {
		return "", errors.New("OpenShell was not installed with Homebrew here; remove it the way it was installed")
	}
	prefix, err := exec.CommandContext(ctx, brew, "--prefix").Output()
	if err != nil {
		return "", fmt.Errorf("brew --prefix: %w", err)
	}
	_ = exec.CommandContext(ctx, brew, "services", "stop", "openshell").Run()
	if msg, err := exec.CommandContext(ctx, brew, "uninstall", "openshell").CombinedOutput(); err != nil && !strings.Contains(string(msg), "No such keg") && !strings.Contains(string(msg), "is not installed") {
		return "", fmt.Errorf("brew uninstall openshell: %s", strings.TrimSpace(string(msg)))
	}
	dirs := []string{
		filepath.Join(home, ".config", "openshell"),
		filepath.Join(home, ".local", "state", "openshell"),
		filepath.Join(strings.TrimSpace(string(prefix)), "var", "openshell"),
	}
	for _, d := range dirs {
		if err := os.RemoveAll(d); err != nil {
			return "", err
		}
	}
	return "OpenShell, its gateway and its data", nil
}
