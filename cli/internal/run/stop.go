package run

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"fenzi/cli/internal/config"
	"fenzi/cli/internal/screen"
	"fenzi/cli/internal/workspace"
)

// Stop ends a sandbox the way an agent exit does: save the log, copy the
// project out to staging, then delete. If the copy fails the sandbox is kept,
// and so is any copy staged before it.
func Stop(ctx context.Context, d Deps, sb config.Sandbox) ([]workspace.Change, error) {
	scr := screen.New(d.Out)
	say := func(label, format string, args ...any) {
		scr.Label(label, fmt.Sprintf(format, args...))
	}
	// A fenzi run still attached to this sandbox copies it out when its
	// agent exits; wait for it rather than copy at the same time.
	unlock, err := lockCopyOut(ctx, d.Dirs, sb.Name)
	if err != nil {
		return nil, err
	}
	defer unlock()
	if stoppedElsewhere(d.Dirs, sb.Name) {
		changes, err := stagedChanges(d, sb.Name, sb.Repo)
		if err != nil {
			return nil, err
		}
		say("sandbox", "%s, already stopped by the fenzi run attached to it", sb.Name)
		sayStaged(say, changes)
		return changes, nil
	}
	runDir := d.Dirs.Run(sb.Name)
	if out, err := settledLog(ctx, d, sb.Name); err == nil {
		_ = os.MkdirAll(runDir, 0o700)
		_ = os.WriteFile(filepath.Join(runDir, LogFile), out, 0o600)
		say("log", "saved, fenzi log")
	} else {
		say("log", "could not be saved: %v", err)
	}

	var changes []workspace.Change
	staging := d.Dirs.Staging(sb.Name)
	base, err := workspace.Load(filepath.Join(staging, "base.json"))
	switch {
	case sb.Repo == "":
		say("changes", "not copied; this sandbox was not started by fenzi run")
	case errors.Is(err, fs.ErrNotExist):
		say("changes", "not copied; the snapshot of %s taken before upload is missing", sb.Repo)
	case err != nil:
		return nil, err
	default:
		if sb.Git != nil && sb.Git.History {
			if err := collectHistory(ctx, d, &sb, ProjectDir(sb.Repo), staging, say); err != nil {
				return nil, fmt.Errorf("%w; the sandbox %s is kept so the agent's work is not lost", err, sb.Name)
			}
		}
		files, err := stageCopy(ctx, d, sb.Name, ProjectDir(sb.Repo), staging)
		if err != nil {
			return nil, fmt.Errorf("copying changes out of %s: %w; the sandbox is kept so the agent's work is not lost", sb.Name, err)
		}
		filter := workspace.All
		if d.Filter != nil {
			filter = d.Filter(sb.Repo)
		}
		if changes, err = workspace.Changes(base, files, filter); err != nil {
			return nil, err
		}
		sayStaged(say, changes)
	}

	if err := d.OpenShell.Delete(ctx, sb.Name); err != nil {
		return changes, err
	}
	markStopped(d.Dirs, sb.Name)
	dropEmptyStaging(d.Dirs, sb.Name)
	if sb.Git != nil && sb.Repo != "" {
		workspace.DropRefs(sb.Repo, sb.Name)
	}
	say("sandbox", "%s, deleted", sb.Name)
	return changes, nil
}

// stagedChanges compares the copy staged for a sandbox with its snapshot.
// Nil when nothing is staged.
func stagedChanges(d Deps, name, repo string) ([]workspace.Change, error) {
	staging := d.Dirs.Staging(name)
	files := filepath.Join(staging, StagedFiles)
	if _, err := os.Stat(files); errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	base, err := workspace.Load(filepath.Join(staging, "base.json"))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	filter := workspace.All
	if d.Filter != nil && repo != "" {
		filter = d.Filter(repo)
	}
	return workspace.Changes(base, files, filter)
}

func sayStaged(say func(label, format string, args ...any), changes []workspace.Change) {
	if len(changes) == 0 {
		say("changes", "none")
	} else {
		say("changes", "%d %s staged, not applied", len(changes), files1(len(changes)))
	}
}

// dropEmptyStaging removes a deleted sandbox's staging folder when no copy
// is left in it to apply.
func dropEmptyStaging(dirs config.Dirs, name string) {
	dir := dirs.Staging(name)
	if _, err := os.Stat(filepath.Join(dir, StagedFiles)); errors.Is(err, fs.ErrNotExist) {
		_ = os.RemoveAll(dir)
	}
}

// Discard deletes a sandbox whose files cannot be copied out: one in phase
// Error that OpenShell would not start again. The log is saved first, so
// fenzi log still shows what it did.
func Discard(ctx context.Context, d Deps, sb config.Sandbox) error {
	scr := screen.New(d.Out)
	unlock, err := lockCopyOut(ctx, d.Dirs, sb.Name)
	if err != nil {
		return err
	}
	defer unlock()
	if out, err := settledLog(ctx, d, sb.Name); err == nil {
		runDir := d.Dirs.Run(sb.Name)
		_ = os.MkdirAll(runDir, 0o700)
		_ = os.WriteFile(filepath.Join(runDir, LogFile), out, 0o600)
		scr.Label("log", "saved, fenzi log")
	} else {
		scr.Label("log", fmt.Sprintf("could not be saved: %v", err))
	}
	scr.Label("changes", "not copied; the sandbox stopped and cannot give back its files")
	if err := d.OpenShell.Delete(ctx, sb.Name); err != nil {
		return err
	}
	markStopped(d.Dirs, sb.Name)
	dropEmptyStaging(d.Dirs, sb.Name)
	scr.Label("sandbox", sb.Name+", deleted")
	return nil
}
