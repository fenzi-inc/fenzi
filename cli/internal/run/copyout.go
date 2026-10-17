package run

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"fenzi/cli/internal/config"
)

// The staging folder of a sandbox holds base.json, the snapshot taken before
// upload, and StagedFiles, the last copy that came back. AppliedMark is
// written there when fenzi apply copied that copy into the project, so a
// missing copy can be told from an applied one.
const (
	StagedFiles = "files"
	AppliedMark = "applied"
)

// MarkApplied records that the staged copy in dir was applied.
func MarkApplied(dir string, at time.Time) error {
	return os.WriteFile(filepath.Join(dir, AppliedMark), []byte(at.UTC().Format(time.RFC3339)+"\n"), 0o600)
}

// lockPoll is how often a command waiting for the copy-out lock tries again.
var lockPoll = 100 * time.Millisecond

// lockCopyOut holds copy.lock in the sandbox's run folder until unlock is
// called. fenzi run and fenzi stop both copy a sandbox out to the same
// staging folder and then delete it; the lock makes them take turns, so one
// never deletes or replaces a copy the other is making. The lock is not in
// the staging folder, which is removed when nothing is left to apply.
func lockCopyOut(ctx context.Context, dirs config.Dirs, name string) (unlock func(), err error) {
	dir := dirs.Run(name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(dir, "copy.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return func() {
				_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
				f.Close()
			}, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) {
			f.Close()
			return nil, err
		}
		select {
		case <-ctx.Done():
			f.Close()
			return nil, ctx.Err()
		case <-time.After(lockPoll):
		}
	}
}

// stoppedElsewhere reports whether another fenzi command stopped the
// sandbox: its record is gone or no longer running. Call it while holding
// the copy-out lock, which every command that stops a sandbox holds until
// the record is written.
func stoppedElsewhere(dirs config.Dirs, name string) bool {
	s, err := dirs.LoadState()
	if err != nil {
		return false
	}
	sb, ok := s.Find(name)
	return !ok || !sb.Running
}

// stageCopy downloads the project from the sandbox into a new folder and
// puts it in place of the staged copy only once the download succeeded. A
// failed download leaves the copy that was staged before it as it was.
func stageCopy(ctx context.Context, d Deps, name, project, staging string) (string, error) {
	files := filepath.Join(staging, StagedFiles)
	tmp, err := os.MkdirTemp(staging, ".download-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(tmp)
	// The download is given a path that does not exist yet, so the
	// project's contents land directly in it.
	fresh := filepath.Join(tmp, StagedFiles)
	if err := d.OpenShell.Download(ctx, name, project, fresh); err != nil {
		return "", err
	}
	old := filepath.Join(tmp, "old")
	if err := os.Rename(files, old); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return "", err
	}
	if err := os.Rename(fresh, files); err != nil {
		_ = os.Rename(old, files)
		return "", err
	}
	_ = os.Remove(filepath.Join(staging, AppliedMark))
	return files, nil
}
