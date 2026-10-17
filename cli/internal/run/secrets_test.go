package run

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSecretsAreNamedBeforeAnythingIsCreated(t *testing.T) {
	h := setup(t)
	os.WriteFile(filepath.Join(h.opts.Repo, ".env"), []byte("TOKEN=x"), 0o600)
	os.WriteFile(filepath.Join(h.opts.Repo, ".env.example"), []byte("TOKEN="), 0o600)
	asked := 0
	h.opts.ConfirmSecrets = func(files []string) (bool, error) {
		asked++
		if strings.Join(files, " ") != ".env" {
			t.Errorf("files = %v", files)
		}
		if h.called("sandbox create") || h.called("provider create") || len(h.images.built) > 0 {
			t.Errorf("asked after something was created: %v", h.os.Calls)
		}
		return true, nil
	}
	if _, err := Run(context.Background(), h.deps, h.opts); err != nil {
		t.Fatalf("%v\n%s", err, h.out)
	}
	out := h.out.String()
	warn := strings.Index(out, "1 file looks like a secret")
	created := strings.Index(out, "fenzi-test-0001, created")
	if asked != 1 || warn < 0 || created < 0 || warn > created {
		t.Fatalf("asked %d times; warning at %d, create at %d:\n%s", asked, warn, created, out)
	}
	if !strings.Contains(out, "because .gitignore does not exclude it") {
		t.Errorf("the warning does not say why:\n%s", out)
	}
}

func TestSecretsDeclinedCreatesNothing(t *testing.T) {
	h := setup(t)
	os.WriteFile(filepath.Join(h.opts.Repo, "server.pem"), []byte("x"), 0o600)
	h.opts.ConfirmSecrets = func([]string) (bool, error) { return false, nil }
	_, err := Run(context.Background(), h.deps, h.opts)
	if !errors.Is(err, ErrSecretsDeclined) {
		t.Fatalf("err = %v", err)
	}
	for _, c := range []string{"sandbox create", "provider create", "profile import", "sandbox upload"} {
		if h.called(c) {
			t.Errorf("%s ran after the person said no", c)
		}
	}
	if len(h.images.built) > 0 {
		t.Error("an image was built after the person said no")
	}
	if _, err := os.Stat(filepath.Join(h.deps.Dirs.Staging(h.opts.Name), "base.json")); err == nil {
		t.Error("a snapshot was saved for a run that did not start")
	}
}

func TestSecretsWarningNamesTenThenCounts(t *testing.T) {
	h := setup(t)
	for i := 0; i < 12; i++ {
		os.WriteFile(filepath.Join(h.opts.Repo, fmt.Sprintf("k%02d.key", i)), []byte("x"), 0o600)
	}
	h.opts.ConfirmSecrets = func([]string) (bool, error) { return false, nil }
	Run(context.Background(), h.deps, h.opts)
	out := h.out.String()
	if !strings.Contains(out, "12 files look like secrets") || !strings.Contains(out, "k09.key") || strings.Contains(out, "k10.key") || !strings.Contains(out, "and 2 more") {
		t.Errorf("warning:\n%s", out)
	}
}

func TestSecretsWithoutAQuestionStillWarn(t *testing.T) {
	h := setup(t)
	os.WriteFile(filepath.Join(h.opts.Repo, ".npmrc"), []byte("x"), 0o600)
	if _, err := Run(context.Background(), h.deps, h.opts); err != nil {
		t.Fatalf("%v\n%s", err, h.out)
	}
	if !strings.Contains(h.out.String(), ".npmrc") || !h.called("sandbox create") {
		t.Errorf("a script run must warn and continue:\n%s", h.out)
	}
}

func TestNoUploadDoesNotWarnAboutSecrets(t *testing.T) {
	h := setup(t)
	os.WriteFile(filepath.Join(h.opts.Repo, ".env"), []byte("x"), 0o600)
	h.opts.NoUpload = true
	h.opts.ConfirmSecrets = func([]string) (bool, error) {
		t.Error("asked about secrets with nothing to copy")
		return false, nil
	}
	if _, err := Run(context.Background(), h.deps, h.opts); err != nil {
		t.Fatalf("%v\n%s", err, h.out)
	}
	if strings.Contains(h.out.String(), "secret") {
		t.Errorf("warned with --no-upload:\n%s", h.out)
	}
}
