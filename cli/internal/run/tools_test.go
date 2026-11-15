package run

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"fenzi/policies"
)

// failingImages builds every tag but one.
type failingImages struct {
	fakeImages
	fail string
}

func (f *failingImages) Build(ctx context.Context, tag string, df []byte) error {
	if strings.HasPrefix(tag, f.fail) {
		return errors.New("apt-get exited 100")
	}
	return f.fakeImages.Build(ctx, tag, df)
}

// toolsRepo makes the harness's project a PHP one with a crate, and
// answers the check with the commands the sandbox has.
func toolsRepo(t *testing.T, h *harness, has ...string) {
	t.Helper()
	os.WriteFile(filepath.Join(h.opts.Repo, "composer.json"), []byte("{}"), 0o644)
	os.WriteFile(filepath.Join(h.opts.Repo, "Cargo.toml"), nil, 0o644)
	h.os.Answer = func(args []string) (string, bool) {
		if len(args) > 8 && args[0] == "sandbox" && args[1] == "exec" && args[6] == "python3" && args[8] == whichScript {
			if got := strings.Join(args[9:], " "); got != "php composer cargo rustc" {
				t.Errorf("checked %q", got)
			}
			return strings.Join(has, "\n") + "\n", true
		}
		return "", false
	}
}

func TestRunAddsAndChecksTheProjectsTools(t *testing.T) {
	h := setup(t)
	toolsRepo(t, h, "php", "composer")
	if _, err := Run(context.Background(), h.deps, h.opts); err != nil {
		t.Fatalf("%v\n%s", err, h.out)
	}
	tag, _ := h.opts.Agent.ToolsImage([]string{"php"}, policies.Toolchains()[2].Packages, nil)
	if len(h.images.built) != 2 || h.images.built[0] != h.opts.Agent.Tag() || h.images.built[1] != tag {
		t.Errorf("built %v, want the agent's image then %s", h.images.built, tag)
	}
	if !h.called("sandbox create --name fenzi-test-0001 --from " + tag + " ") {
		t.Errorf("the sandbox did not start from %s:\n%s", tag, strings.Join(h.os.Calls, "\n"))
	}
	out := h.out.String()
	for _, want := range []string{
		"adding php to the image, building on this machine",
		tag + ", with php",
		"cargo and rustc missing for rust: Fenzi does not add Rust yet",
		"php, composer ready",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	// The agent is told, so it says so instead of trying to install them.
	if !h.called("sandbox exec -n fenzi-test-0001 --tty") || !strings.Contains(strings.Join(h.os.Calls, "\n"), "This sandbox has no cargo or rustc") {
		t.Errorf("the agent was not told:\n%s", strings.Join(h.os.Calls, "\n"))
	}
}

// A build that fails starts the agent's own image, and the check says
// what is missing.
func TestRunStartsWithoutToolsWhenTheBuildFails(t *testing.T) {
	h := setup(t)
	toolsRepo(t, h)
	imgs := &failingImages{fail: h.opts.Agent.Tag() + "-php-"}
	h.deps.Images = imgs
	if _, err := Run(context.Background(), h.deps, h.opts); err != nil {
		t.Fatalf("%v\n%s", err, h.out)
	}
	if !h.called("sandbox create --name fenzi-test-0001 --from " + h.opts.Agent.Tag() + " ") {
		t.Errorf("not started from the agent's image:\n%s", strings.Join(h.os.Calls, "\n"))
	}
	out := h.out.String()
	for _, want := range []string{
		"php could not be added (apt-get exited 100); the agent starts without them",
		"php and composer missing for php: the image was not built with them",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, " ready") {
		t.Errorf("nothing is ready:\n%s", out)
	}
}

// A project with no language files Fenzi knows is not checked.
func TestRunChecksNothingWithoutLanguageFiles(t *testing.T) {
	h := setup(t)
	if _, err := Run(context.Background(), h.deps, h.opts); err != nil {
		t.Fatal(err)
	}
	if h.called("sandbox exec -n fenzi-test-0001 --no-login-shell -- python3") || strings.Contains(h.out.String(), "tools") {
		t.Errorf("checked without language files:\n%s", h.out)
	}
}
