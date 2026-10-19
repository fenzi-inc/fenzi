// Package action holds the tests of the GitHub Action in this folder.
package action

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

type actionFile struct {
	Inputs  map[string]struct{ Default string } `yaml:"inputs"`
	Outputs map[string]struct{ Value string }   `yaml:"outputs"`
	Runs    struct {
		Using string `yaml:"using"`
		Steps []struct {
			ID   string            `yaml:"id"`
			Uses string            `yaml:"uses"`
			Run  string            `yaml:"run"`
			Env  map[string]string `yaml:"env"`
		} `yaml:"steps"`
	} `yaml:"runs"`
}

func load(t *testing.T) (actionFile, string) {
	t.Helper()
	raw, err := os.ReadFile("action.yml")
	if err != nil {
		t.Fatal(err)
	}
	var a actionFile
	if err := yaml.Unmarshal(raw, &a); err != nil {
		t.Fatal(err)
	}
	return a, string(raw)
}

// Every input the steps use is declared, every FENZI_ACTION_ variable the
// script reads is passed, and the outputs are the ones the script writes.
func TestActionMatchesTheScript(t *testing.T) {
	a, raw := load(t)
	if a.Runs.Using != "composite" {
		t.Fatalf("using %q", a.Runs.Using)
	}
	for _, m := range regexp.MustCompile(`inputs\.([a-z-]+)`).FindAllStringSubmatch(raw, -1) {
		if _, ok := a.Inputs[m[1]]; !ok {
			t.Errorf("inputs.%s is used and not declared", m[1])
		}
	}
	script, err := os.ReadFile("run.sh")
	if err != nil {
		t.Fatal(err)
	}
	env := a.Runs.Steps[0].Env
	for _, m := range regexp.MustCompile(`FENZI_ACTION_[A-Z_]+|FENZI_TEAM_TOKEN`).FindAllString(string(script), -1) {
		if _, ok := env[m]; !ok {
			t.Errorf("run.sh reads %s, which action.yml does not pass", m)
		}
	}
	for name, o := range a.Outputs {
		key := strings.TrimSuffix(strings.TrimPrefix(o.Value, "${{ steps.run.outputs."), " }}")
		if !strings.Contains(string(script), key+"=") {
			t.Errorf("output %s reads %s, which run.sh never writes", name, key)
		}
	}
	if info, err := os.Stat("run.sh"); err != nil || info.Mode()&0o111 == 0 {
		t.Error("run.sh must be executable")
	}
	// The token reaches the script through the environment only.
	if strings.Contains(a.Runs.Steps[0].Run, "token") {
		t.Errorf("run = %q", a.Runs.Steps[0].Run)
	}
}

// The script end to end on Linux, with stand-ins for fenzi and docker: a
// shallow checkout is deepened, the token goes to fenzi login on standard
// input and nowhere else, fenzi run gets the task as a file, and the
// summary fenzi wrote becomes the job summary and the outputs. The exit
// status is fenzi's.
func TestRunScript(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the action runs on Linux runners")
	}
	for _, bin := range []string{"bash", "git", "python3"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s is not installed", bin)
		}
	}
	here, _ := os.Getwd()
	tmp := t.TempDir()
	stubs := filepath.Join(tmp, "stubs")
	os.MkdirAll(stubs, 0o755)
	calls := filepath.Join(tmp, "calls.txt")
	tokenSeen := filepath.Join(tmp, "token.txt")
	// The fake fenzi writes what fenzi run --out writes, and exits 6.
	fenzi := `#!/bin/sh
echo "fenzi $*" >> '` + calls + `'
case "$1" in
login) cat > '` + tokenSeen + `' ;;
run)
  while [ $# -gt 0 ]; do
    case "$1" in --out) out=$2; shift ;; --task) task=$2; shift ;; esac
    shift
  done
  cp "$task" "$out/task-seen.md"
  echo '### fenzi run: Claude Code request unanswered' > "$out/summary.md"
  echo '{"outcome":"request unanswered","branch":{"name":"fenzi/project-1a2b"},"refused":[{"destination":"example.com:443"}]}' > "$out/summary.json"
  echo "result    request unanswered, exit 6"
  exit 6 ;;
esac
`
	os.WriteFile(filepath.Join(stubs, "fenzi"), []byte(fenzi), 0o755)
	os.WriteFile(filepath.Join(stubs, "docker"), []byte("#!/bin/sh\n"), 0o755)

	git := func(dir string, args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_AUTHOR_NAME=a", "GIT_AUTHOR_EMAIL=a@b", "GIT_COMMITTER_NAME=a", "GIT_COMMITTER_EMAIL=a@b")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
	}
	src := filepath.Join(tmp, "src")
	os.MkdirAll(src, 0o755)
	git(src, "init", "-q")
	for _, c := range []string{"one", "two"} {
		os.WriteFile(filepath.Join(src, "f"), []byte(c), 0o644)
		git(src, "add", "f")
		git(src, "commit", "-qm", c)
	}
	project := filepath.Join(tmp, "project")
	if out, err := exec.Command("git", "clone", "-q", "--depth", "1", "file://"+src, project).CombinedOutput(); err != nil {
		t.Fatalf("clone: %v %s", err, out)
	}
	runnerTemp := filepath.Join(tmp, "runner")
	os.MkdirAll(runnerTemp, 0o755)
	output, summary, path := filepath.Join(tmp, "output"), filepath.Join(tmp, "summary"), filepath.Join(tmp, "path")

	cmd := exec.Command(filepath.Join(here, "run.sh"))
	cmd.Dir = project
	cmd.Env = append(os.Environ(),
		"PATH="+stubs+string(os.PathListSeparator)+os.Getenv("PATH"),
		"RUNNER_TEMP="+runnerTemp, "GITHUB_OUTPUT="+output, "GITHUB_STEP_SUMMARY="+summary, "GITHUB_PATH="+path,
		"GITHUB_ACTION_PATH="+here, "GITHUB_WORKSPACE="+project,
		"FENZI_ACTION_AGENT=claude", "FENZI_ACTION_TASK=- fix the test", "FENZI_ACTION_TIMEOUT=10m",
		"FENZI_ACTION_REQUEST_TIMEOUT=2m", "FENZI_ACTION_SERVER=https://team.example", "FENZI_ACTION_PATH="+filepath.Join(stubs, "fenzi"),
		"FENZI_TEAM_TOKEN=tok-secret",
	)
	log, err := cmd.CombinedOutput()
	if code := cmd.ProcessState.ExitCode(); code != 6 {
		t.Fatalf("exit %d (%v):\n%s", code, err, log)
	}
	if strings.Contains(string(log), "tok-secret") {
		t.Error("the token is in the log")
	}
	b, _ := os.ReadFile(calls)
	got := strings.Split(strings.TrimSpace(string(b)), "\n")
	want := []string{
		"fenzi version",
		"fenzi setup --runtime",
		"fenzi doctor",
		"fenzi login --token-stdin --server https://team.example",
		"fenzi run --headless --new --task " + filepath.Join(runnerTemp, "fenzi-task.md") + " --timeout 10m --out " + filepath.Join(runnerTemp, "fenzi-out") + " --request-timeout 2m claude",
		"fenzi logout",
	}
	if !slices.Equal(got, want) {
		t.Errorf("calls:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if tok, _ := os.ReadFile(tokenSeen); strings.TrimSpace(string(tok)) != "tok-secret" {
		t.Errorf("fenzi login read %q on standard input", tok)
	}
	if task, _ := os.ReadFile(filepath.Join(runnerTemp, "fenzi-out", "task-seen.md")); string(task) != "- fix the test\n" {
		t.Errorf("task = %q", task)
	}
	if shallow, _ := exec.Command("git", "-C", project, "rev-parse", "--is-shallow-repository").Output(); strings.TrimSpace(string(shallow)) != "false" {
		t.Error("the checkout is still shallow")
	}
	outs, _ := os.ReadFile(output)
	for _, w := range []string{"exit-status=6", "outcome=request unanswered", "branch=fenzi/project-1a2b", "refused=1", "out=" + filepath.Join(runnerTemp, "fenzi-out")} {
		if !strings.Contains(string(outs), w+"\n") {
			t.Errorf("missing %q in outputs:\n%s", w, outs)
		}
	}
	if s, _ := os.ReadFile(summary); !strings.Contains(string(s), "### fenzi run: Claude Code request unanswered") {
		t.Errorf("job summary:\n%s", s)
	}
	if _, err := os.Stat(filepath.Join(runnerTemp, "fenzi-out", "run.log")); err != nil {
		t.Error("run.log was not kept")
	}
}
