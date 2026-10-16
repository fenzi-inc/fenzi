package agents

import (
	"errors"
	"os"
	"path"
	"reflect"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"fenzi/compiler"
	"fenzi/policies"
)

func TestCatalog(t *testing.T) {
	all, err := All()
	if err != nil {
		t.Fatal(err)
	}
	if len(all) == 0 {
		t.Fatal("empty catalog")
	}
	for _, e := range all {
		t.Run(e.Name, func(t *testing.T) {
			df, err := e.Dockerfile()
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(df), e.Version) {
				t.Errorf("Dockerfile does not pin version %s from agent.yaml", e.Version)
			}
			if e.Verified {
				t.Error("no agent is verified until a full run with a real key passes on macOS and Linux")
			}
			if _, err := compiler.Compile(policies.DeveloperDefault(), compiler.Target{Agent: e.CompilerAgent()}); err != nil {
				t.Errorf("developer-default does not compile for %s: %v", e.Name, err)
			}
		})
	}
}

// profile is the part of an OpenShell provider profile the catalog mirrors.
type profile struct {
	ID        string     `yaml:"id"`
	Endpoints []Endpoint `yaml:"endpoints"`
	Binaries  []string   `yaml:"binaries"`
}

// The boundary is built from agent.yaml, and the effective policy from the
// profile. If they drift apart, the check after sandbox create fails.
func TestProfileMatchesManifest(t *testing.T) {
	all, err := All()
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range all {
		t.Run(e.Name, func(t *testing.T) {
			raw, err := e.Profile()
			if errors.Is(err, ErrNoProfile) {
				t.Skip("no reviewed profile yet")
			}
			if err != nil {
				t.Fatal(err)
			}
			var p profile
			if err := yaml.Unmarshal(raw, &p); err != nil {
				t.Fatal(err)
			}
			if p.ID != e.Key.ProfileType {
				t.Errorf("profile id %q, agent.yaml profile_type %q", p.ID, e.Key.ProfileType)
			}
			if !reflect.DeepEqual(p.Endpoints, e.Model) {
				t.Errorf("profile endpoints %+v, agent.yaml model %+v", p.Endpoints, e.Model)
			}
			if !reflect.DeepEqual(p.Binaries, e.Binaries) {
				t.Errorf("profile binaries %v, agent.yaml binaries %v", p.Binaries, e.Binaries)
			}
		})
	}
}

func TestMissingProfileFile(t *testing.T) {
	e := Entry{Name: "opencode", Key: Key{ProfileFile: "missing.yaml"}}
	if _, err := e.Profile(); !errors.Is(err, ErrNoProfile) {
		t.Fatalf("a catalog entry whose profile file is absent must return ErrNoProfile, got %v", err)
	}
}

func TestArgv(t *testing.T) {
	claude := Entry{Command: "claude", GuideFlag: "--append-system-prompt"}
	if got := claude.Argv([]string{"-p", "hi"}); !reflect.DeepEqual(got, []string{"claude", "--append-system-prompt", Guide, "-p", "hi"}) {
		t.Errorf("guide flag: %q", got)
	}
	codex := Entry{Command: "codex", Args: []string{"--no-daemon"}, GuideConfig: "developer_instructions"}
	got := codex.Argv([]string{"exec", "hi"})
	if len(got) != 6 || got[0] != "codex" || got[1] != "--no-daemon" || got[2] != "-c" || got[4] != "exec" || got[5] != "hi" {
		t.Fatalf("guide config: %q", got)
	}
	if want := "developer_instructions=" + tomlString(Guide); got[3] != want {
		t.Errorf("guide config value %q, want %q", got[3], want)
	}
	if (Entry{Command: "opencode"}).HasGuide() {
		t.Error("an entry without guide_flag, guide_config, or guide_file has no guide")
	}
	file := Entry{Command: "opencode", GuideFile: "/sandbox/.fenzi/guide.md"}
	if !file.HasGuide() {
		t.Error("guide_file means the guide is passed")
	}
	if got := file.Argv([]string{"run", "hi"}); !reflect.DeepEqual(got, []string{"opencode", "run", "hi"}) {
		t.Errorf("guide_file must not add arguments, got %q", got)
	}
}

func TestDefaultFlags(t *testing.T) {
	claude, err := Get("claude")
	if err != nil {
		t.Fatal(err)
	}
	if got := claude.CommandLine(nil); !reflect.DeepEqual(got, []string{"claude", "--permission-mode", "manual"}) {
		t.Errorf("default: %q", got)
	}
	for _, args := range [][]string{{"--permission-mode", "auto"}, {"--permission-mode=auto"}} {
		got := claude.Argv(args)
		n := 0
		for _, a := range got {
			if strings.HasPrefix(a, "--permission-mode") {
				n++
			}
		}
		if n != 1 || got[len(got)-1] != args[len(args)-1] {
			t.Errorf("%q: the user's mode must replace the default, got %q", args, got)
		}
	}
	if claude.StartNote == "" {
		t.Error("claude needs the note about the API key prompt")
	}
}

func TestTOMLString(t *testing.T) {
	for in, want := range map[string]string{
		`plain`:           `"plain"`,
		`say "hi"`:        `"say \"hi\""`,
		`C:\dir`:          `"C:\\dir"`,
		"two\nlines\tok":  `"two\nlines\tok"`,
		"bell\x07":        `"bell\u0007"`,
		"café {\"a\": 1}": `"café {\"a\": 1}"`,
	} {
		if got := tomlString(in); got != want {
			t.Errorf("tomlString(%q) = %s, want %s", in, got, want)
		}
	}
	if q := tomlString(Guide); strings.Contains(q, "\n") {
		t.Error("the guide must stay on one line as a TOML basic string")
	}
}

func TestUnknownAgent(t *testing.T) {
	if _, err := Get("cursor-app"); err == nil {
		t.Fatal("expected an error for an agent not in the catalog")
	}
}

func TestBinaryArch(t *testing.T) {
	for p, want := range map[string]string{
		"/usr/local/lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe":                                                         "",
		"/usr/local/lib/node_modules/@openai/codex/node_modules/@openai/codex-linux-arm64/vendor/aarch64-unknown-linux-musl/bin/codex": "arm64",
		"/usr/local/lib/node_modules/@openai/codex/node_modules/@openai/codex-linux-x64/vendor/x86_64-unknown-linux-musl/bin/codex":    "amd64",
		"/opt/tool-amd64/bin/tool":        "amd64",
		"/opt/x64tool/bin/tool":           "",
		"/opt/tool/bin/tool.aarch64":      "arm64",
		"/usr/local/bin/sixty-four-tools": "",
	} {
		got, err := BinaryArch(p)
		if err != nil || got != want {
			t.Errorf("BinaryArch(%q) = %q, %v; want %q", p, got, err, want)
		}
	}
	if _, err := BinaryArch("/opt/tool-arm64/x86_64/bin/tool"); err == nil {
		t.Error("a path that names two processors must be refused")
	}
}

func TestBinariesFor(t *testing.T) {
	codex, err := Get("codex")
	if err != nil {
		t.Fatal(err)
	}
	for _, arch := range Arches {
		got, err := codex.BinariesFor(arch)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 {
			t.Fatalf("codex %s: want the one native program, got %q", arch, got)
		}
		if a, _ := BinaryArch(got[0]); a != arch {
			t.Errorf("codex %s: got the %s program %s", arch, a, got[0])
		}
	}
	if _, err := codex.BinariesFor("386"); err == nil {
		t.Error("expected an error for a processor images are not built for")
	}
}

// Every agent image must have at least one program to match on each
// processor, or the policy names nothing the sandbox can run there.
func TestBinariesPerArch(t *testing.T) {
	all, err := All()
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range all {
		for _, arch := range Arches {
			got, err := e.BinariesFor(arch)
			if err != nil {
				t.Errorf("%s %s: %v", e.Name, arch, err)
				continue
			}
			if len(got) == 0 {
				t.Errorf("%s: agent.yaml lists no binary for %s", e.Name, arch)
			}
			for _, b := range got {
				if !path.IsAbs(b) {
					t.Errorf("%s: binary %q is not an absolute path", e.Name, b)
				}
			}
		}
	}
}

// check-images.sh builds every folder that has an agent.yaml. The CLI only
// knows the folders embedded in the binary, so the two lists must agree.
func TestEveryFolderIsEmbedded(t *testing.T) {
	dirs, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	all, err := All()
	if err != nil {
		t.Fatal(err)
	}
	embedded := map[string]bool{}
	for _, e := range all {
		embedded[e.Name] = true
	}
	n := 0
	for _, d := range dirs {
		if !d.IsDir() {
			continue
		}
		_, yamlErr := os.Stat(path.Join(d.Name(), "agent.yaml"))
		_, dfErr := os.Stat(path.Join(d.Name(), "Dockerfile"))
		if yamlErr != nil && dfErr != nil {
			continue
		}
		n++
		if yamlErr != nil || dfErr != nil {
			t.Errorf("agents/%s needs both agent.yaml and Dockerfile", d.Name())
		}
		if !embedded[d.Name()] {
			t.Errorf("agents/%s is not in the go:embed list in agents.go", d.Name())
		}
	}
	if n != len(all) {
		t.Errorf("%d agent folders on disk, %d in the catalog", n, len(all))
	}
}
