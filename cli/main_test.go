package main

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
)

func TestParseInterspersed(t *testing.T) {
	fs := newFlags("deny", &bytes.Buffer{})
	reason := fs.String("reason", "", "")
	sandbox := fs.String("sandbox", "", "")
	pos, err := parse(fs, []string{"7f3a", "--reason", "use the vendored copy", "--sandbox", "fenzi-x", "--", "--not-a-flag"})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(pos, []string{"7f3a", "--not-a-flag"}) || *reason != "use the vendored copy" || *sandbox != "fenzi-x" {
		t.Fatalf("pos=%v reason=%q sandbox=%q", pos, *reason, *sandbox)
	}
}

func TestExitCodes(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := cli([]string{"nope"}, strings.NewReader(""), &out, &errOut); code != 1 {
		t.Errorf("unknown command exit = %d", code)
	}
	if code := cli([]string{"login", "--server", "http://127.0.0.1:1"}, strings.NewReader(""), &out, &errOut); code != 1 {
		t.Errorf("login with no server exit = %d, stderr %q", code, errOut.String())
	}
	if code := cli([]string{"deny", "x"}, strings.NewReader(""), &out, &errOut); code != 1 {
		t.Errorf("deny without --reason exit = %d", code)
	}
}

func TestUnknownCommandSuggests(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := cli([]string{"stauts"}, strings.NewReader(""), &out, &errOut); code != 1 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(errOut.String(), "Did you mean fenzi status?") {
		t.Errorf("no suggestion: %q", errOut.String())
	}
	if suggest("zzzzzzzz", map[string]func(env, []string) (int, error){"run": nil}) != "" {
		t.Error("suggested a command for nonsense")
	}
}

func TestSubcommandHelp(t *testing.T) {
	for _, args := range [][]string{{"policy"}, {"key"}} {
		var out, errOut bytes.Buffer
		if code := cli(args, strings.NewReader(""), &out, &errOut); code != 0 {
			t.Fatalf("%v: exit %d, %s", args, code, errOut.String())
		}
		if !strings.Contains(out.String(), "fenzi "+args[0]+" ") {
			t.Errorf("%v printed:\n%s", args, out.String())
		}
	}
	var out, errOut bytes.Buffer
	if code := cli([]string{"key", "rotate"}, strings.NewReader(""), &out, &errOut); code != 1 {
		t.Errorf("unknown key command exit %d", code)
	}
}

func TestHelpListsConnect(t *testing.T) {
	var out bytes.Buffer
	writeHelp(&out)
	for _, want := range []string{"connect", "setup", "rm", "Exit codes"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("help is missing %q", want)
		}
	}
	if strings.Contains(out.String(), "\x1b") {
		t.Error("help has escape codes when not on a terminal")
	}
}

func TestRunArgs(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	cases := map[string][]string{
		"":                   {"claude"},
		"codex":              {"codex"},
		"claude --resume":    {"claude", "--resume"},
		"claude -- --resume": {"claude", "--resume"},
		"--resume":           {"claude", "--resume"},
	}
	for in, want := range cases {
		if got := runArgs(strings.Fields(in)); !reflect.DeepEqual(got, want) {
			t.Errorf("%q: got %v, want %v", in, got, want)
		}
	}
}

func TestRunFlagAfterAgent(t *testing.T) {
	cases := map[string]string{
		"":                                  "",
		"claude":                            "",
		"claude --resume":                   "",
		"claude --permission-mode auto":     "",
		"claude --headless --task-text fix": "--headless",
		"claude --resume --rm":              "--rm",
		"codex --task-text=fix":             "--task-text",
		"claude -- --headless":              "",
		"claude --resume -- --rm":           "",
		"--headless":                        "",
	}
	for in, want := range cases {
		if got := runFlagAfterAgent(strings.Fields(in)); got != want {
			t.Errorf("%q: got %q, want %q", in, got, want)
		}
	}
}

func TestRunRefusesItsFlagAfterTheAgent(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	var out, errOut bytes.Buffer
	code := cli([]string{"run", "claude", "--headless", "--task-text", "fix it"}, strings.NewReader(""), &out, &errOut)
	if code != 1 || !strings.Contains(errOut.String(), "Put it before the name: fenzi run --headless ... claude") {
		t.Fatalf("exit %d: %s%s", code, out.String(), errOut.String())
	}
}

func TestSplitDash(t *testing.T) {
	before, after := splitDash([]string{"fenzi-web-1a2b", "--shell", "--", "--resume"})
	if !reflect.DeepEqual(before, []string{"fenzi-web-1a2b", "--shell"}) || !reflect.DeepEqual(after, []string{"--resume"}) {
		t.Fatalf("before %v after %v", before, after)
	}
}

func TestPolicyCompile(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := cli([]string{"policy", "compile", "--agent", "claude"}, strings.NewReader(""), &out, &errOut); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	for _, want := range []string{"include_workdir: false", "compatibility: hard_requirement", "enforcement: enforce", "access: read-only"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("compiled policy is missing %q", want)
		}
	}
}
