// Package agents is the catalog of agents the CLI can start: how to build each
// image, which programs open connections, and which key and profile it uses.
package agents

import (
	"bytes"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"slices"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"

	"fenzi/compiler"
)

//go:embed claude codex grok opencode
var files embed.FS

// Guide tells the agent how to ask for network access through OpenShell's
// policy advisor API. OpenShell 0.1.2 did not install its own guide in the
// sandbox, and a refused connection carries no hint.
//
//go:embed guide.md
var Guide string

// HistoryNote and FilesNote tell the agent what the project folder is: a
// copy of the developer's repository on a branch of its own, or a copy of
// the files with no history. HistoryNote takes the agent's branch, the
// start commit, and the developer's branch. run adds the one that applies
// to the guide with WithNote.
//
//go:embed history.md
var HistoryNote string

//go:embed files.md
var FilesNote string

type Entry struct {
	Name     string     `yaml:"name"`
	Display  string     `yaml:"display"`
	Command  string     `yaml:"command"`
	Image    string     `yaml:"image"`
	Version  string     `yaml:"version"`
	Binaries []string   `yaml:"binaries"`
	Model    []Endpoint `yaml:"model"`
	// Hosts the agent needs to start that are not model endpoints. They get a
	// rule for the agent's binaries, read-only unless allow lists more, and
	// never receive the key.
	Hosts []Host `yaml:"hosts"`
	// Env is passed with `sandbox exec --env`. Non-secret values only.
	Env map[string]string `yaml:"env"`
	// Args go before the guide and the user's arguments. Non-secret values only.
	Args []string `yaml:"args"`
	// DefaultFlags are added after Args unless the user passes the same flag.
	DefaultFlags map[string]string `yaml:"default_flags"`
	// StartNote is printed just before the agent starts.
	StartNote string `yaml:"start_note"`
	// MCPFormat is how the agent reads MCP servers Fenzi gives it: one of
	// the MCP* constants. Empty means the agent takes none yet.
	MCPFormat string `yaml:"mcp_format"`
	// SignInNote is set for an agent that can start with no key stored and
	// sign in itself. run then creates the sandbox without a provider and
	// prints this note instead of StartNote.
	SignInNote string `yaml:"sign_in_note"`
	// SignedIn is set by run for a sandbox started without a provider, never
	// by the catalog. CompilerAgent then compiles the model endpoints into
	// the policy, since no provider adds them.
	SignedIn bool `yaml:"-"`
	// Notes are added by run after the guide, for this sandbox only: what
	// the project folder is, see HistoryNote. Never set by the catalog.
	Notes []string `yaml:"-"`
	// GuideFlag is the agent's flag that appends text to its instructions.
	// GuideConfig is the config key that does it, for agents that take
	// `-c key=<TOML value>` instead. GuideFile is a path in the sandbox where
	// run writes the guide, for agents that read instruction files. With none
	// of them, the agent is not told about policy.local.
	GuideFlag string `yaml:"guide_flag"`
	// Resume goes right after the command when fenzi connect opens the agent
	// again, so it continues its last session in the project folder.
	Resume []string `yaml:"resume"`
	// ResumeWhen is a shell test, run in the project folder in the sandbox,
	// that succeeds when the agent has a session there to resume. Without
	// it, fenzi connect tries Resume and starts a new session when that
	// fails at once.
	ResumeWhen  string `yaml:"resume_when"`
	GuideConfig string `yaml:"guide_config"`
	GuideFile   string `yaml:"guide_file"`
	// Headless is how the agent takes a task with nobody at the terminal,
	// for fenzi run --headless. Nil: the catalog does not say yet.
	Headless *Headless `yaml:"headless"`
	Key      Key       `yaml:"key"`
	Status   string    `yaml:"status"`
	Verified bool      `yaml:"verified"`
}

// Endpoint is a model endpoint, copied from the reviewed provider profile.
type Endpoint struct {
	Host        string `yaml:"host"`
	Port        int    `yaml:"port"`
	Protocol    string `yaml:"protocol,omitempty"`
	Access      string `yaml:"access,omitempty"`
	Enforcement string `yaml:"enforcement,omitempty"`
}

// Host is a host the agent needs that is not a model endpoint. Allow takes
// "METHOD /path" lines, as a policy document's hosts do; empty is read-only.
type Host struct {
	Host  string   `yaml:"host"`
	Port  int      `yaml:"port"`
	Allow []string `yaml:"allow,omitempty"`
}

// Headless is the agent's own non-interactive mode.
type Headless struct {
	// Args go after the command, Args and the flags, before the guide: a
	// subcommand such as Codex's exec, which must follow its top-level
	// options, or a switch such as Claude Code's -p.
	Args []string `yaml:"args"`
	// Flags replace or add to DefaultFlags for an unattended run, unless
	// the user passes the same flag.
	Flags map[string]string `yaml:"flags"`
	// TaskFlag is the flag that takes the task, passed as --flag=<task>.
	// Empty: the task is the last argument.
	TaskFlag string `yaml:"task_flag"`
	// Refused says why the agent cannot run unattended. Set it alone.
	Refused string `yaml:"refused"`
}

func (h *Headless) check() error {
	if h == nil {
		return nil
	}
	mode := len(h.Args) > 0 || len(h.Flags) > 0 || h.TaskFlag != ""
	if mode == (h.Refused != "") {
		return errors.New("headless needs args, flags or task_flag, or refused alone")
	}
	if h.TaskFlag != "" && !strings.HasPrefix(h.TaskFlag, "--") {
		return errors.New("headless task_flag must be a long flag, passed as --flag=<task>")
	}
	return nil
}

type Key struct {
	Env         string `yaml:"env"`
	ProfileType string `yaml:"profile_type"`
	ProfileFile string `yaml:"profile_file"`
}

// ErrNoProfile means the reviewed provider profile for an agent is not in
// the catalog yet.
var ErrNoProfile = errors.New("provider profile not reviewed yet")

// All returns every catalog entry, sorted by name.
func All() ([]Entry, error) {
	dirs, err := fs.ReadDir(files, ".")
	if err != nil {
		return nil, err
	}
	var out []Entry
	for _, d := range dirs {
		if !d.IsDir() {
			continue
		}
		e, err := load(d.Name())
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// Get returns one entry by name.
func Get(name string) (Entry, error) {
	if _, err := fs.Stat(files, path.Join(name, "agent.yaml")); err != nil {
		return Entry{}, fmt.Errorf("agent %q is not in the catalog; run fenzi agents to list them", name)
	}
	return load(name)
}

func load(dir string) (Entry, error) {
	raw, err := files.ReadFile(path.Join(dir, "agent.yaml"))
	if err != nil {
		return Entry{}, err
	}
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	var e Entry
	if err := dec.Decode(&e); err != nil {
		return Entry{}, fmt.Errorf("catalog %s/agent.yaml: %w", dir, err)
	}
	if e.Name != dir {
		return Entry{}, fmt.Errorf("catalog %s/agent.yaml: name %q does not match its folder", dir, e.Name)
	}
	if e.GuideFlag != "" && e.GuideConfig != "" {
		return Entry{}, fmt.Errorf("catalog %s/agent.yaml: set guide_flag or guide_config, not both", dir)
	}
	if e.GuideFile != "" && (!path.IsAbs(e.GuideFile) || strings.Contains(e.GuideFile, "..")) {
		return Entry{}, fmt.Errorf("catalog %s/agent.yaml: guide_file must be an absolute path", dir)
	}
	if err := e.Headless.check(); err != nil {
		return Entry{}, fmt.Errorf("catalog %s/agent.yaml: %w", dir, err)
	}
	return e, nil
}

// Argv is the command started in the sandbox: the agent, its fixed
// arguments, the guide, then the user's arguments.
func (e Entry) Argv(args []string) []string {
	argv := e.head(args)
	switch {
	case e.GuideFlag != "":
		argv = append(argv, e.GuideFlag, e.GuideText())
	case e.GuideConfig != "":
		argv = append(argv, "-c", e.GuideConfig+"="+tomlString(e.GuideText()))
	}
	return append(argv, args...)
}

// GuideText is the guide with the sandbox's notes after it: what the agent
// is told, through GuideFlag, GuideConfig, or the file at GuideFile. With no
// notes it is Guide as it is.
func (e Entry) GuideText() string {
	text := Guide
	for _, n := range e.Notes {
		text += "\n" + n + "\n"
	}
	return text
}

// WithNote returns the entry with one more note for the agent.
func (e Entry) WithNote(text string) Entry {
	e.Notes = append(append([]string(nil), e.Notes...), strings.TrimSpace(text))
	return e
}

// ResumeArgv is Argv with Resume right after the command, or nil for an
// agent with no way to resume.
func (e Entry) ResumeArgv(args []string) []string {
	if len(e.Resume) == 0 {
		return nil
	}
	argv := e.Argv(args)
	return append(append([]string{argv[0]}, e.Resume...), argv[1:]...)
}

// CommandLine is Argv without the guide text, for showing what starts.
func (e Entry) CommandLine(args []string) []string {
	return append(e.head(args), args...)
}

// head is the command, Args, and the default flags the user did not pass.
func (e Entry) head(args []string) []string {
	return e.headWith(e.DefaultFlags, args)
}

// headWith is head with flags in place of the default flags.
func (e Entry) headWith(defaults map[string]string, args []string) []string {
	argv := append([]string{e.Command}, e.Args...)
	flags := make([]string, 0, len(defaults))
	for f := range defaults {
		flags = append(flags, f)
	}
	sort.Strings(flags)
	for _, f := range flags {
		if !hasFlag(args, f) {
			argv = append(argv, f, defaults[f])
		}
	}
	return argv
}

// MaxTask is the longest task fenzi run --headless passes. It goes to the
// agent as one argument, and Linux takes at most 128 KiB in one.
const MaxTask = 64 << 10

// ErrNoHeadless means the catalog has no non-interactive mode for the agent.
var ErrNoHeadless = errors.New("cannot run unattended")

// CanRunHeadless returns nil when the agent has a non-interactive mode, and
// otherwise an error that says why not.
func (e Entry) CanRunHeadless() error {
	switch {
	case e.Headless == nil:
		return fmt.Errorf("%s %w: the catalog does not name its non-interactive mode yet", e.Display, ErrNoHeadless)
	case e.Headless.Refused != "":
		return fmt.Errorf("%s %w: %s", e.Display, ErrNoHeadless, e.Headless.Refused)
	}
	return nil
}

// HeadlessArgv is Argv for an unattended run: the command, Args, the
// default flags with Headless.Flags over them, Headless.Args, the guide,
// the user's arguments, then the task, as the last argument or as the
// value of TaskFlag.
func (e Entry) HeadlessArgv(args []string, task string) ([]string, error) {
	if err := e.CanRunHeadless(); err != nil {
		return nil, err
	}
	task, err := CleanTask(task)
	if err != nil {
		return nil, err
	}
	argv := append(e.headlessHead(args), e.Headless.Args...)
	switch {
	case e.GuideFlag != "":
		argv = append(argv, e.GuideFlag, e.GuideText())
	case e.GuideConfig != "":
		argv = append(argv, "-c", e.GuideConfig+"="+tomlString(e.GuideText()))
	}
	argv = append(argv, args...)
	if e.Headless.TaskFlag != "" {
		return append(argv, e.Headless.TaskFlag+"="+task), nil
	}
	return append(argv, task), nil
}

// HeadlessCommandLine is HeadlessArgv without the guide, and with the
// task's length in place of the task, for showing what starts.
func (e Entry) HeadlessCommandLine(args []string, task string) []string {
	argv := append(e.headlessHead(args), e.Headless.Args...)
	argv = append(argv, args...)
	shown := fmt.Sprintf("<task, %d characters>", len([]rune(strings.TrimSpace(task))))
	if e.Headless.TaskFlag != "" {
		return append(argv, e.Headless.TaskFlag+"="+shown)
	}
	return append(argv, shown)
}

func (e Entry) headlessHead(args []string) []string {
	flags := map[string]string{}
	for f, v := range e.DefaultFlags {
		flags[f] = v
	}
	for f, v := range e.Headless.Flags {
		flags[f] = v
	}
	return e.headWith(flags, args)
}

// CleanTask trims the task and checks it can be passed as one argument. A
// task that starts with a dash, such as a Markdown list, gets a newline in
// front, so the agent does not read it as a flag.
func CleanTask(task string) (string, error) {
	task = strings.TrimSpace(task)
	switch {
	case task == "":
		return "", errors.New("the task is empty")
	case len(task) > MaxTask:
		return "", fmt.Errorf("the task is %d KiB; at most %d KiB is passed to the agent", (len(task)+1023)>>10, MaxTask>>10)
	case strings.ContainsRune(task, 0):
		return "", errors.New("the task holds a NUL byte, which cannot be passed as an argument")
	case strings.HasPrefix(task, "-"):
		task = "\n" + task
	}
	return task, nil
}

func hasFlag(args []string, flag string) bool {
	for _, a := range args {
		if a == flag || strings.HasPrefix(a, flag+"=") {
			return true
		}
	}
	return false
}

// HasGuide reports whether the guide is passed to the agent.
func (e Entry) HasGuide() bool {
	return e.GuideFlag != "" || e.GuideConfig != "" || e.GuideFile != ""
}

// tomlString quotes s as a TOML basic string.
func tomlString(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"':
			b.WriteString(`\"`)
		case r == '\\':
			b.WriteString(`\\`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\t':
			b.WriteString(`\t`)
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&b, `\u%04X`, r)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// Arches are the processors an agent image is built for, as GOARCH and
// Docker platform names use them.
var Arches = []string{"amd64", "arm64"}

// archNames are the spellings packages use in file and folder names.
var archNames = map[string]string{
	"amd64":   "amd64",
	"x64":     "amd64",
	"x86_64":  "amd64",
	"arm64":   "arm64",
	"aarch64": "arm64",
}

// BinaryArch returns the processor a binary path is built for, or "" when the
// path names none and so is the same in every image. A path names a
// processor when one of its folder or file names has a part such as
// "aarch64" or "x64" between dashes or dots.
func BinaryArch(p string) (string, error) {
	found := ""
	for _, elem := range strings.Split(p, "/") {
		for _, part := range strings.FieldsFunc(elem, func(r rune) bool { return r == '-' || r == '.' }) {
			a, ok := archNames[part]
			if !ok {
				continue
			}
			if found != "" && found != a {
				return "", fmt.Errorf("%s names both %s and %s", p, found, a)
			}
			found = a
		}
	}
	return found, nil
}

// BinariesFor returns the binaries an image built for arch must contain:
// the paths that name that processor and the paths that name none. Codex
// lists one native program per processor, and an image has only its own.
func (e Entry) BinariesFor(arch string) ([]string, error) {
	if !slices.Contains(Arches, arch) {
		return nil, fmt.Errorf("unknown processor %q; use %s", arch, strings.Join(Arches, " or "))
	}
	var out []string
	for _, b := range e.Binaries {
		a, err := BinaryArch(b)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", e.Name, err)
		}
		if a == "" || a == arch {
			out = append(out, b)
		}
	}
	return out, nil
}

// Tag is the local image tag for the pinned version.
func (e Entry) Tag() string { return e.Image + ":" + e.Version }

// Dockerfile returns the build recipe for the agent's image.
func (e Entry) Dockerfile() ([]byte, error) {
	return files.ReadFile(path.Join(e.Name, "Dockerfile"))
}

// Profile returns the reviewed provider profile to import into the gateway.
func (e Entry) Profile() ([]byte, error) {
	if e.Key.ProfileFile == "" {
		return nil, fmt.Errorf("%s: %w", e.Name, ErrNoProfile)
	}
	b, err := files.ReadFile(path.Join(e.Name, e.Key.ProfileFile))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%s: %w (agents/%s/%s is added once the upstream profile is reviewed)", e.Name, ErrNoProfile, e.Name, e.Key.ProfileFile)
	}
	return b, err
}

// CanSignIn reports whether the agent can start with no key stored.
func (e Entry) CanSignIn() bool { return e.SignInNote != "" }

// CompilerAgent is the part of the entry the policy compiler needs.
func (e Entry) CompilerAgent() compiler.Agent {
	a := compiler.Agent{Name: e.Name, Binaries: append([]string(nil), e.Binaries...), ModelInPolicy: e.SignedIn}
	for _, m := range e.Model {
		a.Model = append(a.Model, compiler.ModelEndpoint{Host: m.Host, Port: m.Port, Protocol: m.Protocol, Access: m.Access, Enforcement: m.Enforcement})
	}
	for _, h := range e.Hosts {
		a.Hosts = append(a.Hosts, compiler.AgentHost{Host: h.Host, Port: h.Port, Allow: append([]string(nil), h.Allow...)})
	}
	return a
}
