// Package run implements `fenzi run`.
package run

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"fenzi/agents"
	"fenzi/cli/internal/config"
	"fenzi/cli/internal/openshell"
	"fenzi/cli/internal/screen"
	"fenzi/cli/internal/workspace"
	"fenzi/compiler"
)

// PolicyError means the prover did not return within_boundary. Nothing starts.
type PolicyError struct {
	Stage  string
	Result openshell.Result
}

func (e *PolicyError) Error() string {
	msg := fmt.Sprintf("policy check (%s): %s", e.Stage, e.Result.Result)
	if ex := e.Result.Example(); ex != "" {
		msg += "\n  example: " + ex
	}
	if e.Result.Reason != "" {
		msg += "\n  reason:  " + e.Result.Reason
	}
	if missing := e.Result.MissingDomains(); e.Result.Result == openshell.WithinBoundary && len(missing) > 0 {
		msg += "\n  the prover did not cover: " + strings.Join(missing, ", ")
	}
	return msg
}

// GatewayError means OpenShell is missing or not connected.
type GatewayError struct{ Err error }

func (e *GatewayError) Error() string {
	return "OpenShell gateway is not ready: " + e.Err.Error() + "\n  run fenzi doctor"
}
func (e *GatewayError) Unwrap() error { return e.Err }

type Images interface {
	Exists(ctx context.Context, tag string) bool
	Build(ctx context.Context, tag string, dockerfile []byte) error
}

type Deps struct {
	OpenShell openshell.Client
	Prover    openshell.Prover
	Images    Images
	Dirs      config.Dirs
	Out       io.Writer
	Getenv    func(string) string
	Now       func() time.Time
	// Filter decides which project files count; GitFilter in production.
	Filter func(root string) workspace.Filter
	// Sleep waits between log polls; time.Sleep when nil.
	Sleep func(time.Duration)
}

type Options struct {
	Agent    agents.Entry
	Profile  []byte
	Args     []string
	Repo     string
	Policy   Resolved
	Name     string
	Keep     bool
	NoUpload bool
	// SignIn starts the agent without the stored key, so it signs in
	// itself. Only for an agent that can (Entry.CanSignIn).
	SignIn bool
	// OnExit runs after the log is saved and the changes are staged, when
	// Keep is false. Returning true leaves the sandbox running. Nil deletes
	// it, which is what a script does.
	OnExit func(name string) (keep bool, err error)
	// ConfirmSecrets runs after the warning about files that look like
	// secrets, before anything is built or created. Returning false stops the
	// run with ErrSecretsDeclined. Nil continues, which is what a script does.
	ConfirmSecrets func(files []string) (bool, error)
}

// ErrSecretsDeclined means the person chose not to copy files that look like
// secrets. Nothing was built or created.
var ErrSecretsDeclined = errors.New("stopped before the copy; nothing was created")

// shownSecrets is how many secret-looking files the warning names.
const shownSecrets = 10

type Result struct {
	Sandbox  string
	ExitCode int
	Changes  []workspace.Change
	Staging  string
	Kept     bool
}

// Settings turned on for every sandbox Fenzi creates.
var sandboxSettings = [][2]string{
	{"ocsf_json_enabled", "true"},
	{"agent_policy_proposals_enabled", "true"},
}

func settingKeys() []string {
	keys := make([]string, len(sandboxSettings))
	for i, kv := range sandboxSettings {
		keys[i] = kv[0]
	}
	return keys
}

// SettingConflicts lists gateway-wide settings that would make run fail,
// mapped to the value the gateway sets.
func SettingConflicts(ctx context.Context, oc openshell.Client) (map[string]string, error) {
	global, err := oc.GlobalSettings(ctx, settingKeys()...)
	if err != nil {
		return nil, err
	}
	return conflicts(global), nil
}

func conflicts(global map[string]string) map[string]string {
	bad := map[string]string{}
	for _, kv := range sandboxSettings {
		if g := global[kv[0]]; g != openshell.Unset && g != kv[1] {
			bad[kv[0]] = g
		}
	}
	return bad
}

// LogFile is the shorthand log saved for each run, read by `fenzi log`.
const LogFile = "sandbox.log"

// logLines is how many shorthand lines are saved when a run ends.
const logLines = 100000

// AgentFor returns the catalog entry of a sandbox's agent as the sandbox was
// started, so a policy compiled for it again keeps the model endpoints of a
// sandbox started without a provider.
func AgentFor(sb config.Sandbox) (agents.Entry, error) {
	e, err := agents.Get(sb.Agent)
	if err != nil {
		return agents.Entry{}, err
	}
	e.SignedIn = sb.SignIn
	return e, nil
}

// ensureProfile imports the agent's reviewed provider profile, or updates it
// when the catalog's copy changed.
func ensureProfile(ctx context.Context, d Deps, a agents.Entry, profile []byte, runDir string) error {
	pf := filepath.Join(runDir, "profile.yaml")
	if err := os.WriteFile(pf, profile, 0o600); err != nil {
		return err
	}
	return d.OpenShell.EnsureProfile(ctx, a.Key.ProfileType, pf)
}

// ProjectDir is where the project lives in the sandbox. An uploaded directory
// lands as <workdir>/<basename>. HOME is the workdir, so agent config
// such as ~/.claude stays outside the project and out of the diff.
func ProjectDir(repo string) string {
	return path.Join(compiler.DefaultWorkdir, filepath.Base(repo))
}

func Run(ctx context.Context, d Deps, o Options) (res Result, err error) {
	scr := screen.New(d.Out)
	say := func(label, format string, args ...any) {
		scr.Label(label, fmt.Sprintf(format, args...))
	}

	// 1. Check the machine.
	if err := d.OpenShell.Ready(ctx); err != nil {
		return res, &GatewayError{Err: err}
	}
	// A key the gateway sets for every sandbox cannot be set per sandbox
	// (OpenShell 0.1.2 says "managed globally"), so a different value there wins.
	global, err := d.OpenShell.GlobalSettings(ctx, settingKeys()...)
	if err != nil {
		return res, err
	}
	if bad := conflicts(global); len(bad) > 0 {
		keys := make([]string, 0, len(bad))
		for k, v := range bad {
			keys = append(keys, k+" to "+v)
		}
		sort.Strings(keys)
		return res, fmt.Errorf("the gateway sets %s for every sandbox, and Fenzi needs true; run fenzi doctor --fix", strings.Join(keys, " and "))
	}

	// 2. Resolve the agent and its key. The gateway is the source of truth
	// for a stored key, so a lost local state cannot skip or repeat it. With
	// none stored or exported, an agent that signs in itself starts without
	// a provider, and its model endpoints are compiled into the policy.
	a := o.Agent
	if a.Key.Env == "" {
		return res, fmt.Errorf("%s: the catalog does not name a model key for this agent yet", a.Name)
	}
	if len(o.Profile) == 0 {
		return res, fmt.Errorf("%s: %w", a.Name, agents.ErrNoProfile)
	}
	if o.SignIn && !a.CanSignIn() {
		return res, fmt.Errorf("%s does not sign in itself; it runs with a key (fenzi key set %s)", a.Display, a.Name)
	}
	provider := ProviderName(a)
	stored, err := d.OpenShell.ProviderExists(ctx, provider)
	if err != nil {
		return res, err
	}
	if o.SignIn {
		a.SignedIn = true
		provider = ""
	} else if !stored && d.Getenv(a.Key.Env) == "" {
		if !a.CanSignIn() {
			return res, fmt.Errorf("no key stored for %s; run fenzi key set %s, or export %s for this run. The key stays on this machine", a.Name, a.Name, a.Key.Env)
		}
		a.SignedIn = true
		provider = ""
	}

	name := o.Name
	if name == "" {
		name = SandboxName(o.Repo)
	}
	if len(name) > openshell.MaxSandboxName {
		return res, fmt.Errorf("sandbox name %q is %d characters; the runtime accepts at most %d", name, len(name), openshell.MaxSandboxName)
	}
	res.Sandbox = name
	runDir := d.Dirs.Run(name)
	res.Staging = d.Dirs.Staging(name)

	// 5 and 6. Resolve, compile, and prove the policy before anything is created.
	c, err := WriteCompiled(o.Policy, a, runDir)
	if err != nil {
		return res, err
	}
	say("policy", "%s, %s", o.Policy.Sources, c.Revision)
	if o.Policy.Boundary != nil {
		say("boundary", "%s", o.Policy.BoundarySource)
	}
	r, err := d.Prover.Check(ctx, c.ProvePolicy, c.ProveBoundary)
	if err != nil {
		return res, err
	}
	if !r.Passed() {
		return res, &PolicyError{Stage: "compiled policy", Result: r}
	}
	say("prover", "%s", r.Result)
	if c.MCP > 0 {
		say("mcp", "%s, rules checked by Fenzi, not by the prover", plural(c.MCP, "server"))
	}
	// Kept so fenzi policy apply can tell a host change from one that
	// needs a new sandbox.
	if err := SaveResolved(runDir, o.Policy.Doc); err != nil {
		return res, err
	}

	// Snapshot the project before upload, so changes can be compared later,
	// and warn about files that look like secrets while nothing is created.
	filter := d.Filter(o.Repo)
	base, err := workspace.Snapshot(o.Repo, filter)
	if err != nil {
		return res, err
	}
	if !o.NoUpload {
		if found := append(base.Secrets(), MCPConfigSecrets(o.Repo, base)...); len(found) > 0 {
			warnSecrets(say, found)
			if o.ConfirmSecrets != nil {
				ok, err := o.ConfirmSecrets(found)
				if err != nil {
					return res, err
				}
				if !ok {
					return res, ErrSecretsDeclined
				}
			}
		}
	}

	// 3. Ensure the image.
	if !d.Images.Exists(ctx, a.Tag()) {
		df, err := a.Dockerfile()
		if err != nil {
			return res, err
		}
		say("image", "%s, building on this machine", a.Tag())
		if err := d.Images.Build(ctx, a.Tag(), df); err != nil {
			return res, err
		}
	}
	say("image", "%s", a.Tag())

	// 4. Ensure the reviewed profile and the provider. The key is read by
	// openshell from this process's environment, once. A sandbox started
	// without a key needs neither.
	switch {
	case a.SignedIn && stored:
		say("key", "not used (--sign-in); %s signs in inside the sandbox", a.Display)
	case a.SignedIn:
		say("key", "none stored; %s signs in inside the sandbox", a.Display)
	case stored:
		if err := ensureProfile(ctx, d, a, o.Profile, runDir); err != nil {
			return res, err
		}
		say("key", "%s, already stored on this machine", provider)
	default:
		if err := ensureProfile(ctx, d, a, o.Profile, runDir); err != nil {
			return res, err
		}
		if err := d.OpenShell.ProviderCreate(ctx, provider, a.Key.ProfileType); err != nil {
			return res, err
		}
		say("key", "%s, created from %s", provider, a.Key.Env)
	}
	// MCP servers: their tokens are providers bound to their endpoints, and
	// the agent gets its own config for them.
	var mcpProviders []string
	var mcpFiles []agents.File
	if doc := o.Policy.Doc; doc != nil && len(doc.MCP) > 0 {
		if mcpProviders, err = MCPProviders(ctx, d.OpenShell, doc); err != nil {
			return res, err
		}
		if a, mcpFiles, err = a.WithMCP(doc); err != nil {
			return res, err
		}
		if line := mcpSummary(doc, a.Name); line != "" {
			say("mcp", "%s", line)
		}
		if len(doc.Secrets()) > 0 {
			say("secrets", "%s; the agent sees placeholders, bindings checked by Fenzi, not by the prover", secretSummary(doc))
		}
	}
	state, err := d.Dirs.LoadState()
	if err != nil {
		return res, err
	}
	if err := os.MkdirAll(res.Staging, 0o700); err != nil {
		return res, err
	}
	if err := base.Save(filepath.Join(res.Staging, "base.json")); err != nil {
		return res, err
	}

	// 7. Create the sandbox.
	labels := map[string]string{"fenzi": "1", "policy_rev": c.Revision, "agent": a.Name}
	if o.Policy.TeamRevision > 0 {
		labels["team_rev"] = strconv.Itoa(o.Policy.TeamRevision)
	}
	if _, err := d.OpenShell.SandboxCreate(ctx, openshell.CreateOptions{
		Name:      name,
		From:      a.Tag(),
		Policy:    c.Policy,
		Provider:  provider,
		Providers: mcpProviders,
		Labels:    labels,
	}); err != nil {
		return res, err
	}
	say("sandbox", "%s, created", name)
	sb := config.Sandbox{Name: name, Agent: a.Name, SignIn: a.SignedIn, Repo: o.Repo, Revision: c.Revision, TeamRevision: o.Policy.TeamRevision, Created: d.Now(), Running: true}
	state.Put(sb)
	_ = d.Dirs.SaveState(state)

	deleted := false
	defer func() {
		if err != nil && !o.Keep && !deleted {
			if derr := d.OpenShell.Delete(context.WithoutCancel(ctx), name); derr == nil {
				markStopped(d.Dirs, name)
				say("sandbox", "%s, deleted after the error", name)
			}
		}
	}()

	// 8. Prove the effective policy, which includes provider rules.
	eff, err := d.OpenShell.EffectivePolicy(ctx, name)
	if err != nil {
		return res, err
	}
	effPath := filepath.Join(runDir, "effective.yaml")
	if err := os.WriteFile(effPath, eff, 0o600); err != nil {
		return res, err
	}
	if compiler.UnprovableYAML(eff) {
		stripped, err := compiler.ForProverYAML(eff)
		if err != nil {
			return res, err
		}
		effPath = filepath.Join(runDir, "prove.effective.yaml")
		if err := os.WriteFile(effPath, stripped, 0o600); err != nil {
			return res, err
		}
	}
	r, err = d.Prover.Check(ctx, effPath, c.ProveBoundary)
	if err != nil {
		return res, err
	}
	if !r.Passed() {
		return res, &PolicyError{Stage: "effective policy with provider rules", Result: r}
	}

	// 9. Turn on JSON audit and agent proposals for this sandbox, unless the
	// gateway already turns them on for every sandbox.
	for _, kv := range sandboxSettings {
		if global[kv[0]] != openshell.Unset {
			continue
		}
		if err := d.OpenShell.SettingsSet(ctx, name, kv[0], kv[1]); err != nil {
			return res, err
		}
	}

	// 10. Copy the project in.
	project := ProjectDir(o.Repo)
	if o.NoUpload {
		if _, err := d.OpenShell.ExecOutput(ctx, name, "mkdir", "-p", project); err != nil {
			return res, err
		}
	} else {
		if err := d.OpenShell.Upload(ctx, name, o.Repo); err != nil {
			return res, err
		}
		say("upload", "project copied to %s, .gitignore respected, .git left out", project)
		// True only for a folder that does not hold the home folder; the
		// CLI refuses those, but this package does not assume it.
		if home, err := os.UserHomeDir(); err == nil && !workspace.ContainsHome(o.Repo, home) {
			say("", "your home directory is not copied")
		}
	}

	if !settingsLoaded(ctx, d, name) {
		say("settings", "waiting for the sandbox to load them")
		if !waitSettings(ctx, d, name) {
			say("", "not confirmed; the agent's first connections may reset once")
		}
	}

	// 11. Start the agent.
	if err := writeFiles(ctx, d, name, mcpFiles); err != nil {
		return res, err
	}
	if a.GuideFile != "" {
		if err := writeGuide(ctx, d, name, a.GuideFile); err != nil {
			return res, err
		}
	}
	if a.HasGuide() {
		say("guide", "how to ask for access, added to the agent's instructions")
	}
	say("start", "%s", strings.Join(a.CommandLine(o.Args), " "))
	note := a.StartNote
	if a.SignedIn {
		note = a.SignInNote
	}
	if note != "" {
		say("note", "%s", note)
	}
	execErr := d.OpenShell.Exec(ctx, name, project, a.Env, a.Argv(o.Args)...)
	if code := openshell.ExitCode(execErr); code >= 0 {
		res.ExitCode = code
	} else if execErr != nil {
		return res, execErr
	}
	say("agent", "exited")

	// 12. Save the log, stage the changes, delete the sandbox.
	if out, lerr := settledLog(ctx, d, name); lerr == nil {
		_ = os.WriteFile(filepath.Join(runDir, LogFile), out, 0o600)
		say("log", "saved, fenzi log")
	} else {
		say("log", "could not be saved: %v", lerr)
	}

	files := filepath.Join(res.Staging, "files")
	if err := os.RemoveAll(files); err != nil {
		return res, err
	}
	if derr := d.OpenShell.Download(ctx, name, project, files); derr != nil {
		o.Keep = true
		return res, fmt.Errorf("copying changes out of %s: %w; the sandbox is kept so the agent's work is not lost", name, derr)
	}
	res.Changes, err = workspace.Changes(base, files, filter)
	if err != nil {
		return res, err
	}
	if len(res.Changes) == 0 {
		say("changes", "none")
	} else {
		say("changes", "%d %s staged, not applied", len(res.Changes), files1(len(res.Changes)))
	}

	if !o.Keep && o.OnExit != nil {
		keep, err := o.OnExit(name)
		if err != nil {
			keep = true
		}
		o.Keep = keep
		if err != nil {
			res.Kept = true
			say("sandbox", "%s, kept", name)
			return res, err
		}
	}
	if o.Keep {
		res.Kept = true
		say("sandbox", "%s, kept", name)
	} else {
		if err := d.OpenShell.Delete(ctx, name); err != nil {
			return res, err
		}
		deleted = true
		markStopped(d.Dirs, name)
		dropEmptyStaging(d.Dirs, name)
		say("sandbox", "%s, deleted", name)
	}
	return res, nil
}

// writeGuide puts the request guide at dest, which is outside the project
// directory so it stays out of the diff. Agents that read instruction files
// (OpenCode's config `instructions`) are pointed at it.
func writeGuide(ctx context.Context, d Deps, sandbox, dest string) error {
	dest = path.Clean(dest)
	if !strings.HasPrefix(dest, compiler.DefaultWorkdir+"/") {
		return fmt.Errorf("guide file %q is outside the sandbox workdir", dest)
	}
	script := "import base64, pathlib\n" +
		"p = pathlib.Path(" + strconv.Quote(dest) + ")\n" +
		"p.parent.mkdir(parents=True, exist_ok=True)\n" +
		"p.write_bytes(base64.b64decode(" + strconv.Quote(base64.StdEncoding.EncodeToString([]byte(agents.Guide))) + "))\n"
	if _, err := d.OpenShell.ExecOutput(ctx, sandbox, "python3", "-c", script); err != nil {
		return fmt.Errorf("writing the request guide: %w", err)
	}
	return nil
}

// warnSecrets names files that look like secrets: the first shownSecrets,
// then how many more.
func warnSecrets(say func(label, format string, args ...any), found []string) {
	head, why := "%d files look like secrets and will be copied into the sandbox:", "They are copied because .gitignore does not exclude them. Add them to .gitignore to keep them out."
	if len(found) == 1 {
		head, why = "%d file looks like a secret and will be copied into the sandbox:", "It is copied because .gitignore does not exclude it. Add it to .gitignore to keep it out."
	}
	say("secrets", head, len(found))
	for i, f := range found {
		if i == shownSecrets {
			say("", "  and %d more", len(found)-shownSecrets)
			break
		}
		say("", "  %s", f)
	}
	say("", "%s", why)
}

func files1(n int) string {
	if n == 1 {
		return "file"
	}
	return "files"
}

// settingsApplied is what a 0.1.2 supervisor logs when its poll loads changed
// settings, about 10 seconds after `settings set`. Loading them closes open
// connections, so the agent starts after it.
const settingsApplied = "Settings poll: config change detected"

func settingsLoaded(ctx context.Context, d Deps, name string) bool {
	out, err := d.OpenShell.LogLines(ctx, name, 1000)
	return err == nil && bytes.Contains(out, []byte(settingsApplied))
}

func waitSettings(ctx context.Context, d Deps, name string) bool {
	sleep := d.Sleep
	if sleep == nil {
		sleep = time.Sleep
	}
	for i := 0; i < 30; i++ {
		sleep(time.Second)
		if settingsLoaded(ctx, d, name) {
			return true
		}
	}
	return false
}

// settledLog fetches the shorthand log once it stops growing. Supervisors
// ship lines to the gateway in batches; right after the agent exits, 0.1.2
// returned one line where a few seconds later there were dozens.
func settledLog(ctx context.Context, d Deps, name string) ([]byte, error) {
	sleep := d.Sleep
	if sleep == nil {
		sleep = time.Sleep
	}
	var last []byte
	stable := 0
	for i := 0; i < 15; i++ {
		out, err := d.OpenShell.LogLines(ctx, name, logLines)
		if err != nil {
			return nil, err
		}
		if len(out) == len(last) {
			stable++
		} else {
			stable = 0
		}
		last = out
		if stable == 3 {
			break
		}
		sleep(time.Second)
	}
	return last, nil
}

func markStopped(dirs config.Dirs, name string) {
	s, err := dirs.LoadState()
	if err != nil {
		return
	}
	if sb, ok := s.Find(name); ok {
		sb.Running = false
		s.Put(sb)
		_ = dirs.SaveState(s)
	}
}

var unsafe = regexp.MustCompile(`[^a-z0-9-]+`)

// SandboxName is fenzi-<folder>-<4 hex>, with the folder shortened to fit
// openshell.MaxSandboxName.
func SandboxName(repo string) string {
	base := strings.Trim(unsafe.ReplaceAllString(strings.ToLower(filepath.Base(repo)), "-"), "-")
	if base == "" {
		base = "project"
	}
	if room := openshell.MaxSandboxName - len("fenzi--0000"); len(base) > room {
		base = strings.TrimRight(base[:room], "-")
	}
	b := make([]byte, 2)
	_, _ = rand.Read(b)
	return "fenzi-" + base + "-" + hex.EncodeToString(b)
}
