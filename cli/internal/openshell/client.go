package openshell

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Pinned is the OpenShell release line Fenzi is built against. Bump it
// only after reading the upstream migration notes.
var Pinned = VersionRange{Major: 0, Minor: 1}

// Client wraps the openshell CLI. Every method names the upstream page its
// arguments come from. Forms the docs do not show in full were checked
// against OpenShell 0.1.2, and the tests replay that recorded output.
type Client struct {
	R Runner
}

// Status: `openshell status --output json` (Manage gateways).
func (c Client) Status(ctx context.Context) ([]byte, error) {
	return c.R.Output(ctx, "status", "--output", "json")
}

// Ready checks the status JSON, as recorded from 0.1.2:
// {"status":"connected","authentication":{"status":"authenticated"},"version":"0.1.2",...}
func (c Client) Ready(ctx context.Context) error {
	out, err := c.Status(ctx)
	if err != nil {
		return err
	}
	var s struct {
		Status string `json:"status"`
		Auth   struct {
			Status string `json:"status"`
		} `json:"authentication"`
	}
	if err := json.Unmarshal(out, &s); err != nil {
		return fmt.Errorf("openshell status: unreadable output: %q", strings.TrimSpace(string(out)))
	}
	if s.Status != "connected" {
		return fmt.Errorf("gateway status is %q", s.Status)
	}
	if s.Auth.Status != "authenticated" {
		return fmt.Errorf("gateway authentication is %q; the gateway did not accept this machine's client certificate", s.Auth.Status)
	}
	return nil
}

// GatewayInfo: `openshell gateway info -o json` (Manage gateways).
func (c Client) GatewayInfo(ctx context.Context) ([]byte, error) {
	return c.R.Output(ctx, "gateway", "info", "-o", "json")
}

// ComputeDrivers reads compute_drivers[].name from gateway info.
func (c Client) ComputeDrivers(ctx context.Context) ([]string, error) {
	out, err := c.GatewayInfo(ctx)
	if err != nil {
		return nil, err
	}
	var info struct {
		Drivers []struct {
			Name string `json:"name"`
		} `json:"compute_drivers"`
	}
	if err := json.Unmarshal(out, &info); err != nil {
		return nil, fmt.Errorf("openshell gateway info: unreadable output")
	}
	var names []string
	for _, d := range info.Drivers {
		names = append(names, d.Name)
	}
	return names, nil
}

// GlobalSetting reads one gateway-wide setting from
// `openshell settings get --global --json`. Unset values read "<unset>".
// Only the named key is returned, because other settings may be sensitive.
func (c Client) GlobalSetting(ctx context.Context, key string) (string, error) {
	m, err := c.GlobalSettings(ctx, key)
	return m[key], err
}

// GlobalSettings reads several gateway-wide settings in one call.
func (c Client) GlobalSettings(ctx context.Context, keys ...string) (map[string]string, error) {
	out, err := c.R.Output(ctx, "settings", "get", "--global", "--json")
	if err != nil {
		return nil, err
	}
	var s struct {
		Settings map[string]json.RawMessage `json:"settings"`
	}
	if err := json.Unmarshal(out, &s); err != nil {
		return nil, fmt.Errorf("openshell settings get: unreadable output")
	}
	m := make(map[string]string, len(keys))
	for _, key := range keys {
		raw, ok := s.Settings[key]
		if !ok {
			m[key] = Unset
			continue
		}
		var v string
		if json.Unmarshal(raw, &v) == nil {
			m[key] = v
		} else {
			m[key] = string(raw)
		}
	}
	return m, nil
}

// Unset is how `settings get --json` shows a setting with no value.
const Unset = "<unset>"

// GlobalSettingDelete: `openshell settings delete --global --key <key> --yes`
// (0.1.2 help text). The setting falls back to OpenShell's default.
func (c Client) GlobalSettingDelete(ctx context.Context, key string) error {
	_, err := c.R.Output(ctx, "settings", "delete", "--global", "--key", key, "--yes")
	return err
}

// Version: `openshell --version`, which prints "openshell 0.1.2".
func (c Client) Version(ctx context.Context) (string, error) {
	out, err := c.R.Output(ctx, "--version")
	return string(out), err
}

// profileAccess is the part of a provider profile that decides access.
type profileAccess struct {
	ResourceVersion int64 `yaml:"resource_version" json:"resource_version"`
	Credentials     []struct {
		EnvVars []string `yaml:"env_vars" json:"env_vars"`
	} `yaml:"credentials" json:"credentials"`
	Endpoints []struct {
		Host        string `yaml:"host" json:"host"`
		Port        int    `yaml:"port" json:"port"`
		Protocol    string `yaml:"protocol" json:"protocol"`
		Access      string `yaml:"access" json:"access"`
		Enforcement string `yaml:"enforcement" json:"enforcement"`
	} `yaml:"endpoints" json:"endpoints"`
	Binaries []string `yaml:"binaries" json:"binaries"`
}

func (p profileAccess) same(o profileAccess) bool {
	p.ResourceVersion, o.ResourceVersion = 0, 0
	a, _ := json.Marshal(p)
	b, _ := json.Marshal(o)
	return string(a) == string(b)
}

// EnsureProfile makes the gateway hold this provider profile. In 0.1.2 a
// second `profile import` fails with "already exists", and `profile update`
// needs the current resource_version from `profile export`. The update
// runs only when endpoints, binaries, or credential variables differ.
func (c Client) EnsureProfile(ctx context.Context, id, file string) error {
	_, err := c.R.Output(ctx, "profile", "import", "-f", file)
	var oe *Error
	if !errors.As(err, &oe) || !strings.Contains(oe.Stderr, "already exists") {
		return err
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	var want profileAccess
	if err := yaml.Unmarshal(raw, &want); err != nil {
		return fmt.Errorf("%s: %w", file, err)
	}
	out, err := c.R.Output(ctx, "profile", "export", id, "-o", "json")
	if err != nil {
		return err
	}
	var have profileAccess
	if err := json.Unmarshal(out, &have); err != nil {
		return fmt.Errorf("openshell profile export %s: unreadable output", id)
	}
	if want.same(have) {
		return nil
	}
	next := filepath.Join(filepath.Dir(file), "profile.update.yaml")
	body := fmt.Sprintf("resource_version: %d\n%s", have.ResourceVersion, raw)
	if err := os.WriteFile(next, []byte(body), 0o600); err != nil {
		return err
	}
	_, err = c.R.Output(ctx, "profile", "update", "--file", next, id)
	return err
}

// ProviderExists: `openshell provider get <name>` exits 0 when it exists.
func (c Client) ProviderExists(ctx context.Context, name string) (bool, error) {
	_, err := c.R.Output(ctx, "provider", "get", name)
	if err == nil {
		return true, nil
	}
	if ExitCode(err) > 0 {
		return false, nil
	}
	return false, err
}

// ProviderCreate: `openshell provider create --name <n> --type <profile> --from-existing`.
// The key is read from the environment of this process.
func (c Client) ProviderCreate(ctx context.Context, name, profileType string) error {
	_, err := c.R.Output(ctx, "provider", "create", "--name", name, "--type", profileType, "--from-existing")
	return err
}

// ProviderSetKey stores a key in a provider, creating it if needed. The value
// reaches openshell through its environment (`--from-existing` reads it
// there, as in ProviderCreate), never through its arguments.
func (c Client) ProviderSetKey(ctx context.Context, name, profileType, envVar, value string, exists bool) error {
	er, ok := c.R.(EnvRunner)
	if !ok {
		return errors.New("this runner cannot pass a key through the environment")
	}
	args := []string{"provider", "create", "--name", name, "--type", profileType, "--from-existing"}
	if exists {
		args = []string{"provider", "update", name, "--from-existing"}
	}
	_, err := er.OutputEnv(ctx, []string{envVar + "=" + value}, args...)
	return err
}

// ProviderDelete: `openshell provider delete <name>`.
func (c Client) ProviderDelete(ctx context.Context, name string) error {
	_, err := c.R.Output(ctx, "provider", "delete", name)
	return err
}

// MaxSandboxName is the longest name the gateway accepts. OpenShell 0.1.2
// refused a 20-character name with `name exceeds maximum length (20 > 19)`;
// the docs do not state the limit.
const MaxSandboxName = 19

type CreateOptions struct {
	Name     string
	From     string
	Policy   string
	Provider string
	Labels   map[string]string
}

// SandboxCreate: `openshell sandbox create --detach` with a saved policy,
// a provider, labels, and manual approval (Manage sandboxes).
func (c Client) SandboxCreate(ctx context.Context, o CreateOptions) ([]byte, error) {
	args := []string{"sandbox", "create", "--name", o.Name, "--from", o.From, "--policy", o.Policy}
	if o.Provider != "" {
		args = append(args, "--provider", o.Provider)
	}
	for _, k := range sortedKeys(o.Labels) {
		args = append(args, "--label", k+"="+o.Labels[k])
	}
	// --no-auto-providers: Fenzi creates its own providers, and without the
	// flag a non-interactive create errors if one is missing.
	args = append(args, "--approval-mode", "manual", "--no-auto-providers", "--detach", "--output", "json")
	return c.R.Output(ctx, args...)
}

// EffectivePolicy: `openshell sandbox get <name> --policy-only`, which
// includes provider rules (Policy prover, Check a Sandbox's Policy).
func (c Client) EffectivePolicy(ctx context.Context, name string) ([]byte, error) {
	return c.R.Output(ctx, "sandbox", "get", name, "--policy-only")
}

// SandboxGet: `openshell sandbox get <name>`.
func (c Client) SandboxGet(ctx context.Context, name string) ([]byte, error) {
	return c.R.Output(ctx, "sandbox", "get", name)
}

// SettingsSet: `openshell settings set <name> --key <k> --value <v>`.
func (c Client) SettingsSet(ctx context.Context, name, key, value string) error {
	_, err := c.R.Output(ctx, "settings", "set", name, "--key", key, "--value", value)
	return err
}

// Upload: `openshell sandbox upload <name> <dir>`. Respects .gitignore and
// skips .git. A directory lands as <workdir>/<basename of dir>.
func (c Client) Upload(ctx context.Context, name, path string) error {
	_, err := c.R.Output(ctx, "sandbox", "upload", name, path)
	return err
}

// Download: `openshell sandbox download <name> <remote> <local>`. When local
// does not exist, the contents of remote land directly in it.
func (c Client) Download(ctx context.Context, name, remote, local string) error {
	_, err := c.R.Output(ctx, "sandbox", "download", name, remote, local)
	return err
}

// Exec: `openshell sandbox exec -n <name> --tty --workdir <dir> --env K=V -- <cmd>`,
// with the terminal attached. env is for non-secret values only; keys come
// from the provider.
func (c Client) Exec(ctx context.Context, name, workdir string, env map[string]string, cmd ...string) error {
	args := []string{"sandbox", "exec", "-n", name, "--tty"}
	if workdir != "" {
		args = append(args, "--workdir", workdir)
	}
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		args = append(args, "--env", k+"="+env[k])
	}
	args = append(append(args, "--"), cmd...)
	return c.R.Attach(ctx, args...)
}

// ExecOutput runs a command without a terminal and returns its stdout
// (`--no-login-shell`, as in the Network rules examples).
func (c Client) ExecOutput(ctx context.Context, name string, cmd ...string) ([]byte, error) {
	args := append([]string{"sandbox", "exec", "-n", name, "--no-login-shell", "--"}, cmd...)
	return c.R.Output(ctx, args...)
}

// Sandboxes: `openshell sandbox list --names --selector fenzi=1`, one name
// per line (0.1.2 help text). Every sandbox run creates carries that label.
// Sandboxes created before the rename from Boundlane carry boundlane=1
// instead, so both are listed.
func (c Client) Sandboxes(ctx context.Context) ([]string, error) {
	var names []string
	seen := map[string]bool{}
	for _, label := range []string{"fenzi=1", "boundlane=1"} {
		out, err := c.R.Output(ctx, "sandbox", "list", "--names", "--selector", label)
		if err != nil {
			return nil, err
		}
		for _, n := range strings.Fields(string(out)) {
			if !seen[n] {
				seen[n] = true
				names = append(names, n)
			}
		}
	}
	return names, nil
}

// Delete: `openshell sandbox delete <name>`. Deletes the sandbox's logs too.
func (c Client) Delete(ctx context.Context, name string) error {
	_, err := c.R.Output(ctx, "sandbox", "delete", name)
	return err
}

// PendingRules: `openshell rule get <name> --status pending`. 0.1.2 has no
// structured output; the text is printed as given.
func (c Client) PendingRules(ctx context.Context, name string) ([]byte, error) {
	return c.R.Output(ctx, "rule", "get", name, "--status", "pending")
}

// RuleApprove: `openshell rule approve <name> --chunk-id <id>`. The new
// revision loads on the supervisor's next poll, about 10 seconds.
func (c Client) RuleApprove(ctx context.Context, name, chunk string) error {
	_, err := c.R.Output(ctx, "rule", "approve", name, "--chunk-id", chunk)
	return err
}

// RuleReject: `openshell rule reject <name> --chunk-id <id> --reason <text>`.
func (c Client) RuleReject(ctx context.Context, name, chunk, reason string) error {
	_, err := c.R.Output(ctx, "rule", "reject", name, "--chunk-id", chunk, "--reason", reason)
	return err
}

// PolicySet: `openshell policy set <name> --policy <file> --wait` (Manage sandbox policies).
// Only network sections change on a running sandbox.
func (c Client) PolicySet(ctx context.Context, name, file string) error {
	_, err := c.R.Output(ctx, "policy", "set", name, "--policy", file, "--wait")
	return err
}

// PolicyList: `openshell policy list <name>`, which shows revision status such as Loaded.
func (c Client) PolicyList(ctx context.Context, name string) ([]byte, error) {
	return c.R.Output(ctx, "policy", "list", name)
}

// Logs: `openshell logs <name> --source sandbox [--since <d>]` (Accessing logs).
// Do not add --level warn, which hides policy events.
func (c Client) Logs(ctx context.Context, name, since string, follow bool) error {
	args := []string{"logs", name, "--source", "sandbox"}
	if since != "" {
		args = append(args, "--since", since)
	}
	if follow {
		args = append(args, "--tail")
	}
	return c.R.Attach(ctx, args...)
}

// LogLines: `openshell logs <name> --source sandbox -n <n>`, the shorthand
// format. 0.1.2 has no JSON output here, and the OCSF JSONL file is not
// visible to commands run with sandbox exec.
func (c Client) LogLines(ctx context.Context, name string, n int) ([]byte, error) {
	return c.R.Output(ctx, "logs", name, "--source", "sandbox", "-n", strconv.Itoa(n))
}

// VersionRange is a major.minor release line.
type VersionRange struct{ Major, Minor int }

func (v VersionRange) String() string { return fmt.Sprintf("%d.%d.x", v.Major, v.Minor) }

var semver = regexp.MustCompile(`(\d+)\.(\d+)\.(\d+)`)

// Contains reports whether the first x.y.z in s is on this release line.
func (v VersionRange) Contains(s string) (string, bool) {
	m := semver.FindStringSubmatch(s)
	if m == nil {
		return "", false
	}
	major, _ := strconv.Atoi(m[1])
	minor, _ := strconv.Atoi(m[2])
	return m[0], major == v.Major && minor == v.Minor
}
