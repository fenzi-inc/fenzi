package relay

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// providerClaude is the rule the runtime added for the bl_claude provider:
// the profile's endpoint and the agent's program, copied as written.
const providerClaude = `
  _provider_bl_claude:
    endpoints:
      - host: api.anthropic.com
        port: 443
        protocol: rest
        enforcement: enforce
        access: read-write
    binaries:
      - path: /usr/local/lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe`

// effectiveDefault reproduces the shape recorded on 16 October 2026 from a
// live OpenShell 0.1.2 sandbox, as `sandbox get --policy-only` printed it:
// the compiled policy without its leading comment line and without a
// trailing newline, with one added _provider_bl_claude entry under
// network_policies. The rest is compiler/testdata/golden/default.policy.yaml
// as written; TestEffectiveFixtureIsTheGoldenPolicy keeps the two together.
const effectiveDefault = `version: 1
filesystem_policy:
  include_workdir: false
  read_only:
    - /bin
    - /usr
    - /lib
    - /etc
    - /app
    - /var/log
    - /proc
    - /dev/urandom
  read_write:
    - /sandbox
    - /tmp
    - /dev/null
landlock:
  compatibility: hard_requirement
process:
  run_as_user: sandbox
  run_as_group: sandbox
network_policies:
  api_github_com:
    name: api.github.com
    endpoints:
      - host: api.github.com
        port: 443
        protocol: rest
        enforcement: enforce
        access: read-only
    binaries:
      - path: /usr/local/lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe
  files_pythonhosted_org:
    name: files.pythonhosted.org
    endpoints:
      - host: files.pythonhosted.org
        port: 443
        protocol: rest
        enforcement: enforce
        access: read-only
    binaries:
      - path: /usr/local/lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe
  pypi_org:
    name: pypi.org
    endpoints:
      - host: pypi.org
        port: 443
        protocol: rest
        enforcement: enforce
        access: read-only
    binaries:
      - path: /usr/local/lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe
  registry_npmjs_org:
    name: registry.npmjs.org
    endpoints:
      - host: registry.npmjs.org
        port: 443
        protocol: rest
        enforcement: enforce
        access: read-only
    binaries:
      - path: /usr/local/lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe` + providerClaude

func goldenDefault(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "compiler", "testdata", "golden", "default.policy.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestEffectiveFixtureIsTheGoldenPolicy(t *testing.T) {
	golden := string(goldenDefault(t))
	if !strings.HasPrefix(golden, "# ") {
		t.Fatal("the golden policy lost its comment line")
	}
	body := strings.TrimSuffix(golden[strings.Index(golden, "\n")+1:], "\n")
	if strings.TrimSuffix(effectiveDefault, providerClaude) != body {
		t.Fatal("effectiveDefault without its provider rule must be the golden policy without its comment line and trailing newline")
	}
	if strings.HasSuffix(effectiveDefault, "\n") {
		t.Fatal("the recorded output has no trailing newline")
	}
}

func TestPolicyDiffLeavesOutProviderRules(t *testing.T) {
	differs, err := policyDiff(goldenDefault(t), []byte(effectiveDefault))
	if err != nil || len(differs) != 0 {
		t.Fatalf("differs %v err %v", differs, err)
	}
	// A provider rule is all a policy without hosts gets from the runtime.
	bare := "version: 1\nlandlock:\n  compatibility: hard_requirement\n"
	differs, err = policyDiff([]byte("# comment\n"+bare), []byte(bare+"network_policies:"+providerClaude))
	if err != nil || len(differs) != 0 {
		t.Fatalf("bare policy: differs %v err %v", differs, err)
	}
}

func TestPolicyDiffNamesTheSectionsThatDiffer(t *testing.T) {
	golden := goldenDefault(t)
	cases := map[string]struct {
		effective string
		want      []string
	}{
		"wider host": {
			strings.Replace(effectiveDefault, "host: pypi.org\n        port: 443\n        protocol: rest\n        enforcement: enforce\n        access: read-only",
				"host: pypi.org\n        port: 443\n        protocol: rest\n        enforcement: enforce\n        access: read-write", 1),
			[]string{"network_policies"},
		},
		"added rule": {
			effectiveDefault + "\n  paste_example_net:\n    name: paste.example.net\n    endpoints:\n      - host: paste.example.net\n        port: 443",
			[]string{"network_policies"},
		},
		"rule gone": {
			strings.Replace(effectiveDefault, "  pypi_org:\n    name: pypi.org\n", "  pypi_org_gone:\n    name: pypi.org\n", 1),
			[]string{"network_policies"},
		},
		"path": {
			strings.Replace(effectiveDefault, "    - /tmp\n", "    - /tmp\n    - /home\n", 1),
			[]string{"filesystem_policy"},
		},
		"two sections": {
			strings.Replace(strings.Replace(effectiveDefault, "run_as_user: sandbox", "run_as_user: root", 1), "    - /proc\n", "", 1),
			[]string{"filesystem_policy", "process"},
		},
		"number type": {
			strings.Replace(effectiveDefault, "version: 1", "version: \"1\"", 1),
			[]string{"version"},
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			differs, err := policyDiff(golden, []byte(c.effective))
			if err != nil || !reflect.DeepEqual(differs, c.want) {
				t.Fatalf("differs %v err %v, want %v", differs, err, c.want)
			}
		})
	}
	if _, err := policyDiff(golden, nil); err == nil {
		t.Fatal("an empty read is not a policy")
	}
	if _, err := policyDiff(golden, []byte("version: [")); err == nil {
		t.Fatal("output that does not parse is not compared")
	}
}
