package run

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"fenzi/agents"
	"fenzi/cli/internal/config"
	"fenzi/cli/internal/openshell"
	"fenzi/cli/internal/workspace"
	"fenzi/compiler"
)

const pass = `{"result":"within_boundary","coverage":{"domains":["filesystem","network_l4","network_rest","process","landlock"]}}`

// Recorded from OpenShell 0.1.2.
const statusOK = `{"authentication":{"provider":"mTLS transport","status":"authenticated"},"gateway":"openshell","server":"https://localhost:17670","status":"connected","version":"0.1.2"}`

type fakeImages struct{ built []string }

func (f *fakeImages) Exists(context.Context, string) bool { return false }
func (f *fakeImages) Build(_ context.Context, tag string, _ []byte) error {
	f.built = append(f.built, tag)
	return nil
}

type harness struct {
	os, prover *openshell.Fake
	images     *fakeImages
	deps       Deps
	opts       Options
	out        *bytes.Buffer
}

// Recorded from OpenShell 0.1.2.
const settingsLine = "[1791061242.935] [sandbox] [OCSF ] [ocsf] CONFIG:DETECTED [INFO] Settings poll: config change detected [old_revision:4376335306479293579 new_revision:7049278607115123709 policy_changed:false provider_env_changed:true]\n"

// Unset values read "<unset>".
const globalUnset = `{"settings":{"ocsf_json_enabled":"<unset>","agent_policy_proposals_enabled":"<unset>","proposal_approval_mode":"<unset>"}}`

func setup(t *testing.T) *harness {
	t.Helper()
	repo := t.TempDir()
	os.WriteFile(filepath.Join(repo, "main.go"), []byte("package main"), 0o644)
	os.WriteFile(filepath.Join(repo, "old.go"), []byte("package old"), 0o644)

	claude, err := agents.Get("claude")
	if err != nil {
		t.Fatal(err)
	}
	res, err := ResolveFree(repo, "")
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{
		os: &openshell.Fake{Replies: map[string]openshell.Reply{
			"status":       {Out: statusOK},
			"settings get": {Out: globalUnset},
			"provider get": {Exit: 1},
			"logs":         {Out: settingsLine},
		}},
		prover: &openshell.Fake{Replies: map[string]openshell.Reply{"check": {Out: pass}}},
		images: &fakeImages{},
		out:    &bytes.Buffer{},
	}
	// The download writes the agent's version of the project.
	h.os.Hook = func(args []string) {
		if len(args) >= 5 && args[0] == "sandbox" && args[1] == "download" {
			dst := args[4]
			os.MkdirAll(dst, 0o755)
			os.WriteFile(filepath.Join(dst, "main.go"), []byte("package main // edited"), 0o644)
			os.WriteFile(filepath.Join(dst, "new.go"), []byte("package new"), 0o644)
		}
	}
	h.deps = Deps{
		OpenShell: openshell.Client{R: h.os},
		Prover:    openshell.Prover{R: h.prover},
		Images:    h.images,
		Dirs:      config.Dirs{Config: t.TempDir(), Cache: t.TempDir()},
		Out:       h.out,
		Getenv:    func(k string) string { return map[string]string{"ANTHROPIC_API_KEY": "sk-test"}[k] },
		Now:       func() time.Time { return time.Unix(0, 0) },
		Filter:    func(string) workspace.Filter { return workspace.All },
		Sleep:     func(time.Duration) {},
	}
	profile, err := claude.Profile()
	if err != nil {
		t.Fatal(err)
	}
	h.opts = Options{Agent: claude, Profile: profile, Args: []string{"--model", "x"}, Repo: repo, Policy: res, Name: "fenzi-test-0001"}
	return h
}

func (h *harness) called(prefix string) bool {
	for _, c := range h.os.Calls {
		if strings.HasPrefix(c, prefix) {
			return true
		}
	}
	return false
}

func TestRunSequence(t *testing.T) {
	h := setup(t)
	res, err := Run(context.Background(), h.deps, h.opts)
	if err != nil {
		t.Fatalf("%v\n%s", err, h.out)
	}

	project := "/sandbox/" + filepath.Base(h.opts.Repo)
	want := []string{
		"status --output json",
		"settings get --global --json",
		"provider get fenzi-claude",
		"profile import -f ",
		"provider create --name fenzi-claude --type fenzi-claude-code --from-existing",
		"sandbox create --name fenzi-test-0001 --from fenzi/claude:2.1.288 --policy ",
		"sandbox get fenzi-test-0001 --policy-only",
		"settings set fenzi-test-0001 --key ocsf_json_enabled --value true",
		"settings set fenzi-test-0001 --key agent_policy_proposals_enabled --value true",
		"sandbox upload fenzi-test-0001 " + h.opts.Repo,
		"logs fenzi-test-0001 --source sandbox -n 1000",
		"sandbox exec -n fenzi-test-0001 --tty --workdir " + project + " --env CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1 -- claude --permission-mode manual --append-system-prompt " + agents.Guide + " --model x",
		"logs fenzi-test-0001 --source sandbox -n 100000",
		"sandbox download fenzi-test-0001 " + project + " ",
		"sandbox delete fenzi-test-0001",
	}
	// The log is polled until it stops growing; count that as one step.
	var calls []string
	for _, c := range h.os.Calls {
		if strings.HasPrefix(c, "logs ") && len(calls) > 0 && calls[len(calls)-1] == c {
			continue
		}
		calls = append(calls, c)
	}
	if len(calls) != len(want) {
		t.Fatalf("got %d openshell calls, want %d:\n%s", len(calls), len(want), strings.Join(calls, "\n"))
	}
	for i, w := range want {
		if !strings.HasPrefix(calls[i], w) {
			t.Errorf("call %d:\n got  %s\n want %s...", i, calls[i], w)
		}
	}
	create := calls[5]
	for _, frag := range []string{"--provider fenzi-claude", "--label fenzi=1", "--label policy_rev=local-", "--approval-mode manual", "--no-auto-providers", "--detach"} {
		if !strings.Contains(create, frag) {
			t.Errorf("sandbox create is missing %q: %s", frag, create)
		}
	}
	if strings.Contains(create, "--approval-mode auto") {
		t.Error("sandbox create must never use automatic approval")
	}

	if len(h.prover.Calls) != 2 {
		t.Errorf("prover ran %d times, want 2 (compiled and effective)", len(h.prover.Calls))
	}
	saved, err := LoadResolved(h.deps.Dirs.Run("fenzi-test-0001"))
	if err != nil {
		t.Fatalf("the document the sandbox started with was not saved: %v", err)
	}
	if !reflect.DeepEqual(saved.WithDefaults(), h.opts.Policy.Doc.WithDefaults()) {
		t.Errorf("saved document differs:\n%+v\n%+v", saved, h.opts.Policy.Doc)
	}
	if len(h.images.built) != 1 {
		t.Errorf("image built %d times", len(h.images.built))
	}
	if got := len(res.Changes); got != 3 {
		t.Errorf("want 3 staged changes (M main.go, A new.go, D old.go), got %v", res.Changes)
	}
	if b, _ := os.ReadFile(filepath.Join(h.opts.Repo, "main.go")); string(b) != "package main" {
		t.Error("run must not change the repo; apply does")
	}
}

func TestExistingProviderIsReused(t *testing.T) {
	h := setup(t)
	h.os.Replies["provider get"] = openshell.Reply{}
	h.deps.Getenv = func(string) string { return "" }
	if _, err := Run(context.Background(), h.deps, h.opts); err != nil {
		t.Fatalf("an existing provider needs no key in the environment: %v", err)
	}
	if h.called("provider create") {
		t.Error("provider exists on the gateway; it must not be created again")
	}
}

func TestGatewayWideSettingIsNotSetAgain(t *testing.T) {
	h := setup(t)
	h.os.Replies["settings get"] = openshell.Reply{Out: `{"settings":{"ocsf_json_enabled":"<unset>","agent_policy_proposals_enabled":true}}`}
	if _, err := Run(context.Background(), h.deps, h.opts); err != nil {
		t.Fatalf("%v\n%s", err, h.out)
	}
	if h.called("settings set fenzi-test-0001 --key agent_policy_proposals_enabled") {
		t.Error("the gateway refuses a per-sandbox value for a key it manages globally")
	}
	if !h.called("settings set fenzi-test-0001 --key ocsf_json_enabled") {
		t.Error("keys the gateway leaves unset are still set per sandbox")
	}
}

func TestGatewayWideConflictStopsBeforeCreate(t *testing.T) {
	h := setup(t)
	h.os.Replies["settings get"] = openshell.Reply{Out: `{"settings":{"ocsf_json_enabled":false,"agent_policy_proposals_enabled":"<unset>"}}`}
	_, err := Run(context.Background(), h.deps, h.opts)
	if err == nil || !strings.Contains(err.Error(), "ocsf_json_enabled to false") || !strings.Contains(err.Error(), "fenzi doctor --fix") {
		t.Fatalf("want a conflict naming the key and the fix, got %v", err)
	}
	if h.called("sandbox create") {
		t.Error("a conflict must stop the run before a sandbox exists")
	}
}

func TestExistingProfile(t *testing.T) {
	claude, err := agents.Get("claude")
	if err != nil {
		t.Fatal(err)
	}
	profile, err := claude.Profile()
	if err != nil {
		t.Fatal(err)
	}
	// Recorded from OpenShell 0.1.2: a second import, and the export shape.
	exists := openshell.Reply{Exit: 1, Stderr: "error profile=fenzi-claude-code field=id custom provider profile 'fenzi-claude-code' already exists"}
	same := `{"id":"fenzi-claude-code","resource_version":3,"credentials":[{"env_vars":["ANTHROPIC_API_KEY","CLAUDE_API_KEY"]}],"endpoints":[{"host":"api.anthropic.com","port":443,"protocol":"rest","access":"read-write","enforcement":"enforce"}],"binaries":["/usr/local/lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe"]}`
	if !strings.Contains(string(profile), "api.anthropic.com") {
		t.Fatal("fixture assumes the claude profile")
	}

	t.Run("unchanged", func(t *testing.T) {
		h := setup(t)
		h.os.Replies["profile import"] = exists
		h.os.Replies["profile export"] = openshell.Reply{Out: same}
		if _, err := Run(context.Background(), h.deps, h.opts); err != nil {
			t.Fatal(err)
		}
		if h.called("profile update") {
			t.Error("an identical profile must not be rewritten on every run")
		}
	})

	t.Run("changed", func(t *testing.T) {
		h := setup(t)
		h.os.Replies["profile import"] = exists
		h.os.Replies["profile export"] = openshell.Reply{Out: strings.Replace(same, `"rest"`, `"tcp"`, 1)}
		if _, err := Run(context.Background(), h.deps, h.opts); err != nil {
			t.Fatal(err)
		}
		var update string
		for _, c := range h.os.Calls {
			if strings.HasPrefix(c, "profile update --file ") {
				update = c
			}
		}
		if !strings.HasSuffix(update, "profile.update.yaml fenzi-claude-code") {
			t.Fatalf("want profile update --file <dir>/profile.update.yaml fenzi-claude-code, calls:\n%s", strings.Join(h.os.Calls, "\n"))
		}
		body, err := os.ReadFile(strings.Fields(update)[3])
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(string(body), "resource_version: 3\n") {
			t.Errorf("update must carry the exported resource_version:\n%s", body)
		}
	})
}

func TestCompiledPolicyFailsClosed(t *testing.T) {
	h := setup(t)
	h.prover.Replies["check"] = openshell.Reply{Out: `{"result":"exceeds_boundary","counterexample":"filesystem write /tmp"}`, Exit: 1}
	_, err := Run(context.Background(), h.deps, h.opts)
	var pe *PolicyError
	if !errors.As(err, &pe) {
		t.Fatalf("want PolicyError, got %v", err)
	}
	if h.called("sandbox create") {
		t.Error("no sandbox may be created when the compiled policy fails the check")
	}
}

func TestMissingCoverageFailsClosed(t *testing.T) {
	h := setup(t)
	h.prover.Replies["check"] = openshell.Reply{Out: `{"result":"within_boundary","coverage":{"domains":["filesystem"]}}`}
	_, err := Run(context.Background(), h.deps, h.opts)
	var pe *PolicyError
	if !errors.As(err, &pe) {
		t.Fatalf("partial coverage must not pass, got %v", err)
	}
}

func TestEffectivePolicyFailureDeletesSandbox(t *testing.T) {
	h := setup(t)
	h.os.Replies["sandbox get fenzi-test-0001 --policy-only"] = openshell.Reply{Out: "version: 1\n"}
	// Second prover call (effective policy) fails.
	orig := h.deps.Prover
	h.deps.Prover = openshell.Prover{R: &switchRunner{first: orig.R, then: &openshell.Fake{Replies: map[string]openshell.Reply{
		"check": {Out: `{"result":"exceeds_boundary","counterexample":"network connect evil.example.com:443"}`, Exit: 1},
	}}}}
	_, err := Run(context.Background(), h.deps, h.opts)
	var pe *PolicyError
	if !errors.As(err, &pe) || pe.Stage != "effective policy with provider rules" {
		t.Fatalf("want effective-policy PolicyError, got %v", err)
	}
	if !h.called("sandbox delete fenzi-test-0001") {
		t.Error("sandbox must be deleted when its effective policy fails the check")
	}
	if h.called("sandbox upload") || h.called("sandbox exec") {
		t.Error("nothing may be uploaded or started after a failed check")
	}
}

func TestMissingKey(t *testing.T) {
	h := setup(t)
	h.deps.Getenv = func(string) string { return "" }
	h.opts.Agent.SignInNote = ""
	if _, err := Run(context.Background(), h.deps, h.opts); err == nil || !strings.Contains(err.Error(), "ANTHROPIC_API_KEY") {
		t.Fatalf("want a missing key error, got %v", err)
	}
	if h.called("provider create") || h.called("sandbox create") || len(h.images.built) > 0 {
		t.Errorf("nothing may be built or created without the key, got %v", h.os.Calls)
	}
}

// --sign-in starts without the key even when one is stored, for a person
// who wants their subscription; the key stays stored for other runs.
func TestSignInWithAStoredKey(t *testing.T) {
	h := setup(t)
	h.os.Replies["provider get"] = openshell.Reply{}
	h.opts.SignIn = true
	res, err := Run(context.Background(), h.deps, h.opts)
	if err != nil {
		t.Fatalf("%v\n%s", err, h.out)
	}
	if h.called("profile import") || h.called("provider create") || h.called("provider delete") {
		t.Errorf("--sign-in must neither use nor touch the stored key, got %v", h.os.Calls)
	}
	for _, c := range h.os.Calls {
		if strings.HasPrefix(c, "sandbox create") && strings.Contains(c, "--provider") {
			t.Errorf("created with a provider: %q", c)
		}
	}
	b, err := os.ReadFile(filepath.Join(h.deps.Dirs.Run(res.Sandbox), "policy.yaml"))
	if err != nil || !strings.Contains(string(b), "model_api_anthropic_com:") {
		t.Errorf("policy.yaml must hold the model API rule: %v\n%s", err, b)
	}
	if out := h.out.String(); !strings.Contains(out, "not used (--sign-in)") || !strings.Contains(out, h.opts.Agent.SignInNote) {
		t.Errorf("output:\n%s", out)
	}
	state, _ := h.deps.Dirs.LoadState()
	if sb, ok := state.Find(res.Sandbox); !ok || !sb.SignIn {
		t.Errorf("state %+v", sb)
	}
}

func TestSignInRefusedForAnAgentThatCannot(t *testing.T) {
	h := setup(t)
	h.opts.SignIn = true
	h.opts.Agent.SignInNote = ""
	if _, err := Run(context.Background(), h.deps, h.opts); err == nil || !strings.Contains(err.Error(), "does not sign in itself") {
		t.Fatalf("got %v", err)
	}
	if h.called("sandbox create") {
		t.Errorf("nothing may be created, got %v", h.os.Calls)
	}
}

func TestSignInWithoutKey(t *testing.T) {
	h := setup(t)
	h.deps.Getenv = func(string) string { return "" }
	res, err := Run(context.Background(), h.deps, h.opts)
	if err != nil {
		t.Fatalf("claude signs in itself, so no key is needed: %v\n%s", err, h.out)
	}
	if h.called("profile import") || h.called("provider create") {
		t.Errorf("a sandbox without a key needs no profile or provider, got %v", h.os.Calls)
	}
	var create string
	for _, c := range h.os.Calls {
		if strings.HasPrefix(c, "sandbox create") {
			create = c
		}
	}
	if create == "" || strings.Contains(create, "--provider") || !strings.Contains(create, "--no-auto-providers") {
		t.Errorf("want a sandbox created with no provider and none picked automatically: %q", create)
	}
	if len(h.prover.Calls) != 2 {
		t.Errorf("prover ran %d times, want 2 (compiled and effective)", len(h.prover.Calls))
	}

	// No provider adds the model API, so the policy holds it, for the
	// agent's program only.
	b, err := os.ReadFile(filepath.Join(h.deps.Dirs.Run("fenzi-test-0001"), "policy.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"model_api_anthropic_com:", "host: api.anthropic.com", "access: read-write"} {
		if !strings.Contains(string(b), want) {
			t.Errorf("policy.yaml is missing %q:\n%s", want, b)
		}
	}

	out := h.out.String()
	if !strings.Contains(out, "none stored") || !strings.Contains(out, h.opts.Agent.SignInNote) || strings.Contains(out, h.opts.Agent.StartNote) {
		t.Errorf("want the sign-in note instead of the key note:\n%s", out)
	}
	state, err := h.deps.Dirs.LoadState()
	if err != nil {
		t.Fatal(err)
	}
	sb, ok := state.Find(res.Sandbox)
	if !ok || !sb.SignIn {
		t.Errorf("the sandbox must be recorded as started without a key: %+v", sb)
	}
	a, err := AgentFor(sb)
	if err != nil || !a.SignedIn {
		t.Errorf("AgentFor must keep the sandbox's sign-in: %+v %v", a.SignedIn, err)
	}
}

// A key in the environment still wins over signing in.
func TestKeyInEnvironmentIsStillStored(t *testing.T) {
	h := setup(t)
	if _, err := Run(context.Background(), h.deps, h.opts); err != nil {
		t.Fatal(err)
	}
	if !h.called("provider create --name fenzi-claude") {
		t.Errorf("want the provider created from the key, got %v", h.os.Calls)
	}
	state, _ := h.deps.Dirs.LoadState()
	if sb, _ := state.Find("fenzi-test-0001"); sb.SignIn {
		t.Error("a sandbox with a key is not a sign-in sandbox")
	}
}

func TestGatewayDown(t *testing.T) {
	h := setup(t)
	h.os.Replies["status"] = openshell.Reply{Exit: 1}
	_, err := Run(context.Background(), h.deps, h.opts)
	var ge *GatewayError
	if !errors.As(err, &ge) {
		t.Fatalf("want GatewayError, got %v", err)
	}
}

func TestGatewayNotAuthenticated(t *testing.T) {
	h := setup(t)
	h.os.Replies["status"] = openshell.Reply{Out: `{"authentication":{"status":"unauthenticated"},"status":"connected"}`}
	_, err := Run(context.Background(), h.deps, h.opts)
	var ge *GatewayError
	if !errors.As(err, &ge) || !strings.Contains(err.Error(), "authentication") || strings.Contains(err.Error(), "openshell ") {
		t.Fatalf("want GatewayError about authentication, with no openshell command, got %v", err)
	}
}

func TestNoUploadCreatesProjectDir(t *testing.T) {
	h := setup(t)
	h.opts.NoUpload = true
	if _, err := Run(context.Background(), h.deps, h.opts); err != nil {
		t.Fatal(err)
	}
	if h.called("sandbox upload") || !h.called("sandbox exec -n fenzi-test-0001 --no-login-shell -- mkdir -p /sandbox/") {
		t.Errorf("calls: %v", h.os.Calls)
	}
}

// OpenShell 0.1.4 refuses to upload a repository Git filtering leaves empty,
// such as one just made with `git init` (recorded 19 October 2026, the folder
// replaced). The run goes on with an empty project folder, as it did on 0.1.2.
func TestEmptyRepositoryStartsInAnEmptyFolder(t *testing.T) {
	h := setup(t)
	h.os.Replies["sandbox upload fenzi-test-0001"] = openshell.Reply{Exit: 1, Stderr: "Error:   × Git filtering selected no files for /tmp/up-empty-git;\n  │ upload stopped.\n  │ Git returned 0 uploadable paths: the source may be empty or all files may\n  │ be ignored.\n  │ Use --no-git-ignore to upload intentionally without filtering\n"}
	if _, err := Run(context.Background(), h.deps, h.opts); err != nil {
		t.Fatalf("%v\n%s", err, h.out)
	}
	if !h.called("sandbox exec -n fenzi-test-0001 --no-login-shell -- mkdir -p /sandbox/") {
		t.Errorf("calls: %v", h.os.Calls)
	}
	if out := h.out.String(); !strings.Contains(out, "nothing to copy") || strings.Contains(out, "project copied") {
		t.Errorf("output:\n%s", out)
	}
}

func TestLogIsSavedOnceSettled(t *testing.T) {
	h := setup(t)
	n := 0
	growing := h.os.Hook
	h.os.Hook = func(args []string) {
		growing(args)
		if args[0] == "logs" && args[len(args)-1] == "100000" {
			n++
		}
	}
	lines := []string{settingsLine, settingsLine + "b\n", settingsLine + "b\nc\n"}
	h.os.Replies["logs"] = openshell.Reply{Out: lines[0]}
	h.deps.Sleep = func(time.Duration) {
		if n < len(lines) {
			h.os.Replies["logs"] = openshell.Reply{Out: lines[n]}
		}
	}
	if _, err := Run(context.Background(), h.deps, h.opts); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(h.deps.Dirs.Run("fenzi-test-0001"), LogFile))
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != settingsLine+"b\nc\n" {
		t.Errorf("saved log %q, want the settled one", b)
	}
}

func TestAgentStartsAfterSettingsLoad(t *testing.T) {
	h := setup(t)
	h.os.Replies["logs"] = openshell.Reply{Out: "[1] [sandbox] [INFO ] starting\n"}
	sleeps := 0
	h.deps.Sleep = func(time.Duration) {
		if sleeps++; sleeps == 3 {
			h.os.Replies["logs"] = openshell.Reply{Out: settingsLine}
		}
	}
	if _, err := Run(context.Background(), h.deps, h.opts); err != nil {
		t.Fatal(err)
	}
	execAt, loadedAt := -1, -1
	for i, c := range h.os.Calls {
		if strings.HasPrefix(c, "sandbox exec -n fenzi-test-0001 --tty") {
			execAt = i
		}
	}
	if sleeps < 3 || execAt < 0 {
		t.Fatalf("sleeps %d, calls %v", sleeps, h.os.Calls)
	}
	loadedAt = execAt - 1
	if !strings.HasPrefix(h.os.Calls[loadedAt], "logs ") {
		t.Errorf("the agent started before the settings check: %v", h.os.Calls)
	}
	if !strings.Contains(h.out.String(), "waiting for the sandbox to load them") || strings.Contains(h.out.String(), "not confirmed") {
		t.Errorf("output:\n%s", h.out)
	}
}

func TestStopStagesThenDeletes(t *testing.T) {
	h := setup(t)
	h.opts.Keep = true
	if _, err := Run(context.Background(), h.deps, h.opts); err != nil {
		t.Fatal(err)
	}
	s, _ := h.deps.Dirs.LoadState()
	sb, ok := s.Find("fenzi-test-0001")
	if !ok || !sb.Running {
		t.Fatalf("kept sandbox not recorded as running: %+v", s)
	}
	h.os.Calls = nil
	changes, err := Stop(context.Background(), h.deps, sb)
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 3 {
		t.Errorf("changes = %v", changes)
	}
	var order []string
	for _, c := range h.os.Calls {
		if f := strings.Fields(c); len(f) > 1 && (len(order) == 0 || order[len(order)-1] != f[0]+" "+f[1]) {
			order = append(order, f[0]+" "+f[1])
		}
	}
	want := []string{"logs fenzi-test-0001", "sandbox download", "sandbox delete"}
	if strings.Join(order, ",") != strings.Join(want, ",") {
		t.Errorf("calls %v, want %v", order, want)
	}
	s, _ = h.deps.Dirs.LoadState()
	if sb, _ := s.Find("fenzi-test-0001"); sb.Running {
		t.Error("stopped sandbox still marked running")
	}
	// The end is recorded once, for the Mac app's timeline.
	if sb, _ := s.Find("fenzi-test-0001"); sb.Ended.IsZero() || time.Since(sb.Ended) > time.Minute {
		t.Errorf("ended = %v, want now", sb.Ended)
	}
	stopped, _ := s.Find("fenzi-test-0001")
	markStopped(h.deps.Dirs, "fenzi-test-0001")
	s, _ = h.deps.Dirs.LoadState()
	if again, _ := s.Find("fenzi-test-0001"); !again.Ended.Equal(stopped.Ended) {
		t.Errorf("a second stop moved ended from %v to %v", stopped.Ended, again.Ended)
	}
}

func TestStopKeepsSandboxWhenCopyFails(t *testing.T) {
	h := setup(t)
	h.opts.Keep = true
	if _, err := Run(context.Background(), h.deps, h.opts); err != nil {
		t.Fatal(err)
	}
	s, _ := h.deps.Dirs.LoadState()
	sb, _ := s.Find("fenzi-test-0001")
	h.os.Replies["sandbox download"] = openshell.Reply{Exit: 1}
	h.os.Calls = nil
	if _, err := Stop(context.Background(), h.deps, sb); err == nil {
		t.Fatal("want an error when the copy fails")
	}
	if h.called("sandbox delete") {
		t.Error("the sandbox must be kept when its changes could not be copied")
	}
}

func TestSandboxName(t *testing.T) {
	n := SandboxName("/Users/dana/code/My Web_App")
	if !strings.HasPrefix(n, "fenzi-my-web-a-") || len(n) != openshell.MaxSandboxName {
		t.Errorf("SandboxName = %q", n)
	}
	cases := map[string]string{
		"/Users/dana/mouse-keeper":             "fenzi-mouse-ke-",
		"/Users/dana/a-very-long-project-name": "fenzi-a-very-l-",
		"/Users/dana/abcdefghij-k":             "fenzi-abcdefgh-",
		"/Users/dana/rs-brain":                 "fenzi-rs-brain-",
	}
	for repo, prefix := range cases {
		n := SandboxName(repo)
		if !strings.HasPrefix(n, prefix) || len(n) > openshell.MaxSandboxName {
			t.Errorf("SandboxName(%q) = %q (%d characters)", repo, n, len(n))
		}
	}
}

func TestWriteGuide(t *testing.T) {
	fake := &openshell.Fake{}
	d := Deps{OpenShell: openshell.Client{R: fake}}
	dest := "/sandbox/.fenzi/guide.md"
	if err := writeGuide(context.Background(), d, "sb", dest, agents.Guide); err != nil {
		t.Fatal(err)
	}
	if len(fake.Calls) != 1 || !strings.Contains(fake.Calls[0], "python3 -c") {
		t.Fatalf("call = %q", fake.Calls)
	}
	_, payload, ok := strings.Cut(fake.Calls[0], `base64.b64decode("`)
	if !ok {
		t.Fatalf("script has no payload: %s", fake.Calls[0])
	}
	payload, _, ok = strings.Cut(payload, `"`)
	if !ok {
		t.Fatal("payload is not quoted")
	}
	raw, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != agents.Guide {
		t.Fatalf("decoded guide does not match agents.Guide (%d bytes)", len(raw))
	}
	if err := writeGuide(context.Background(), d, "sb", "/tmp/guide.md", agents.Guide); err == nil {
		t.Fatal("a guide path outside the workdir must be refused")
	}
}

func TestOnExitKeepsTheSandbox(t *testing.T) {
	h := setup(t)
	h.opts.OnExit = func(name string) (bool, error) {
		if name != "fenzi-test-0001" {
			t.Fatalf("asked about %s", name)
		}
		return true, nil
	}
	res, err := Run(context.Background(), h.deps, h.opts)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Kept || h.called("sandbox delete") {
		t.Fatalf("kept %v, calls %v", res.Kept, h.os.Calls)
	}
	if !strings.Contains(h.out.String(), "fenzi-test-0001, kept") {
		t.Fatalf("output:\n%s", h.out)
	}
}

func TestOnExitCanStillDelete(t *testing.T) {
	h := setup(t)
	h.opts.OnExit = func(string) (bool, error) { return false, nil }
	if _, err := Run(context.Background(), h.deps, h.opts); err != nil {
		t.Fatal(err)
	}
	if !h.called("sandbox delete fenzi-test-0001") {
		t.Fatal("choosing delete must remove the sandbox")
	}
}

// switchRunner answers the first call from one runner and later calls from another.
type switchRunner struct {
	first, then openshell.Runner
	n           int
}

func (s *switchRunner) Output(ctx context.Context, args ...string) ([]byte, error) {
	s.n++
	if s.n == 1 {
		return s.first.Output(ctx, args...)
	}
	return s.then.Output(ctx, args...)
}

func (s *switchRunner) Attach(ctx context.Context, args ...string) error {
	return s.then.Attach(ctx, args...)
}

func withMCP(t *testing.T, h *harness) {
	t.Helper()
	project, err := compiler.Parse([]byte("version: 1\nmcp:\n  linear:\n    url: https://mcp.linear.app/mcp\n    token: true\n    tools: {allow: [list_issues]}\n  files:\n    command: [npx, -y, server-filesystem]\n"))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := compiler.Merge(h.opts.Policy.Doc, project)
	if err != nil {
		t.Fatal(err)
	}
	h.opts.Policy.Doc = doc
}

// A run with MCP servers: the token's provider is attached, the prover gets
// the policy without the MCP rule (0.1.2 returns unsupported for it), the
// agent's config is written before it starts, and its flags are on the line.
func TestRunWithMCP(t *testing.T) {
	h := setup(t)
	withMCP(t, h)
	h.os.Replies["provider get fenzi-mcp-linear"] = openshell.Reply{}
	res, err := Run(context.Background(), h.deps, h.opts)
	if err != nil {
		t.Fatalf("%v\n%s", err, h.out)
	}
	var create, exec string
	wrote := false
	for _, c := range h.os.Calls {
		switch {
		case strings.HasPrefix(c, "sandbox create"):
			create = c
		case strings.HasPrefix(c, "sandbox exec") && strings.Contains(c, "--tty"):
			exec = c
		case strings.HasPrefix(c, "sandbox exec") && strings.Contains(c, "python3") && strings.Contains(c, "/sandbox/.fenzi/mcp.json"):
			wrote = true
		}
	}
	if !strings.Contains(create, "--provider fenzi-claude --provider fenzi-mcp-linear") {
		t.Errorf("create: %q", create)
	}
	if !wrote {
		t.Errorf("the MCP config was not written: %v", h.os.Calls)
	}
	if !strings.Contains(exec, "--mcp-config /sandbox/.fenzi/mcp.json --strict-mcp-config") {
		t.Errorf("exec: %q", exec)
	}
	for _, c := range h.prover.Calls {
		if !strings.Contains(c, "prove.") {
			t.Errorf("the prover read a file with MCP rules: %s", c)
		}
	}
	pol, err := os.ReadFile(filepath.Join(h.deps.Dirs.Run(res.Sandbox), "policy.yaml"))
	if err != nil || !strings.Contains(string(pol), "protocol: mcp") || !strings.Contains(string(pol), "provider: fenzi-mcp-linear") {
		t.Errorf("the loaded policy keeps the MCP rule: %v\n%s", err, pol)
	}
	out := h.out.String()
	if !strings.Contains(out, "rules checked by Fenzi, not by the prover") || !strings.Contains(out, "files (local), linear (1 tool)") {
		t.Errorf("output:\n%s", out)
	}
}

func TestRunWithMCPNeedsTheToken(t *testing.T) {
	h := setup(t)
	withMCP(t, h)
	_, err := Run(context.Background(), h.deps, h.opts)
	var missing *ErrNoMCPToken
	if !errors.As(err, &missing) || missing.Server != "linear" {
		t.Fatalf("want ErrNoMCPToken, got %v", err)
	}
	if h.called("sandbox create") {
		t.Error("nothing may be created without the token")
	}
}

func withSecrets(t *testing.T, h *harness) {
	t.Helper()
	project, err := compiler.Parse([]byte("version: 1\nmcp:\n  droplets:\n    command: [npx, -y, \"@digitalocean/mcp\", --services, droplets]\n    secrets: [DIGITALOCEAN_API_TOKEN]\n    hosts: [api.digitalocean.com]\n"))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := compiler.Merge(h.opts.Policy.Doc, project)
	if err != nil {
		t.Fatal(err)
	}
	h.opts.Policy.Doc = doc
}

// A run with a local server's secret: its provider is attached, the policy
// binds it on the server's host, the prover gets every file without the
// binding (0.1.2 returns unsupported for it), and the agent's config
// passes the variable to the server.
func TestRunWithMCPSecret(t *testing.T) {
	h := setup(t)
	withSecrets(t, h)
	h.os.Replies["provider get fenzi-secret-digitalocean-api-token"] = openshell.Reply{}
	res, err := Run(context.Background(), h.deps, h.opts)
	if err != nil {
		t.Fatalf("%v\n%s", err, h.out)
	}
	var create string
	wrote := false
	for _, c := range h.os.Calls {
		switch {
		case strings.HasPrefix(c, "sandbox create"):
			create = c
		case strings.HasPrefix(c, "sandbox exec") && strings.Contains(c, "python3") && strings.Contains(c, "/sandbox/.fenzi/mcp.json"):
			wrote = true
		}
	}
	if !strings.Contains(create, "--provider fenzi-claude --provider fenzi-secret-digitalocean-api-token") {
		t.Errorf("create: %q", create)
	}
	if !wrote {
		t.Errorf("the MCP config was not written: %v", h.os.Calls)
	}
	dir := h.deps.Dirs.Run(res.Sandbox)
	pol, err := os.ReadFile(filepath.Join(dir, "policy.yaml"))
	if err != nil || !strings.Contains(string(pol), "provider: fenzi-secret-digitalocean-api-token") || !strings.Contains(string(pol), "host: api.digitalocean.com") {
		t.Errorf("the loaded policy binds the secret: %v\n%s", err, pol)
	}
	for _, c := range h.prover.Calls {
		if !strings.Contains(c, "prove.") {
			t.Errorf("the prover read a file with a binding: %s", c)
		}
	}
	prove, err := os.ReadFile(filepath.Join(dir, "prove.policy.yaml"))
	if err != nil || strings.Contains(string(prove), "credential_binding") || !strings.Contains(string(prove), "host: api.digitalocean.com") {
		t.Errorf("the prover's copy keeps the host without the binding: %v\n%s", err, prove)
	}
	out := h.out.String()
	if !strings.Contains(out, "DIGITALOCEAN_API_TOKEN on api.digitalocean.com") || !strings.Contains(out, "droplets (local)") {
		t.Errorf("output:\n%s", out)
	}
}

func TestRunWithMCPSecretNeedsTheValue(t *testing.T) {
	h := setup(t)
	withSecrets(t, h)
	_, err := Run(context.Background(), h.deps, h.opts)
	var missing *ErrNoMCPSecret
	if !errors.As(err, &missing) || missing.Server != "droplets" || missing.Variable != "DIGITALOCEAN_API_TOKEN" {
		t.Fatalf("want ErrNoMCPSecret, got %v", err)
	}
	if !strings.Contains(err.Error(), "fenzi mcp token droplets --env DIGITALOCEAN_API_TOKEN") {
		t.Errorf("message %q", err)
	}
	if h.called("sandbox create") {
		t.Error("nothing may be created without the secret")
	}
}

// An agent's own MCP config that holds a token in plain text is copied with
// the project, so run names it with the other files that look like secrets.
// A reference to a variable is not a secret.
func TestMCPConfigSecrets(t *testing.T) {
	repo := t.TempDir()
	if err := os.MkdirAll(filepath.Join(repo, ".cursor"), 0o755); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		".cursor/mcp.json": `{"mcpServers":{"do":{"command":"npx","env":{"DIGITALOCEAN_API_TOKEN":"dop_v1_abc","LOG_LEVEL":"warn"}},"ctx":{"url":"https://x","headers":{"X-API-Key":"ctx7sk-123","Authorization":"Bearer ${TOKEN}"}}}}`,
		".mcp.json":        `{"mcpServers":{"gh":{"command":"gh-mcp","env":{"GITHUB_TOKEN":"${GITHUB_TOKEN}"}}}}`,
	}
	m := workspace.Manifest{}
	for rel, body := range files {
		if err := os.WriteFile(filepath.Join(repo, filepath.FromSlash(rel)), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		m[rel] = "x"
	}
	got := MCPConfigSecrets(repo, m)
	if len(got) != 1 || got[0] != ".cursor/mcp.json (holds DIGITALOCEAN_API_TOKEN, X-API-Key)" {
		t.Errorf("got %v", got)
	}
	if got := MCPConfigSecrets(repo, workspace.Manifest{}); len(got) != 0 {
		t.Errorf("a file .gitignore leaves out is not copied, so not listed: %v", got)
	}
}

// In the app the sign-in note names the Keys screen, not commands.
func TestSignInNoteForTheApp(t *testing.T) {
	note := "Claude asks you to sign in. Choose your Claude subscription and paste back the code your browser shows. To use a key instead, run fenzi key set claude, then fenzi run without --sign-in."
	t.Setenv("FENZI_APP", "")
	if got := forClient(note); got != note {
		t.Errorf("in a terminal the note changed: %q", got)
	}
	t.Setenv("FENZI_APP", "1")
	got := forClient(note)
	if strings.Contains(got, "fenzi key set") || !strings.Contains(got, "add it under Keys") {
		t.Errorf("in the app: %q", got)
	}
	start := "Claude may ask whether to use the API key it found. Choose Yes for the key you stored: Claude sees a placeholder, not your key. To use your Claude subscription instead, choose No, then type /login, or start with fenzi run --sign-in claude."
	if got := forClient(start); strings.Contains(got, "fenzi run") || !strings.HasSuffix(got, "or choose the subscription in New Sandbox.") {
		t.Errorf("the start note in the app: %q", got)
	}
}

func TestSandboxNameKeepsAccentedLetters(t *testing.T) {
	name := SandboxName("/Users/ana/Été projet")
	if !strings.HasPrefix(name, "fenzi-ete-proj") {
		t.Errorf("got %q", name)
	}
}
