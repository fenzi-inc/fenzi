// Command fenzi runs AI agents inside an OpenShell sandbox with an org policy.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"

	"fenzi/cli/internal/run"
	"fenzi/cli/internal/tui"
)

// Version is set at build time with -ldflags "-X main.Version=...".
var Version = "dev"

var helpGroups = []struct {
	name string
	rows [][2]string
}{
	{"Start", [][2]string{
		{"setup", "Guided setup: checks, agent, key, folder"},
		{"run", "Start an agent in a sandbox"},
		{"connect", "Open the agent again in a running sandbox"},
	}},
	{"While it runs", [][2]string{
		{"ps", "List sandboxes"},
		{"requests", "See and answer requests for more access"},
		{"approve", "Approve a request"},
		{"deny", "Deny a request"},
		{"log", "Show allows and denies"},
		{"stop", "End a sandbox and review its changes"},
		{"rm", "Delete finished sandboxes"},
	}},
	{"Changes", [][2]string{
		{"diff", "Show the agent's changes"},
		{"apply", "Apply them to this folder"},
	}},
	{"Machine and policy", [][2]string{
		{"doctor", "Check this machine"},
		{"key", "Store, replace, or remove a model key"},
		{"init", "Write a starter fenzi.yaml"},
		{"policy", "Compile or check a policy file"},
		{"agents", "List agents, or build an image"},
		{"update", "Install the latest fenzi"},
		{"version", "Show the version. --version does the same"},
	}},
}

var teamHelp = [][2]string{
	{"login", "Sign this machine in to a team"},
	{"logout", "Forget the sign-in"},
	{"status", "Show the sign-in and the policy"},
	{"sync", "Load a host change onto running sandboxes"},
	{"forward", "Send decisions to the console, apply reviews"},
}

func writeHelp(w io.Writer) {
	u := tui.ForOutput(w)
	team := teamHelp
	if includedTeam {
		team = append([][2]string{{"server", "Local team server"}}, teamHelp...)
	}
	groups := append(helpGroups[:len(helpGroups):len(helpGroups)], struct {
		name string
		rows [][2]string
	}{"Team", team})
	u.Blank()
	u.Println(fmt.Sprintf("  %s %s  %s", u.Accent("■"), u.Bold("Fenzi "+Version), u.Dim("the agent you already use, in a sandbox on your machine")))
	u.Blank()
	u.Println(fmt.Sprintf("  %s  %s", u.Bold("fenzi"), u.Dim("with no command opens a menu for this folder")))
	for _, g := range groups {
		u.Blank()
		u.Println("  " + u.Accent(g.name))
		for _, r := range g.rows {
			u.Println(fmt.Sprintf("    %s  %s", u.Bold(fmt.Sprintf("%-9s", r[0])), r[1]))
		}
	}
	u.Blank()
	u.Println("  " + u.Dim("Free on one machine with no account. Team: fenzi login, then the console at https://fenzi.dev/console."))
	u.Blank()
	u.Println("  " + u.Dim("fenzi <command> -h shows its flags. Docs: https://fenzi.dev/docs"))
	u.Println("  " + u.Dim("Exit codes: 0 ok, 1 error, 2 policy check failed, 3 runtime not ready."))
	u.Println("  " + u.Dim("run and connect exit with the agent's code."))
	u.Blank()
}

// suggest returns the command closest to a mistyped one, or "".
func suggest(name string, cmds map[string]func(env, []string) (int, error)) string {
	best, bestD := "", 3
	for c := range cmds {
		if c == "home" {
			continue
		}
		if d := distance(name, c); d < bestD || (d == bestD && c < best) {
			best, bestD = c, d
		}
	}
	return best
}

func distance(a, b string) int {
	prev := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur := make([]int, len(b)+1)
		cur[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev = cur
	}
	return prev[len(b)]
}

func main() {
	legacyEnv()
	if strings.TrimSuffix(filepath.Base(os.Args[0]), ".exe") == "boundlane" {
		fmt.Fprintln(os.Stderr, "Boundlane is now Fenzi. This command still works; new installs are called fenzi (https://fenzi.dev).")
	}
	os.Exit(cli(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

// legacyEnv copies each BOUNDLANE_ variable, the names before the rename,
// to its FENZI_ name when that one is not set.
func legacyEnv() {
	for _, kv := range os.Environ() {
		k, v, ok := strings.Cut(kv, "=")
		if !ok || !strings.HasPrefix(k, "BOUNDLANE_") {
			continue
		}
		n := "FENZI_" + strings.TrimPrefix(k, "BOUNDLANE_")
		if _, set := os.LookupEnv(n); !set {
			os.Setenv(n, v)
		}
	}
}

type env struct {
	ctx    context.Context
	stdin  io.Reader
	stdout io.Writer
	stderr io.Writer
}

func cli(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	e := env{ctx: context.Background(), stdin: stdin, stdout: stdout, stderr: stderr}
	if len(args) == 0 && setupNeeded(e) {
		args = []string{"setup"}
	} else if len(args) == 0 && tui.New(stdin, stdout).Interactive() {
		args = []string{"home"}
	}
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		writeHelp(stdout)
		return 0
	}
	if args[0] == "--version" {
		args[0] = "version"
	}
	// The agent owns Ctrl-C while it runs. Handled signals reset to default in
	// child processes, so the agent still receives it.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	defer signal.Stop(sig)

	cmds := map[string]func(env, []string) (int, error){
		"home":     cmdHome,
		"setup":    cmdSetup,
		"connect":  cmdConnect,
		"update":   cmdUpdate,
		"doctor":   cmdDoctor,
		"init":     cmdInit,
		"run":      cmdRun,
		"requests": cmdRequests,
		"approve":  cmdApprove,
		"deny":     cmdDeny,
		"log":      cmdLog,
		"diff":     cmdDiff,
		"apply":    cmdApply,
		"policy":   cmdPolicy,
		"agents":   cmdAgents,
		"ps":       cmdPs,
		"key":      cmdKey,
		"stop":     cmdStop,
		"rm":       cmdRm,
		"server":   cmdServer,
		"login":    cmdLogin,
		"logout":   cmdLogout,
		"status":   cmdStatus,
		"sync":     cmdSync,
		"forward":  cmdForward,
		"version":  cmdVersion,
	}
	eu := tui.ForOutput(stderr)
	fn, ok := cmds[args[0]]
	if !ok {
		msg := fmt.Sprintf("unknown command %q.", args[0])
		if s := suggest(args[0], cmds); s != "" {
			msg += " Did you mean " + eu.Bold("fenzi "+s) + "?"
		}
		fmt.Fprintf(stderr, "%s fenzi: %s\n  %s\n", eu.Bold("!"), msg, eu.Dim("fenzi help lists every command."))
		return 1
	}
	defer announceUpdate(e, startUpdateCheck(e, args[0]))
	code, err := fn(e, args[1:])
	if err != nil {
		var help helpRequested
		if errors.As(err, &help) || errors.Is(err, flag.ErrHelp) {
			return 0
		}
		var quiet quietExit
		if errors.As(err, &quiet) {
			return int(quiet)
		}
		if errors.Is(err, tui.ErrCancelled) {
			return 130
		}
		fmt.Fprintf(stderr, "%s fenzi %s: %v\n", eu.Bold("!"), args[0], err)
		var pe *run.PolicyError
		var ge *run.GatewayError
		switch {
		case errors.As(err, &pe):
			return 2
		case errors.As(err, &ge):
			return 3
		case code == 0:
			return 1
		}
	}
	return code
}
