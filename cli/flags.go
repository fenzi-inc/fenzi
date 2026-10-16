package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"fenzi/cli/internal/config"
	"fenzi/cli/internal/tui"
)

func newFlags(name string, out io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet("fenzi "+name, flag.ContinueOnError)
	fs.SetOutput(out)
	fs.Usage = func() { writeFlags(out, fs) }
	return fs
}

// helpRequested is returned when the user asked for -h. The flag text is
// already printed. Callers exit 0 and do not add an error line.
type helpRequested struct{}

func (helpRequested) Error() string { return "help" }

// usage is the shape of each command, shown above its flags.
var usage = map[string]string{
	"fenzi run":      "fenzi run [agent] [-- agent arguments]",
	"fenzi connect":  "fenzi connect [sandbox] [-- agent arguments]",
	"fenzi stop":     "fenzi stop [sandbox]",
	"fenzi rm":       "fenzi rm <sandbox> [<sandbox>...] | fenzi rm --finished",
	"fenzi approve":  "fenzi approve <id> [--save [--dry-run] [--policy-from <file>]]",
	"fenzi deny":     `fenzi deny <id> --reason "text"`,
	"fenzi requests": "fenzi requests",
	"fenzi diff":     "fenzi diff",
	"fenzi apply":    "fenzi apply",
	"fenzi log":      "fenzi log",
	"fenzi ps":       "fenzi ps",
	"fenzi doctor":   "fenzi doctor",
	"fenzi init":     "fenzi init",
	"fenzi setup":    "fenzi setup",
	"fenzi update":   "fenzi update [--check]",
	"fenzi version":  "fenzi version",
	"fenzi status":   "fenzi status",
	"fenzi login":    "fenzi login",
	"fenzi logout":   "fenzi logout",
	"fenzi server":   "fenzi server",
	"fenzi sync":     "fenzi sync",
	"fenzi forward":  "fenzi forward [--once]",
	"fenzi agents":   "fenzi agents",
	"fenzi key":      "fenzi key",
	"fenzi policy":   "fenzi policy",
}

func writeFlags(out io.Writer, fs *flag.FlagSet) {
	u := tui.ForOutput(out)
	shape := usage[fs.Name()]
	if shape == "" {
		shape = fs.Name()
	}
	u.Title(shape, "")
	width := 0
	fs.VisitAll(func(f *flag.Flag) { width = max(width, len(f.Name)+2) })
	if width == 0 {
		u.Println("    " + u.Dim("No flags."))
		u.Blank()
		return
	}
	fs.VisitAll(func(f *flag.Flag) {
		u.Println(fmt.Sprintf("    %s  %s", u.Bold(fmt.Sprintf("%-*s", width, "--"+f.Name)), u.Dim(f.Usage)))
	})
	u.Blank()
}

// parse allows flags before and after positional arguments. Everything after
// a literal -- is positional.
func parse(fs *flag.FlagSet, args []string) ([]string, error) {
	var tail []string
	for i, a := range args {
		if a == "--" {
			args, tail = args[:i], args[i+1:]
			break
		}
	}
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return nil, helpRequested{}
			}
			return nil, err
		}
		args = fs.Args()
		if len(args) == 0 {
			return append(pos, tail...), nil
		}
		pos = append(pos, args[0])
		args = args[1:]
	}
}

// pickSandbox returns the named sandbox, or the most recent one Fenzi
// started for the current folder. Outside any project it takes the most
// recent one overall and says which, so output from another project is never
// shown silently.
func pickSandbox(e env, dirs config.Dirs, name string, runningOnly bool) (config.Sandbox, error) {
	s, err := dirs.LoadState()
	if err != nil {
		return config.Sandbox{}, err
	}
	if name != "" {
		if sb, ok := s.Find(name); ok {
			return sb, nil
		}
		return config.Sandbox{Name: name}, nil
	}
	if dir, err := cwd(); err == nil {
		if sb, ok := s.LatestIn(dir, runningOnly); ok {
			return sb, nil
		}
	}
	if sb, ok := s.Latest(runningOnly); ok {
		u := tui.ForOutput(e.stderr)
		u.Println("  " + u.Dim("No sandbox for this folder, so this is "+sb.Name+", from "+tilde(sb.Repo, homeDir())+"."))
		return sb, nil
	}
	if runningOnly {
		return config.Sandbox{}, errors.New("no sandbox is running. fenzi run starts one")
	}
	return config.Sandbox{}, errors.New("no sandbox has run on this machine yet. fenzi run starts one")
}

func cwd() (string, error) { return os.Getwd() }
