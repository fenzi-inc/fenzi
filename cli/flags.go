package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"boundlane/cli/internal/config"
	"boundlane/cli/internal/tui"
)

func newFlags(name string, out io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet("boundlane "+name, flag.ContinueOnError)
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
	"boundlane run":      "boundlane run [agent] [-- agent arguments]",
	"boundlane connect":  "boundlane connect [sandbox] [-- agent arguments]",
	"boundlane stop":     "boundlane stop [sandbox]",
	"boundlane rm":       "boundlane rm <sandbox> [<sandbox>...] | boundlane rm --finished",
	"boundlane approve":  "boundlane approve <id> [--save [--dry-run] [--policy-from <file>]]",
	"boundlane deny":     `boundlane deny <id> --reason "text"`,
	"boundlane requests": "boundlane requests",
	"boundlane diff":     "boundlane diff",
	"boundlane apply":    "boundlane apply",
	"boundlane log":      "boundlane log",
	"boundlane ps":       "boundlane ps",
	"boundlane doctor":   "boundlane doctor",
	"boundlane init":     "boundlane init",
	"boundlane setup":    "boundlane setup",
	"boundlane update":   "boundlane update [--check]",
	"boundlane version":  "boundlane version",
	"boundlane status":   "boundlane status",
	"boundlane login":    "boundlane login",
	"boundlane logout":   "boundlane logout",
	"boundlane server":   "boundlane server",
	"boundlane sync":     "boundlane sync",
	"boundlane forward":  "boundlane forward [--once]",
	"boundlane agents":   "boundlane agents",
	"boundlane key":      "boundlane key",
	"boundlane policy":   "boundlane policy",
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

// pickSandbox returns the named sandbox, or the most recent one Boundlane
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
		return config.Sandbox{}, errors.New("no sandbox is running. boundlane run starts one")
	}
	return config.Sandbox{}, errors.New("no sandbox has run on this machine yet. boundlane run starts one")
}

func cwd() (string, error) { return os.Getwd() }
