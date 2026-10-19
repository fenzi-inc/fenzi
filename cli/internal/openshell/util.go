package openshell

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
)

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// Fake is a Runner for tests. It records every call and answers from Replies,
// keyed by the joined argument list or by its first words.
type Fake struct {
	mu      sync.Mutex
	Calls   []string
	Replies map[string]Reply
	// Hook runs on every call, for side effects such as writing downloaded files.
	Hook func(args []string)
	// Answer, when set, is asked for the output of a call before Replies.
	// It returns false to leave the call to Replies.
	Answer func(args []string) (out string, ok bool)
	// Env holds every KEY=VALUE passed with OutputEnv, so tests can check that
	// secrets went through the environment and not the arguments.
	Env []string
}

func (f *Fake) OutputEnv(_ context.Context, env []string, args ...string) ([]byte, error) {
	f.mu.Lock()
	f.Env = append(f.Env, env...)
	f.mu.Unlock()
	return f.answer(args)
}

type Reply struct {
	Out    string
	Exit   int
	Stderr string
}

func (f *Fake) Output(_ context.Context, args ...string) ([]byte, error) {
	return f.answer(args)
}

func (f *Fake) Attach(_ context.Context, args ...string) error {
	_, err := f.answer(args)
	return err
}

func (f *Fake) answer(args []string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	line := strings.Join(args, " ")
	f.Calls = append(f.Calls, line)
	if f.Hook != nil {
		f.Hook(args)
	}
	if f.Answer != nil {
		if out, ok := f.Answer(args); ok {
			return []byte(out), nil
		}
	}
	best := ""
	for k := range f.Replies {
		if (line == k || strings.HasPrefix(line, k+" ")) && len(k) > len(best) {
			best = k
		}
	}
	r, ok := f.Replies[best]
	if !ok {
		return nil, nil
	}
	if r.Exit != 0 {
		stderr := r.Stderr
		if stderr == "" {
			stderr = fmt.Sprintf("fake exit %d", r.Exit)
		}
		return []byte(r.Out), &Error{Bin: "fake", Args: args, ExitCode: r.Exit, Stderr: stderr}
	}
	return []byte(r.Out), nil
}
