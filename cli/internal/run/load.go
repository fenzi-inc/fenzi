package run

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"go.yaml.in/yaml/v3"

	"fenzi/cli/internal/openshell"
	"fenzi/compiler"
)

// Checker is the policy prover. openshell.Prover implements it.
type Checker interface {
	Check(ctx context.Context, candidate, boundary string) (openshell.Result, error)
}

// Loader loads a network change onto a running sandbox. openshell.Client
// implements it.
type Loader interface {
	PolicySet(ctx context.Context, name, file string) error
	PolicyList(ctx context.Context, name string) ([]byte, error)
}

// ProverError means the prover could not be run, so nothing was checked.
type ProverError struct{ Err error }

func (e *ProverError) Error() string { return "the policy prover could not run: " + e.Err.Error() }
func (e *ProverError) Unwrap() error { return e.Err }

// Prove checks a compiled policy against its boundary the way run does
// before it creates a sandbox. It returns *PolicyError when the result is not
// within_boundary with full coverage, and *ProverError when there is no
// prover or it failed to run.
func Prove(ctx context.Context, p Checker, c Compiled, stage string) (openshell.Result, error) {
	if p == nil {
		return openshell.Result{}, &ProverError{Err: errors.New("no prover on this machine")}
	}
	r, err := p.Check(ctx, c.Policy, c.Boundary)
	if err != nil {
		return r, &ProverError{Err: err}
	}
	if !r.Passed() {
		return r, &PolicyError{Stage: stage, Result: r}
	}
	return r, nil
}

// LoadState is what `policy list` said after `policy set --wait` returned.
type LoadState int

const (
	// LoadAccepted means policy set returned and policy list named neither
	// state.
	LoadAccepted LoadState = iota
	// LoadPending means the supervisor loads it on its next poll.
	LoadPending
	// LoadLoaded means the supervisor has loaded it.
	LoadLoaded
)

// LoadNetwork runs `policy set --wait` with a compiled policy, then reads
// `policy list`. OpenShell 0.1.2 showed a new revision Pending and then
// Loaded there; the full text of the list was not recorded, so only those
// two words are read.
func LoadNetwork(ctx context.Context, gw Loader, name, policy string) (LoadState, error) {
	if err := gw.PolicySet(ctx, name, policy); err != nil {
		return LoadAccepted, err
	}
	list, err := gw.PolicyList(ctx, name)
	if err != nil {
		return LoadAccepted, err
	}
	return ListState(list), nil
}

// ListState reads the output of `policy list` the way LoadNetwork does: only
// the words Loaded and Pending, since the full text was not recorded.
func ListState(list []byte) LoadState {
	switch {
	case bytes.Contains(list, []byte("Loaded")):
		return LoadLoaded
	case bytes.Contains(list, []byte("Pending")):
		return LoadPending
	default:
		return LoadAccepted
	}
}

// ResolvedFile is the org document a sandbox was started with, saved in its
// run folder so a later change can be compared with it.
const ResolvedFile = "resolved.yaml"

// SaveResolved writes the document a sandbox starts with into its run folder.
func SaveResolved(dir string, doc *compiler.Document) error {
	b, err := yaml.Marshal(doc)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, ResolvedFile), b, 0o600)
}

// ErrNoResolved means the sandbox was started by a release that did not save
// its document.
var ErrNoResolved = errors.New("the policy this sandbox started with was not saved")

// LoadResolved reads the document a sandbox was started with.
func LoadResolved(dir string) (*compiler.Document, error) {
	b, err := os.ReadFile(filepath.Join(dir, ResolvedFile))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNoResolved
	}
	if err != nil {
		return nil, err
	}
	doc, err := compiler.Parse(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", filepath.Join(dir, ResolvedFile), err)
	}
	return doc, nil
}
