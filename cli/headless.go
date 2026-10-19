package main

import (
	"errors"
	"fmt"
	"io"
	"os"

	"fenzi/cli/internal/run"
	"fenzi/cli/internal/screen"
)

// readTask reads the task of fenzi run --headless from --task (a file, or
// - for standard input) or --task-text, exactly one of them.
func readTask(e env, file, text string) (string, error) {
	switch {
	case file != "" && text != "":
		return "", errors.New("--headless takes --task or --task-text, not both")
	case file == "" && text == "":
		return "", errors.New("--headless needs the task: --task <file> or --task-text \"<text>\"")
	case text != "":
		return text, nil
	}
	var b []byte
	var err error
	if file == "-" {
		b, err = io.ReadAll(io.LimitReader(e.stdin, maxTaskRead))
	} else {
		b, err = readLimited(file)
	}
	if err != nil {
		return "", fmt.Errorf("--task: %w", err)
	}
	return string(b), nil
}

// maxTaskRead stops reading a task file well past what the agent is
// given, so the length check can say how long it is.
const maxTaskRead = 1 << 20

func readLimited(file string) ([]byte, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, maxTaskRead))
}

// finishHeadless ends fenzi run --headless: the summary into --out, and
// the run's outcome as the exit status. Nothing is applied to the checkout.
func finishHeadless(e env, repo, out string, res run.Result) (int, error) {
	s := res.Summary
	if s == nil {
		return 1, fmt.Errorf("%s was stopped by another command before its summary; fenzi log --sandbox %s shows what it did", res.Sandbox, res.Sandbox)
	}
	scr := screen.New(e.stdout)
	if out != "" {
		if err := run.WriteOut(out, repo, s); err != nil {
			return 1, err
		}
		what := "summary.json and summary.md"
		if s.Bundle != "" {
			what += ", and the branch in " + s.Bundle
		}
		scr.Label("summary", fmt.Sprintf("%s written to %s", what, out))
	}
	return s.ExitStatus, nil
}
