package workspace

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// Limits past which a file is summarised instead of compared line by line.
const (
	maxDiffBytes = 2 << 20
	maxDiffEdits = 2000
	contextLines = 3
)

// Op is one line of a hunk: ' ' kept, '-' removed, '+' added.
type Op struct {
	Kind byte
	Text string
}

// Hunk is a run of edits with up to three kept lines around it. Starts are
// 1-based line numbers, as in a unified diff.
type Hunk struct {
	OldStart, OldLines int
	NewStart, NewLines int
	Ops                []Op
}

// FileDiff is what changed in one file.
type FileDiff struct {
	Change
	Added, Removed int
	Binary         bool
	// Large means the file is past the size or edit limit; only the counts
	// are filled when they could be computed.
	Large bool
	Hunks []Hunk
}

// Diff compares one change: the file in root before, the file in staged after.
func Diff(root, staged string, c Change) (FileDiff, error) {
	d := FileDiff{Change: c}
	var before, after []byte
	var err error
	if c.Kind != Added {
		if before, err = readSmall(root, c.Path); err != nil {
			return d, err
		}
	}
	if c.Kind != Deleted {
		if after, err = readSmall(staged, c.Path); err != nil {
			return d, err
		}
	}
	if before == nil && c.Kind != Added || after == nil && c.Kind != Deleted {
		d.Large = true
		return d, nil
	}
	if isBinary(before) || isBinary(after) {
		d.Binary = true
		return d, nil
	}
	a, b := splitLines(before), splitLines(after)
	ops, ok := lineDiff(a, b)
	if !ok {
		d.Large = true
		return d, nil
	}
	for _, o := range ops {
		switch o.Kind {
		case '+':
			d.Added++
		case '-':
			d.Removed++
		}
	}
	d.Hunks = hunks(ops)
	return d, nil
}

// Hunks compares two texts line by line, as Diff compares a file. ok is
// false past the edit limit.
func Hunks(before, after []byte) (h []Hunk, ok bool) {
	ops, ok := lineDiff(splitLines(before), splitLines(after))
	if !ok {
		return nil, false
	}
	return hunks(ops), true
}

// readSmall returns nil without an error for a file past maxDiffBytes. A file
// that does not exist reads as empty.
func readSmall(dir, rel string) ([]byte, error) {
	path := filepath.Join(dir, filepath.FromSlash(rel))
	info, err := os.Stat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return []byte{}, nil
	}
	if err != nil {
		return nil, err
	}
	if info.Size() > maxDiffBytes {
		return nil, nil
	}
	b, err := os.ReadFile(path)
	if b == nil && err == nil {
		b = []byte{}
	}
	return b, err
}

func isBinary(b []byte) bool {
	if len(b) > 8000 {
		b = b[:8000]
	}
	return bytes.IndexByte(b, 0) >= 0
}

func splitLines(b []byte) []string {
	if len(b) == 0 {
		return nil
	}
	s := strings.TrimSuffix(string(b), "\n")
	return strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n")
}

// lineDiff is Myers' O(ND) algorithm. Trace row d keeps diagonals -d-1 to
// d+1 only, so memory grows with the square of the edits, not the file. It
// gives up past maxDiffEdits.
func lineDiff(a, b []string) ([]Op, bool) {
	n, m := len(a), len(b)
	limit := min(n+m, maxDiffEdits)
	off := limit + 1
	v := make([]int, 2*limit+3)
	var trace [][]int
	found := false
	for d := 0; d <= limit; d++ {
		trace = append(trace, append([]int(nil), v[off-d-1:off+d+2]...))
		for k := -d; k <= d; k += 2 {
			var x int
			if k == -d || (k != d && v[off+k-1] < v[off+k+1]) {
				x = v[off+k+1]
			} else {
				x = v[off+k-1] + 1
			}
			y := x - k
			for x < n && y < m && a[x] == b[y] {
				x++
				y++
			}
			v[off+k] = x
			if x >= n && y >= m {
				found = true
				break
			}
		}
		if found {
			break
		}
	}
	if !found {
		return nil, false
	}

	var rev []Op
	x, y := n, m
	for d := len(trace) - 1; d >= 0; d-- {
		row := trace[d]
		at := func(k int) int { return row[k+d+1] }
		k := x - y
		var prevK int
		if k == -d || (k != d && at(k-1) < at(k+1)) {
			prevK = k + 1
		} else {
			prevK = k - 1
		}
		prevX := at(prevK)
		prevY := prevX - prevK
		for x > prevX && y > prevY {
			rev = append(rev, Op{' ', a[x-1]})
			x--
			y--
		}
		if d > 0 {
			if x == prevX {
				rev = append(rev, Op{'+', b[y-1]})
			} else {
				rev = append(rev, Op{'-', a[x-1]})
			}
		}
		x, y = prevX, prevY
	}
	ops := make([]Op, len(rev))
	for i, o := range rev {
		ops[len(rev)-1-i] = o
	}
	return ops, true
}

// hunks groups edits that are at most 2*contextLines kept lines apart, with
// contextLines kept lines on each side.
func hunks(ops []Op) []Hunk {
	oldAt := make([]int, len(ops)+1)
	newAt := make([]int, len(ops)+1)
	oldAt[0], newAt[0] = 1, 1
	var edits []int
	for i, o := range ops {
		oldAt[i+1], newAt[i+1] = oldAt[i], newAt[i]
		if o.Kind != '+' {
			oldAt[i+1]++
		}
		if o.Kind != '-' {
			newAt[i+1]++
		}
		if o.Kind != ' ' {
			edits = append(edits, i)
		}
	}
	var out []Hunk
	for g := 0; g < len(edits); {
		first, last := edits[g], edits[g]
		for g++; g < len(edits) && edits[g]-last-1 <= 2*contextLines; g++ {
			last = edits[g]
		}
		from := max(0, first-contextLines)
		to := min(len(ops), last+1+contextLines)
		h := Hunk{OldStart: oldAt[from], NewStart: newAt[from], Ops: ops[from:to]}
		h.OldLines = oldAt[to] - oldAt[from]
		h.NewLines = newAt[to] - newAt[from]
		out = append(out, h)
	}
	return out
}
