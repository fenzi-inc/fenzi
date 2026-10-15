package relay

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"boundlane/cli/internal/config"
	"boundlane/cli/internal/forward"
)

// spoolLimit is how many records wait on disk while the control plane is away.
const spoolLimit = 10000

// spoolGap starts the reason of the gap record a full spool leaves behind.
const spoolGap = "spool full: "

// spool keeps records on disk until the control plane has stored them, oldest
// first. When it is full the oldest records are dropped, and one gap record
// per sandbox says how many and between which times, so the console shows the
// hole instead of hiding it.
type spool struct {
	path  string
	limit int
	recs  []forward.Record
}

func spoolPath(dirs config.Dirs) string { return filepath.Join(dirs.Config, "spool.jsonl") }

func openSpool(dirs config.Dirs, limit int) (*spool, error) {
	if limit <= 0 {
		limit = spoolLimit
	}
	s := &spool{path: spoolPath(dirs), limit: limit}
	b, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var r forward.Record
		// A line cut short by a crash during save is skipped.
		if json.Unmarshal(line, &r) == nil {
			s.recs = append(s.recs, r)
		}
	}
	return s, sc.Err()
}

// add appends records and returns how many records were dropped to stay
// within the limit. Gap records left by an earlier overflow are merged into
// the new ones rather than counted.
func (s *spool) add(recs []forward.Record) int {
	all := append(s.recs, recs...)
	if len(all) <= s.limit {
		s.recs = all
		return 0
	}
	k := len(all) - s.limit
	var gaps []forward.Record
	for {
		gaps = summarize(all[:k])
		if len(all)-k+len(gaps) <= s.limit || k == len(all) {
			break
		}
		k++
	}
	dropped := 0
	for _, r := range all[:k] {
		if _, _, _, ok := spoolGapSpan(r); !ok {
			dropped++
		}
	}
	s.recs = append(gaps, all[k:]...)
	return dropped
}

type span struct {
	n        int
	from, to time.Time
	last     forward.Record
}

// summarize turns dropped records into one gap record per sandbox, in the
// order the sandboxes first appear.
func summarize(drop []forward.Record) []forward.Record {
	var order []string
	spans := map[string]*span{}
	for _, r := range drop {
		n, from, to, ok := spoolGapSpan(r)
		if !ok {
			n, from, to = 1, r.Time, r.Time
		}
		sp := spans[r.Sandbox]
		if sp == nil {
			sp = &span{from: from, to: to}
			spans[r.Sandbox] = sp
			order = append(order, r.Sandbox)
		}
		sp.n += n
		if from.Before(sp.from) {
			sp.from = from
		}
		if to.After(sp.to) {
			sp.to = to
		}
		sp.last = r
	}
	out := make([]forward.Record, 0, len(order))
	for _, name := range order {
		sp := spans[name]
		out = append(out, forward.Record{
			Time: sp.from, Sandbox: name, Machine: sp.last.Machine, PolicyRevision: sp.last.PolicyRevision,
			Class: "gap", Action: "Gap", Destination: "log stream", Gap: true,
			Reason: fmt.Sprintf("%s%d records dropped between %s and %s", spoolGap, sp.n,
				sp.from.UTC().Format(time.RFC3339Nano), sp.to.UTC().Format(time.RFC3339Nano)),
		})
	}
	return out
}

// spoolGapSpan reads back a gap record that summarize wrote.
func spoolGapSpan(r forward.Record) (int, time.Time, time.Time, bool) {
	if !r.Gap || !strings.HasPrefix(r.Reason, spoolGap) {
		return 0, time.Time{}, time.Time{}, false
	}
	var n int
	var from, to string
	if _, err := fmt.Sscanf(strings.TrimPrefix(r.Reason, spoolGap), "%d records dropped between %s and %s", &n, &from, &to); err != nil {
		return 0, time.Time{}, time.Time{}, false
	}
	f, err1 := time.Parse(time.RFC3339Nano, from)
	t, err2 := time.Parse(time.RFC3339Nano, to)
	if err1 != nil || err2 != nil {
		return 0, time.Time{}, time.Time{}, false
	}
	return n, f, t, true
}

// save rewrites the spool. The file is readable only by this user. An empty
// spool removes it.
func (s *spool) save() error {
	if len(s.recs) == 0 {
		err := os.Remove(s.path)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, r := range s.recs {
		if err := enc.Encode(r); err != nil {
			return err
		}
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, buf.Bytes(), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}
