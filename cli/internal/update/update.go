// Package update finds out whether a newer fenzi is published and
// replaces the running binary with it. It reads the same files as the
// install script: latest.txt, the binary, and the release's sha256 list.
package update

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// DefaultBase is where releases are published. FENZI_DOWNLOAD_BASE
// overrides it, as it does for the install script.
const DefaultBase = "https://fenzi.dev/dl"

// Every is how often the background check asks for latest.txt.
const Every = 24 * time.Hour

func Base() string {
	if b := os.Getenv("FENZI_DOWNLOAD_BASE"); b != "" {
		return strings.TrimRight(b, "/")
	}
	return DefaultBase
}

var numbered = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)

// Latest returns the version in latest.txt.
func Latest(ctx context.Context, c *http.Client, base string) (string, error) {
	body, err := get(ctx, c, base+"/latest.txt", 64)
	if err != nil {
		return "", err
	}
	v := strings.TrimSpace(string(body))
	if !numbered.MatchString(v) {
		return "", fmt.Errorf("latest.txt holds %q, not a release number", v)
	}
	return v, nil
}

// Newer reports whether a is a later release than b. Builds that are not
// numbered, such as "dev", are never older or newer than anything.
func Newer(a, b string) bool {
	pa, oka := parts(a)
	pb, okb := parts(b)
	if !oka || !okb {
		return false
	}
	for i := range pa {
		if pa[i] != pb[i] {
			return pa[i] > pb[i]
		}
	}
	return false
}

func parts(v string) ([3]int, bool) {
	var out [3]int
	if !numbered.MatchString(v) {
		return out, false
	}
	for i, s := range strings.Split(v, ".") {
		n, err := strconv.Atoi(s)
		if err != nil {
			return out, false
		}
		out[i] = n
	}
	return out, true
}

type cache struct {
	Checked time.Time `json:"checked"`
	Latest  string    `json:"latest"`
}

// Notifier checks in the background, at most once per Every, and remembers
// the answer in a small file so the next command can mention it.
type Notifier struct {
	path    string
	current string
	known   cache
	done    chan struct{}
}

// Start reads the cached answer and, when it is older than Every, asks again
// in the background. It never blocks.
func Start(ctx context.Context, cacheDir, current string, now time.Time) *Notifier {
	n := &Notifier{path: filepath.Join(cacheDir, "update.json"), current: current}
	if b, err := os.ReadFile(n.path); err == nil {
		_ = json.Unmarshal(b, &n.known)
	}
	if now.Sub(n.known.Checked) < Every {
		return n
	}
	n.done = make(chan struct{})
	go func() {
		defer close(n.done)
		ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		c := cache{Checked: now, Latest: n.known.Latest}
		if v, err := Latest(ctx, http.DefaultClient, Base()); err == nil {
			c.Latest = v
		}
		if b, err := json.Marshal(c); err == nil && os.MkdirAll(cacheDir, 0o700) == nil {
			_ = os.WriteFile(n.path, b, 0o600)
		}
		n.known = c
	}()
	return n
}

// Available waits up to max for a check in progress, then returns the newer
// version, or "" when there is none or nothing is known yet.
func (n *Notifier) Available(max time.Duration) string {
	if n.done != nil {
		select {
		case <-n.done:
		case <-time.After(max):
			return ""
		}
	}
	if Newer(n.known.Latest, n.current) {
		return n.known.Latest
	}
	return ""
}

// Install downloads version for goos/goarch, checks it against the release's
// sha256 list, and puts it in place of exe. Nothing changes if any step fails.
func Install(ctx context.Context, c *http.Client, base, version, goos, goarch, exe string) error {
	name := fmt.Sprintf("fenzi-%s-%s-%s", version, goos, goarch)
	sums, err := get(ctx, c, fmt.Sprintf("%s/fenzi-%s-sha256.txt", base, version), 1<<16)
	if err != nil {
		return fmt.Errorf("checksum list: %w", err)
	}
	want := ""
	sc := bufio.NewScanner(strings.NewReader(string(sums)))
	for sc.Scan() {
		if f := strings.Fields(sc.Text()); len(f) == 2 && f[1] == name {
			want = f[0]
		}
	}
	if want == "" {
		return fmt.Errorf("there is no %s for this machine", name)
	}
	bin, err := get(ctx, c, base+"/"+name, 256<<20)
	if err != nil {
		return fmt.Errorf("download: %w", err)
	}
	sum := sha256.Sum256(bin)
	if hex.EncodeToString(sum[:]) != want {
		return errors.New("the checksum did not match, so nothing was replaced")
	}
	tmp, err := os.CreateTemp(filepath.Dir(exe), ".fenzi-update-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(bin); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o755); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), exe)
}

func get(ctx context.Context, c *http.Client, url string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s answered %s", url, resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, limit))
}
