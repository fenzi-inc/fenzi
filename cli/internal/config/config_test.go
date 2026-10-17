package config

import (
	"testing"
	"time"
)

func TestLatestIn(t *testing.T) {
	s := &State{Sandboxes: []Sandbox{
		{Name: "trial", Repo: "/code/fenzi-trial", Created: time.Unix(1, 0), Running: true},
		{Name: "trial-old", Repo: "/code/fenzi-trial", Created: time.Unix(0, 0)},
		{Name: "other", Repo: "/code/fenzi-request", Created: time.Unix(2, 0)},
		{Name: "prefix", Repo: "/code/bl", Created: time.Unix(3, 0)},
	}}
	for dir, want := range map[string]string{
		"/code/fenzi-trial":     "trial",
		"/code/fenzi-trial/src": "trial",
		"/code/fenzi-request":   "other",
		"/code/bl/x":            "prefix",
	} {
		if sb, ok := s.LatestIn(dir, false); !ok || sb.Name != want {
			t.Errorf("LatestIn(%s) = %q, want %q", dir, sb.Name, want)
		}
	}
	if sb, ok := s.LatestIn("/code/fenzi-trial-2", false); ok {
		t.Errorf("a folder whose name only starts like a project must not match, got %s", sb.Name)
	}
	if _, ok := s.LatestIn("/code/fenzi-request", true); ok {
		t.Error("runningOnly must skip finished sandboxes")
	}
}
