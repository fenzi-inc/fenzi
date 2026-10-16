package relay

import (
	"context"
	"testing"
)

func TestRequestsCarryTheAccessTheyNeed(t *testing.T) {
	// The first three Endpoints shapes are recorded from OpenShell 0.1.2. The
	// fourth is the recorded allow shape with a write method, and the fifth
	// a shape that has not been recorded.
	rules := `  Chunk: ccd96a39-17bd-4710-af49-c88725b0540f
  Status: pending
  Binary: /usr/bin/curl
  Rationale: Need a single read-only GET of the homepage with curl.
  Endpoints: www.example.com:443 [L7 rest, allow GET /]

  Chunk: 59b83e6d-8a8a-43e4-a597-066a5d16fc36
  Status: pending
  Binary: /usr/lib/git-core/git-remote-http
  Rationale: Allow git-remote-http to connect to github.com:443 (HTTPS).
  Endpoints: github.com:443 [L4]

  Chunk: df10f171-e5d2-41f0-b4f5-b58fa89ca326
  Status: pending
  Binary: /usr/bin/curl
  Rationale: Allow curl to connect to registry.npmjs.org:443 (HTTPS).
  Endpoints: registry.npmjs.org:443 [L7 rest, access=read-only]

  Chunk: 00000000-0000-4000-8000-000000000004
  Status: pending
  Binary: /usr/bin/curl
  Rationale: Create the thing the task needs.
  Endpoints: api.example.com:8443 [L7 rest, allow POST /v1/things]

  Chunk: 00000000-0000-4000-8000-000000000005
  Status: pending
  Binary: /usr/bin/curl
  Rationale: Something else.
  Endpoints: paste.example.net:443 [L7]
`
	f, opt := fakeFixture(t, &fakeGW{rules: []byte(rules)})
	if _, err := Pass(context.Background(), opt); err != nil {
		t.Fatal(err)
	}
	if len(f.proposals) != 5 {
		t.Fatalf("proposals %+v", f.proposals)
	}
	type want struct {
		access string
		allow  string
		l4     bool
	}
	wants := map[string]want{
		"www.example.com:443":    {access: "read-only"},
		"github.com:443":         {access: "read-only", l4: true},
		"registry.npmjs.org:443": {access: "read-only"},
		"api.example.com:8443":   {access: "read-write", allow: "POST /v1/things"},
		"paste.example.net:443":  {},
	}
	for _, p := range f.proposals {
		w, ok := wants[p.Destination]
		allow := ""
		if len(p.Allow) == 1 {
			allow = p.Allow[0]
		}
		if !ok || p.Access != w.access || p.L4 != w.l4 || allow != w.allow || len(p.Allow) > 1 {
			t.Errorf("%s: access %q allow %v l4 %v", p.Destination, p.Access, p.Allow, p.L4)
		}
	}
}
