package forward

import (
	"strings"
	"testing"
)

// Synthetic events shaped like OCSF 1.x. Replace them with recorded output
// once OpenShell's JSON events have been captured.
const events = `{"time":1759484527000,"class_name":"HTTP Activity","action":"Denied","container":{"uid":"c1"},"dst_endpoint":{"domain":"api.github.com","port":443},"http_request":{"http_method":"POST","url":{"path":"/repos/acme/web/hooks?token=secret"}},"actor":{"process":{"name":"gh"}},"firewall_rule":{"name":"api_github_com"},"http_headers":[{"name":"Authorization","value":"Bearer x"}]}
{"time":1759484528000,"class_name":"Network Activity","action":"Denied","dst_endpoint":{"domain":"paste.example.net","port":443},"actor":{"process":{"name":"curl"}}}
not json
{"time":1759484529000,"class_name":"Network Activity","action":"Allowed","dst_endpoint":{"domain":"pypi.org","port":443},"actor":{"process":{"name":"python3.11"}},"firewall_rule":{"name":"pypi_org"}}
`

func TestReadJSONL(t *testing.T) {
	recs, skipped, err := ReadJSONL(strings.NewReader(events), "fenzi-web-4f2a")
	if err != nil {
		t.Fatal(err)
	}
	if skipped != 1 || len(recs) != 3 {
		t.Fatalf("got %d records, %d skipped", len(recs), skipped)
	}
	r := recs[0]
	if r.Destination != "POST api.github.com/repos/acme/web/hooks" {
		t.Errorf("destination = %q; the query string must be dropped", r.Destination)
	}
	if r.Sandbox != "fenzi-web-4f2a" || r.Process != "gh" || r.Rule != "api_github_com" || !r.Denied() {
		t.Errorf("record = %+v", r)
	}
	if r.Time.Unix() != 1759484527 {
		t.Errorf("time = %v", r.Time)
	}
	if recs[1].Destination != "paste.example.net:443" {
		t.Errorf("destination = %q", recs[1].Destination)
	}
	if recs[2].Denied() {
		t.Error("allowed event reported as denied")
	}
}

func TestRecordCarriesNoSecrets(t *testing.T) {
	recs, _, _ := ReadJSONL(strings.NewReader(events), "s")
	for _, r := range recs {
		s := r.Destination + r.Process + r.Rule + r.Class
		if strings.Contains(s, "secret") || strings.Contains(s, "Bearer") {
			t.Errorf("record leaks request data: %+v", r)
		}
	}
}
