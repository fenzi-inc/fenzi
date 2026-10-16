package run

import (
	"errors"
	"testing"

	"fenzi/compiler"
)

func TestWithHost(t *testing.T) {
	doc := &compiler.Document{Version: 1, Hosts: []compiler.Host{
		{Host: "registry.npmjs.org", Access: compiler.AccessReadOnly},
		{Host: "api.github.com", Port: 443, Access: compiler.AccessReadWrite, Allow: []string{"POST /repos/acme/web/pulls"}},
	}}

	if _, changed, err := WithHost(doc, compiler.Host{Host: "registry.npmjs.org", Port: 443, Access: compiler.AccessReadOnly}); changed || err != nil {
		t.Fatalf("read-only host again: changed=%v err=%v", changed, err)
	}
	next, changed, err := WithHost(doc, compiler.Host{Host: "pypi.org", Port: 443, Access: compiler.AccessReadOnly})
	if !changed || err != nil || len(next.Hosts) != 3 || len(doc.Hosts) != 2 {
		t.Fatalf("new host: changed=%v err=%v hosts=%v original=%v", changed, err, next.Hosts, doc.Hosts)
	}
	next, changed, err = WithHost(doc, compiler.Host{Host: "api.github.com", Port: 443, Access: compiler.AccessReadWrite, Allow: []string{"POST /repos/acme/web/issues"}})
	if !changed || err != nil || len(next.Hosts[1].Allow) != 2 || len(doc.Hosts[1].Allow) != 1 {
		t.Fatalf("added allow line: changed=%v err=%v next=%v original=%v", changed, err, next.Hosts[1].Allow, doc.Hosts[1].Allow)
	}
	if _, _, err := WithHost(doc, compiler.Host{Host: "registry.npmjs.org", Port: 443, Access: compiler.AccessReadWrite, Allow: []string{"PUT /x"}}); !errors.Is(err, ErrNarrower) {
		t.Fatalf("write to a read-only host: %v", err)
	}
}

func TestApprovedHostsRoundTrip(t *testing.T) {
	dir := t.TempDir()
	if hosts, err := LoadApproved(dir); err != nil || hosts != nil {
		t.Fatalf("empty: %v %v", hosts, err)
	}
	for _, h := range []string{"pypi.org", "files.pythonhosted.org"} {
		if err := SaveApproved(dir, compiler.Host{Host: h, Port: 443, Access: compiler.AccessReadOnly}); err != nil {
			t.Fatal(err)
		}
	}
	hosts, err := LoadApproved(dir)
	if err != nil || len(hosts) != 2 || hosts[1].Host != "files.pythonhosted.org" {
		t.Fatalf("%v %v", hosts, err)
	}
}
