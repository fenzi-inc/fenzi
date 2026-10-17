package screen

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"text/tabwriter"
)

func TestPlainLayoutMatchesPrintf(t *testing.T) {
	var buf bytes.Buffer
	s := Screen{w: &buf}
	s.Label("policy", "developer-default")
	s.Label("", "M  src/api/client.ts")
	s.Check("ok", "Runtime", "0.1.2")
	s.Check("FAIL", "Gateway", "not connected")
	s.Check("--", "Plan", "Free, this machine")

	want := "" +
		fmt.Sprintf("%-9s %s\n", "policy", "developer-default") +
		fmt.Sprintf("%-9s %s\n", "", "M  src/api/client.ts") +
		fmt.Sprintf("%-4s  %-18s %s\n", "ok", "Runtime", "0.1.2") +
		fmt.Sprintf("%-4s  %-18s %s\n", "FAIL", "Gateway", "not connected") +
		fmt.Sprintf("%-4s  %-18s %s\n", "--", "Plan", "Free, this machine")
	if buf.String() != want {
		t.Fatalf("plain layout:\n got %q\nwant %q", buf.String(), want)
	}
}

func TestTableMatchesTabwriter(t *testing.T) {
	rows := [][]Cell{
		{{Text: "time"}, {Text: "action"}, {Text: "process"}, {Text: "destination"}, {Text: "rule"}},
		{{Text: "10:42:05", Tone: "allow"}, {Text: "allowed", Tone: "allow"}, {Text: "claude"}, {Text: "POST api.anthropic.com/v1/messages"}, {Text: "_provider_fenzi_claude"}},
		{{Text: "10:42:07"}, {Text: "denied", Tone: "deny"}, {Text: "curl"}, {Text: "paste.example.net:443"}, {Text: "-"}},
	}
	var got bytes.Buffer
	Screen{w: &got}.Table(rows)

	var want bytes.Buffer
	tw := tabwriter.NewWriter(&want, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "time\taction\tprocess\tdestination\trule")
	fmt.Fprintln(tw, "10:42:05\tallowed\tclaude\tPOST api.anthropic.com/v1/messages\t_provider_fenzi_claude")
	fmt.Fprintln(tw, "10:42:07\tdenied\tcurl\tpaste.example.net:443\t-")
	tw.Flush()
	if got.String() != want.String() {
		t.Fatalf("table:\n got %q\nwant %q", got.String(), want.String())
	}
}

func TestColorDoesNotChangeVisibleText(t *testing.T) {
	var buf bytes.Buffer
	s := Screen{w: &buf, color: true}
	s.Check("ok", "Runtime", "0.1.2")
	s.Check("FAIL", "Approvals", "a person is missing")
	s.Label("policy", "developer-default")
	plain := strip(buf.String())
	if strings.Contains(plain, "\x1b") {
		t.Fatalf("escapes left in %q", plain)
	}
	if !strings.Contains(buf.String(), "\x1b[") {
		t.Fatal("expected color codes")
	}
	if !strings.Contains(plain, "ok    Runtime") || !strings.Contains(plain, "FAIL  Approvals") || !strings.Contains(plain, "policy    developer-default") {
		t.Fatalf("visible text changed: %q", plain)
	}
	if strings.Contains(buf.String(), allowOn) || strings.Contains(buf.String(), denyOn) {
		t.Fatal("checks must not use allow or deny colors")
	}
}

func strip(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != 0x1b {
			b.WriteByte(s[i])
			continue
		}
		j := strings.IndexByte(s[i:], 'm')
		if j < 0 {
			break
		}
		i += j
	}
	return b.String()
}
