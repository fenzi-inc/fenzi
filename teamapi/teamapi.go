// Package teamapi is what a machine and a Team control plane agree on: the
// signed policy bundle and how to verify it, and the request a person reviews.
// The CLI verifies every bundle with the team's public key before it uses it;
// a bad signature or an older revision is refused.
package teamapi

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Bundle formats. Format 1 signs the policy document alone; every bundle
// before team boundaries is format 1, and a bundle without a boundary still
// is, so a CLI that knows only format 1 keeps verifying it. Format 2 also
// signs the team's boundary document.
const (
	FormatDocument = 1
	FormatBoundary = 2
)

// Bundle is one published policy revision. Document is the org policy as
// submitted. Boundary, when set, is the team's boundary document: the most
// any of its policies may allow, in the same schema. The signature covers
// Tenant, Revision, Published, Document, and in format 2 Boundary.
type Bundle struct {
	Tenant   string
	Revision int
	// Format is FormatDocument or FormatBoundary. Zero means FormatDocument.
	Format    int
	Document  []byte
	Boundary  []byte
	Published time.Time
	Signature []byte
}

// formatHead starts every format 2 message. A format 1 message starts with
// the tenant and then the revision number, so the two cannot be confused:
// a tenant cannot hold a space, and "acme" is not a revision number.
const formatHead = "boundlane bundle 2\n"

// Message is the signed bytes.
//
// Format 1: the tenant, the revision, and the published time in RFC 3339 with
// nanoseconds, each on its own line, then the document.
//
// Format 2: the line "boundlane bundle 2", the same three lines, then the
// document's length in bytes on its own line and the document, then the
// boundary's length on its own line and the boundary.
func Message(b Bundle) []byte {
	published := b.Published.UTC().Format(time.RFC3339Nano)
	if b.Format == FormatBoundary {
		head := fmt.Sprintf("%s%s\n%d\n%s\n%d\n", formatHead, b.Tenant, b.Revision, published, len(b.Document))
		out := append([]byte(head), b.Document...)
		out = append(out, fmt.Sprintf("%d\n", len(b.Boundary))...)
		return append(out, b.Boundary...)
	}
	head := fmt.Sprintf("%s\n%d\n%s\n", b.Tenant, b.Revision, published)
	return append([]byte(head), b.Document...)
}

// FormatFor is the format a signer uses: 2 when there is a boundary, else 1,
// which every CLI can verify.
func FormatFor(boundary []byte) int {
	if len(boundary) > 0 {
		return FormatBoundary
	}
	return FormatDocument
}

// Verify checks the signature and the required fields. It does not compare
// revisions. Accept does that.
func Verify(pub ed25519.PublicKey, b Bundle) error {
	switch {
	case b.Tenant == "":
		return errors.New("bundle has no tenant")
	case b.Revision < 1:
		return fmt.Errorf("bundle revision %d is not valid", b.Revision)
	case len(b.Document) == 0:
		return errors.New("bundle has no policy document")
	case b.Format > FormatBoundary:
		return fmt.Errorf("bundle format %d is newer than this boundlane knows; run boundlane update", b.Format)
	case b.Format < 0:
		return fmt.Errorf("bundle format %d is not valid", b.Format)
	case b.Format != FormatBoundary && len(b.Boundary) > 0:
		return errors.New("bundle carries a boundary its signature does not cover")
	case len(pub) != ed25519.PublicKeySize:
		return errors.New("team public key is missing")
	case !ed25519.Verify(pub, Message(b), b.Signature):
		return errors.New("policy signature does not verify")
	}
	return nil
}

// Accept is the check a machine runs before it replaces its cached policy.
// have is the revision it already trusts. Zero means it has none.
func Accept(pub ed25519.PublicKey, have int, b Bundle) error {
	if err := Verify(pub, b); err != nil {
		return err
	}
	if have > 0 && b.Revision <= have {
		return fmt.Errorf("revision %d is not newer than %d", b.Revision, have)
	}
	return nil
}

// Wire is a bundle as the API sends it. A format 1 bundle has neither format
// nor boundary, so it is the same JSON a CLI from before boundaries reads.
type Wire struct {
	Tenant    string `json:"tenant"`
	Revision  int    `json:"revision"`
	Format    int    `json:"format,omitempty"`
	Document  string `json:"document"`
	Boundary  string `json:"boundary,omitempty"`
	Published string `json:"published"`
	Signature string `json:"signature"`
}

// ToWire is the API form of a bundle.
func ToWire(b Bundle) Wire {
	w := Wire{
		Tenant:    b.Tenant,
		Revision:  b.Revision,
		Document:  string(b.Document),
		Published: b.Published.UTC().Format(time.RFC3339Nano),
		Signature: base64.StdEncoding.EncodeToString(b.Signature),
	}
	if b.Format > FormatDocument {
		w.Format = b.Format
		w.Boundary = string(b.Boundary)
	}
	return w
}

// ParseBundle reads a bundle from the API's JSON form.
func ParseBundle(data []byte) (Bundle, error) {
	var w Wire
	if err := json.Unmarshal(data, &w); err != nil {
		return Bundle{}, err
	}
	sig, err := base64.StdEncoding.DecodeString(w.Signature)
	if err != nil {
		return Bundle{}, err
	}
	published, err := time.Parse(time.RFC3339Nano, w.Published)
	if err != nil {
		return Bundle{}, err
	}
	b := Bundle{Tenant: w.Tenant, Revision: w.Revision, Format: w.Format, Document: []byte(w.Document), Published: published, Signature: sig}
	if w.Boundary != "" {
		b.Boundary = []byte(w.Boundary)
	}
	return b, nil
}

// Proposal is a request for more access, filed on a machine and reviewed in
// the console. A machine applies a review with OpenShell's rule approve or
// rule reject on its own gateway.
type Proposal struct {
	ID          int    `json:"id"`
	Chunk       string `json:"chunk"`
	Sandbox     string `json:"sandbox"`
	Machine     string `json:"machine"`
	Destination string `json:"destination"`
	Binary      string `json:"binary,omitempty"`
	Rationale   string `json:"rationale,omitempty"`
	Prover      string `json:"prover,omitempty"`
	Status      string `json:"status"`
	Reviewer    string `json:"reviewer,omitempty"`
	Reason      string `json:"reason,omitempty"`
	Applied     bool   `json:"applied"`
	// Draft is true when the sandbox drafted the request from a refused
	// connection, and false when the agent filed it. The machine decides with
	// the rule boundlane requests uses. A server that predates the field
	// reads every request as filed by the agent.
	Draft bool `json:"draft"`
	// Revision is the team revision the machine held when it reported the
	// request, 0 when it held none.
	Revision int `json:"revision,omitempty"`
	// Rule is the rule name OpenShell gave the request. Once the request is
	// approved, the decisions it allows carry that name. Only the full list
	// (PUT /v1/proposals) sends it: a server that predates the field refuses
	// it on the older call.
	Rule string `json:"rule,omitempty"`
}

// Results of the policy compare a machine reports for each sandbox in its
// heartbeat, as "policy_check", with the top-level sections that differ in
// "policy_differs". The forwarder reads the policy the runtime holds for a
// running sandbox and compares it, section by section, with the policy
// compiled from the team revision the sandbox runs, leaving out the rules the
// runtime adds for a provider. A sandbox that was not compared on a pass
// carries neither field, and a server keeps the last result it had for it.
// A server that predates the fields ignores them.
const (
	PolicyMatch    = "match"
	PolicyMismatch = "mismatch"
	// PolicyPending means the forwarder loaded the revision and the runtime
	// has not confirmed it Loaded, so the sandbox was not compared.
	PolicyPending = "pending"
)
