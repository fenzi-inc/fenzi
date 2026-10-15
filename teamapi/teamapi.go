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

// Bundle is one published policy revision. Document is the org policy as
// submitted. The signature covers Tenant, Revision, Published, and Document.
type Bundle struct {
	Tenant    string
	Revision  int
	Document  []byte
	Published time.Time
	Signature []byte
}

// Message is the signed bytes: the tenant, the revision, and the published
// time in RFC 3339 with nanoseconds, each on its own line, then the document.
func Message(b Bundle) []byte {
	head := fmt.Sprintf("%s\n%d\n%s\n", b.Tenant, b.Revision, b.Published.UTC().Format(time.RFC3339Nano))
	return append([]byte(head), b.Document...)
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

// Wire is a bundle as the API sends it.
type Wire struct {
	Tenant    string `json:"tenant"`
	Revision  int    `json:"revision"`
	Document  string `json:"document"`
	Published string `json:"published"`
	Signature string `json:"signature"`
}

// ToWire is the API form of a bundle.
func ToWire(b Bundle) Wire {
	return Wire{
		Tenant:    b.Tenant,
		Revision:  b.Revision,
		Document:  string(b.Document),
		Published: b.Published.UTC().Format(time.RFC3339Nano),
		Signature: base64.StdEncoding.EncodeToString(b.Signature),
	}
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
	return Bundle{Tenant: w.Tenant, Revision: w.Revision, Document: []byte(w.Document), Published: published, Signature: sig}, nil
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
}
