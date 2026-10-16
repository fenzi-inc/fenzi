// Package team is the CLI's client for the Team control plane: the hosted
// service, or fenzi server on one machine.
package team

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"fenzi/teamapi"
)

// DefaultServer is the hosted Team control plane. fenzi server on one
// machine is http://127.0.0.1:8787; pass it with login --server.
const DefaultServer = "https://fenzi.dev"

// ErrNotEnrolled means this machine has not signed in.
var ErrNotEnrolled = errors.New("not signed in")

// ErrPending means the browser has not approved the code yet.
var ErrPending = errors.New("authorization pending")

// Client talks to one Team server.
type Client struct {
	Base string
	HTTP *http.Client
}

func (c Client) base() string {
	if c.Base == "" {
		return DefaultServer
	}
	return c.Base
}

func (c Client) http() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return http.DefaultClient
}

// Start is the beginning of a device login.
type Start struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURL string `json:"verification_url"`
	Interval        int    `json:"interval"`
}

// Enrollment is what this machine keeps after login. The token never leaves it.
type Enrollment struct {
	Server  string `json:"server"`
	Token   string `json:"token"`
	Email   string `json:"email"`
	Name    string `json:"name"`
	Tenant  string `json:"tenant"`
	Machine string `json:"machine"`
	Admin   bool   `json:"admin"`
	// Role is admin, reviewer, developer, or auditor. Empty when the server
	// predates roles and sent only Admin; RoleName covers both.
	Role      string `json:"role,omitempty"`
	PublicKey string `json:"public_key"`
	Revision  int    `json:"revision"`
	Document  string `json:"document,omitempty"`
	// Format and Boundary are set when the cached bundle carries the team's
	// boundary (bundle format 2).
	Format    int    `json:"format,omitempty"`
	Boundary  string `json:"boundary,omitempty"`
	Published string `json:"published,omitempty"`
	Signature string `json:"signature,omitempty"`
	// Refused says why the last bundle the server sent was not taken, while
	// the cached revision stays in use. Empty once a good bundle arrives.
	Refused string `json:"refused,omitempty"`
}

// ErrUnverified means a bundle failed the signature check.
var ErrUnverified = errors.New("failed the signature check")

// ErrOlder means a bundle is older than the revision already cached.
var ErrOlder = errors.New("older than the cached revision")

func (c Client) StartDevice(ctx context.Context, machine string) (Start, error) {
	var out Start
	err := c.call(ctx, http.MethodPost, "/v1/device/start", "", map[string]string{"machine": machine}, &out)
	return out, err
}

func (c Client) Exchange(ctx context.Context, deviceCode string) (Enrollment, error) {
	var raw struct {
		Token     string          `json:"token"`
		Email     string          `json:"email"`
		Name      string          `json:"name"`
		Tenant    string          `json:"tenant"`
		Machine   string          `json:"machine"`
		Admin     bool            `json:"admin"`
		Role      string          `json:"role"`
		PublicKey string          `json:"public_key"`
		Error     string          `json:"error"`
		Bundle    json.RawMessage `json:"bundle"`
	}
	err := c.call(ctx, http.MethodPost, "/v1/device/token", "", map[string]string{"device_code": deviceCode}, &raw)
	if err != nil {
		return Enrollment{}, err
	}
	if raw.Error == "authorization_pending" {
		return Enrollment{}, ErrPending
	}
	en := Enrollment{
		Server: c.base(), Token: raw.Token, Email: raw.Email, Name: raw.Name,
		Tenant: raw.Tenant, Machine: raw.Machine, Admin: raw.Admin, Role: raw.Role, PublicKey: raw.PublicKey,
	}
	if len(raw.Bundle) > 0 && string(raw.Bundle) != "null" {
		if err := en.applyBundle(raw.Bundle); err != nil {
			return Enrollment{}, err
		}
	}
	return en, nil
}

// Take stores a newer verified bundle. The same revision is left as it is.
// An older revision is refused with ErrOlder, a bad one with ErrUnverified.
func (e *Enrollment) Take(b teamapi.Bundle) error {
	pub, err := base64.StdEncoding.DecodeString(e.PublicKey)
	if err != nil {
		return err
	}
	if err := teamapi.Verify(pub, b); err != nil {
		return fmt.Errorf("revision %d %w: %v", b.Revision, ErrUnverified, err)
	}
	if e.Revision > 0 && b.Revision < e.Revision {
		return fmt.Errorf("revision %d is %w (%d)", b.Revision, ErrOlder, e.Revision)
	}
	if b.Revision == e.Revision {
		return nil
	}
	w := teamapi.ToWire(b)
	e.Revision = w.Revision
	e.Document = w.Document
	e.Format = w.Format
	e.Boundary = w.Boundary
	e.Published = w.Published
	e.Signature = w.Signature
	return nil
}

// Me is the member this machine acts for, as the server sees them now.
type Me struct {
	Email   string `json:"email"`
	Name    string `json:"name"`
	Tenant  string `json:"tenant"`
	Machine string `json:"machine"`
	Admin   bool   `json:"admin"`
	// Role is empty from a server that predates roles.
	Role string `json:"role"`
}

// Me asks who this machine acts for. Roles change in the console after
// login, so status and publish ask rather than trust the enrollment.
func (c Client) Me(ctx context.Context, token string) (Me, error) {
	var out Me
	err := c.call(ctx, http.MethodGet, "/v1/me", token, nil, &out)
	return out, err
}

// RoleName is the member's role: admin, reviewer, developer, or auditor.
// A server that predates roles sends only the admin flag, which reads as
// admin or member.
func (e Enrollment) RoleName() string { return roleName(e.Role, e.Admin) }

// WithRole copies what the server said now over what login stored.
func (e Enrollment) WithRole(m Me) Enrollment {
	e.Admin, e.Role = m.Admin, m.Role
	return e
}

func roleName(role string, admin bool) string {
	switch {
	case role != "":
		return role
	case admin:
		return "admin"
	default:
		return "member"
	}
}

// Policy fetches the current signed bundle. A 404 means nothing is published.
func (c Client) Policy(ctx context.Context, token string) (teamapi.Bundle, bool, error) {
	var raw json.RawMessage
	status, err := c.callStatus(ctx, http.MethodGet, "/v1/policy", token, nil, &raw)
	if status == http.StatusNotFound {
		return teamapi.Bundle{}, false, nil
	}
	if err != nil {
		return teamapi.Bundle{}, false, err
	}
	b, err := teamapi.ParseBundle(raw)
	return b, err == nil, err
}

// Publish sends an org policy. The server proves it before it stores it.
func (c Client) Publish(ctx context.Context, token, document string) (teamapi.Bundle, error) {
	var raw json.RawMessage
	err := c.call(ctx, http.MethodPost, "/v1/revisions", token, map[string]string{"document": document}, &raw)
	if err != nil {
		return teamapi.Bundle{}, err
	}
	return teamapi.ParseBundle(raw)
}

// Ingest posts decision records. The count is how many were new.
func (c Client) Ingest(ctx context.Context, token string, records any) (int, error) {
	var out struct {
		Stored int `json:"stored"`
	}
	err := c.call(ctx, http.MethodPost, "/v1/decisions", token, map[string]any{"records": records}, &out)
	return out.Stored, err
}

// PutProposals reports pending requests for one sandbox. The server adds
// or refreshes them and leaves the others as they are.
func (c Client) PutProposals(ctx context.Context, token, sandbox string, proposals any) error {
	return c.call(ctx, http.MethodPost, "/v1/proposals", token, map[string]any{"sandbox": sandbox, "proposals": proposals}, nil)
}

// ReplaceProposals reports every request pending on one sandbox, an empty
// list included. The server takes a request it holds as pending for this
// machine and sandbox, and that is not in the list, as answered on the
// machine. A server that predates the call answers 405.
func (c Client) ReplaceProposals(ctx context.Context, token, sandbox string, proposals any) error {
	return c.call(ctx, http.MethodPut, "/v1/proposals", token, map[string]any{"sandbox": sandbox, "proposals": proposals}, nil)
}

// Applies lists reviews this machine still has to send to OpenShell.
func (c Client) Applies(ctx context.Context, token string) ([]teamapi.Proposal, error) {
	var out struct {
		Applies []teamapi.Proposal `json:"applies"`
	}
	err := c.call(ctx, http.MethodGet, "/v1/applies", token, nil, &out)
	return out.Applies, err
}

// ReleaseReview returns a review OpenShell refused. pending sends it back to the console.
func (c Client) ReleaseReview(ctx context.Context, token string, id int, pending bool) error {
	return c.call(ctx, http.MethodPost, fmt.Sprintf("/v1/proposals/%d/release", id), token, map[string]bool{"pending": pending}, nil)
}

// MarkApplied tells the server the review was sent to OpenShell.
func (c Client) MarkApplied(ctx context.Context, token string, id int) error {
	return c.call(ctx, http.MethodPost, fmt.Sprintf("/v1/applies/%d", id), token, map[string]any{}, nil)
}

// Revision fetches one signed revision.
func (c Client) Revision(ctx context.Context, token string, n int) (teamapi.Bundle, error) {
	var raw json.RawMessage
	if err := c.call(ctx, http.MethodGet, fmt.Sprintf("/v1/revisions/%d", n), token, nil, &raw); err != nil {
		return teamapi.Bundle{}, err
	}
	return teamapi.ParseBundle(raw)
}

// Beat is what a machine reports on each heartbeat.
type Beat struct {
	OpenShellVersion string `json:"openshell_version"`
	Driver           string `json:"driver"`
	PolicyRevision   int    `json:"policy_revision"`
	// ApprovalMode is the gateway-wide proposal_approval_mode, "" when unset
	// or unreadable.
	ApprovalMode string        `json:"approval_mode"`
	Sandboxes    []BeatSandbox `json:"sandboxes"`
	// Notes are what the machine wants the console to see, such as a bundle
	// it refused while it keeps its cached revision. Always sent, empty when
	// there is nothing, so the server can clear an earlier note. A server
	// that predates the field ignores it; an older CLI does not send it.
	Notes []string `json:"notes"`
}

// BeatSandbox is one sandbox in this machine's local state. Revision is the
// team revision it was started from, 0 when it was not.
type BeatSandbox struct {
	Name     string `json:"name"`
	Agent    string `json:"agent"`
	Revision int    `json:"revision"`
	Running  bool   `json:"running"`
	// PolicyCheck is teamapi.PolicyMatch, PolicyMismatch, or PolicyPending
	// for a sandbox the forwarder compared against Revision on this pass, and
	// empty otherwise. PolicyDiffers names the top-level policy sections that
	// differ. Neither carries any policy content.
	PolicyCheck   string   `json:"policy_check,omitempty"`
	PolicyDiffers []string `json:"policy_differs,omitempty"`
}

// Heartbeat tells the server what this machine is running.
func (c Client) Heartbeat(ctx context.Context, token string, b Beat) error {
	if b.Sandboxes == nil {
		b.Sandboxes = []BeatSandbox{}
	}
	if b.Notes == nil {
		b.Notes = []string{}
	}
	_, err := c.callStatus(ctx, http.MethodPost, "/v1/heartbeat", token, b, nil)
	return err
}

// Unreachable reports an error that never got an HTTP status from the server.
func Unreachable(err error) bool {
	var h *httpError
	return err != nil && !errors.As(err, &h) && !errors.Is(err, ErrPending)
}

// Status is the HTTP status of a server error, or 0.
func Status(err error) int {
	var h *httpError
	if errors.As(err, &h) {
		return h.Status
	}
	return 0
}

func (e *Enrollment) applyBundle(raw []byte) error {
	b, err := teamapi.ParseBundle(raw)
	if err != nil {
		return err
	}
	return e.Take(b)
}

// Bundle rebuilds the signed policy and checks the signature.
func (e Enrollment) Bundle() (teamapi.Bundle, error) {
	if e.Revision == 0 || e.Document == "" {
		return teamapi.Bundle{}, errors.New("no team policy cached")
	}
	raw, err := json.Marshal(teamapi.Wire{
		Tenant: e.Tenant, Revision: e.Revision, Format: e.Format, Document: e.Document,
		Boundary: e.Boundary, Published: e.Published, Signature: e.Signature,
	})
	if err != nil {
		return teamapi.Bundle{}, err
	}
	b, err := teamapi.ParseBundle(raw)
	if err != nil {
		return teamapi.Bundle{}, err
	}
	pub, err := base64.StdEncoding.DecodeString(e.PublicKey)
	if err != nil {
		return teamapi.Bundle{}, err
	}
	if err := teamapi.Verify(pub, b); err != nil {
		return teamapi.Bundle{}, err
	}
	return b, nil
}

type httpError struct {
	Status int
	Body   string
}

func (e *httpError) Error() string {
	if e.Body == "" {
		return fmt.Sprintf("team server returned %d", e.Status)
	}
	return stringsTrim(e.Body)
}

func stringsTrim(s string) string {
	if len(s) > 300 {
		s = s[:300]
	}
	return s
}

func (c Client) call(ctx context.Context, method, path, token string, body, dst any) error {
	_, err := c.callStatus(ctx, method, path, token, body, dst)
	return err
}

func (c Client) callStatus(ctx context.Context, method, path, token string, body, dst any) (int, error) {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base()+path, rdr)
	if err != nil {
		return 0, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := c.http().Do(req)
	if err != nil {
		return 0, err
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if res.StatusCode == http.StatusNoContent {
		return res.StatusCode, nil
	}
	if res.StatusCode >= 300 {
		var pending struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(raw, &pending)
		if pending.Error == "authorization_pending" {
			return res.StatusCode, ErrPending
		}
		msg := stringsTrim(string(raw))
		return res.StatusCode, &httpError{Status: res.StatusCode, Body: msg}
	}
	if dst != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, dst); err != nil {
			return res.StatusCode, err
		}
	}
	return res.StatusCode, nil
}
