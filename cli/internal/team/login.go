package team

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"fenzi/cli/internal/tui"
)

// Login prints the code and waits until someone approves it in the browser.
func Login(ctx context.Context, c Client, machine string, out io.Writer) (Enrollment, error) {
	start, err := c.StartDevice(ctx, machine)
	if err != nil {
		return Enrollment{}, err
	}
	u := tui.ForOutput(out)
	u.Title("Sign in", "")
	u.Done("Open", start.VerificationURL)
	u.Done("Code", start.UserCode)
	u.Note("Approve it in the browser.")
	interval := time.Duration(start.Interval) * time.Second
	if interval < time.Second {
		interval = time.Second
	}
	for {
		en, err := c.Exchange(ctx, start.DeviceCode)
		if errors.Is(err, ErrPending) {
			timer := time.NewTimer(interval)
			select {
			case <-ctx.Done():
				timer.Stop()
				return Enrollment{}, ctx.Err()
			case <-timer.C:
			}
			continue
		}
		if err != nil {
			return Enrollment{}, err
		}
		u.Done("Signed in", en.Email+", team "+en.Tenant)
		u.Done("Machine", en.Machine+", enrolled")
		if en.Revision == 0 {
			u.Skip("Policy", "none published yet")
		} else {
			u.Done("Policy", fmt.Sprintf("%s r%d, verified and cached", en.Tenant, en.Revision))
		}
		u.Blank()
		return en, nil
	}
}

// ErrTokenRefused means the server did not take a token: it was signed
// out in the console, or it is not a machine token of a team.
var ErrTokenRefused = errors.New("the server refused the token")

// LoginToken signs in with the token of a machine that an earlier device
// login enrolled, for a CI runner where nobody can open a browser. The
// member, the team and the machine are the token's, as the server says;
// the public key and the policy come from the same server, as they do in
// a device login, and the policy is checked against the key before it is
// cached.
func LoginToken(ctx context.Context, c Client, token string) (Enrollment, error) {
	me, err := c.Me(ctx, token)
	if Status(err) == http.StatusUnauthorized || Status(err) == http.StatusForbidden {
		return Enrollment{}, ErrTokenRefused
	}
	if err != nil {
		return Enrollment{}, err
	}
	key, err := c.Key(ctx, token)
	if err != nil {
		return Enrollment{}, err
	}
	en := Enrollment{
		Server: c.base(), Token: token, Email: me.Email, Name: me.Name, Tenant: me.Tenant,
		Machine: me.Machine, Admin: me.Admin, Role: me.Role, PublicKey: key,
	}
	b, ok, err := c.Policy(ctx, token)
	if err != nil {
		return Enrollment{}, err
	}
	if ok {
		if err := en.Take(b); err != nil {
			return Enrollment{}, fmt.Errorf("the team policy r%d %w", b.Revision, err)
		}
	}
	return en, nil
}

// ErrNoPolicy means the server could not be reached and no policy is cached.
var ErrNoPolicy = errors.New("control plane unreachable, and no policy is cached")

// Refresh fetches the current policy. If the server cannot be reached, the
// cached policy is kept after its signature is checked again. A bundle that
// fails the signature check or is older than the cached one is not taken:
// the cached revision stays in use, is checked again, and the note says so,
// and e.Refused keeps the note for the heartbeat. With nothing cached such a
// bundle is still an error.
func Refresh(ctx context.Context, c Client, e Enrollment) (Enrollment, string, error) {
	b, ok, err := c.Policy(ctx, e.Token)
	if err != nil {
		if e.Revision == 0 {
			return e, "", ErrNoPolicy
		}
		if _, verr := e.Bundle(); verr != nil {
			return e, "", verr
		}
		if Status(err) == http.StatusUnauthorized {
			// Signed out in the console. The gateway keeps enforcing what it has.
			return e, fmt.Sprintf("this machine was signed out of team %s, still using r%d. Run fenzi login", e.Tenant, e.Revision), nil
		}
		return e, fmt.Sprintf("control plane unreachable, using %s r%d", e.Tenant, e.Revision), nil
	}
	if !ok {
		if e.Revision == 0 {
			return e, "no policy published yet", nil
		}
		return e, "", nil
	}
	if err := e.Take(b); err != nil {
		var note string
		switch {
		case errors.Is(err, ErrUnverified):
			note = fmt.Sprintf("the server sent r%d, which failed the signature check; still on r%d", b.Revision, e.Revision)
		case errors.Is(err, ErrOlder):
			note = fmt.Sprintf("the server sent r%d, older than r%d; still on r%d", b.Revision, e.Revision, e.Revision)
		default:
			return e, "", err
		}
		if e.Revision == 0 {
			return e, "", err
		}
		if _, verr := e.Bundle(); verr != nil {
			return e, "", verr
		}
		e.Refused = note
		return e, note, nil
	}
	e.Refused = ""
	return e, "", nil
}
