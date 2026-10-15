//go:build team

package openshell

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"time"

	datamodel "github.com/NVIDIA/OpenShell/sdk/go/proto/datamodelv1"
	pb "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)

// The gateway's WatchSandbox stream is the one behind `openshell logs`. It is
// read with the generated client of the upstream Go SDK at the v0.1.2 commit;
// the SDK's own Watch helper does not pass a resume cursor. Checked against
// OpenShell 0.1.2:
//
//   - The CLI's mTLS files for the gateway named "openshell" are in
//     ~/.config/openshell/gateways/openshell/mtls/ (ca.crt, tls.crt, tls.key).
//   - Every log event carries a cursor, such as
//     v1:6b2b79f4-f923-4ba9-9041-5e954f5d3321:00000000000000000023. The
//     sequence is zero-padded, so the byte-wise comparison the proto
//     documents keeps the highest. Resuming after the highest cursor replays
//     nothing; after an earlier one, exactly the later events.
//   - A cursor from another cursor space ends the stream with OUT_OF_RANGE,
//     "Restart the watch with an empty resume_after_cursor"; a malformed one
//     with INVALID_ARGUMENT.
//   - OCSF lines arrive with level "OCSF" and the shorthand text without its
//     time and source prefix.
//
// What a gateway restart does to cursors was not tried.

// StreamLine is one log event from the stream.
type StreamLine struct {
	Cursor  string
	Time    time.Time
	Level   string
	Message string
}

// StreamRead is what one read of a sandbox's stream returned.
type StreamRead struct {
	Lines []StreamLine
	// Cursor is the highest cursor seen, or the one the read resumed after.
	Cursor string
	// Warnings are SandboxStreamWarning messages: events the gateway lost.
	Warnings []string
	// Reset is the gateway's message when it refused the resume cursor. The
	// read then started again without one.
	Reset string
}

// ErrNoStream means this machine has no client certificate for the gateway's
// stream. Callers read the log with `openshell logs` instead.
var ErrNoStream = errors.New("the gateway log stream needs the CLI's mTLS files")

// Watch reads sandbox log streams from the active gateway. It holds one
// connection until Close.
type Watch struct {
	Client Client
	// Idle ends a read when no event arrived for this long. Later events are
	// read on the next call, after the cursor.
	Idle time.Duration
	// Max bounds one read of a busy sandbox.
	Max time.Duration

	dial func(ctx context.Context) (*grpc.ClientConn, error)
	conn *grpc.ClientConn
}

// NewWatch returns a Watch on the gateway that c reports in `openshell status`.
func NewWatch(c Client) *Watch { return &Watch{Client: c} }

// Close drops the connection.
func (w *Watch) Close() error {
	if w.conn == nil {
		return nil
	}
	err := w.conn.Close()
	w.conn = nil
	return err
}

// ReadStream reads the sandbox's log events after the cursor, or its last
// tail lines when there is no cursor, and returns once the stream goes quiet.
// A refused cursor restarts the read without it and sets Reset.
func (w *Watch) ReadStream(ctx context.Context, sandbox, after string, tail int) (StreamRead, error) {
	if w.conn == nil {
		dial := w.dial
		if dial == nil {
			dial = w.dialGateway
		}
		conn, err := dial(ctx)
		if err != nil {
			return StreamRead{Cursor: after}, err
		}
		w.conn = conn
	}
	read, err := w.read(ctx, sandbox, after, tail)
	if code := status.Code(err); after != "" && (code == codes.OutOfRange || code == codes.InvalidArgument) {
		reset := status.Convert(err).Message()
		read, err = w.read(ctx, sandbox, "", tail)
		read.Reset = reset
	}
	return read, err
}

func (w *Watch) read(ctx context.Context, sandbox, after string, tail int) (StreamRead, error) {
	idle, most := w.Idle, w.Max
	if idle <= 0 {
		idle = 1500 * time.Millisecond
	}
	if most <= 0 {
		most = 10 * time.Second
	}
	read := StreamRead{Cursor: after}
	rctx, cancel := context.WithTimeout(ctx, most)
	defer cancel()
	req := &pb.WatchSandboxRequest{
		WorkspaceScope:    &datamodel.WorkspaceSelector{Selection: &datamodel.WorkspaceSelector_Workspace{Workspace: "default"}},
		Sandbox:           sandbox,
		FollowLogs:        true,
		LogSources:        []string{"sandbox"},
		ResumeAfterCursor: after,
	}
	if after == "" && tail > 0 {
		req.LogTailLines = uint32(tail)
	}
	stream, err := pb.NewOpenShellClient(w.conn).WatchSandbox(rctx, req)
	if err != nil {
		return read, err
	}
	type recv struct {
		ev  *pb.SandboxStreamEvent
		err error
	}
	ch := make(chan recv)
	go func() {
		for {
			ev, err := stream.Recv()
			select {
			case ch <- recv{ev, err}:
			case <-rctx.Done():
				return
			}
			if err != nil {
				return
			}
		}
	}()
	timer := time.NewTimer(idle)
	defer timer.Stop()
	got := false
	for {
		select {
		case <-timer.C:
			return read, nil
		case <-rctx.Done():
			return read, ctx.Err()
		case r := <-ch:
			if r.err != nil {
				// An error after events is the end of this read; the next one
				// resumes after the cursor. One before any event is the answer.
				if errors.Is(r.err, io.EOF) || got {
					return read, nil
				}
				return read, r.err
			}
			got = true
			if c := r.ev.GetCursor(); c > read.Cursor {
				read.Cursor = c
			}
			switch p := r.ev.Payload.(type) {
			case *pb.SandboxStreamEvent_Log:
				l := p.Log
				read.Lines = append(read.Lines, StreamLine{
					Cursor: r.ev.GetCursor(), Time: l.GetEventTime().AsTime(), Level: l.GetLevel(), Message: l.GetMessage(),
				})
			case *pb.SandboxStreamEvent_Warning:
				read.Warnings = append(read.Warnings, p.Warning.GetMessage())
			}
			timer.Reset(idle)
		}
	}
}

var gatewayName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// dialGateway connects to the gateway `openshell status` names, with the
// CLI's client certificate for it. The status JSON, as recorded from 0.1.2:
// {"gateway":"openshell","server":"https://localhost:17670",...}
func (w *Watch) dialGateway(ctx context.Context) (*grpc.ClientConn, error) {
	out, err := w.Client.Status(ctx)
	if err != nil {
		return nil, err
	}
	var s struct {
		Gateway string `json:"gateway"`
		Server  string `json:"server"`
	}
	if err := json.Unmarshal(out, &s); err != nil {
		return nil, fmt.Errorf("openshell status: unreadable output")
	}
	u, err := url.Parse(s.Server)
	if err != nil || u.Scheme != "https" || u.Host == "" || !gatewayName.MatchString(s.Gateway) {
		return nil, ErrNoStream
	}
	creds, err := mtlsCreds(filepath.Join(configHome(), "openshell", "gateways", s.Gateway, "mtls"))
	if err != nil {
		return nil, err
	}
	return grpc.NewClient(u.Host, grpc.WithTransportCredentials(creds))
}

func mtlsCreds(dir string) (credentials.TransportCredentials, error) {
	cert, err := tls.LoadX509KeyPair(filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key"))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNoStream
	}
	if err != nil {
		return nil, err
	}
	ca, err := os.ReadFile(filepath.Join(dir, "ca.crt"))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNoStream
	}
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, fmt.Errorf("%s: no certificate", filepath.Join(dir, "ca.crt"))
	}
	return credentials.NewTLS(&tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: pool, MinVersion: tls.VersionTLS12}), nil
}

// configHome is where the OpenShell CLI keeps gateway files: XDG_CONFIG_HOME,
// else ~/.config, the layout the upstream SDK's gateway package reads.
func configHome() string {
	if d := os.Getenv("XDG_CONFIG_HOME"); filepath.IsAbs(d) {
		return d
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config")
}
