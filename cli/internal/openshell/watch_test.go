package openshell

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	pb "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Messages recorded from the gateway's watch stream, OpenShell 0.1.2. The
// approval is the shorthand line recorded in a Codex session without its
// prefix; the host is replaced.
const (
	streamAllow    = "NET:OPEN [INFO] ALLOWED /usr/local/lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe(0) -> api.anthropic.com:443 [policy:_provider_fenzi_claude engine:opa]"
	streamApproval = "CONFIG:APPROVED [INFO] chunk:fad7c2ed-3aca-4fb7-bb37-495820dd7562 approved on example.com:443 HEAD / by /usr/bin/curl"
	// Recorded from OpenShell 0.1.4 for a cursor from another cursor space,
	// after the sandbox snapshot the stream always sends first.
	streamOutOfRange = "resume_after_cursor belongs to a cursor space that no longer exists; the gateway restarted or the sandbox's buffers were torn down. Restart the watch with an empty resume_after_cursor. Events published in the meantime are not recoverable."
)

// fakeShell replays a stream in one cursor space, "v1:s1:<n>", the way
// OpenShell 0.1.4 answered on 19 October 2026: a cursor it cannot parse is
// refused before anything is sent; otherwise the sandbox's snapshot comes
// first, with no cursor, and a cursor from another space is refused after it.
type fakeShell struct {
	pb.UnimplementedOpenShellServer
	mu     sync.Mutex
	reqs   []*pb.WatchSandboxRequest
	events []*pb.SandboxStreamEvent
}

func (f *fakeShell) WatchSandbox(req *pb.WatchSandboxRequest, stream grpc.ServerStreamingServer[pb.SandboxStreamEvent]) error {
	f.mu.Lock()
	f.reqs = append(f.reqs, req)
	events := f.events
	f.mu.Unlock()
	after := req.GetResumeAfterCursor()
	if after != "" && after != "v1:old:7" && (len(after) < 6 || after[:6] != "v1:s1:") {
		return status.Error(codes.InvalidArgument, "resume_after_cursor is not a valid watch cursor")
	}
	snapshot := &pb.SandboxStreamEvent{Payload: &pb.SandboxStreamEvent_Sandbox{Sandbox: &pb.Sandbox{}}}
	if err := stream.Send(snapshot); err != nil {
		return err
	}
	if after == "v1:old:7" {
		return status.Error(codes.OutOfRange, streamOutOfRange)
	}
	for _, ev := range events {
		if after != "" && ev.GetCursor() != "" && ev.GetCursor() <= after {
			continue
		}
		if err := stream.Send(ev); err != nil {
			return err
		}
	}
	<-stream.Context().Done()
	return nil
}

func logEvent(cursor string, at time.Time, msg string) *pb.SandboxStreamEvent {
	return &pb.SandboxStreamEvent{Cursor: cursor, Payload: &pb.SandboxStreamEvent_Log{Log: &pb.SandboxLogLine{
		EventTime: timestamppb.New(at), Level: "OCSF", Target: "ocsf", Message: msg, Source: "sandbox",
	}}}
}

func bufWatch(t *testing.T, f *fakeShell) *Watch {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	pb.RegisterOpenShellServer(srv, f)
	go srv.Serve(lis)
	t.Cleanup(srv.Stop)
	w := &Watch{Idle: 100 * time.Millisecond, Max: 2 * time.Second}
	w.dial = func(context.Context) (*grpc.ClientConn, error) {
		return grpc.NewClient("passthrough:///bufnet",
			grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
			grpc.WithTransportCredentials(insecure.NewCredentials()))
	}
	t.Cleanup(func() { w.Close() })
	return w
}

func TestReadStreamResumesAfterTheCursor(t *testing.T) {
	at := time.Date(2026, 10, 3, 21, 46, 19, 337e6, time.UTC)
	f := &fakeShell{events: []*pb.SandboxStreamEvent{
		logEvent("v1:s1:1", at, streamAllow),
		logEvent("v1:s1:2", at.Add(time.Second), streamApproval),
	}}
	w := bufWatch(t, f)
	ctx := context.Background()

	read, err := w.ReadStream(ctx, "fenzi-1", "", 200)
	if err != nil {
		t.Fatal(err)
	}
	if len(read.Lines) != 2 || read.Cursor != "v1:s1:2" || read.Reset != "" {
		t.Fatalf("read %+v", read)
	}
	if l := read.Lines[0]; l.Level != "OCSF" || l.Message != streamAllow || !l.Time.Equal(at) {
		t.Errorf("line %+v", l)
	}
	req := f.reqs[0]
	if req.GetSandbox() != "fenzi-1" || !req.GetFollowLogs() || req.GetLogTailLines() != 200 ||
		len(req.GetLogSources()) != 1 || req.GetLogSources()[0] != "sandbox" || req.GetWorkspaceScope().GetWorkspace() != "default" {
		t.Errorf("request %v", req)
	}

	// Resuming after the highest cursor replays nothing.
	read, err = w.ReadStream(ctx, "fenzi-1", read.Cursor, 200)
	if err != nil || len(read.Lines) != 0 || read.Cursor != "v1:s1:2" {
		t.Fatalf("resume %+v %v", read, err)
	}
	if f.reqs[1].GetResumeAfterCursor() != "v1:s1:2" || f.reqs[1].GetLogTailLines() != 0 {
		t.Errorf("resume request %v", f.reqs[1])
	}

	f.mu.Lock()
	f.events = append(f.events,
		&pb.SandboxStreamEvent{Payload: &pb.SandboxStreamEvent_Warning{Warning: &pb.SandboxStreamWarning{Message: "log buffer overflowed"}}},
		logEvent("v1:s1:3", at.Add(2*time.Second), streamAllow))
	f.mu.Unlock()
	read, err = w.ReadStream(ctx, "fenzi-1", "v1:s1:2", 200)
	if err != nil || len(read.Lines) != 1 || read.Cursor != "v1:s1:3" || len(read.Warnings) != 1 {
		t.Fatalf("after more events %+v %v", read, err)
	}
}

func TestReadStreamRestartsOnARefusedCursor(t *testing.T) {
	at := time.Date(2026, 10, 3, 21, 46, 19, 0, time.UTC)
	f := &fakeShell{events: []*pb.SandboxStreamEvent{logEvent("v1:s1:1", at, streamAllow)}}
	w := bufWatch(t, f)
	for _, cursor := range []string{"v1:old:7", "garbage"} {
		read, err := w.ReadStream(context.Background(), "fenzi-1", cursor, 200)
		if err != nil {
			t.Fatal(err)
		}
		if read.Reset == "" || len(read.Lines) != 1 || read.Cursor != "v1:s1:1" {
			t.Fatalf("%s: read %+v", cursor, read)
		}
	}
	if f.reqs[1].GetResumeAfterCursor() != "" || f.reqs[1].GetLogTailLines() != 200 {
		t.Errorf("the restart must drop the cursor and replay the tail: %v", f.reqs[1])
	}
}

func TestWatchNeedsTheCLIClientCertificate(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	fake := &Fake{Replies: map[string]Reply{"status --output json": {Out: statusRecorded}}}
	if _, err := NewWatch(Client{R: fake}).ReadStream(context.Background(), "fenzi-1", "", 200); !errors.Is(err, ErrNoStream) {
		t.Fatalf("err = %v", err)
	}
	fake.Replies["status --output json"] = Reply{Out: `{"gateway":"../../etc","server":"https://localhost:17670","status":"connected"}`}
	if _, err := NewWatch(Client{R: fake}).ReadStream(context.Background(), "fenzi-1", "", 200); !errors.Is(err, ErrNoStream) {
		t.Fatalf("a gateway name that is not a plain name must not become a path: %v", err)
	}
}

// statusRecorded is `openshell status --output json` from OpenShell 0.1.2.
const statusRecorded = `{"authentication":{"provider":"mTLS transport","status":"authenticated"},"gateway":"openshell","server":"https://localhost:17670","status":"connected","version":"0.1.2"}`

func TestWatchDialsWithTheCLIClientCertificate(t *testing.T) {
	home := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", home)
	dir := filepath.Join(home, "openshell", "gateways", "openshell", "mtls")
	serverCert, pool := writeMTLS(t, dir)

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeShell{events: []*pb.SandboxStreamEvent{logEvent("v1:s1:1", time.Now(), streamAllow)}}
	srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{serverCert}, ClientCAs: pool, ClientAuth: tls.RequireAndVerifyClientCert,
	})))
	pb.RegisterOpenShellServer(srv, f)
	go srv.Serve(lis)
	t.Cleanup(srv.Stop)

	status := `{"authentication":{"provider":"mTLS transport","status":"authenticated"},"gateway":"openshell","server":"https://` + lis.Addr().String() + `","status":"connected","version":"0.1.2"}`
	w := NewWatch(Client{R: &Fake{Replies: map[string]Reply{"status --output json": {Out: status}}}})
	w.Idle = 200 * time.Millisecond
	t.Cleanup(func() { w.Close() })
	read, err := w.ReadStream(context.Background(), "fenzi-1", "", 200)
	if err != nil || len(read.Lines) != 1 {
		t.Fatalf("read %+v %v", read, err)
	}
}

// writeMTLS writes a CA and a client pair the way the CLI keeps them, and
// returns a server certificate for 127.0.0.1 from the same CA.
func writeMTLS(t *testing.T, dir string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test ca"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	issue := func(serial int64, usage x509.ExtKeyUsage, ip net.IP) ([]byte, []byte) {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
			ExtKeyUsage: []x509.ExtKeyUsage{usage}, KeyUsage: x509.KeyUsageDigitalSignature,
		}
		if ip != nil {
			tmpl.IPAddresses = []net.IP{ip}
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		kb, _ := x509.MarshalECPrivateKey(key)
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})
	}
	clientCert, clientKey := issue(2, x509.ExtKeyUsageClientAuth, nil)
	for name, b := range map[string][]byte{
		"ca.crt":  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		"tls.crt": clientCert,
		"tls.key": clientKey,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	srvCert, srvKey := issue(3, x509.ExtKeyUsageServerAuth, net.ParseIP("127.0.0.1"))
	pair, err := tls.X509KeyPair(srvCert, srvKey)
	if err != nil {
		t.Fatal(err)
	}
	return pair, pool
}
