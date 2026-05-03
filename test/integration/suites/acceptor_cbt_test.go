package suites

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"testing"
	"time"

	"github.com/f0oster/gokrb5/gssapi"
	"github.com/f0oster/gokrb5/spnego"
	"github.com/f0oster/gokrb5/test/integration/framework"
)

// TestAcceptorCBT_Match_MIT runs a full handshake over a TLS-wrapped
// connection where the initiator hashes the server's leaf certificate
// into its authenticator checksum and the acceptor verifies the same
// hash. The bind succeeds and the post-auth Wrap round trip completes.
func TestAcceptorCBT_Match_MIT(t *testing.T) {
	kdc := requireMIT(t)
	cert := framework.SelfSignedTLSCert(t)

	serviceKeytab, err := kdc.Keytab(kdc.HTTPSPN())
	if err != nil {
		t.Fatalf("get service keytab: %v", err)
	}
	acceptor, err := framework.StartTLSGSSAcceptor(serviceKeytab, framework.DefaultReply, cert)
	if err != nil {
		t.Fatalf("start TLS acceptor: %v", err)
	}
	t.Cleanup(func() { _ = acceptor.Close() })

	runCBTHandshake(t, kdc, kdc.HTTPSPN(), acceptor, cert.Leaf, framework.AuthenticatedReply)
}

// TestAcceptorCBT_Mismatch_MIT runs a handshake where the acceptor's
// expected bindings (derived from its own cert) do not match the
// bindings the initiator hashed in (derived from a different cert).
// The acceptor returns ErrChannelBindingMismatch.
func TestAcceptorCBT_Mismatch_MIT(t *testing.T) {
	kdc := requireMIT(t)
	serverCert := framework.SelfSignedTLSCert(t)
	differentCert := framework.SelfSignedTLSCert(t)

	serviceKeytab, err := kdc.Keytab(kdc.HTTPSPN())
	if err != nil {
		t.Fatalf("get service keytab: %v", err)
	}
	acceptor, err := framework.StartTLSGSSAcceptor(serviceKeytab, framework.DefaultReply, serverCert)
	if err != nil {
		t.Fatalf("start TLS acceptor: %v", err)
	}
	t.Cleanup(func() { _ = acceptor.Close() })

	cl, err := kdc.NewClient("preauth_user", framework.MITUserPassword)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer cl.Destroy()
	if err := cl.Login(); err != nil {
		t.Fatalf("login: %v", err)
	}

	wrongCB, err := gssapi.NewTLSChannelBindingsFromCert(differentCert.Leaf)
	if err != nil {
		t.Fatalf("build mismatched bindings: %v", err)
	}
	init, err := spnego.NewInitiator(cl, kdc.HTTPSPN(),
		gssapi.WithMutualAuth(),
		gssapi.WithChannelBindings(wrongCB),
	)
	if err != nil {
		t.Fatalf("NewInitiator: %v", err)
	}
	sptBytes, err := init.Step(nil)
	if err != nil {
		t.Fatalf("build SPNEGO init: %v", err)
	}

	conn, err := tls.Dial("tcp", acceptor.Addr(), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("TLS dial: %v", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	if err := framework.WriteFramed(conn, sptBytes); err != nil {
		t.Fatalf("send SPNEGO init: %v", err)
	}

	// The acceptor closes the connection after the CB mismatch; expect
	// the next read to fail and the acceptor's error channel to surface
	// ErrChannelBindingMismatch.
	if _, err := framework.ReadFramed(conn); err == nil {
		t.Fatalf("expected EOF/error after CB mismatch, got success")
	}

	select {
	case acceptorErr := <-acceptor.Errors():
		if !errors.Is(acceptorErr, gssapi.ErrChannelBindingMismatch) {
			t.Fatalf("acceptor error = %v, want ErrChannelBindingMismatch", acceptorErr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for acceptor to report ErrChannelBindingMismatch")
	}
}

// runCBTHandshake drives an end-to-end TLS+CBT handshake against
// acceptor and asserts the post-auth reply.
func runCBTHandshake(t *testing.T, kdc framework.KDC, spn string, acceptor *framework.GSSAcceptor, leafCert *x509.Certificate, expectedReply string) {
	t.Helper()

	cl, err := kdc.NewClient("preauth_user", framework.MITUserPassword)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer cl.Destroy()
	if err := cl.Login(); err != nil {
		t.Fatalf("login: %v", err)
	}

	cb, err := gssapi.NewTLSChannelBindingsFromCert(leafCert)
	if err != nil {
		t.Fatalf("build channel bindings: %v", err)
	}
	init, err := spnego.NewInitiator(cl, spn,
		gssapi.WithMutualAuth(),
		gssapi.WithChannelBindings(cb),
	)
	if err != nil {
		t.Fatalf("NewInitiator: %v", err)
	}
	sptBytes, err := init.Step(nil)
	if err != nil {
		t.Fatalf("build SPNEGO init: %v", err)
	}

	conn, err := tls.Dial("tcp", acceptor.Addr(), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("TLS dial: %v", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}

	if err := framework.WriteFramed(conn, sptBytes); err != nil {
		t.Fatalf("send SPNEGO init: %v", err)
	}
	respBytes, err := framework.ReadFramed(conn)
	if err != nil {
		t.Fatalf("receive SPNEGO response: %v", err)
	}
	if _, err := init.Step(respBytes); err != nil {
		t.Fatalf("verify SPNEGO response: %v", err)
	}
	ctx, err := init.SecurityContext()
	if err != nil {
		t.Fatalf("SecurityContext: %v", err)
	}

	pingTok, err := ctx.Wrap([]byte("ping"))
	if err != nil {
		t.Fatalf("wrap ping: %v", err)
	}
	if err := framework.WriteFramed(conn, pingTok); err != nil {
		t.Fatalf("send ping: %v", err)
	}
	replyBytes, err := framework.ReadFramed(conn)
	if err != nil {
		t.Fatalf("receive reply: %v", err)
	}
	msg, err := ctx.Unwrap(replyBytes)
	if err != nil {
		t.Fatalf("unwrap reply: %v", err)
	}
	if string(msg) != expectedReply {
		t.Fatalf("reply = %q, want %q", msg, expectedReply)
	}

	select {
	case err := <-acceptor.Errors():
		t.Fatalf("acceptor error: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
}
