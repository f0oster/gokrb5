package suites

import (
	"context"
	"io"
	"net/http"
	"sync"
	"testing"

	"github.com/f0oster/gokrb5/spnego"
	"github.com/f0oster/gokrb5/test/integration/framework"
)

var (
	mitHTTPOnce     sync.Once
	mitHTTPAcceptor framework.HTTPAcceptor
	mitHTTPErr      error

	adHTTPOnce     sync.Once
	adHTTPAcceptor framework.HTTPAcceptor
	adHTTPErr      error
)

// requireMITHTTPAcceptor lazily starts an Apache+mod_auth_gssapi
// container keyed for the MIT HTTP SPN and returns the shared handle.
func requireMITHTTPAcceptor(t *testing.T) framework.HTTPAcceptor {
	t.Helper()
	kdc := requireMIT(t)
	mitHTTPOnce.Do(func() {
		a, cleanup, err := framework.StartHTTPAcceptor(context.Background(), kdc, framework.MITHTTPSPN)
		if err != nil {
			mitHTTPErr = err
			return
		}
		mitHTTPAcceptor = a
		registerFixtureCleanup(cleanup)
	})
	if mitHTTPAcceptor == nil {
		t.Skipf("krbhttp acceptor (MIT) not available: %v", mitHTTPErr)
	}
	return mitHTTPAcceptor
}

// requireADHTTPAcceptor lazily starts an Apache+mod_auth_gssapi
// container keyed for the AD HTTP SPN and returns the shared handle.
func requireADHTTPAcceptor(t *testing.T) framework.HTTPAcceptor {
	t.Helper()
	kdc := requireAD(t)
	adHTTPOnce.Do(func() {
		a, cleanup, err := framework.StartHTTPAcceptor(context.Background(), kdc, framework.SambaHTTPSPN)
		if err != nil {
			adHTTPErr = err
			return
		}
		adHTTPAcceptor = a
		registerFixtureCleanup(cleanup)
	})
	if adHTTPAcceptor == nil {
		t.Skipf("krbhttp acceptor (AD) not available: %v", adHTTPErr)
	}
	return adHTTPAcceptor
}

// TestSPNEGO_HTTP_MIT runs an end-to-end SPNEGO HTTP exchange against
// the krbhttp Apache acceptor with an MIT-issued service ticket.
func TestSPNEGO_HTTP_MIT(t *testing.T) {
	kdc := requireMIT(t)
	acceptor := requireMITHTTPAcceptor(t)
	t.Cleanup(func() { dumpAcceptorLogsOnFailure(t, acceptor) })

	cl, err := kdc.NewClient("nopreauth_user", framework.MITUserPassword)
	if err != nil {
		t.Fatalf("build client: %v", err)
	}
	defer cl.Destroy()
	if err := cl.Login(); err != nil {
		t.Fatalf("login: %v", err)
	}

	spc := spnego.NewClient(cl, nil, acceptor.SPN())
	resp, err := spc.Get(acceptor.BaseURL() + "/spnego/")
	if err != nil {
		t.Fatalf("authenticated GET: %v", err)
	}
	defer resp.Body.Close()
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		t.Fatalf("read body: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}

// TestSPNEGO_HTTP_AD runs the same exchange against an AD-issued
// service ticket. Same fork code, same acceptor image, different KDC.
func TestSPNEGO_HTTP_AD(t *testing.T) {
	kdc := requireAD(t)
	acceptor := requireADHTTPAcceptor(t)
	t.Cleanup(func() { dumpAcceptorLogsOnFailure(t, acceptor) })

	cl, err := kdc.NewClient("testuser1", framework.MITUserPassword)
	if err != nil {
		t.Fatalf("build client: %v", err)
	}
	defer cl.Destroy()
	if err := cl.Login(); err != nil {
		t.Fatalf("login: %v", err)
	}

	spc := spnego.NewClient(cl, nil, acceptor.SPN())
	resp, err := spc.Get(acceptor.BaseURL() + "/spnego/")
	if err != nil {
		t.Fatalf("authenticated GET: %v", err)
	}
	defer resp.Body.Close()
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		t.Fatalf("read body: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}

// dumpAcceptorLogsOnFailure prints the acceptor's accumulated
// stdout/stderr (Apache error/access log + startup output) when the
// test has failed, so a 401/403/500 from mod_auth_gssapi can be
// diagnosed without re-running with shell access to the container.
func dumpAcceptorLogsOnFailure(t *testing.T, a framework.HTTPAcceptor) {
	t.Helper()
	if !t.Failed() {
		return
	}
	out, err := a.Logs(context.Background())
	if err != nil {
		t.Logf("acceptor logs: read failed: %v", err)
		return
	}
	t.Logf("acceptor container logs:\n%s", string(out))
}

// TestSPNEGO_HTTP_NoAuth_Refused_MIT verifies the acceptor refuses an
// unauthenticated request with 401 Negotiate, confirming the protected
// location is in fact protected.
func TestSPNEGO_HTTP_NoAuth_Refused_MIT(t *testing.T) {
	acceptor := requireMITHTTPAcceptor(t)

	resp, err := http.Get(acceptor.BaseURL() + "/spnego/")
	if err != nil {
		t.Fatalf("plain GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
	if got, want := resp.Header.Get("WWW-Authenticate"), "Negotiate"; got != want {
		t.Errorf("WWW-Authenticate = %q, want %q", got, want)
	}
}
