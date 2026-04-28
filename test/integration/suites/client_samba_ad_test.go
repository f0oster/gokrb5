package suites

import (
	"context"
	"io"
	"net"
	"net/http"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/f0oster/gokrb5/client"
	"github.com/f0oster/gokrb5/iana/errorcode"
	"github.com/f0oster/gokrb5/krberror"
	"github.com/f0oster/gokrb5/spnego"
	"github.com/f0oster/gokrb5/test"
	"github.com/f0oster/gokrb5/test/integration/framework"
)

// requireAD lazily starts the Samba AD-DC fixture on first call.
var (
	adOnce sync.Once
	adKDC  framework.ActiveDirectory
	adErr  error
)

func requireAD(t *testing.T) framework.ActiveDirectory {
	t.Helper()
	test.Integration(t)
	framework.SkipIfNoDocker(t)
	adOnce.Do(func() {
		kdc, cleanup, err := framework.StartSambaAD(context.Background())
		if err != nil {
			adErr = err
			return
		}
		adKDC = kdc
		registerFixtureCleanup(cleanup)
	})
	if adKDC == nil {
		t.Skipf("Samba AD not available: %v", adErr)
	}
	return adKDC
}

// TestSambaAD_FixtureUp_AD verifies the fixture exposes the expected
// realm and a reachable LDAP endpoint.
func TestSambaAD_FixtureUp_AD(t *testing.T) {
	kdc := requireAD(t)

	if got, want := kdc.Realm(), "AD.GOKRB5"; got != want {
		t.Errorf("Realm() = %q, want %q", got, want)
	}

	host, port := kdc.LDAPEndpoint()
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("LDAP endpoint %s not reachable: %v", addr, err)
	}
	_ = conn.Close()
}

// TestClient_Login_AD exercises an AS exchange with a password.
func TestClient_Login_AD(t *testing.T) {
	kdc := requireAD(t)

	cl, err := kdc.NewClient("testuser1", framework.SambaUserPassword)
	if err != nil {
		t.Fatalf("build client: %v", err)
	}
	defer cl.Destroy()

	if err := cl.Login(); err != nil {
		t.Fatalf("login: %v", err)
	}
}

// TestClient_Login_InvalidPassword_AD verifies a wrong password is
// rejected with KDC_ERR_PREAUTH_FAILED.
func TestClient_Login_InvalidPassword_AD(t *testing.T) {
	kdc := requireAD(t)

	cl, err := kdc.NewClient("testuser1", "wrong-password")
	if err != nil {
		t.Fatalf("build client: %v", err)
	}
	defer cl.Destroy()

	requireKrbError(t, cl.Login(),
		krberror.KDCError,
		errorcode.Lookup(errorcode.KDC_ERR_PREAUTH_FAILED))
}

// TestClient_Login_UnknownUser_AD verifies an unknown principal is
// rejected with KDC_ERR_C_PRINCIPAL_UNKNOWN.
func TestClient_Login_UnknownUser_AD(t *testing.T) {
	kdc := requireAD(t)

	cl, err := kdc.NewClient("nosuchuser", "anything")
	if err != nil {
		t.Fatalf("build client: %v", err)
	}
	defer cl.Destroy()

	requireKrbError(t, cl.Login(),
		krberror.KDCError,
		errorcode.Lookup(errorcode.KDC_ERR_C_PRINCIPAL_UNKNOWN))
}

// TestClient_Login_Keytab_AD exercises a keytab-based AS exchange.
func TestClient_Login_Keytab_AD(t *testing.T) {
	kdc := requireAD(t)

	kt, err := kdc.Keytab("testuser1")
	if err != nil {
		t.Fatalf("get keytab: %v", err)
	}

	cfg, err := kdc.Config()
	if err != nil {
		t.Fatalf("config: %v", err)
	}

	cl := client.NewWithKeytab("testuser1", kdc.Realm(), kt, cfg)
	defer cl.Destroy()

	if err := cl.Login(); err != nil {
		t.Fatalf("login: %v", err)
	}
}

// TestClient_GetServiceTicket_LDAP_AD exercises a TGS exchange for
// the DC's LDAP SPN.
func TestClient_GetServiceTicket_LDAP_AD(t *testing.T) {
	kdc := requireAD(t)

	cl, err := kdc.NewClient("testuser1", framework.SambaUserPassword)
	if err != nil {
		t.Fatalf("build client: %v", err)
	}
	defer cl.Destroy()
	if err := cl.Login(); err != nil {
		t.Fatalf("login: %v", err)
	}

	spn := kdc.LDAPSPN()
	tkt, sessionKey, err := cl.GetServiceTicket(spn)
	if err != nil {
		t.Fatalf("get service ticket for %s: %v", spn, err)
	}

	if tkt.Realm != kdc.Realm() {
		t.Errorf("ticket realm = %q, want %q", tkt.Realm, kdc.Realm())
	}
	wantSName := []string{"ldap", "dc.ad.gokrb5"}
	if !slices.Equal(tkt.SName.NameString, wantSName) {
		t.Errorf("ticket SName.NameString = %v, want %v",
			tkt.SName.NameString, wantSName)
	}
	if len(sessionKey.KeyValue) == 0 {
		t.Error("session key value is empty")
	}
}

var (
	adHTTPOnce     sync.Once
	adHTTPAcceptor framework.HTTPAcceptor
	adHTTPErr      error
)

// requireADHTTPAcceptor lazily starts an HTTP acceptor keyed for
// the AD HTTP SPN.
func requireADHTTPAcceptor(t *testing.T) framework.HTTPAcceptor {
	t.Helper()
	kdc := requireAD(t)
	adHTTPOnce.Do(func() {
		a, cleanup, err := framework.StartHTTPAcceptor(context.Background(), kdc, kdc.HTTPSPN())
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

// TestSPNEGO_HTTP_AD runs an end-to-end SPNEGO HTTP exchange with
// an AD-issued service ticket.
func TestSPNEGO_HTTP_AD(t *testing.T) {
	kdc := requireAD(t)
	acceptor := requireADHTTPAcceptor(t)
	t.Cleanup(func() { dumpAcceptorLogsOnFailure(t, acceptor) })

	cl, err := kdc.NewClient("testuser1", framework.SambaUserPassword)
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
