package suites

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/f0oster/gokrb5/client"
	"github.com/f0oster/gokrb5/iana/errorcode"
	"github.com/f0oster/gokrb5/iana/etypeID"
	"github.com/f0oster/gokrb5/krberror"
	"github.com/f0oster/gokrb5/spnego"
	"github.com/f0oster/gokrb5/test"
	"github.com/f0oster/gokrb5/test/integration/framework"
)

// requireMIT lazily starts the MIT KDC fixture on first call.
var (
	mitOnce sync.Once
	mitKDC  *framework.MITKDC
	mitErr  error
)

func requireMIT(t *testing.T) *framework.MITKDC {
	t.Helper()
	test.Integration(t)
	framework.SkipIfNoDocker(t)
	mitOnce.Do(func() {
		kdc, cleanup, err := framework.StartMITKDC(context.Background())
		if err != nil {
			mitErr = err
			return
		}
		mitKDC = kdc
		registerFixtureCleanup(cleanup)
	})
	if mitKDC == nil {
		t.Skipf("MIT KDC not available: %v", mitErr)
	}
	return mitKDC
}

// requireKrbError asserts the error is a krberror.Krberror with the
// given RootCause and an error text containing wantSubstr. The
// krberror package doesn't expose the inner error via Unwrap, so
// substring matching is the closest structural check.
func requireKrbError(t *testing.T, err error, wantRootCause, wantSubstr string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected krberror with RootCause %q and text containing %q, got nil",
			wantRootCause, wantSubstr)
	}
	var ke krberror.Krberror
	if !errors.As(err, &ke) {
		t.Fatalf("expected krberror.Krberror, got %T: %v", err, err)
	}
	if ke.RootCause != wantRootCause {
		t.Fatalf("RootCause = %q, want %q (err: %v)", ke.RootCause, wantRootCause, err)
	}
	if !strings.Contains(err.Error(), wantSubstr) {
		t.Fatalf("error text does not contain %q; got: %v", wantSubstr, err)
	}
}

// TestClient_Login_PreauthUser_MIT exercises the AS exchange against
// a principal that requires PA-ENC-TIMESTAMP pre-authentication.
func TestClient_Login_PreauthUser_MIT(t *testing.T) {
	kdc := requireMIT(t)

	cl, err := kdc.NewClient("preauth_user", framework.MITUserPassword)
	if err != nil {
		t.Fatalf("build client: %v", err)
	}
	defer cl.Destroy()

	if err := cl.Login(); err != nil {
		t.Fatalf("login: %v", err)
	}
}

// TestClient_Login_NoPreauthUser_MIT exercises the AS exchange
// against a principal that does not require pre-authentication.
func TestClient_Login_NoPreauthUser_MIT(t *testing.T) {
	kdc := requireMIT(t)

	cl, err := kdc.NewClient("nopreauth_user", framework.MITUserPassword)
	if err != nil {
		t.Fatalf("build client: %v", err)
	}
	defer cl.Destroy()

	if err := cl.Login(); err != nil {
		t.Fatalf("login: %v", err)
	}
}

// TestClient_Login_InvalidPassword_PreauthUser_MIT verifies a wrong
// password against a preauth-required principal is rejected at the
// KDC with KDC_ERR_PREAUTH_FAILED.
func TestClient_Login_InvalidPassword_PreauthUser_MIT(t *testing.T) {
	kdc := requireMIT(t)

	cl, err := kdc.NewClient("preauth_user", "wrong-password")
	if err != nil {
		t.Fatalf("build client: %v", err)
	}
	defer cl.Destroy()

	requireKrbError(t, cl.Login(),
		krberror.KDCError,
		errorcode.Lookup(errorcode.KDC_ERR_PREAUTH_FAILED))
}

// TestClient_Login_InvalidPassword_NoPreauthUser_MIT verifies a
// wrong password against a non-preauth principal fails at client-side
// decryption (no KDC rejection because no preauth was requested).
func TestClient_Login_InvalidPassword_NoPreauthUser_MIT(t *testing.T) {
	kdc := requireMIT(t)

	cl, err := kdc.NewClient("nopreauth_user", "wrong-password")
	if err != nil {
		t.Fatalf("build client: %v", err)
	}
	defer cl.Destroy()

	requireKrbError(t, cl.Login(),
		krberror.DecryptingError,
		"integrity verification failed")
}

// TestClient_Login_UnknownUser_MIT verifies an unknown principal is
// rejected with KDC_ERR_C_PRINCIPAL_UNKNOWN.
func TestClient_Login_UnknownUser_MIT(t *testing.T) {
	kdc := requireMIT(t)

	cl, err := kdc.NewClient("nosuchuser", "anything")
	if err != nil {
		t.Fatalf("build client: %v", err)
	}
	defer cl.Destroy()

	requireKrbError(t, cl.Login(),
		krberror.KDCError,
		errorcode.Lookup(errorcode.KDC_ERR_C_PRINCIPAL_UNKNOWN))
}

// TestClient_Login_PreauthUser_Keytab_MIT exercises the AS exchange
// using a keytab instead of a password.
func TestClient_Login_PreauthUser_Keytab_MIT(t *testing.T) {
	kdc := requireMIT(t)

	kt, err := kdc.Keytab("preauth_user")
	if err != nil {
		t.Fatalf("get keytab: %v", err)
	}

	cfg, err := kdc.Config()
	if err != nil {
		t.Fatalf("config: %v", err)
	}

	cl := client.NewWithKeytab("preauth_user", kdc.Realm(), kt, cfg)
	defer cl.Destroy()

	if err := cl.Login(); err != nil {
		t.Fatalf("login: %v", err)
	}
}

// TestClient_Login_NoPreauthUser_Keytab_MIT exercises a keytab-based
// AS exchange against a non-preauth principal.
func TestClient_Login_NoPreauthUser_Keytab_MIT(t *testing.T) {
	kdc := requireMIT(t)

	kt, err := kdc.Keytab("nopreauth_user")
	if err != nil {
		t.Fatalf("get keytab: %v", err)
	}

	cfg, err := kdc.Config()
	if err != nil {
		t.Fatalf("config: %v", err)
	}

	cl := client.NewWithKeytab("nopreauth_user", kdc.Realm(), kt, cfg)
	defer cl.Destroy()

	if err := cl.Login(); err != nil {
		t.Fatalf("login: %v", err)
	}
}

// loggedInClient builds a client and performs the AS exchange. Fails
// the test on any error.
func loggedInClient(t *testing.T, kdc framework.KDC, username, password string) *client.Client {
	t.Helper()
	cl, err := kdc.NewClient(username, password)
	if err != nil {
		t.Fatalf("build client: %v", err)
	}
	if err := cl.Login(); err != nil {
		cl.Destroy()
		t.Fatalf("login: %v", err)
	}
	return cl
}

// TestClient_GetServiceTicket_MIT exercises a TGS exchange for a
// service in the home realm.
func TestClient_GetServiceTicket_MIT(t *testing.T) {
	kdc := requireMIT(t)

	cl := loggedInClient(t, kdc, "preauth_user", framework.MITUserPassword)
	defer cl.Destroy()

	const spn = "HTTP/host.home.gokrb5"
	tkt, sessionKey, err := cl.GetServiceTicket(spn)
	if err != nil {
		t.Fatalf("get service ticket: %v", err)
	}

	if tkt.Realm != kdc.Realm() {
		t.Errorf("ticket realm = %q, want %q", tkt.Realm, kdc.Realm())
	}
	wantSName := []string{"HTTP", "host.home.gokrb5"}
	if !slices.Equal(tkt.SName.NameString, wantSName) {
		t.Errorf("ticket SName.NameString = %v, want %v",
			tkt.SName.NameString, wantSName)
	}
	if len(sessionKey.KeyValue) == 0 {
		t.Error("session key value is empty")
	}
	if sessionKey.KeyType == 0 {
		t.Error("session key etype is zero")
	}
}

// TestClient_GetServiceTicket_UnknownSPN_MIT verifies a TGS request
// for an unknown SPN is rejected with KDC_ERR_S_PRINCIPAL_UNKNOWN.
func TestClient_GetServiceTicket_UnknownSPN_MIT(t *testing.T) {
	kdc := requireMIT(t)

	cl := loggedInClient(t, kdc, "preauth_user", framework.MITUserPassword)
	defer cl.Destroy()

	_, _, err := cl.GetServiceTicket("HTTP/nosuchservice.test.gokrb5")
	requireKrbError(t, err,
		krberror.KDCError,
		errorcode.Lookup(errorcode.KDC_ERR_S_PRINCIPAL_UNKNOWN))
}

// TestClient_GetServiceTicket_Cached_MIT verifies the client caches
// service tickets. Tested via byte-equality on the ticket cipher; a
// re-fetch from the KDC would produce a different cipher.
func TestClient_GetServiceTicket_Cached_MIT(t *testing.T) {
	kdc := requireMIT(t)

	cl := loggedInClient(t, kdc, "preauth_user", framework.MITUserPassword)
	defer cl.Destroy()

	const spn = "HTTP/host.home.gokrb5"
	first, firstKey, err := cl.GetServiceTicket(spn)
	if err != nil {
		t.Fatalf("first get service ticket: %v", err)
	}
	second, secondKey, err := cl.GetServiceTicket(spn)
	if err != nil {
		t.Fatalf("second get service ticket: %v", err)
	}

	if !bytes.Equal(first.EncPart.Cipher, second.EncPart.Cipher) {
		t.Error("second GetServiceTicket returned a different ticket cipher; expected the cached one")
	}
	if !bytes.Equal(firstKey.KeyValue, secondKey.KeyValue) {
		t.Error("second GetServiceTicket returned a different session key; expected the cached one")
	}
}

// TestClient_NetworkTryNextKDC_MIT verifies the client falls through
// unreachable KDCs in the realm's kdc list and succeeds on the
// reachable one.
func TestClient_NetworkTryNextKDC_MIT(t *testing.T) {
	kdc := requireMIT(t)
	cfg, err := kdc.Config()
	if err != nil {
		t.Fatalf("config: %v", err)
	}

	homeRealm := kdc.Realm()
	for i, r := range cfg.Realms {
		if r.Realm == homeRealm {
			cfg.Realms[i].KDC = append(
				[]string{"127.0.0.1:1", "127.0.0.1:1"},
				cfg.Realms[i].KDC...,
			)
			break
		}
	}

	cl := client.NewWithPassword("preauth_user", homeRealm, framework.MITUserPassword, cfg)
	defer cl.Destroy()
	if err := cl.Login(); err != nil {
		t.Fatalf("login should have fallen through unreachable KDCs: %v", err)
	}
}

// TestClient_NoReachableKDC_MIT verifies that with no reachable KDC
// in the realm's kdc list, Login returns a Networking_Error rather
// than hanging or panicking.
func TestClient_NoReachableKDC_MIT(t *testing.T) {
	kdc := requireMIT(t)
	cfg, err := kdc.Config()
	if err != nil {
		t.Fatalf("config: %v", err)
	}

	homeRealm := kdc.Realm()
	for i, r := range cfg.Realms {
		if r.Realm == homeRealm {
			cfg.Realms[i].KDC = []string{"127.0.0.1:1"}
			break
		}
	}

	cl := client.NewWithPassword("preauth_user", homeRealm, framework.MITUserPassword, cfg)
	defer cl.Destroy()
	requireKrbError(t, cl.Login(), krberror.NetworkingError, "")
}

// TestClient_GetServiceTicket_CrossRealm_MIT exercises the
// cross-realm TGS flow: a HOME user requests a TRUSTED service and
// the client traverses the trust to obtain the ticket.
func TestClient_GetServiceTicket_CrossRealm_MIT(t *testing.T) {
	kdc := requireMIT(t)

	cl := loggedInClient(t, kdc, "preauth_user", framework.MITUserPassword)
	defer cl.Destroy()

	const spn = "HTTP/host.trusted.gokrb5"
	tkt, sessionKey, err := cl.GetServiceTicket(spn)
	if err != nil {
		t.Fatalf("get cross-realm service ticket: %v", err)
	}

	const wantRealm = "TRUSTED.GOKRB5"
	if tkt.Realm != wantRealm {
		t.Errorf("ticket realm = %q, want %q", tkt.Realm, wantRealm)
	}
	wantSName := []string{"HTTP", "host.trusted.gokrb5"}
	if !slices.Equal(tkt.SName.NameString, wantSName) {
		t.Errorf("ticket SName.NameString = %v, want %v",
			tkt.SName.NameString, wantSName)
	}
	if len(sessionKey.KeyValue) == 0 {
		t.Error("session key value is empty")
	}
}

// TestClient_Enctypes_MIT runs Login + GetServiceTicket under each
// supported AES enctype and asserts the session key etype matches
// the requested one.
func TestClient_Enctypes_MIT(t *testing.T) {
	kdc := requireMIT(t)

	enctypes := []string{
		"aes256-cts-hmac-sha1-96",
		"aes128-cts-hmac-sha1-96",
		"aes256-cts-hmac-sha384-192",
		"aes128-cts-hmac-sha256-128",
	}

	for _, et := range enctypes {
		t.Run(et, func(t *testing.T) {
			cfg, err := kdc.Config()
			if err != nil {
				t.Fatalf("config: %v", err)
			}
			id := etypeID.ETypesByName[et]
			cfg.LibDefaults.DefaultTktEnctypes = []string{et}
			cfg.LibDefaults.DefaultTktEnctypeIDs = []int32{id}
			cfg.LibDefaults.DefaultTGSEnctypes = []string{et}
			cfg.LibDefaults.DefaultTGSEnctypeIDs = []int32{id}
			cfg.LibDefaults.PermittedEnctypes = []string{et}
			cfg.LibDefaults.PermittedEnctypeIDs = []int32{id}

			cl := client.NewWithPassword("preauth_user", kdc.Realm(), framework.MITUserPassword, cfg)
			defer cl.Destroy()
			if err := cl.Login(); err != nil {
				t.Fatalf("login: %v", err)
			}

			_, key, err := cl.GetServiceTicket("HTTP/host.home.gokrb5")
			if err != nil {
				t.Fatalf("get service ticket: %v", err)
			}
			if key.KeyType != id {
				t.Errorf("session key etype = %d, want %d", key.KeyType, id)
			}
		})
	}
}

// TestClient_Login_Concurrent_MIT runs N concurrent Login calls on a
// shared client.
func TestClient_Login_Concurrent_MIT(t *testing.T) {
	kdc := requireMIT(t)

	cl, err := kdc.NewClient("preauth_user", framework.MITUserPassword)
	if err != nil {
		t.Fatalf("build client: %v", err)
	}
	defer cl.Destroy()

	const n = 8
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for range n {
		wg.Go(func() {
			if err := cl.Login(); err != nil {
				errs <- err
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("concurrent login: %v", err)
	}
}

var (
	mitHTTPOnce     sync.Once
	mitHTTPAcceptor framework.HTTPAcceptor
	mitHTTPErr      error
)

// requireMITHTTPAcceptor lazily starts an HTTP acceptor keyed for
// the MIT HTTP SPN.
func requireMITHTTPAcceptor(t *testing.T) framework.HTTPAcceptor {
	t.Helper()
	kdc := requireMIT(t)
	mitHTTPOnce.Do(func() {
		a, cleanup, err := framework.StartHTTPAcceptor(context.Background(), kdc, kdc.HTTPSPN())
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

// TestSPNEGO_HTTP_MIT runs an end-to-end SPNEGO HTTP exchange with
// an MIT-issued service ticket under each supported AES enctype.
func TestSPNEGO_HTTP_MIT(t *testing.T) {
	kdc := requireMIT(t)
	acceptor := requireMITHTTPAcceptor(t)
	t.Cleanup(func() { dumpAcceptorLogsOnFailure(t, acceptor) })

	enctypes := []string{
		"aes256-cts-hmac-sha1-96",
		"aes128-cts-hmac-sha1-96",
		"aes256-cts-hmac-sha384-192",
		"aes128-cts-hmac-sha256-128",
	}

	for _, et := range enctypes {
		t.Run(et, func(t *testing.T) {
			cfg, err := kdc.Config()
			if err != nil {
				t.Fatalf("config: %v", err)
			}
			id := etypeID.ETypesByName[et]
			cfg.LibDefaults.DefaultTktEnctypes = []string{et}
			cfg.LibDefaults.DefaultTktEnctypeIDs = []int32{id}
			cfg.LibDefaults.DefaultTGSEnctypes = []string{et}
			cfg.LibDefaults.DefaultTGSEnctypeIDs = []int32{id}
			cfg.LibDefaults.PermittedEnctypes = []string{et}
			cfg.LibDefaults.PermittedEnctypeIDs = []int32{id}

			cl := client.NewWithPassword("nopreauth_user", kdc.Realm(), framework.MITUserPassword, cfg)
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
		})
	}
}

// TestSPNEGO_HTTP_NoAuth_Refused_MIT verifies the acceptor refuses an
// unauthenticated request with 401 Negotiate.
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
