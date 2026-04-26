package suites

import (
	"bytes"
	"context"
	"errors"
	"log"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/f0oster/gokrb5/client"
	"github.com/f0oster/gokrb5/iana/errorcode"
	"github.com/f0oster/gokrb5/iana/etypeID"
	"github.com/f0oster/gokrb5/krberror"
	"github.com/f0oster/gokrb5/test"
	"github.com/f0oster/gokrb5/test/integration/framework"
)

// mitKDC is the shared MIT Kerberos KDC for every test in this binary.
// Set up once in TestMain; nil if integration is disabled or container
// startup failed (in which case individual tests skip).
var mitKDC framework.KDC

func TestMain(m *testing.M) {
	if os.Getenv(test.IntegrationEnvVar) != "1" {
		os.Exit(m.Run())
	}

	ctx := context.Background()
	kdc, cleanup, err := framework.StartMITKDC(ctx)
	if err != nil {
		log.Printf("MIT KDC setup failed: %v; integration tests will skip", err)
		os.Exit(m.Run())
	}
	mitKDC = kdc
	code := m.Run()
	cleanup()
	os.Exit(code)
}

// requireMIT ensures the test runs only when the integration env var is
// set and the shared MIT KDC came up successfully. Returns the shared
// KDC.
func requireMIT(t *testing.T) framework.KDC {
	t.Helper()
	test.Integration(t)
	if mitKDC == nil {
		t.Skip("MIT KDC not available; check TestMain logs")
	}
	return mitKDC
}

// requireKrbError asserts the error is a krberror.Krberror with the
// given RootCause and an EText that contains the given substring.
// gokrb5's krberror package concatenates wrapped error text via fmt
// rather than preserving the underlying error in an Unwrap chain, so
// substring matching is the most precise structural check available
// for the underlying KDC error code or decryption failure cause.
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

// TestClient_Login_PreauthUser_MIT exercises the AS exchange happy path
// against a principal that requires pre-authentication. The first
// AS-REQ has no preauth, the KDC responds with KDC_ERR_PREAUTH_REQUIRED,
// the client retries with PA-ENC-TIMESTAMP encrypted under the correct
// key, and the KDC returns an AS-REP carrying a TGT.
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

// TestClient_Login_NoPreauthUser_MIT exercises the AS exchange happy
// path against a principal that does not require pre-authentication.
// The KDC issues an AS-REP on the first AS-REQ with no preauth round
// trip, and the client decrypts EncASRepPart with the user's long-term
// key.
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

// TestClient_Login_InvalidPassword_PreauthUser_MIT verifies that an
// AS exchange with a wrong password against a preauth-required
// principal is rejected at the KDC with KDC_ERR_PREAUTH_FAILED. The
// client retries with PA-ENC-TIMESTAMP encrypted under the wrong key;
// the KDC fails to decrypt that and rejects the request.
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

// TestClient_Login_InvalidPassword_NoPreauthUser_MIT verifies that an
// AS exchange with a wrong password against a non-preauth principal
// fails at client-side decryption rather than at the KDC. The KDC
// happily issues an AS-REP because no preauth was requested; the
// client then fails to decrypt EncASRepPart because the key derived
// from the wrong password produces an integrity verification failure.
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

// TestClient_Login_UnknownUser_MIT verifies that an AS exchange for a
// principal that does not exist in the KDC database fails with
// KDC_ERR_C_PRINCIPAL_UNKNOWN. The KDC returns this immediately on the
// first AS-REQ; no preauth round trip is involved.
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
// happy path using a keytab instead of a password. The PA-ENC-TIMESTAMP
// is encrypted under the key extracted from the keytab; the KDC accepts
// it and returns an AS-REP carrying a TGT.
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

// TestClient_Login_NoPreauthUser_Keytab_MIT exercises keytab-based AS
// exchange against a principal that does not require pre-authentication.
// The KDC issues an AS-REP on the first AS-REQ; the client decrypts
// EncASRepPart with the long-term key recovered from the keytab.
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

// loggedInClient builds a client for the given user, performs the AS
// exchange to obtain a TGT, and returns the ready-to-use client.
// Failures during construction or login are fatal: the test wanted a
// logged-in client and got nothing usable.
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

// TestClient_GetServiceTicket_MIT exercises the TGS exchange happy
// path. The client logs in, then requests a service ticket for the
// HTTP service principal. The KDC returns a TGS-REP carrying a ticket
// encrypted with the service's long-term key plus a fresh session key
// shared between the client and the service.
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

// TestClient_GetServiceTicket_UnknownSPN_MIT verifies that a TGS
// request for a service principal that does not exist in the KDC's
// database is rejected with KDC_ERR_S_PRINCIPAL_UNKNOWN. The TGT is
// valid; only the requested service is unknown.
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
// service tickets: a second call for the same SPN returns the same
// ticket bytes without going back to the KDC. The shape of this test
// is byte-equality on the encrypted ticket cipher; if the client had
// re-requested, the KDC would issue a fresh ticket with a different
// random session key and different EncPart bytes.
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

// TestClient_GetServiceTicket_CrossRealm_MIT exercises the cross-realm
// TGS flow. The user authenticates to its home realm (HOME.GOKRB5) and
// then requests a service ticket for a principal in the trusted realm
// (TRUSTED.GOKRB5). The client transparently fetches a cross-realm TGT
// for TRUSTED.GOKRB5 from HOME.GOKRB5's KDC (using the
// krbtgt/TRUSTED.GOKRB5@HOME.GOKRB5 trust principal) and presents that
// to TRUSTED.GOKRB5's KDC to get the service ticket. The returned ticket
// should be in the trusted realm with the requested SName.
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
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := cl.Login(); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("concurrent login: %v", err)
	}
}
