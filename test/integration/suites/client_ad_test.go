package suites

import (
	"context"
	"net"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/f0oster/gokrb5/client"
	"github.com/f0oster/gokrb5/iana/errorcode"
	"github.com/f0oster/gokrb5/krberror"
	"github.com/f0oster/gokrb5/test"
	"github.com/f0oster/gokrb5/test/integration/framework"
)

// requireAD lazily starts the Samba AD-DC fixture on first call and
// returns the shared handle. Skips the test if integration is
// disabled or the fixture failed to start.
var (
	adOnce sync.Once
	adKDC  framework.SambaAD
	adErr  error
)

func requireAD(t *testing.T) framework.SambaAD {
	t.Helper()
	test.Integration(t)
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

// TestSambaAD_FixtureUp_AD verifies the Samba AD-DC fixture comes up
// and exposes the expected realm and endpoints.
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

// TestClient_Login_AD exercises the AS exchange against a Heimdal-based
// Samba AD-DC using a password.
func TestClient_Login_AD(t *testing.T) {
	kdc := requireAD(t)

	cl, err := kdc.NewClient("testuser1", framework.MITUserPassword)
	if err != nil {
		t.Fatalf("build client: %v", err)
	}
	defer cl.Destroy()

	if err := cl.Login(); err != nil {
		t.Fatalf("login: %v", err)
	}
}

// TestClient_Login_InvalidPassword_AD verifies that wrong password is
// rejected by the Heimdal KDC with KDC_ERR_PREAUTH_FAILED.
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

// TestClient_Login_UnknownUser_AD verifies that an unknown principal
// is rejected by the Heimdal KDC with KDC_ERR_C_PRINCIPAL_UNKNOWN.
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

// TestClient_Login_Keytab_AD exercises keytab-based AS exchange against
// the Heimdal KDC. The keytab is exported during fixture provisioning
// via samba-tool and contains the user's password-derived keys.
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

// TestClient_GetServiceTicket_LDAP_AD exercises the TGS exchange against
// the Heimdal KDC for the LDAP service principal Samba registers for
// the DC.
func TestClient_GetServiceTicket_LDAP_AD(t *testing.T) {
	kdc := requireAD(t)

	cl, err := kdc.NewClient("testuser1", framework.MITUserPassword)
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
