package suites

import (
	"crypto/tls"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/f0oster/gokrb5/client"
	"github.com/f0oster/gokrb5/gssapi"
	"github.com/f0oster/gokrb5/test/integration/framework"
)

// dialLDAP opens a plain TCP connection to the AD-DC's LDAP port.
func dialLDAP(t *testing.T, kdc framework.ActiveDirectory) net.Conn {
	t.Helper()
	host, port := kdc.LDAPEndpoint()
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial LDAP %s: %v", addr, err)
	}
	return conn
}

// dialLDAPS opens a TLS connection to the AD-DC's LDAPS port. Returns
// *tls.Conn so callers can extract channel bindings from the state.
func dialLDAPS(t *testing.T, kdc framework.ActiveDirectory) *tls.Conn {
	t.Helper()
	host, port := kdc.LDAPSEndpoint()
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := tls.Dial("tcp", addr, &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true, // self-signed; CBT validates the cert via channel binding hash
	})
	if err != nil {
		t.Fatalf("dial LDAPS %s: %v", addr, err)
	}
	return conn
}

// loggedInADClient returns a krb5 client logged in as testuser1.
func loggedInADClient(t *testing.T, kdc framework.ActiveDirectory) *client.Client {
	t.Helper()
	cl, err := kdc.NewClient("testuser1", framework.SambaUserPassword)
	if err != nil {
		t.Fatalf("build client: %v", err)
	}
	if err := cl.Login(); err != nil {
		cl.Destroy()
		t.Fatalf("login: %v", err)
	}
	return cl
}

// channelBindingsFor returns the tls-server-end-point channel
// bindings derived from the TLS state of conn.
func channelBindingsFor(t *testing.T, conn *tls.Conn) *gssapi.ChannelBindings {
	t.Helper()
	state := conn.ConnectionState()
	bindings, err := gssapi.NewTLSChannelBindingsFromState(&state)
	if err != nil {
		t.Fatalf("build channel bindings: %v", err)
	}
	return bindings
}

// TestSASL_LDAP_Bind_NoLayer_Refused_AD verifies a plain-LDAP SASL
// bind with no security layer is refused with strongerAuthRequired (8).
func TestSASL_LDAP_Bind_NoLayer_Refused_AD(t *testing.T) {
	kdc := requireAD(t)

	cl := loggedInADClient(t, kdc)
	defer cl.Destroy()

	init, err := gssapi.NewInitiator(cl, kdc.LDAPSPN(), gssapi.WithMutualAuth())
	if err != nil {
		t.Fatalf("NewInitiator: %v", err)
	}

	conn := dialLDAP(t, kdc)
	defer conn.Close()

	_, err = framework.SASLBindGSSAPI(conn, init, gssapi.SASLSecurityNone)
	if err == nil {
		t.Fatal("plain LDAP SASL bind without security layer should be refused")
	}
	if !strings.Contains(err.Error(), "resultCode=8") {
		t.Errorf("expected resultCode=8 (strongerAuthRequired), got: %v", err)
	}
}

// TestSASL_LDAP_Bind_Integrity_AD binds with the integrity layer and
// runs a wrapped rootDSE search to roundtrip a MIC token.
func TestSASL_LDAP_Bind_Integrity_AD(t *testing.T) {
	kdc := requireAD(t)

	cl := loggedInADClient(t, kdc)
	defer cl.Destroy()

	init, err := gssapi.NewInitiator(cl, kdc.LDAPSPN(), gssapi.WithMutualAuth())
	if err != nil {
		t.Fatalf("NewInitiator: %v", err)
	}

	conn := dialLDAP(t, kdc)
	defer conn.Close()

	ctx, err := framework.SASLBindGSSAPI(conn, init, gssapi.SASLSecurityIntegrity)
	if err != nil {
		t.Fatalf("SASL bind: %v", err)
	}

	if _, err := framework.WrappedRootDSESearch(conn, ctx, "defaultNamingContext"); err != nil {
		t.Fatalf("wrapped search: %v", err)
	}
}

// TestSASL_LDAP_Bind_Confidentiality_AD binds with confidentiality
// (sealed WrapTokens) and runs a wrapped rootDSE search.
func TestSASL_LDAP_Bind_Confidentiality_AD(t *testing.T) {
	kdc := requireAD(t)

	cl := loggedInADClient(t, kdc)
	defer cl.Destroy()

	init, err := gssapi.NewInitiator(cl, kdc.LDAPSPN(),
		gssapi.WithMutualAuth(),
		gssapi.WithConfidentiality(),
	)
	if err != nil {
		t.Fatalf("NewInitiator: %v", err)
	}

	conn := dialLDAP(t, kdc)
	defer conn.Close()

	ctx, err := framework.SASLBindGSSAPI(conn, init, gssapi.SASLSecurityConfidential)
	if err != nil {
		t.Fatalf("SASL bind: %v", err)
	}

	if _, err := framework.WrappedRootDSESearch(conn, ctx, "defaultNamingContext"); err != nil {
		t.Fatalf("wrapped search: %v", err)
	}
}

// TestSASL_LDAPS_CBT_AD runs a SASL/GSSAPI bind over LDAPS with
// matching channel bindings (RFC 5929 tls-server-end-point).
func TestSASL_LDAPS_CBT_AD(t *testing.T) {
	kdc := requireAD(t)

	cl := loggedInADClient(t, kdc)
	defer cl.Destroy()

	conn := dialLDAPS(t, kdc)
	defer conn.Close()

	init, err := gssapi.NewInitiator(cl, kdc.LDAPSPN(),
		gssapi.WithMutualAuth(),
		gssapi.WithChannelBindings(channelBindingsFor(t, conn)),
	)
	if err != nil {
		t.Fatalf("NewInitiator: %v", err)
	}

	if _, err := framework.SASLBindGSSAPI(conn, init, gssapi.SASLSecurityNone); err != nil {
		t.Fatalf("SASL bind: %v", err)
	}
}

// TestSASL_LDAPS_CBT_Mismatch_AD runs a SASL/GSSAPI bind over LDAPS
// with deliberately wrong channel binding bytes. Whether the bind
// fails depends on Samba's CBT enforcement mode; this test asserts
// the server rejects the mismatch when validation is active. With
// the fixture's default config (no strong-auth requirement) Samba
// still validates CBT when sent, so this should fail.
func TestSASL_LDAPS_CBT_Mismatch_AD(t *testing.T) {
	kdc := requireAD(t)

	cl := loggedInADClient(t, kdc)
	defer cl.Destroy()

	conn := dialLDAPS(t, kdc)
	defer conn.Close()

	bindings := channelBindingsFor(t, conn)
	if len(bindings.ApplicationData) == 0 {
		t.Fatal("channel binding ApplicationData is empty; cannot tamper")
	}
	// Flip the last byte so the binding hash no longer matches what
	// Samba derives from its end of the TLS connection.
	bindings.ApplicationData[len(bindings.ApplicationData)-1] ^= 0xFF

	init, err := gssapi.NewInitiator(cl, kdc.LDAPSPN(),
		gssapi.WithMutualAuth(),
		gssapi.WithChannelBindings(bindings),
	)
	if err != nil {
		t.Fatalf("NewInitiator: %v", err)
	}

	if _, err := framework.SASLBindGSSAPI(conn, init, gssapi.SASLSecurityNone); err == nil {
		t.Fatal("SASL bind with mismatched CBT should have failed")
	}
}
