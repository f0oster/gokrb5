package suites

import (
	"context"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

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
