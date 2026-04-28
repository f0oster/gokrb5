package suites

import (
	"context"
	"os"
	"sync"
	"testing"

	"github.com/f0oster/gokrb5/test"
	"github.com/f0oster/gokrb5/test/integration/framework"
)

// fixtureCleanups runs in reverse order at the end of TestMain.
var (
	fixtureCleanupsMu sync.Mutex
	fixtureCleanups   []func()
)

func registerFixtureCleanup(f func()) {
	fixtureCleanupsMu.Lock()
	fixtureCleanups = append(fixtureCleanups, f)
	fixtureCleanupsMu.Unlock()
}

// TestMain skips without INTEGRATION=1; otherwise runs the suite and
// tears down any fixtures lazy-started via require helpers.
func TestMain(m *testing.M) {
	if os.Getenv(test.IntegrationEnvVar) != "1" {
		os.Exit(m.Run())
	}
	code := m.Run()
	fixtureCleanupsMu.Lock()
	for i := len(fixtureCleanups) - 1; i >= 0; i-- {
		fixtureCleanups[i]()
	}
	fixtureCleanupsMu.Unlock()
	os.Exit(code)
}

// dumpAcceptorLogsOnFailure prints the acceptor's stdout/stderr if
// the test failed, so a 401/403/500 from mod_auth_gssapi can be
// diagnosed without re-running the test.
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
