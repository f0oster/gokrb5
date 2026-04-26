package suites

import (
	"os"
	"sync"
	"testing"

	"github.com/f0oster/gokrb5/test"
)

// fixtureCleanups holds tear-down functions registered by per-fixture
// require helpers. Run in reverse order at the end of TestMain.
var (
	fixtureCleanupsMu sync.Mutex
	fixtureCleanups   []func()
)

func registerFixtureCleanup(f func()) {
	fixtureCleanupsMu.Lock()
	fixtureCleanups = append(fixtureCleanups, f)
	fixtureCleanupsMu.Unlock()
}

// TestMain skips entirely without INTEGRATION=1; otherwise runs the
// suite and tears down whichever fixtures the tests caused to start.
// Fixture startup is lazy via require helpers (requireMIT, requireAD)
// so a test that uses one fixture doesn't pay startup cost for the
// others.
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
