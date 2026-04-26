package framework

import (
	"testing"

	"github.com/testcontainers/testcontainers-go"
)

// SkipIfNoDocker skips the test cleanly when a Docker daemon is not
// reachable. Integration tests rely on Docker for spinning up KDC
// containers; without it they cannot run and should not fail.
func SkipIfNoDocker(t *testing.T) {
	t.Helper()
	testcontainers.SkipIfProviderIsNotHealthy(t)
}
