package framework

import (
	"testing"

	"github.com/testcontainers/testcontainers-go"
)

// SkipIfNoDocker skips the test if no Docker daemon is reachable.
func SkipIfNoDocker(t *testing.T) {
	t.Helper()
	testcontainers.SkipIfProviderIsNotHealthy(t)
}
