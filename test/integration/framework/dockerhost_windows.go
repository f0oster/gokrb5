//go:build windows

package framework

import (
	"os"
	"os/exec"
	"strings"
)

// init populates DOCKER_HOST from the active Docker CLI context on
// Windows when the env var is not already set.
//
// testcontainers-go v0.36.0 has no Windows-aware Docker host discovery
// beyond reading DOCKER_HOST or ~/.testcontainers.properties. Its
// dockerSocketPath strategy probes /var/run/docker.sock with os.Stat,
// which never finds a Windows named pipe; its rootlessDockerSocketPath
// returns ErrRootlessDockerNotSupportedWindows; and isHostNotSet does
// not filter that rootless error. The result is that
// MustExtractDockerHost panics with the rootless message and
// SkipIfProviderIsNotHealthy surfaces it as the skip reason, even when
// Docker Desktop is fully healthy on the machine.
//
// Reading the active Docker context and exporting its endpoint as
// DOCKER_HOST lets testcontainers-go's dockerHostFromEnv strategy
// succeed first, sidestepping the broken probe order without changing
// any test code. If the docker CLI is not in PATH or the context query
// fails, this init silently does nothing and the existing testcontainers
// failure surfaces unchanged.
func init() {
	if os.Getenv("DOCKER_HOST") != "" {
		return
	}
	out, err := exec.Command("docker", "context", "inspect",
		"--format", "{{.Endpoints.docker.Host}}").Output()
	if err != nil {
		return
	}
	host := strings.TrimSpace(string(out))
	if host != "" {
		os.Setenv("DOCKER_HOST", host)
	}
}
