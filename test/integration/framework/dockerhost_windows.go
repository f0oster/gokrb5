//go:build windows

package framework

import (
	"os"
	"os/exec"
	"strings"
)

// TODO: investigate the root cause. Without this, testcontainers-go
// fails to discover a healthy Docker Desktop install on Windows.
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
