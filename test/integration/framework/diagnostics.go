package framework

import (
	"context"
	"fmt"
	"io"
	"log"
	"strings"

	"github.com/f0oster/gokrb5/keytab"
	"github.com/testcontainers/testcontainers-go"
	tcexec "github.com/testcontainers/testcontainers-go/exec"
)

// logFixtureVersions logs the OS pretty name and dpkg-reported
// versions of the named packages from inside c, prefixed with label.
// Best-effort; failures are logged but don't abort.
func logFixtureVersions(ctx context.Context, c testcontainers.Container, label string, packages ...string) {
	parts := []string{`. /etc/os-release && echo "os=$PRETTY_NAME"`}
	for _, pkg := range packages {
		parts = append(parts, fmt.Sprintf(`dpkg-query -W -f='%s=${Version}\n' %s 2>/dev/null`, pkg, pkg))
	}
	cmd := strings.Join(parts, "; ")
	_, reader, err := c.Exec(ctx, []string{"sh", "-c", cmd}, tcexec.Multiplexed())
	if err != nil {
		log.Printf("%s: version probe failed: %v", label, err)
		return
	}
	out, _ := io.ReadAll(reader)
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line != "" {
			log.Printf("%s: %s", label, line)
		}
	}
}

// logKeytabSummary parses keytab bytes and logs a klist-like summary
// of every entry: principal name, kvno, and enctype id. Key material
// is not logged. Failures are swallowed; this is a diagnostic, not
// a correctness check.
func logKeytabSummary(label string, data []byte) {
	kt := keytab.New()
	if err := kt.Unmarshal(data); err != nil {
		log.Printf("keytab[%s]: unmarshal failed: %v", label, err)
		return
	}
	if len(kt.Entries) == 0 {
		log.Printf("keytab[%s]: no entries", label)
		return
	}
	for _, e := range kt.Entries {
		log.Printf("keytab[%s]: kvno=%d etype=%d principal=%s",
			label, e.KVNO, e.Key.KeyType, e.Principal)
	}
}

// dumpContainerLogs reads the container's stdout/stderr and logs each
// non-empty line prefixed with label. Best-effort; surfaces a
// Docker-level error so a startup failure can be diagnosed without
// re-running with shell access to the container.
func dumpContainerLogs(ctx context.Context, c testcontainers.Container, label string) {
	rc, err := c.Logs(ctx)
	if err != nil {
		log.Printf("%s: read container logs: %v", label, err)
		return
	}
	defer rc.Close()
	out, err := io.ReadAll(rc)
	if err != nil {
		log.Printf("%s: drain container logs: %v", label, err)
		return
	}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line != "" {
			log.Printf("%s [container]: %s", label, line)
		}
	}
}
