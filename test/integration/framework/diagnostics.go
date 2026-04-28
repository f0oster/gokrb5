package framework

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/f0oster/gokrb5/iana/etypeID"
	"github.com/f0oster/gokrb5/keytab"
	"github.com/testcontainers/testcontainers-go"
	tcexec "github.com/testcontainers/testcontainers-go/exec"
)

// fixtureLog emits framework-side diagnostic lines with a distinct
// prefix so they're easy to pick out from go test and testcontainers
// output.
var fixtureLog = log.New(os.Stderr, "[fixture] ", 0)

// logFixtureVersions logs OS and package versions from c.
func logFixtureVersions(ctx context.Context, c testcontainers.Container, label string, packages ...string) {
	// Build a single shell pipeline that emits "os=<value>" followed
	// by "<pkg>=<version>" for each package. dpkg-query's stderr is
	// silenced so a missing package doesn't pollute the log.
	parts := []string{`. /etc/os-release && echo "os=$PRETTY_NAME"`}
	for _, pkg := range packages {
		parts = append(parts, fmt.Sprintf(`dpkg-query -W -f='%s=${Version}\n' %s 2>/dev/null`, pkg, pkg))
	}
	cmd := strings.Join(parts, "; ")

	_, reader, err := c.Exec(ctx, []string{"sh", "-c", cmd}, tcexec.Multiplexed())
	if err != nil {
		fixtureLog.Printf("%s: version probe failed: %v", label, err)
		return
	}
	out, _ := io.ReadAll(reader)

	// Log each pipeline line with the fixture's label prefix.
	for line := range strings.SplitSeq(strings.TrimSpace(string(out)), "\n") {
		if line != "" {
			fixtureLog.Printf("%s: %s", label, line)
		}
	}
}

// logKeytabSummary logs principal, kvno, and enctype for each entry
// in the keytab. Key material is not logged.
func logKeytabSummary(label string, data []byte) {
	kt := keytab.New()
	if err := kt.Unmarshal(data); err != nil {
		fixtureLog.Printf("keytab[%s]: unmarshal failed: %v", label, err)
		return
	}
	if len(kt.Entries) == 0 {
		fixtureLog.Printf("keytab[%s]: no entries", label)
		return
	}
	for _, e := range kt.Entries {
		fixtureLog.Printf("keytab[%s]: kvno=%d etype=%d (%s) principal=%s",
			label, e.KVNO, e.Key.KeyType, etypeName(e.Key.KeyType), e.Principal)
	}
}

// etypeName returns the canonical name for a Kerberos etype id, or
// "etype-N" if not recognised.
func etypeName(etype int32) string {
	switch etype {
	case etypeID.DES_CBC_CRC:
		return "des-cbc-crc"
	case etypeID.DES_CBC_MD5:
		return "des-cbc-md5"
	case etypeID.DES3_CBC_SHA1_KD:
		return "des3-cbc-sha1-kd"
	case etypeID.AES128_CTS_HMAC_SHA1_96:
		return "aes128-cts-hmac-sha1-96"
	case etypeID.AES256_CTS_HMAC_SHA1_96:
		return "aes256-cts-hmac-sha1-96"
	case etypeID.AES128_CTS_HMAC_SHA256_128:
		return "aes128-cts-hmac-sha256-128"
	case etypeID.AES256_CTS_HMAC_SHA384_192:
		return "aes256-cts-hmac-sha384-192"
	case etypeID.RC4_HMAC:
		return "rc4-hmac"
	}
	return fmt.Sprintf("etype-%d", etype)
}

// dumpContainerLogs logs the container's stdout/stderr line-by-line
// with the given label.
func dumpContainerLogs(ctx context.Context, c testcontainers.Container, label string) {
	rc, err := c.Logs(ctx)
	if err != nil {
		fixtureLog.Printf("%s: read container logs: %v", label, err)
		return
	}
	defer rc.Close()
	out, err := io.ReadAll(rc)
	if err != nil {
		fixtureLog.Printf("%s: drain container logs: %v", label, err)
		return
	}
	for line := range strings.SplitSeq(strings.TrimSpace(string(out)), "\n") {
		if line != "" {
			fixtureLog.Printf("%s [container]: %s", label, line)
		}
	}
}
