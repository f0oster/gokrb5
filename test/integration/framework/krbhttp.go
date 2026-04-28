package framework

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/testcontainers/testcontainers-go"
)

const (
	krbhttpFixtureDir = "../fixtures/krbhttp"
	krbhttpImageRepo  = "gokrb5-krbhttp"
	krbhttpImageTag   = "test"
	krbhttpPort       = "80/tcp"
	krbhttpReadyFile  = "/var/run/krbhttp-ready"
)

// HTTPAcceptor is a containerised Apache instance running
// mod_auth_gssapi, configured with a keytab provisioned by a KDC
// fixture. The acceptor protects the path /spnego with GSSAPI/SPNEGO.
//
// mod_auth_gssapi does not contact the KDC at request time; it
// decrypts the AP-REQ inside the SPNEGO token using the keytab. The
// container therefore does not require network reachability to the
// KDC, only the keytab and the realm name.
type HTTPAcceptor interface {
	// Endpoint returns the host and TCP port the test client dials.
	Endpoint() (host string, port int)
	// BaseURL returns "http://host:port" with no trailing slash.
	BaseURL() string
	// SPN returns the canonical service principal name the acceptor
	// is configured for. The test client must specify this SPN
	// explicitly when constructing a SPNEGO request, because the
	// dial address is a random localhost port and would otherwise
	// be used to derive a non-canonical SPN.
	SPN() string
	// Logs returns the container's accumulated stdout/stderr output.
	// Apache's error and access logs are wired to stderr/stdout in
	// the image, so this captures both alongside any startup output.
	Logs(ctx context.Context) ([]byte, error)
	// Close terminates the container.
	Close(ctx context.Context) error
}

type httpAcceptor struct {
	container testcontainers.Container
	host      string
	port      int
	spn       string
}

// StartHTTPAcceptor builds and starts an Apache container, copies the
// service keytab for spn and a minimal krb5.conf into it, and returns
// a handle the test code can dial. kdc must already have provisioned
// spn (i.e. spn appears in the topology's Services or Keytabs lists).
func StartHTTPAcceptor(ctx context.Context, kdc KDC, spn string) (HTTPAcceptor, func(), error) {
	kt, err := kdc.Keytab(spn)
	if err != nil {
		return nil, nil, fmt.Errorf("retrieve keytab for %s: %w", spn, err)
	}
	ktBytes, err := kt.Marshal()
	if err != nil {
		return nil, nil, fmt.Errorf("marshal keytab for %s: %w", spn, err)
	}

	req := testcontainers.ContainerRequest{
		FromDockerfile: testcontainers.FromDockerfile{
			Context:    krbhttpFixtureDir,
			Dockerfile: "Dockerfile",
			Repo:       krbhttpImageRepo,
			Tag:        krbhttpImageTag,
			KeepImage:  true,
		},
		ExposedPorts: []string{krbhttpPort},
	}

	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("start krbhttp container: %w", err)
	}

	a := &httpAcceptor{container: c, spn: spn}
	cleanup := func() {
		_ = a.Close(context.Background())
	}

	host, err := c.Host(ctx)
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("read krbhttp host: %w", err)
	}
	mapped, err := c.MappedPort(ctx, krbhttpPort)
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("read krbhttp port: %w", err)
	}
	a.host = host
	a.port = mapped.Int()

	logFixtureVersions(ctx, c, "krbhttp", "apache2", "libapache2-mod-auth-gssapi")

	if err := a.provision(ctx, kdc.Realm(), ktBytes); err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("provision krbhttp: %w", err)
	}

	if err := signalKrbHTTPReady(ctx, c); err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("signal krbhttp ready: %w", err)
	}
	if err := waitForKrbHTTP(ctx, a); err != nil {
		dumpContainerLogs(ctx, c, "krbhttp")
		cleanup()
		return nil, nil, fmt.Errorf("wait for krbhttp: %w", err)
	}

	return a, cleanup, nil
}

func (a *httpAcceptor) provision(ctx context.Context, realm string, keytab []byte) error {
	c := a.container

	if err := c.CopyToContainer(ctx, keytab, "/etc/apache2/http.keytab", 0o600); err != nil {
		return fmt.Errorf("copy keytab: %w", err)
	}
	if err := execIn(ctx, c, []string{"chown", "www-data:www-data", "/etc/apache2/http.keytab"}); err != nil {
		return fmt.Errorf("chown keytab: %w", err)
	}
	if err := c.CopyToContainer(ctx, []byte(renderAcceptorKrb5Conf(realm)), "/etc/krb5.conf", 0o644); err != nil {
		return fmt.Errorf("copy krb5.conf: %w", err)
	}
	return nil
}

func signalKrbHTTPReady(ctx context.Context, c testcontainers.Container) error {
	return execIn(ctx, c, []string{"touch", krbhttpReadyFile})
}

// waitForKrbHTTP polls the acceptor's /spnego endpoint until it returns
// 401 Unauthorized with a WWW-Authenticate: Negotiate header, which
// confirms apache started, mod_auth_gssapi loaded, and the site is
// serving the protected location.
func waitForKrbHTTP(ctx context.Context, a *httpAcceptor) error {
	addr := net.JoinHostPort(a.host, strconv.Itoa(a.port))
	url := "http://" + addr + "/spnego/"
	const maxAttempts = 100
	var lastErr error
	for range maxAttempts {
		resp, err := http.Get(url)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusUnauthorized &&
				resp.Header.Get("WWW-Authenticate") == "Negotiate" {
				return nil
			}
			lastErr = fmt.Errorf("status=%d www-auth=%q", resp.StatusCode, resp.Header.Get("WWW-Authenticate"))
		} else {
			lastErr = err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
	return fmt.Errorf("krbhttp at %s not ready within %d attempts: %v", addr, maxAttempts, lastErr)
}

// renderAcceptorKrb5Conf produces a minimal krb5.conf for the Apache
// container. mod_auth_gssapi never dials the KDC for SPNEGO acceptance
// so the kdc address is a placeholder; only the realm name and
// enctypes matter.
func renderAcceptorKrb5Conf(realm string) string {
	return fmt.Sprintf(`[libdefaults]
    default_realm = %s
    dns_lookup_realm = false
    dns_lookup_kdc = false
    permitted_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96 aes256-cts-hmac-sha384-192 aes128-cts-hmac-sha256-128

[realms]
    %s = {
        kdc = localhost:88
    }
`, realm, realm)
}

func (a *httpAcceptor) Endpoint() (string, int) { return a.host, a.port }
func (a *httpAcceptor) BaseURL() string {
	return "http://" + net.JoinHostPort(a.host, strconv.Itoa(a.port))
}
func (a *httpAcceptor) SPN() string { return a.spn }

func (a *httpAcceptor) Logs(ctx context.Context) ([]byte, error) {
	rc, err := a.container.Logs(ctx)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(rc)
}

func (a *httpAcceptor) Close(ctx context.Context) error {
	if a.container == nil {
		return nil
	}
	return a.container.Terminate(ctx)
}

var _ HTTPAcceptor = (*httpAcceptor)(nil)
