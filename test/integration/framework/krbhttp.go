package framework

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/f0oster/gokrb5/keytab"
	"github.com/testcontainers/testcontainers-go"
)

const (
	krbhttpFixtureDir = "../fixtures/krbhttp"
	krbhttpImageRepo  = "gokrb5-krbhttp"
	krbhttpImageTag   = "test"
	krbhttpPort       = "80/tcp"
	krbhttpReadyFile  = "/var/run/krbhttp-ready"
)

// HTTPAcceptor is a containerised Apache+mod_auth_gssapi instance
// that protects /spnego with GSSAPI/SPNEGO using a fixture-provisioned
// keytab.
type HTTPAcceptor interface {
	// Endpoint returns the host and TCP port the test client dials.
	Endpoint() (host string, port int)
	// BaseURL returns "http://host:port".
	BaseURL() string
	// SPN returns the SPN the acceptor is keyed for. The client must
	// specify this explicitly because the dial address is a random
	// localhost port and wouldn't derive the canonical SPN.
	SPN() string
	// Logs returns the container's stdout/stderr.
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

// StartHTTPAcceptor builds and starts an Apache acceptor container
// using kdc's keytab for spn. kdc must already have provisioned spn.
func StartHTTPAcceptor(ctx context.Context, kdc KDC, spn string) (HTTPAcceptor, func(), error) {
	kt, err := kdc.Keytab(spn)
	if err != nil {
		return nil, nil, fmt.Errorf("retrieve keytab for %s: %w", spn, err)
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

	if err := a.provision(ctx, kdc.Realm(), kt); err != nil {
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

func (a *httpAcceptor) provision(ctx context.Context, realm string, kt *keytab.Keytab) error {
	c := a.container

	ktBytes, err := kt.Marshal()
	if err != nil {
		return fmt.Errorf("marshal keytab: %w", err)
	}
	if err := c.CopyToContainer(ctx, ktBytes, "/etc/apache2/http.keytab", 0o600); err != nil {
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

// waitForKrbHTTP polls /spnego until apache returns 401 Negotiate,
// confirming mod_auth_gssapi is serving the protected location.
func waitForKrbHTTP(ctx context.Context, a *httpAcceptor) error {
	addr := net.JoinHostPort(a.host, strconv.Itoa(a.port))
	url := "http://" + addr + "/spnego/"
	const maxAttempts = 25
	var lastErr error
	for range maxAttempts {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return fmt.Errorf("build probe request: %w", err)
		}
		resp, err := http.DefaultClient.Do(req)
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
	return fmt.Errorf("krbhttp at %s not ready within %d attempts: %w", addr, maxAttempts, lastErr)
}

// renderAcceptorKrb5Conf returns a minimal krb5.conf for the
// acceptor. The kdc address is a placeholder: mod_auth_gssapi
// validates AP-REQs from the keytab and never dials.
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
