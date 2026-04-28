package framework

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/f0oster/gokrb5/client"
	"github.com/f0oster/gokrb5/config"
	"github.com/f0oster/gokrb5/keytab"
	"github.com/testcontainers/testcontainers-go"
)

const (
	sambaFixtureDir = "../fixtures/samba-ad"
	sambaImageRepo  = "gokrb5-samba-ad"
	sambaImageTag   = "test"
	sambaKDCPort    = "88/tcp"
	sambaLDAPPort   = "389/tcp"
	sambaLDAPSPort  = "636/tcp"

	sambaAdminPassword = "AdminPass1!"
	sambaReadyFile     = "/var/run/samba-ready"
	// sambaDCHostname is the DC's NetBIOS short name; the FQDN
	// becomes <sambaDCHostname>.<lowercased realm>.
	sambaDCHostname = "DC"

	// SambaUserPassword is the password set on every AD user and
	// service account.
	SambaUserPassword = "Password1!"
)

const sambaHTTPSPN = "HTTP/web.ad.gokrb5"

// adRealmTopology: two test users plus an HTTP service account for
// the krbhttp acceptor.
var adRealmTopology = Topology{
	Realms: []RealmSpec{
		{
			Name: "AD.GOKRB5",
			Users: []UserSpec{
				{Name: "testuser1", Password: SambaUserPassword, WithKeytab: true},
				{Name: "testuser2", Password: SambaUserPassword, WithKeytab: true},
			},
			Services: []ServiceSpec{
				{
					SPN:     sambaHTTPSPN,
					Account: &ServiceAccount{Name: "websvc", Password: SambaUserPassword},
				},
			},
		},
	},
}

type sambaAD struct {
	topology  Topology
	container testcontainers.Container
	endpoint  RealmEndpoint
	ldapHost  string
	ldapPort  int
	ldapsPort int
	keytabs   map[string][]byte
}

// StartSambaAD starts a Samba AD-DC container and provisions
// adRealmTopology. Returns the handle and a cleanup function.
func StartSambaAD(ctx context.Context) (ActiveDirectory, func(), error) {
	topo := adRealmTopology
	if len(topo.Realms) != 1 {
		return nil, nil, fmt.Errorf("Samba fixture currently provisions a single realm; topology has %d", len(topo.Realms))
	}
	if len(topo.Trusts) != 0 {
		return nil, nil, fmt.Errorf("Samba fixture does not yet provision trusts; topology has %d", len(topo.Trusts))
	}

	req := testcontainers.ContainerRequest{
		FromDockerfile: testcontainers.FromDockerfile{
			Context:    sambaFixtureDir,
			Dockerfile: "Dockerfile",
			Repo:       sambaImageRepo,
			Tag:        sambaImageTag,
			KeepImage:  true,
		},
		ExposedPorts: []string{sambaKDCPort, sambaLDAPPort, sambaLDAPSPort},
		// Port readiness is checked by waitForSambaKDC after provisioning
		// finishes and the framework signals samba to start.
	}

	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("start Samba container: %w", err)
	}

	s := &sambaAD{topology: topo, container: c, keytabs: make(map[string][]byte)}
	cleanup := func() {
		_ = s.Close(context.Background())
	}

	host, err := c.Host(ctx)
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("read Samba host: %w", err)
	}
	kdcMapped, err := c.MappedPort(ctx, sambaKDCPort)
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("read Samba KDC port: %w", err)
	}
	ldapMapped, err := c.MappedPort(ctx, sambaLDAPPort)
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("read Samba LDAP port: %w", err)
	}
	ldapsMapped, err := c.MappedPort(ctx, sambaLDAPSPort)
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("read Samba LDAPS port: %w", err)
	}
	s.endpoint = RealmEndpoint{Realm: topo.Realms[0].Name, Host: host, Port: kdcMapped.Int()}
	s.ldapHost = host
	s.ldapPort = ldapMapped.Int()
	s.ldapsPort = ldapsMapped.Int()

	logFixtureVersions(ctx, c, "Samba AD", "samba", "samba-ad-dc")

	if err := s.provision(ctx); err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("provision Samba: %w", err)
	}

	if err := signalSambaReady(ctx, c); err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("signal samba ready: %w", err)
	}
	if err := waitForSambaKDC(ctx, s); err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("wait for Samba KDC: %w", err)
	}
	if err := waitForSambaLDAPS(ctx, s); err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("wait for Samba LDAPS: %w", err)
	}

	return s, cleanup, nil
}

func (s *sambaAD) provision(ctx context.Context) error {
	c := s.container
	realm := s.topology.Realms[0]

	// Samba ships a default smb.conf that interferes with provisioning;
	// remove it so samba-tool can write its own from scratch.
	if err := execIn(ctx, c, []string{"rm", "-f", "/etc/samba/smb.conf"}); err != nil {
		return fmt.Errorf("remove default smb.conf: %w", err)
	}

	netbios := netbiosName(realm.Name)
	provisionCmd := []string{
		"samba-tool", "domain", "provision",
		"--use-rfc2307",
		"--realm=" + realm.Name,
		"--domain=" + netbios,
		"--host-name=" + sambaDCHostname,
		"--adminpass=" + sambaAdminPassword,
		"--server-role=dc",
		"--dns-backend=SAMBA_INTERNAL",
		"--option=dns forwarder = 8.8.8.8",
		// Store NT ACLs in user.* xattrs instead of security.*
		// to avoid needing CAP_SYS_ADMIN in the container.
		"--option=acl_xattr:security_acl_name = user.NTACL",
		// Default the domain-wide msDS-SupportedEncryptionTypes to
		// AES128+AES256 (0x18 = 24). Samba's stock default is 0,
		// which Windows-compat code treats as RC4-only for accounts
		// that have the attribute unset, causing the KDC to issue
		// RC4-HMAC service tickets even when AES keys are present.
		"--option=kdc default domain supported enctypes = 24",
	}
	if err := execIn(ctx, c, provisionCmd); err != nil {
		return fmt.Errorf("samba-tool domain provision: %w", err)
	}

	for _, u := range realm.Users {
		if err := execIn(ctx, c, []string{"samba-tool", "user", "create", u.Name, u.Password}); err != nil {
			return fmt.Errorf("samba-tool user create %s: %w", u.Name, err)
		}
		if u.WithKeytab {
			if err := s.exportKeytab(ctx, u.Name, realm.Name); err != nil {
				return err
			}
		}
	}

	for _, svc := range realm.Services {
		if svc.Account == nil {
			return fmt.Errorf("Samba service %q requires Account", svc.SPN)
		}
		if err := execIn(ctx, c, []string{"samba-tool", "user", "create", svc.Account.Name, svc.Account.Password}); err != nil {
			return fmt.Errorf("samba-tool user create %s: %w", svc.Account.Name, err)
		}
		if err := execIn(ctx, c, []string{"samba-tool", "spn", "add", svc.SPN, svc.Account.Name}); err != nil {
			return fmt.Errorf("samba-tool spn add %s -> %s: %w", svc.SPN, svc.Account.Name, err)
		}
		if err := s.exportKeytab(ctx, svc.SPN, realm.Name); err != nil {
			return err
		}
	}

	return nil
}

// exportKeytab runs samba-tool exportkeytab for principal, copies
// the file out, and stores it under "principal@realm".
func (s *sambaAD) exportKeytab(ctx context.Context, principal, realm string) error {
	c := s.container
	path := "/tmp/" + strings.ReplaceAll(principal, "/", "_") + ".keytab"
	if err := execIn(ctx, c, []string{
		"samba-tool", "domain", "exportkeytab", path,
		"--principal=" + principal,
	}); err != nil {
		return fmt.Errorf("exportkeytab %s: %w", principal, err)
	}
	rc, err := c.CopyFileFromContainer(ctx, path)
	if err != nil {
		return fmt.Errorf("copy keytab for %s: %w", principal, err)
	}
	defer rc.Close()
	data, err := io.ReadAll(rc)
	if err != nil {
		return fmt.Errorf("read keytab for %s: %w", principal, err)
	}
	key := principal + "@" + realm
	s.keytabs[key] = data
	logKeytabSummary(key, data)
	return nil
}

func signalSambaReady(ctx context.Context, c testcontainers.Container) error {
	return execIn(ctx, c, []string{"touch", sambaReadyFile})
}

func waitForSambaKDC(ctx context.Context, s *sambaAD) error {
	cfg, err := config.NewFromString(GenerateKRB5Conf([]RealmEndpoint{s.endpoint}))
	if err != nil {
		return fmt.Errorf("build probe config: %w", err)
	}
	const maxAttempts = 100 // samba startup is slower than MIT
	var lastErr error
	for range maxAttempts {
		if err := probeKDC(cfg, s.Realm()); err == nil {
			return nil
		} else {
			lastErr = err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
	return fmt.Errorf("Samba KDC at %s:%d not ready within %d attempts: %w",
		s.endpoint.Host, s.endpoint.Port, maxAttempts, lastErr)
}

// waitForSambaLDAPS polls with TLS handshakes; the TCP port may
// bind before LDAPS can complete a handshake.
func waitForSambaLDAPS(ctx context.Context, s *sambaAD) error {
	addr := net.JoinHostPort(s.ldapHost, strconv.Itoa(s.ldapsPort))
	const maxAttempts = 100
	var lastErr error
	for range maxAttempts {
		dialer := &tls.Dialer{
			NetDialer: &net.Dialer{Timeout: 500 * time.Millisecond},
			Config:    &tls.Config{InsecureSkipVerify: true},
		}
		conn, err := dialer.DialContext(ctx, "tcp", addr)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		lastErr = err
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
	return fmt.Errorf("Samba LDAPS at %s not ready within %d attempts: %w",
		addr, maxAttempts, lastErr)
}

// netbiosName returns the first label of a realm name, used as the
// NetBIOS short domain. "AD.GOKRB5" -> "AD".
func netbiosName(realm string) string {
	if first, _, ok := strings.Cut(realm, "."); ok {
		return first
	}
	return realm
}

func (s *sambaAD) Realm() string { return s.topology.Realms[0].Name }

func (s *sambaAD) Config() (*config.Config, error) {
	cfg, err := config.NewFromString(GenerateKRB5Conf([]RealmEndpoint{s.endpoint}))
	if err != nil {
		return nil, fmt.Errorf("parse generated krb5.conf: %w", err)
	}
	return cfg, nil
}

func (s *sambaAD) NewClient(username, password string) (*client.Client, error) {
	cfg, err := s.Config()
	if err != nil {
		return nil, err
	}
	return client.NewWithPassword(username, s.Realm(), password, cfg), nil
}

// Keytab returns the keytab for principal. principal may be bare
// ("testuser1") or fully qualified ("testuser1@AD.GOKRB5"); bare
// names must resolve to exactly one entry.
func (s *sambaAD) Keytab(principal string) (*keytab.Keytab, error) {
	return loadKeytab(s.keytabs, principal)
}

func (s *sambaAD) LDAPEndpoint() (string, int)  { return s.ldapHost, s.ldapPort }
func (s *sambaAD) LDAPSEndpoint() (string, int) { return s.ldapHost, s.ldapsPort }
func (s *sambaAD) LDAPSPN() string              { return "ldap/" + dcHostname(s.Realm()) }
func (s *sambaAD) HTTPSPN() string              { return sambaHTTPSPN }

// dcHostname returns the DC's FQDN as Samba registers it during
// provisioning: <sambaDCHostname>.<lowercased realm>.
func dcHostname(realm string) string {
	return strings.ToLower(sambaDCHostname) + "." + strings.ToLower(realm)
}

func (s *sambaAD) Close(ctx context.Context) error {
	if s.container == nil {
		return nil
	}
	return s.container.Terminate(ctx)
}

// Compile-time check that sambaAD satisfies ActiveDirectory (and thus KDC).
var _ ActiveDirectory = (*sambaAD)(nil)
