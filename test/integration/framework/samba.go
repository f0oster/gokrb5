package framework

import (
	"context"
	"errors"
	"fmt"
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
)

// SambaTopology declares what to provision into a Samba AD-DC fixture.
type SambaTopology struct {
	Realm string
	Users []SambaUserSpec
}

// SambaUserSpec describes an AD user principal.
type SambaUserSpec struct {
	Name     string
	Password string
}

// SambaAD is the test-side handle to a containerised Samba AD-DC.
// Adds LDAP/LDAPS endpoints on top of the KDC interface so SASL/LDAP
// tests can dial the directory service.
type SambaAD interface {
	KDC
	LDAPEndpoint() (host string, port int)
	LDAPSEndpoint() (host string, port int)
	LDAPSPN() string
}

// adRealmTopology mirrors the test scenarios that suites/client_ad_test.go
// expects: one realm, two AD users.
var adRealmTopology = SambaTopology{
	Realm: "AD.GOKRB5",
	Users: []SambaUserSpec{
		{Name: "testuser1", Password: MITUserPassword},
		{Name: "testuser2", Password: MITUserPassword},
	},
}

type sambaAD struct {
	topology  SambaTopology
	container testcontainers.Container
	endpoint  RealmEndpoint
	ldapHost  string
	ldapPort  int
	ldapsPort int
}

// StartSambaAD starts a Samba AD-DC container and provisions the
// realm in adRealmTopology. Returns the SambaAD handle and a cleanup
// function that terminates the container.
func StartSambaAD(ctx context.Context) (SambaAD, func(), error) {
	topo := adRealmTopology

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

	s := &sambaAD{topology: topo, container: c}
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
	s.endpoint = RealmEndpoint{Realm: topo.Realm, Host: host, Port: kdcMapped.Int()}
	s.ldapHost = host
	s.ldapPort = ldapMapped.Int()
	s.ldapsPort = ldapsMapped.Int()

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

	return s, cleanup, nil
}

func (s *sambaAD) provision(ctx context.Context) error {
	c := s.container

	// Samba ships a default smb.conf that interferes with provisioning;
	// remove it so samba-tool can write its own from scratch.
	if err := execIn(ctx, c, []string{"rm", "-f", "/etc/samba/smb.conf"}); err != nil {
		return fmt.Errorf("remove default smb.conf: %w", err)
	}

	netbios := netbiosName(s.topology.Realm)
	provisionCmd := []string{
		"samba-tool", "domain", "provision",
		"--use-rfc2307",
		"--realm=" + s.topology.Realm,
		"--domain=" + netbios,
		"--adminpass=" + sambaAdminPassword,
		"--server-role=dc",
		"--dns-backend=SAMBA_INTERNAL",
		"--option=dns forwarder = 8.8.8.8",
		// Store NT ACLs in user.* xattrs instead of security.*
		// to avoid needing CAP_SYS_ADMIN in the container.
		"--option=acl_xattr:security_acl_name = user.NTACL",
	}
	if err := execIn(ctx, c, provisionCmd); err != nil {
		return fmt.Errorf("samba-tool domain provision: %w", err)
	}

	for _, u := range s.topology.Users {
		if err := execIn(ctx, c, []string{"samba-tool", "user", "create", u.Name, u.Password}); err != nil {
			return fmt.Errorf("samba-tool user create %s: %w", u.Name, err)
		}
	}

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
	for i := 0; i < maxAttempts; i++ {
		if err := probeKDC(cfg, s.topology.Realm); err == nil {
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
	return fmt.Errorf("Samba KDC at %s:%d not ready within %d attempts: %v",
		s.endpoint.Host, s.endpoint.Port, maxAttempts, lastErr)
}

// netbiosName returns the first label of a realm name, used as the
// NetBIOS short domain. "AD.GOKRB5" -> "AD".
func netbiosName(realm string) string {
	if i := strings.IndexByte(realm, '.'); i >= 0 {
		return realm[:i]
	}
	return realm
}

func (s *sambaAD) Realm() string { return s.topology.Realm }

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
	return client.NewWithPassword(username, s.topology.Realm, password, cfg), nil
}

// Keytab is not yet supported by the Samba fixture. Returns an error
// so tests that require keytabs surface a clear failure rather than a
// nil-pointer surprise.
func (s *sambaAD) Keytab(principal string) (*keytab.Keytab, error) {
	return nil, errors.New("Samba fixture does not provision keytabs yet")
}

func (s *sambaAD) LDAPEndpoint() (string, int)  { return s.ldapHost, s.ldapPort }
func (s *sambaAD) LDAPSEndpoint() (string, int) { return s.ldapHost, s.ldapsPort }
func (s *sambaAD) LDAPSPN() string              { return "ldap/" + dcHostname(s.topology.Realm) }

// dcHostname returns the DC's FQDN as Samba registers it during
// provisioning. Samba uses the lowercased realm with no host prefix
// when dns_backend=SAMBA_INTERNAL.
func dcHostname(realm string) string {
	return strings.ToLower(realm)
}

func (s *sambaAD) Close(ctx context.Context) error {
	if s.container == nil {
		return nil
	}
	return s.container.Terminate(ctx)
}

// Compile-time check that sambaAD satisfies SambaAD (and thus KDC).
var _ SambaAD = (*sambaAD)(nil)
