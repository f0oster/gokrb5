package framework

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"strings"
	"time"

	"github.com/f0oster/gokrb5/client"
	"github.com/f0oster/gokrb5/config"
	"github.com/f0oster/gokrb5/keytab"
	"github.com/f0oster/gokrb5/krberror"
	"github.com/testcontainers/testcontainers-go"
	tcexec "github.com/testcontainers/testcontainers-go/exec"
)

const (
	mitFixtureDir = "../fixtures/mit-kdc"
	mitImageRepo  = "gokrb5-mit-kdc"
	mitImageTag   = "test"
	mitKDCPort    = "88/tcp"

	mitMasterPassword = "masterpw"

	// MITUserPassword is the password the framework sets on every
	// provisioned user principal. Tests use this when constructing
	// clients via KDC.NewClient.
	MITUserPassword = "Password1!"

	// readyFile gates the container's CMD: krb5kdc starts only once
	// this file exists.
	readyFile = "/var/run/kdc-ready"

	// trustEnctypes pins the cross-realm krbtgt to AES enctypes both
	// KDCs support.
	trustEnctypes = "aes256-cts-hmac-sha1-96:normal,aes128-cts-hmac-sha1-96:normal,aes256-cts-hmac-sha384-192:normal,aes128-cts-hmac-sha256-128:normal"
)

// MITTopology declares the realms, principals, and trusts to
// provision into an MIT fixture.
type MITTopology struct {
	Realms []RealmSpec
	Trusts []TrustSpec
}

// RealmSpec is the per-realm provisioning data.
type RealmSpec struct {
	Name     string
	Users    []UserSpec
	Services []string // SPN strings, e.g. "HTTP/host.example.com" (no @REALM; the realm is implicit)
}

// UserSpec describes a user principal to provision.
type UserSpec struct {
	Name            string
	Password        string
	RequiresPreauth bool
	WithKeytab      bool
}

// TrustSpec is a one-way cross-realm trust. Users in From can request
// service tickets for principals in To. The framework provisions the
// shared krbtgt/To@From principal in both realms with matching keys.
type TrustSpec struct {
	From string
	To   string
}

// multiRealmTopology declares two realms (HOME, TRUSTED) joined by a
// one-way trust HOME -> TRUSTED. HOME holds the test users plus a
// service; TRUSTED holds a service that HOME users reach via the trust.
var multiRealmTopology = MITTopology{
	Realms: []RealmSpec{
		{
			Name: "HOME.GOKRB5",
			Users: []UserSpec{
				{Name: "preauth_user", Password: MITUserPassword, RequiresPreauth: true, WithKeytab: true},
				{Name: "nopreauth_user", Password: MITUserPassword, RequiresPreauth: false, WithKeytab: true},
			},
			Services: []string{"HTTP/host.home.gokrb5"},
		},
		{
			Name:     "TRUSTED.GOKRB5",
			Services: []string{"HTTP/host.trusted.gokrb5"},
		},
	},
	Trusts: []TrustSpec{
		{From: "HOME.GOKRB5", To: "TRUSTED.GOKRB5"},
	},
}

// realmHandle pairs a realm spec with its container and endpoint.
type realmHandle struct {
	Spec      RealmSpec
	Container testcontainers.Container
	Endpoint  RealmEndpoint
}

type mitKDC struct {
	topology MITTopology
	realms   []realmHandle
	// keytabs is keyed by bare principal name (e.g. "preauth_user",
	// "HTTP/host.home.gokrb5"). Names must be unique across realms;
	// otherwise later provisioning silently overwrites earlier entries.
	keytabs map[string][]byte
}

// StartMITKDC starts one container per realm in the test topology
// and provisions realms, principals, and the trusts between them.
// Returns the KDC handle and a cleanup function that terminates
// every container.
func StartMITKDC(ctx context.Context) (KDC, func(), error) {
	topo := multiRealmTopology
	kdc := &mitKDC{
		topology: topo,
		realms:   make([]realmHandle, 0, len(topo.Realms)),
		keytabs:  make(map[string][]byte),
	}
	cleanup := func() {
		_ = kdc.Close(context.Background())
	}

	// Start a container per realm. Each container's CMD blocks in a
	// polling loop until signalReady touches the ready file.
	for _, spec := range topo.Realms {
		c, ep, err := startContainer(ctx, spec.Name)
		if err != nil {
			cleanup()
			return nil, nil, fmt.Errorf("start container for %s: %w", spec.Name, err)
		}
		kdc.realms = append(kdc.realms, realmHandle{Spec: spec, Container: c, Endpoint: ep})
	}
	if len(kdc.realms) > 0 {
		logFixtureVersions(ctx, kdc.realms[0].Container, "MIT KDC", "krb5-kdc")
	}

	for i := range kdc.realms {
		h := &kdc.realms[i]
		if err := kdc.provisionRealm(ctx, h); err != nil {
			cleanup()
			return nil, nil, fmt.Errorf("provision %s: %w", h.Spec.Name, err)
		}
	}

	for _, t := range topo.Trusts {
		from, ok := kdc.containerFor(t.From)
		if !ok {
			cleanup()
			return nil, nil, fmt.Errorf("trust references unknown source realm %s", t.From)
		}
		to, ok := kdc.containerFor(t.To)
		if !ok {
			cleanup()
			return nil, nil, fmt.Errorf("trust references unknown target realm %s", t.To)
		}
		if err := bootstrapTrust(ctx, from, to, t); err != nil {
			cleanup()
			return nil, nil, fmt.Errorf("bootstrap trust %s -> %s: %w", t.From, t.To, err)
		}
	}

	// Release the container's CMD polling loop so it execs krb5kdc,
	// then wait for each KDC to bind port 88.
	for _, h := range kdc.realms {
		if err := signalReady(ctx, h.Container); err != nil {
			cleanup()
			return nil, nil, fmt.Errorf("signal ready for %s: %w", h.Spec.Name, err)
		}
	}
	for _, h := range kdc.realms {
		if err := waitForPort(ctx, h); err != nil {
			cleanup()
			return nil, nil, fmt.Errorf("wait for %s KDC port: %w", h.Spec.Name, err)
		}
	}

	return kdc, cleanup, nil
}

func startContainer(ctx context.Context, realm string) (testcontainers.Container, RealmEndpoint, error) {
	req := testcontainers.ContainerRequest{
		FromDockerfile: testcontainers.FromDockerfile{
			Context:    mitFixtureDir,
			Dockerfile: "Dockerfile",
			Repo:       mitImageRepo,
			Tag:        mitImageTag,
			KeepImage:  true,
		},
		ExposedPorts: []string{mitKDCPort},
		// Port readiness is checked by waitForPort once provisioning
		// finishes and signalReady releases the CMD's polling loop;
		// krb5kdc does not bind port 88 before then.
	}

	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		return nil, RealmEndpoint{}, err
	}

	host, err := c.Host(ctx)
	if err != nil {
		return nil, RealmEndpoint{}, fmt.Errorf("read host: %w", err)
	}
	mapped, err := c.MappedPort(ctx, mitKDCPort)
	if err != nil {
		return nil, RealmEndpoint{}, fmt.Errorf("read mapped port: %w", err)
	}
	return c, RealmEndpoint{Realm: realm, Host: host, Port: mapped.Int()}, nil
}

func (k *mitKDC) provisionRealm(ctx context.Context, h *realmHandle) error {
	c := h.Container
	realm := h.Spec.Name

	// kdb5_util and kadmin.local both need the realm in kdc.conf to
	// open the database; krb5.conf supplies the default_realm.
	if err := c.CopyToContainer(ctx, []byte(renderKrb5Conf(realm)), "/etc/krb5.conf", 0o644); err != nil {
		return fmt.Errorf("write /etc/krb5.conf: %w", err)
	}
	if err := c.CopyToContainer(ctx, []byte(renderKDCConf(realm)), "/etc/krb5kdc/kdc.conf", 0o644); err != nil {
		return fmt.Errorf("write /etc/krb5kdc/kdc.conf: %w", err)
	}
	if err := c.CopyToContainer(ctx, []byte(renderKadm5ACL(realm)), "/etc/krb5kdc/kadm5.acl", 0o644); err != nil {
		return fmt.Errorf("write /etc/krb5kdc/kadm5.acl: %w", err)
	}

	if err := execIn(ctx, c, []string{"kdb5_util", "-r", realm, "create", "-s", "-P", mitMasterPassword}); err != nil {
		return fmt.Errorf("kdb5_util create: %w", err)
	}

	for _, u := range h.Spec.Users {
		preauth := "+requires_preauth"
		if !u.RequiresPreauth {
			preauth = "-requires_preauth"
		}
		query := fmt.Sprintf("addprinc -pw %s %s %s@%s", u.Password, preauth, u.Name, realm)
		if err := kadminLocal(ctx, c, query); err != nil {
			return fmt.Errorf("addprinc %s: %w", u.Name, err)
		}
		if u.WithKeytab {
			path := fmt.Sprintf("/etc/krb5/keytabs/%s.keytab", u.Name)
			kt, err := extractKeytab(ctx, c, fmt.Sprintf("%s@%s", u.Name, realm), path, true)
			if err != nil {
				return fmt.Errorf("ktadd %s: %w", u.Name, err)
			}
			k.keytabs[u.Name] = kt
		}
	}

	for _, spn := range h.Spec.Services {
		query := fmt.Sprintf("addprinc -randkey %s@%s", spn, realm)
		if err := kadminLocal(ctx, c, query); err != nil {
			return fmt.Errorf("addprinc %s: %w", spn, err)
		}
		path := fmt.Sprintf("/etc/krb5/keytabs/%s.keytab", keytabBasename(spn))
		kt, err := extractKeytab(ctx, c, fmt.Sprintf("%s@%s", spn, realm), path, false)
		if err != nil {
			return fmt.Errorf("ktadd %s: %w", spn, err)
		}
		k.keytabs[spn] = kt
	}

	return nil
}

func bootstrapTrust(ctx context.Context, from, to testcontainers.Container, t TrustSpec) error {
	pw, err := randomTrustPassword()
	if err != nil {
		return fmt.Errorf("generate trust password: %w", err)
	}
	query := fmt.Sprintf("addprinc -e %s -pw %s krbtgt/%s@%s", trustEnctypes, pw, t.To, t.From)
	if err := kadminLocal(ctx, from, query); err != nil {
		return fmt.Errorf("addprinc on source: %w", err)
	}
	if err := kadminLocal(ctx, to, query); err != nil {
		return fmt.Errorf("addprinc on target: %w", err)
	}
	return nil
}

func signalReady(ctx context.Context, c testcontainers.Container) error {
	return execIn(ctx, c, []string{"touch", readyFile})
}

func waitForPort(ctx context.Context, h realmHandle) error {
	cfg, err := config.NewFromString(GenerateKRB5Conf([]RealmEndpoint{h.Endpoint}))
	if err != nil {
		return fmt.Errorf("build probe config: %w", err)
	}
	const maxAttempts = 50
	var lastErr error
	for i := 0; i < maxAttempts; i++ {
		if err := probeKDC(cfg, h.Spec.Name); err == nil {
			return nil
		} else {
			lastErr = err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	return fmt.Errorf("KDC at %s:%d not ready within %d attempts: %v",
		h.Endpoint.Host, h.Endpoint.Port, maxAttempts, lastErr)
}

// probeKDC sends a real AS-REQ for an unknown principal. A KDCError
// response (e.g. KDC_ERR_C_PRINCIPAL_UNKNOWN) means the round-trip
// path is live; a Networking_Error means the path isn't ready yet.
// krb5kdc silently drops malformed TCP messages, so a byte-level
// probe wouldn't distinguish "KDC not ready" from "KDC ignored
// garbage" — only a well-formed Kerberos exchange does.
func probeKDC(cfg *config.Config, realm string) error {
	cl := client.NewWithPassword("__probe__", realm, "x", cfg)
	defer cl.Destroy()
	err := cl.Login()
	if err == nil {
		return nil
	}
	var ke krberror.Krberror
	if errors.As(err, &ke) && ke.RootCause == krberror.KDCError {
		return nil
	}
	return err
}

// kadminLocal runs a kadmin.local query inside c.
func kadminLocal(ctx context.Context, c testcontainers.Container, query string) error {
	return execIn(ctx, c, []string{"kadmin.local", "-q", query})
}

// execIn runs cmd inside c. Returns an error if the process exits
// non-zero, including the captured output.
func execIn(ctx context.Context, c testcontainers.Container, cmd []string) error {
	exitCode, reader, err := c.Exec(ctx, cmd, tcexec.Multiplexed())
	if err != nil {
		return fmt.Errorf("exec %v: %w", cmd, err)
	}
	if exitCode != 0 {
		out, _ := io.ReadAll(reader)
		return fmt.Errorf("%v exited %d: %s", cmd, exitCode, string(out))
	}
	return nil
}

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

// extractKeytab returns the keytab bytes for the given principal.
// norandkey preserves the principal's stored key; otherwise ktadd
// rotates it before export.
func extractKeytab(ctx context.Context, c testcontainers.Container, principal, path string, norandkey bool) ([]byte, error) {
	if err := execIn(ctx, c, []string{"mkdir", "-p", "/etc/krb5/keytabs"}); err != nil {
		return nil, err
	}
	q := fmt.Sprintf("ktadd -k %s %s", path, principal)
	if norandkey {
		q = fmt.Sprintf("ktadd -norandkey -k %s %s", path, principal)
	}
	if err := kadminLocal(ctx, c, q); err != nil {
		return nil, err
	}
	rc, err := c.CopyFileFromContainer(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("copy keytab %s: %w", path, err)
	}
	defer rc.Close()
	return io.ReadAll(rc)
}

// keytabBasename turns an SPN into a filename-safe form by replacing
// slashes with underscores.
func keytabBasename(spn string) string {
	return strings.ReplaceAll(spn, "/", "_")
}

func randomTrustPassword() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

func renderKrb5Conf(realm string) string {
	return fmt.Sprintf(`[libdefaults]
    default_realm = %s
    dns_lookup_realm = false
    dns_lookup_kdc = false

[realms]
    %s = {
        kdc = localhost:88
    }
`, realm, realm)
}

func renderKDCConf(realm string) string {
	return fmt.Sprintf(`[kdcdefaults]
    kdc_ports = 88
    kdc_tcp_ports = 88

[logging]
    kdc = FILE:/var/log/krb5kdc.log
    admin_server = FILE:/var/log/kadmind.log
    default = FILE:/var/log/krb5lib.log

[realms]
    %s = {
        database_name = /var/lib/krb5kdc/principal
        admin_keytab = /etc/krb5kdc/kadm5.keytab
        acl_file = /etc/krb5kdc/kadm5.acl
        key_stash_file = /etc/krb5kdc/.k5.%s
        max_life = 10h 0m 0s
        max_renewable_life = 7d 0h 0m 0s
        supported_enctypes = aes256-cts-hmac-sha1-96:normal aes128-cts-hmac-sha1-96:normal aes256-cts-hmac-sha384-192:normal aes128-cts-hmac-sha256-128:normal
    }
`, realm, realm)
}

func renderKadm5ACL(realm string) string {
	return fmt.Sprintf("*/admin@%s    *\n", realm)
}

func (k *mitKDC) containerFor(realm string) (testcontainers.Container, bool) {
	for _, h := range k.realms {
		if h.Spec.Name == realm {
			return h.Container, true
		}
	}
	return nil, false
}

func (k *mitKDC) Realm() string {
	return k.topology.Realms[0].Name
}

func (k *mitKDC) Config() (*config.Config, error) {
	endpoints := make([]RealmEndpoint, len(k.realms))
	for i, h := range k.realms {
		endpoints[i] = h.Endpoint
	}
	cfg, err := config.NewFromString(GenerateKRB5Conf(endpoints))
	if err != nil {
		return nil, fmt.Errorf("parse generated krb5.conf: %w", err)
	}
	return cfg, nil
}

func (k *mitKDC) NewClient(username, password string) (*client.Client, error) {
	cfg, err := k.Config()
	if err != nil {
		return nil, err
	}
	return client.NewWithPassword(username, k.Realm(), password, cfg), nil
}

// Keytab returns the keytab for the given principal. Keytabs are
// extracted during provisioning and held in memory.
func (k *mitKDC) Keytab(principal string) (*keytab.Keytab, error) {
	data, ok := k.keytabs[principal]
	if !ok {
		return nil, fmt.Errorf("no keytab provisioned for %q", principal)
	}
	kt := keytab.New()
	if err := kt.Unmarshal(data); err != nil {
		return nil, fmt.Errorf("unmarshal keytab for %s: %w", principal, err)
	}
	return kt, nil
}

func (k *mitKDC) Close(ctx context.Context) error {
	var firstErr error
	for _, h := range k.realms {
		if h.Container == nil {
			continue
		}
		if err := h.Container.Terminate(ctx); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("terminate %s container: %w", h.Spec.Name, err)
		}
	}
	return firstErr
}
