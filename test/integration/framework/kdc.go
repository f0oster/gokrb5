// Package framework provides container-based test fixtures for Kerberos
// KDCs. Each backend implementation owns the lifecycle of its containers
// and exposes the connection details, principal topology, and convenience
// helpers tests use to acquire tickets and build clients.
package framework

import (
	"context"
	"errors"

	"github.com/f0oster/gokrb5/client"
	"github.com/f0oster/gokrb5/config"
	"github.com/f0oster/gokrb5/keytab"
	"github.com/f0oster/gokrb5/krberror"
)

// KDC is a containerised Kerberos KDC test fixture.
type KDC interface {
	// Realm returns the home realm: the realm in which user principals
	// live and that NewClient authenticates against.
	Realm() string

	// Config returns a parsed krb5.conf covering every realm the
	// fixture serves.
	Config() (*config.Config, error)

	// NewClient returns a *client.Client for a user in the home realm.
	// The caller is responsible for calling Login.
	NewClient(username, password string) (*client.Client, error)

	// Keytab returns the keytab for the given principal.
	Keytab(principal string) (*keytab.Keytab, error)

	// Close stops and removes every container backing the fixture.
	Close(ctx context.Context) error
}

// probeKDC sends an AS-REQ for an unknown principal. A KDCError
// response confirms the KDC is alive. A TCP probe is insufficient
// because krb5kdc silently drops malformed messages.
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
