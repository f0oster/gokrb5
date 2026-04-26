// Package framework provides container-based test fixtures for Kerberos
// KDCs. Each backend implementation owns the lifecycle of its containers
// and exposes the connection details, principal topology, and convenience
// helpers tests use to acquire tickets and build clients.
package framework

import (
	"context"

	"github.com/f0oster/gokrb5/client"
	"github.com/f0oster/gokrb5/config"
	"github.com/f0oster/gokrb5/keytab"
)

// KDC is the test-side handle to a containerised Kerberos KDC fixture.
type KDC interface {
	// Realm is the home realm: the realm in which user principals live
	// and which clients built via NewClient authenticate against.
	Realm() string

	// Config returns a parsed krb5.conf covering every realm the
	// fixture serves. Suitable for passing directly to
	// client.NewWithPassword or client.NewWithKeytab.
	Config() (*config.Config, error)

	// NewClient returns a *client.Client for a user in the home realm.
	// The caller is still responsible for calling Login.
	NewClient(username, password string) (*client.Client, error)

	// Keytab returns the keytab for the given principal. The principal
	// must be one the fixture provisioned with a keytab.
	Keytab(principal string) (*keytab.Keytab, error)

	// Close stops and removes every container backing the fixture.
	Close(ctx context.Context) error
}
