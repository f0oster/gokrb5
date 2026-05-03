package framework

// ActiveDirectory is an AD-style Kerberos directory test fixture: a
// KDC plus an LDAP/LDAPS server.
type ActiveDirectory interface {
	KDC

	// LDAPEndpoint returns the host and TCP port serving plain LDAP.
	LDAPEndpoint() (host string, port int)

	// LDAPSEndpoint returns the host and TCP port serving LDAPS.
	LDAPSEndpoint() (host string, port int)

	// LDAPSPN returns the LDAP service principal name, e.g.
	// "ldap/dc.ad.example.com".
	LDAPSPN() string

	// HTTPSPN returns the HTTP service principal name the fixture
	// provisions, e.g. "HTTP/web.ad.example.com".
	HTTPSPN() string

	// GroupSID returns the SID string for a provisioned security group
	// (e.g. "S-1-5-21-..."). The group name is the bare CN, without
	// the domain prefix.
	GroupSID(name string) (string, error)
}
