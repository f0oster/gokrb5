package framework

// Topology declares the realms and trusts to provision into a KDC
// fixture.
type Topology struct {
	Realms []RealmSpec
	Trusts []TrustSpec
}

// UserSpec describes a user principal to provision into a realm.
type UserSpec struct {
	Name     string
	Password string
	// RequiresPreauth sets +requires_preauth on MIT KDCs. Samba/AD
	// always requires pre-authentication and ignores this flag.
	RequiresPreauth bool
	// WithKeytab extracts a keytab for this principal at provisioning
	// time, retrievable via KDC.Keytab.
	WithKeytab bool
}

// ServiceSpec describes a service principal name and, when required,
// the account that holds the SPN.
type ServiceSpec struct {
	SPN string
	// Account binds the SPN to a directory account. Required by
	// Samba/AD; ignored by MIT.
	Account *ServiceAccount
}

// ServiceAccount is the directory account that holds an SPN.
type ServiceAccount struct {
	Name     string
	Password string
}

// RealmSpec is the per-realm provisioning data.
type RealmSpec struct {
	Name     string
	Users    []UserSpec
	Services []ServiceSpec
}

// TrustSpec is a one-way cross-realm trust: users in From can request
// service tickets for principals in To.
type TrustSpec struct {
	From string
	To   string
}
