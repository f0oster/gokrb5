package framework

import (
	"fmt"
	"strings"
)

// RealmEndpoint binds a realm to the host:port its KDC is reachable
// at from the test host.
type RealmEndpoint struct {
	Realm string
	Host  string
	Port  int
}

// GenerateKRB5Conf produces a krb5.conf string covering all endpoints.
// The first endpoint's realm is the default_realm. DNS-based KDC and
// realm discovery is disabled so tests don't depend on host DNS.
func GenerateKRB5Conf(endpoints []RealmEndpoint) string {
	if len(endpoints) == 0 {
		return ""
	}

	var b strings.Builder
	// udp_preference_limit = 1 forces TCP for test reliability.
	fmt.Fprintf(&b, `[libdefaults]
    default_realm = %s
    dns_lookup_realm = false
    dns_lookup_kdc = false
    dns_canonicalize_hostname = false
    rdns = false
    udp_preference_limit = 1
    ticket_lifetime = 24h
    renew_lifetime = 7d
    forwardable = true

[realms]
`, endpoints[0].Realm)

	for _, e := range endpoints {
		fmt.Fprintf(&b, "    %s = {\n        kdc = %s:%d\n    }\n", e.Realm, e.Host, e.Port)
	}

	b.WriteString("\n[domain_realm]\n")
	for _, e := range endpoints {
		domain := strings.ToLower(e.Realm)
		fmt.Fprintf(&b, "    .%s = %s\n", domain, e.Realm)
		fmt.Fprintf(&b, "    %s = %s\n", domain, e.Realm)
	}

	return b.String()
}
