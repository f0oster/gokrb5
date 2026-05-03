package config

import (
	"fmt"
	"math/rand"
	"net"
	"strconv"
	"strings"

	"github.com/jcmturner/dnsutils/v2"
)

// GetKDCs returns KDC host names in preference order for the realm.
func (c *Config) GetKDCs(realm string, tcp bool) ([]string, error) {
	if realm == "" {
		realm = c.LibDefaults.DefaultRealm
	}

	// Get the KDCs from the krb5.conf.
	var ks []string
	for _, r := range c.Realms {
		if r.Realm != realm {
			continue
		}
		ks = r.KDC
	}

	if len(ks) > 0 {
		return randServOrder(ks), nil
	}

	if !c.LibDefaults.DNSLookupKDC {
		return nil, fmt.Errorf("no KDCs defined in configuration for realm %s", realm)
	}

	// Use DNS to resolve kerberos SRV records.
	proto := "udp"
	if tcp {
		proto = "tcp"
	}
	index, addrs, err := dnsutils.OrderedSRV("kerberos", proto, realm)
	if err != nil {
		return nil, err
	}
	if len(addrs) < 1 {
		return nil, fmt.Errorf("no KDC SRV records found for realm %s", realm)
	}
	return srvAddrsInOrder(index, addrs), nil
}

// GetKpasswdServers returns kpasswd server host names in preference order for the realm.
// https://web.mit.edu/kerberos/krb5-latest/doc/admin/conf_files/krb5_conf.html#realms - see kpasswd_server section
func (c *Config) GetKpasswdServers(realm string, tcp bool) ([]string, error) {
	// Use DNS to resolve kerberos SRV records if configured to do so in krb5.conf.
	if c.LibDefaults.DNSLookupKDC {
		proto := "udp"
		if tcp {
			proto = "tcp"
		}
		index, addrs, err := dnsutils.OrderedSRV("kpasswd", proto, realm)
		if err != nil {
			return nil, err
		}
		if index < 1 {
			index, addrs, err = dnsutils.OrderedSRV("kerberos-adm", proto, realm)
			if err != nil {
				return nil, err
			}
		}
		if len(addrs) < 1 {
			return nil, fmt.Errorf("no kpasswd or kadmin SRV records found for realm %s", realm)
		}
		return srvAddrsInOrder(index, addrs), nil
	}
	// Get the kpasswd servers from the krb5.conf and order them randomly for preference.
	var ks []string
	var ka []string
	for _, r := range c.Realms {
		if r.Realm == realm {
			ks = r.KPasswdServer
			ka = r.AdminServer
			break
		}
	}
	if len(ks) < 1 {
		for _, k := range ka {
			h, _, err := net.SplitHostPort(k)
			if err != nil {
				continue
			}
			ks = append(ks, h+":464")
		}
	}
	if len(ks) < 1 {
		return nil, fmt.Errorf("no kpasswd or kadmin defined in configuration for realm %s", realm)
	}
	return randServOrder(ks), nil
}

// srvAddrsInOrder flattens the dnsutils.OrderedSRV map (keyed 1..index) into
// a slice of host:port strings preserving the priority/weight order.
func srvAddrsInOrder(index int, addrs map[int]*net.SRV) []string {
	out := make([]string, 0, len(addrs))
	for i := 1; i <= index; i++ {
		s, ok := addrs[i]
		if !ok {
			continue
		}
		out = append(out, strings.TrimRight(s.Target, ".")+":"+strconv.Itoa(int(s.Port)))
	}
	return out
}

func randServOrder(ks []string) []string {
	if len(ks) <= 1 {
		out := make([]string, len(ks))
		copy(out, ks)
		return out
	}
	out := make([]string, 0, len(ks))
	work := make([]string, len(ks))
	copy(work, ks)
	for len(work) > 0 {
		ri := rand.Intn(len(work))
		out = append(out, work[ri])
		work[len(work)-1], work[ri] = work[ri], work[len(work)-1]
		work = work[:len(work)-1]
	}
	return out
}
