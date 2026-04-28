package framework

import (
	"fmt"
	"strings"

	"github.com/f0oster/gokrb5/keytab"
)

// loadKeytab resolves principal against store (keyed by full
// "name@realm") and returns the parsed keytab. principal may be
// fully qualified or bare; a bare name must match exactly one entry.
func loadKeytab(store map[string][]byte, principal string) (*keytab.Keytab, error) {
	data, ok := store[principal]
	if !ok {
		var matches []string
		for key := range store {
			if strings.HasPrefix(key, principal+"@") {
				matches = append(matches, key)
			}
		}
		switch len(matches) {
		case 0:
			return nil, fmt.Errorf("no keytab provisioned for %q", principal)
		case 1:
			data = store[matches[0]]
		default:
			return nil, fmt.Errorf("ambiguous keytab lookup for %q: matches %v", principal, matches)
		}
	}
	kt := keytab.New()
	if err := kt.Unmarshal(data); err != nil {
		return nil, fmt.Errorf("unmarshal keytab for %q: %w", principal, err)
	}
	return kt, nil
}

