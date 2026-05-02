package gssapi

import (
	"testing"
)

func FuzzWrapTokenUnmarshal(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte, expectFromAcceptor bool) {
		var wt WrapToken
		_ = wt.Unmarshal(data, expectFromAcceptor)
	})
}
