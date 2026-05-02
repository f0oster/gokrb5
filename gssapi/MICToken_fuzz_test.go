package gssapi

import (
	"testing"
)

func FuzzMICTokenUnmarshal(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte, expectFromAcceptor bool) {
		var mt MICToken
		_ = mt.Unmarshal(data, expectFromAcceptor)
	})
}
