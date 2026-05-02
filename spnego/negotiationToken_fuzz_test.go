package spnego

import (
	"testing"
)

func FuzzUnmarshalNegToken(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _ = UnmarshalNegToken(data)
	})
}
