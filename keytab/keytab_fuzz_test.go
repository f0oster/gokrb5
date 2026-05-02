package keytab

import (
	"encoding/hex"
	"testing"

	"github.com/f0oster/gokrb5/test/testdata"
)

func FuzzKeytabUnmarshal(f *testing.F) {
	if seed, err := hex.DecodeString(testdata.KEYTAB_TESTUSER1_TEST_GOKRB5); err == nil {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		kt := New()
		_ = kt.Unmarshal(data)
	})
}
