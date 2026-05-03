package rfc4757

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Reference vectors are MD4 of the password encoded as UTF-16 little-endian.
// They match the NT password hash by construction: RFC 4757 §4 specifies
// the same operation as the NTLMv1 NT-hash, even though this code path is
// only used for Kerberos RC4-HMAC string-to-key.
//
// Values were computed independently with golang.org/x/crypto/md4 over
// utf16.Encode([]rune(password)). They are also the values reported by
// MIT krb5 and Heimdal RC4-HMAC implementations for the same inputs.
func TestStringToKey(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		password string
		expected string
	}{
		{
			name:     "ascii",
			password: "foo",
			expected: "ac8e657f83df82beea5d43bdaf7800cc",
		},
		{
			name:     "ascii_longer",
			password: "test1234",
			expected: "3b1b47e42e0463276e3ded6cef349f93",
		},
		{
			name:     "bmp_non_ascii_2byte_utf8",
			password: "café",
			expected: "b1db12409c00d1fc586fc48ecadc36a1",
		},
		{
			name:     "bmp_non_ascii_mixed",
			password: "passwørd",
			expected: "c11b3cedea9f7471484dfbe6b441f8e3",
		},
		{
			name:     "bmp_single_codepoint",
			password: "Σ",
			expected: "3783758abfd58b7efbf679caca1bbe2d",
		},
		{
			name:     "empty",
			password: "",
			expected: "31d6cfe0d16ae931b73c59d7e0c089c0",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := hex.EncodeToString(StringToKey(tt.password))
			assert.Equal(t, tt.expected, got)
		})
	}
}
