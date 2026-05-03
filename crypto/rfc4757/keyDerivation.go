package rfc4757

import (
	"unicode/utf16"

	"golang.org/x/crypto/md4"
)

// StringToKey derives an RC4-HMAC key from the password per RFC 4757 §4:
// MD4 of the password encoded as UTF-16 little-endian. Code points above
// the BMP are encoded as surrogate pairs by unicode/utf16; invalid code
// points are replaced with U+FFFD.
func StringToKey(secret string) []byte {
	u16 := utf16.Encode([]rune(secret))
	b := make([]byte, len(u16)*2)
	for i, c := range u16 {
		b[2*i] = byte(c)
		b[2*i+1] = byte(c >> 8)
	}
	h := md4.New()
	h.Write(b)
	return h.Sum(nil)
}

func deriveKeys(key, checksum []byte, usage uint32, export bool) (k1, k2, k3 []byte) {
	k1 = key
	k2 = HMAC(k1, UsageToMSMsgType(usage))
	k3 = HMAC(k2, checksum)
	return
}
