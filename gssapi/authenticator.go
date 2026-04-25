package gssapi

import (
	"encoding/binary"

	"github.com/f0oster/gokrb5/credentials"
	"github.com/f0oster/gokrb5/iana/chksumtype"
	"github.com/f0oster/gokrb5/krberror"
	"github.com/f0oster/gokrb5/types"
)

// NewGSSAuthenticator creates a Kerberos Authenticator with the
// RFC 4121 §4.1.1 GSS-API checksum. The checksum carries channel
// binding information and context establishment flags; see
// BuildGSSChecksum for the checksum layout. bindings and
// delegationCredDER may both be nil.
func NewGSSAuthenticator(creds *credentials.Credentials, flags []int, bindings *ChannelBindings, delegationCredDER []byte) (types.Authenticator, error) {
	auth, err := types.NewAuthenticator(creds.Domain(), creds.CName())
	if err != nil {
		return auth, krberror.Errorf(err, krberror.KRBMsgError, "error generating new authenticator")
	}
	auth.Cksum = types.Checksum{
		CksumType: chksumtype.GSSAPI,
		Checksum:  BuildGSSChecksum(flags, bindings, delegationCredDER),
	}
	return auth, nil
}

// BuildGSSChecksum builds the RFC 4121 §4.1.1.1 GSS authenticator
// checksum. The layout is:
//
//	Byte 0..3   Lgth         length of Bnd (always 16)
//	Byte 4..19  Bnd          MD5 hash of the serialized channel bindings
//	Byte 20..23 Flags        GSS context establishment flags
//	Byte 24..25 DlgOpt       delegation option (1 if delegation follows, 0 otherwise)
//	Byte 26..27 Dlgth        length of Deleg in octets
//	Byte 28..   Deleg        DER-encoded KRB_CRED forwarded TGT
//
// When bindings is nil the Bnd field is all zeros. When delegationCredDER
// is non-nil, DlgOpt=1 and Deleg contains the caller-supplied bytes;
// ContextFlagDeleg is forced on in the flags field to match. When
// delegationCredDER is nil but ContextFlagDeleg is set in flags, a
// zero-length DlgOpt/Dlgth pair is appended for compatibility with
// acceptors that insist on the full checksum length.
func BuildGSSChecksum(flags []int, bindings *ChannelBindings, delegationCredDER []byte) []byte {
	a := make([]byte, 24)

	binary.LittleEndian.PutUint32(a[:4], 16)

	if bindings != nil {
		hash := bindings.MD5Hash()
		copy(a[4:20], hash[:])
	}

	var gssFlags uint32
	var wantDeleg bool
	for _, i := range flags {
		gssFlags |= uint32(i)
		if i == ContextFlagDeleg {
			wantDeleg = true
		}
	}
	if delegationCredDER != nil {
		gssFlags |= uint32(ContextFlagDeleg)
		wantDeleg = true
	}
	binary.LittleEndian.PutUint32(a[20:24], gssFlags)

	if !wantDeleg {
		return a
	}

	tail := make([]byte, 4+len(delegationCredDER))
	if delegationCredDER != nil {
		binary.LittleEndian.PutUint16(tail[0:2], 1)
	}
	binary.LittleEndian.PutUint16(tail[2:4], uint16(len(delegationCredDER)))
	copy(tail[4:], delegationCredDER)
	return append(a, tail...)
}
