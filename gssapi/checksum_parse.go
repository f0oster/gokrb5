package gssapi

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/f0oster/gokrb5/iana/chksumtype"
	"github.com/f0oster/gokrb5/messages"
)

// ErrChannelBindingMismatch is returned by Acceptor.Accept when
// WithExpectedChannelBindings was set and the initiator's hashed
// bindings do not match.
var ErrChannelBindingMismatch = errors.New("gssapi: channel bindings mismatch")

// GSSChecksum is the parsed RFC 4121 §4.1.1.1 GSS authenticator
// checksum carried in the AP-REQ Authenticator's Cksum.Checksum bytes.
type GSSChecksum struct {
	// Bnd is the 16-byte MD5 hash of the initiator's serialized channel
	// bindings, or all-zero when the initiator did not request bindings.
	Bnd [16]byte
	// Flags carries the GSS context establishment flags (mutual,
	// integrity, confidentiality, delegation, etc.).
	Flags uint32
	// DlgOpt is 1 when a delegation credential follows, 0 otherwise.
	// Present only when the checksum carries the optional delegation
	// tail (length >= 28 bytes).
	DlgOpt uint16
	// Deleg is the DER-encoded KRB_CRED forwarded TGT, present when
	// DlgOpt = 1.
	Deleg []byte
}

// ParseGSSChecksum parses RFC 4121 §4.1.1.1 GSS authenticator checksum
// bytes. Layout:
//
//	Byte 0..3   Lgth         length of Bnd (always 16, little-endian uint32)
//	Byte 4..19  Bnd          MD5 hash of channel bindings
//	Byte 20..23 Flags        GSS context establishment flags
//	Byte 24..25 DlgOpt       optional: 1 if delegation follows
//	Byte 26..27 Dlgth        optional: length of Deleg
//	Byte 28..   Deleg        optional: DER-encoded KRB_CRED
//
// Bytes 24+ are absent when the initiator did not request delegation.
// All length-prefixed reads are bounds-checked against the input slice.
func ParseGSSChecksum(data []byte) (*GSSChecksum, error) {
	if len(data) < 24 {
		return nil, fmt.Errorf("GSS checksum too short: %d bytes (need >= 24)", len(data))
	}
	lgth := binary.LittleEndian.Uint32(data[0:4])
	if lgth != 16 {
		return nil, fmt.Errorf("GSS checksum Lgth = %d, expected 16 per RFC 4121 §4.1.1.1", lgth)
	}
	cs := &GSSChecksum{
		Flags: binary.LittleEndian.Uint32(data[20:24]),
	}
	copy(cs.Bnd[:], data[4:20])

	// Delegation tail is optional. If present, it carries 4 bytes of
	// header (DlgOpt + Dlgth) followed by Dlgth bytes of credential.
	if len(data) == 24 {
		return cs, nil
	}
	if len(data) < 28 {
		return nil, fmt.Errorf("GSS checksum delegation header truncated: %d bytes after Flags", len(data)-24)
	}
	cs.DlgOpt = binary.LittleEndian.Uint16(data[24:26])
	dlgth := binary.LittleEndian.Uint16(data[26:28])
	if int(dlgth) > len(data)-28 {
		return nil, fmt.Errorf("GSS checksum Dlgth = %d exceeds remaining %d bytes", dlgth, len(data)-28)
	}
	if dlgth > 0 {
		cs.Deleg = make([]byte, dlgth)
		copy(cs.Deleg, data[28:28+dlgth])
	}
	return cs, nil
}

// verifyChannelBindings compares the Bnd hash carried in an AP-REQ
// authenticator's GSS checksum to MD5(expected.Marshal()). Returns
// ErrChannelBindingMismatch if the checksum is not a GSS checksum,
// is malformed, or carries a different hash.
func verifyChannelBindings(apReq *messages.APReq, expected *ChannelBindings) error {
	cksum := apReq.Authenticator.Cksum
	if cksum.CksumType != chksumtype.GSSAPI {
		return ErrChannelBindingMismatch
	}
	parsed, err := ParseGSSChecksum(cksum.Checksum)
	if err != nil {
		return fmt.Errorf("parse GSS checksum: %w", err)
	}
	if parsed.Bnd != expected.MD5Hash() {
		return ErrChannelBindingMismatch
	}
	return nil
}
