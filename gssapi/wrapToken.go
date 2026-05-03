package gssapi

import (
	"bytes"
	"crypto/hmac"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/f0oster/gokrb5/crypto"
	"github.com/f0oster/gokrb5/types"
)

// GSS-API Wrap tokens per RFC 4121 §4.2.

const (
	// HdrLen is the length of the WrapToken header.
	HdrLen = 16
	// FillerByte is the filler byte used in the WrapToken header.
	FillerByte byte = 0xFF

	// WrapToken flag bits per RFC 4121 §4.2.2.

	// SentByAcceptorFlag indicates the token was emitted by the GSS acceptor.
	SentByAcceptorFlag byte = 0x01
	// SealedFlag indicates the payload is encrypted per RFC 4121 §4.2.4.
	SealedFlag byte = 0x02
	// AcceptorSubkeyFlag indicates the acceptor's subkey (from the AP-REP
	// EncAPRepPart) is the key used for this token's checksum or encryption.
	// When clear, the session or authenticator subkey is used instead.
	AcceptorSubkeyFlag byte = 0x04
)

// WrapToken represents a GSS-API Wrap token per RFC 4121 §4.2.6.2.
// It carries the header fields, the payload, and (for integrity-only
// tokens) the checksum, and provides the logic for marshaling and for
// computing and verifying checksums.
//
// For integrity-only tokens (SealedFlag clear), EC carries the
// checksum length and the wire layout is { header || payload ||
// checksum }.
//
// For sealed tokens (SealedFlag set), EC carries the filler length
// per RFC 4121 §4.2.3 (zero for AES enctypes; see SealPayload),
// CheckSum is unused because the integrity HMAC is embedded inside
// the ciphertext by the enctype per RFC 3961, and Payload is the
// opaque encrypted blob. SealPayload emits RRC=0 and applies no
// rotation (matching MIT k5sealv3.c); Unmarshal still un-rotates any
// non-zero RRC it sees on the wire to interoperate with Heimdal and
// SSPI peers per RFC 4121 §4.2.5.
type WrapToken struct {
	// const GSS Token ID: 0x0504
	Flags byte // contains three flags: acceptor, sealed, acceptor subkey
	// const Filler: 0xFF
	EC        uint16 // integrity: HMAC length; sealed: filler/pad length
	RRC       uint16 // right rotation count. big-endian
	SndSeqNum uint64 // sender's sequence number. big-endian
	Payload   []byte // plaintext (integrity) or ciphertext blob (sealed)
	CheckSum  []byte // authenticated checksum of { payload | header }, nil for sealed tokens
}

// Return the 2 bytes identifying a GSS API Wrap token
func getGssWrapTokenId() *[2]byte {
	return &[2]byte{0x05, 0x04}
}

// Marshal the WrapToken into a byte slice.
//
// For integrity-only tokens, payload and checksum must both be set;
// the wire layout is { header || payload || checksum }.
//
// For sealed tokens (SealedFlag set), payload must be the encrypted
// blob produced by SealPayload, and checksum must be nil; the wire
// layout is { header || ciphertext }.
func (wt *WrapToken) Marshal() ([]byte, error) {
	if wt.Payload == nil {
		return nil, errors.New("payload has not been set")
	}
	header := wt.marshalHeader()

	if wt.Flags&SealedFlag != 0 {
		if wt.CheckSum != nil {
			return nil, errors.New("sealed WrapToken must not carry a separate checksum; the HMAC is embedded in the ciphertext")
		}
		out := make([]byte, HdrLen+len(wt.Payload))
		copy(out, header)
		copy(out[HdrLen:], wt.Payload)
		return out, nil
	}

	if wt.CheckSum == nil {
		return nil, errors.New("checksum has not been set")
	}
	out := make([]byte, HdrLen+len(wt.Payload)+len(wt.CheckSum))
	copy(out, header)
	copy(out[HdrLen:], wt.Payload)
	copy(out[HdrLen+len(wt.Payload):], wt.CheckSum)
	return out, nil
}

// marshalHeader serializes the 16-byte WrapToken header using the
// current field values.
func (wt *WrapToken) marshalHeader() []byte {
	header := make([]byte, HdrLen)
	copy(header[0:2], getGssWrapTokenId()[:])
	header[2] = wt.Flags
	header[3] = FillerByte
	binary.BigEndian.PutUint16(header[4:6], wt.EC)
	binary.BigEndian.PutUint16(header[6:8], wt.RRC)
	binary.BigEndian.PutUint64(header[8:16], wt.SndSeqNum)
	return header
}

// SetCheckSum uses the passed encryption key and key usage to compute the checksum over the payload and
// the header, and sets the CheckSum field of this WrapToken.
// If the payload has not been set or the checksum has already been set, an error is returned.
func (wt *WrapToken) SetCheckSum(key types.EncryptionKey, keyUsage uint32) error {
	if wt.Payload == nil {
		return errors.New("payload has not been set")
	}
	if wt.CheckSum != nil {
		return errors.New("checksum has already been computed")
	}
	chkSum, cErr := wt.computeCheckSum(key, keyUsage)
	if cErr != nil {
		return cErr
	}
	wt.CheckSum = chkSum
	return nil
}

// ComputeCheckSum computes and returns the checksum of this token, computed using the passed key and key usage.
// Note: This will NOT update the struct's Checksum field.
func (wt *WrapToken) computeCheckSum(key types.EncryptionKey, keyUsage uint32) ([]byte, error) {
	if wt.Payload == nil {
		return nil, errors.New("cannot compute checksum with uninitialized payload")
	}
	// Build a slice containing { payload | header }
	checksumMe := make([]byte, HdrLen+len(wt.Payload))
	copy(checksumMe[0:], wt.Payload)
	copy(checksumMe[len(wt.Payload):], getChecksumHeader(wt.Flags, wt.SndSeqNum))

	encType, err := crypto.GetEtype(key.KeyType)
	if err != nil {
		return nil, err
	}
	return encType.GetChecksumHash(key.KeyValue, checksumMe, keyUsage)
}

// Build a header suitable for a checksum computation
func getChecksumHeader(flags byte, senderSeqNum uint64) []byte {
	header := make([]byte, 16)
	copy(header[0:], []byte{0x05, 0x04, flags, 0xFF, 0x00, 0x00, 0x00, 0x00})
	binary.BigEndian.PutUint64(header[8:], senderSeqNum)
	return header
}

// Verify computes the token's checksum with the provided key and usage,
// and compares it to the checksum present in the token.
// In case of any failure, (false, Err) is returned, with Err an explanatory error.
func (wt *WrapToken) Verify(key types.EncryptionKey, keyUsage uint32) (bool, error) {
	computed, cErr := wt.computeCheckSum(key, keyUsage)
	if cErr != nil {
		return false, cErr
	}
	if !hmac.Equal(computed, wt.CheckSum) {
		return false, fmt.Errorf(
			"checksum mismatch. Computed: %s, Contained in token: %s",
			hex.EncodeToString(computed), hex.EncodeToString(wt.CheckSum))
	}
	return true, nil
}

// Unmarshal bytes into the corresponding WrapToken.
// If expectFromAcceptor is true, we expect the token to have been emitted by the gss acceptor,
// and will check the according flag, returning an error if the token does not match the expectation.
func (wt *WrapToken) Unmarshal(b []byte, expectFromAcceptor bool) error {
	// Check if we can read a whole header
	if len(b) < 16 {
		return errors.New("bytes shorter than header length")
	}
	// Is the Token ID correct?
	if !bytes.Equal(getGssWrapTokenId()[:], b[0:2]) {
		return fmt.Errorf("wrong Token ID. Expected %s, was %s",
			hex.EncodeToString(getGssWrapTokenId()[:]),
			hex.EncodeToString(b[0:2]))
	}
	// Check the acceptor flag
	flags := b[2]
	isFromAcceptor := flags&SentByAcceptorFlag != 0
	if isFromAcceptor && !expectFromAcceptor {
		return errors.New("unexpected acceptor flag is set: not expecting a token from the acceptor")
	}
	if !isFromAcceptor && expectFromAcceptor {
		return errors.New("expected acceptor flag is not set: expecting a token from the acceptor, not the initiator")
	}
	// Check the filler byte
	if b[3] != FillerByte {
		return fmt.Errorf("unexpected filler byte: expecting 0xFF, was %s ", hex.EncodeToString(b[3:4]))
	}
	ec := binary.BigEndian.Uint16(b[4:6])
	sealed := flags&SealedFlag != 0

	// For integrity-only tokens EC is the checksum length and must fit
	// within the post-header bytes. For sealed tokens EC is the filler
	// length, which lives inside the ciphertext and is not independently
	// sanity-checkable until after decryption.
	if !sealed && int(ec) > len(b)-HdrLen {
		return fmt.Errorf("inconsistent checksum length: %d bytes to parse, checksum length is %d", len(b), ec)
	}

	wt.Flags = flags
	wt.EC = ec
	wt.RRC = binary.BigEndian.Uint16(b[6:8])
	wt.SndSeqNum = binary.BigEndian.Uint64(b[8:16])

	// Copy the post-header region so Payload and CheckSum do not alias the
	// caller's input buffer. Without this, a caller that reuses b (for
	// example a long-lived SASL receive loop) can silently corrupt an
	// already-unmarshaled token.
	data := make([]byte, len(b)-HdrLen)
	copy(data, b[HdrLen:])

	// Handle RRC (Right Rotation Count) per RFC 4121 §4.2.5.
	// The sender may have rotated the data right by RRC bytes; reverse it
	// by rotating left (moving the first RRC bytes to the end). Per the
	// RFC: "The receiver MUST be able to interpret all possible rotation
	// count values, including rotation counts greater than the length of
	// the token."
	if wt.RRC > 0 && len(data) > 0 {
		rrc := int(wt.RRC) % len(data)
		if rrc > 0 {
			rotated := make([]byte, len(data))
			copy(rotated, data[rrc:])
			copy(rotated[len(data)-rrc:], data[:rrc])
			data = rotated
		}
	}

	if sealed {
		// The entire post-header region is the encrypted blob; its
		// contents (confounder, inner plaintext, HMAC) are only
		// interpretable by OpenSealed with the correct key.
		wt.Payload = data
		wt.CheckSum = nil
		return nil
	}

	// Integrity-only canonical layout: Payload | Checksum
	wt.Payload = data[:len(data)-int(ec)]
	wt.CheckSum = data[len(data)-int(ec):]
	return nil
}

// SealPayload encrypts wt.Payload per RFC 4121 §4.2.4. The plaintext
// laid out before encryption is { original_payload || EC bytes of
// filler || inner header copy } and the inner header copy carries
// RRC=0 as §4.2.4 requires. SealedFlag must already be set and
// CheckSum must be nil; the integrity HMAC is embedded inside the
// ciphertext by the enctype per RFC 3961.
//
// The wire RRC is set to 0 and no rotation is applied, matching MIT
// krb5 src/lib/gssapi/krb5/k5sealv3.c (which hardcodes
// store_16_be(0, outbuf+6) on the production path). Heimdal and
// Windows SSPI emit a non-zero rotation value (header_size + cksumsize
// per Heimdal lib/gssapi/krb5/cfx.c:1310 _gssapi_wrap_cfx) for the
// benefit of in-place SSPI buffer layouts, but RFC 4121 §4.2.5
// requires every receiver to interpret any RRC, so RRC=0 is
// interoperable with all three implementations.
func (wt *WrapToken) SealPayload(key types.EncryptionKey, keyUsage uint32) error {
	if wt.Payload == nil {
		return errors.New("payload has not been set")
	}
	if wt.CheckSum != nil {
		return errors.New("sealed WrapToken must not carry a separate checksum")
	}
	if wt.Flags&SealedFlag == 0 {
		return errors.New("SealedFlag must be set on Flags before calling SealPayload")
	}

	encType, err := crypto.GetEtype(key.KeyType)
	if err != nil {
		return fmt.Errorf("get etype: %w", err)
	}

	// Inner header copy per RFC 4121 §4.2.4 carries RRC=0; the outer
	// RRC is also 0 (see godoc above), so the inner copy is identical
	// to what Marshal will emit.
	wt.RRC = 0
	innerHeader := wt.marshalHeader()

	ec := int(wt.EC)
	plain := make([]byte, len(wt.Payload)+ec+HdrLen)
	copy(plain, wt.Payload)
	for i := 0; i < ec; i++ {
		plain[len(wt.Payload)+i] = FillerByte
	}
	copy(plain[len(wt.Payload)+ec:], innerHeader)

	// EncryptMessage returns (iv, ciphertext, error). The iv is unused
	// for GSS wrap. The returned ciphertext already includes the
	// confounder and trailing HMAC per RFC 3961.
	_, ciphertext, err := encType.EncryptMessage(key.KeyValue, plain, keyUsage)
	if err != nil {
		return fmt.Errorf("encrypt sealed wrap token: %w", err)
	}

	wt.Payload = ciphertext
	return nil
}

// OpenSealed decrypts a sealed WrapToken and returns the original
// plaintext. It verifies the integrity HMAC embedded in the ciphertext,
// authenticates the inner header copy against the outer header fields
// (TOK_ID, Flags, filler, EC, SND_SEQ), and strips the trailing filler
// and inner header. Callers must call Unmarshal first so any RRC
// rotation is already reversed. The inner header copy carries RRC=0
// per RFC 4121 §4.2.4 and is not compared against the outer RRC.
func (wt *WrapToken) OpenSealed(key types.EncryptionKey, keyUsage uint32) ([]byte, error) {
	if wt.Flags&SealedFlag == 0 {
		return nil, errors.New("token is not sealed")
	}
	if wt.Payload == nil {
		return nil, errors.New("payload has not been set")
	}
	encType, err := crypto.GetEtype(key.KeyType)
	if err != nil {
		return nil, fmt.Errorf("get etype: %w", err)
	}

	plain, err := encType.DecryptMessage(key.KeyValue, wt.Payload, keyUsage)
	if err != nil {
		return nil, fmt.Errorf("decrypt sealed wrap token: %w", err)
	}

	ec := int(wt.EC)
	if len(plain) < ec+HdrLen {
		return nil, fmt.Errorf("decrypted wrap token too short: %d bytes, need at least EC(%d)+header(%d)", len(plain), ec, HdrLen)
	}

	innerStart := len(plain) - HdrLen
	inner := plain[innerStart:]
	if !bytes.Equal(inner[0:2], getGssWrapTokenId()[:]) {
		return nil, errors.New("inner header TOK_ID mismatch")
	}
	if inner[2] != wt.Flags {
		return nil, errors.New("inner header Flags mismatch")
	}
	if inner[3] != FillerByte {
		return nil, errors.New("inner header filler mismatch")
	}
	if binary.BigEndian.Uint16(inner[4:6]) != wt.EC {
		return nil, errors.New("inner header EC mismatch")
	}
	// Inner RRC is always 0 per RFC 4121 §4.2.4 and is not compared
	// against the outer (post-rotation) RRC.
	if binary.BigEndian.Uint64(inner[8:16]) != wt.SndSeqNum {
		return nil, errors.New("inner header SND_SEQ mismatch")
	}

	payloadEnd := innerStart - ec
	if payloadEnd < 0 {
		return nil, fmt.Errorf("inconsistent EC %d vs plaintext length %d", ec, len(plain))
	}
	// Verify the filler bytes match what we'd emit. This is defensive:
	// any tampering of the filler is already caught by the enctype HMAC,
	// but an explicit check makes corrupted state easier to debug.
	for i := payloadEnd; i < innerStart; i++ {
		if plain[i] != FillerByte {
			return nil, fmt.Errorf("inner filler byte at offset %d is %#x, want %#x", i, plain[i], FillerByte)
		}
	}
	return plain[:payloadEnd], nil
}

