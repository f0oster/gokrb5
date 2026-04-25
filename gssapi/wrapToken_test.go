package gssapi

import (
	"encoding/binary"
	"encoding/hex"
	"testing"

	"github.com/f0oster/gokrb5/iana/keyusage"
	"github.com/f0oster/gokrb5/types"
	"github.com/stretchr/testify/assert"
)

const (
	// What a kerberized server might send
	testChallengeFromAcceptor = "050401ff000c000000000000575e85d601010000853b728d5268525a1386c19f"
	// What an initiator client could reply
	testChallengeReplyFromInitiator = "050400ff000c000000000000000000000101000079a033510b6f127212242b97"
	// session key used to sign the tokens above
	sessionKey     = "14f9bde6b50ec508201a97f74c4e5bd3"
	sessionKeyType = 17

	acceptorSeal  = keyusage.GSSAPI_ACCEPTOR_SEAL
	initiatorSeal = keyusage.GSSAPI_INITIATOR_SEAL
)

func getSessionKey() types.EncryptionKey {
	key, _ := hex.DecodeString(sessionKey)
	return types.EncryptionKey{
		KeyType:  sessionKeyType,
		KeyValue: key,
	}
}

func getChallengeReference() *WrapToken {
	challenge, _ := hex.DecodeString(testChallengeFromAcceptor)
	return &WrapToken{
		Flags:     0x01,
		EC:        12,
		RRC:       0,
		SndSeqNum: binary.BigEndian.Uint64(challenge[8:16]),
		Payload:   []byte{0x01, 0x01, 0x00, 0x00},
		CheckSum:  challenge[20:32],
	}
}

func getChallengeReferenceNoChksum() *WrapToken {
	c := getChallengeReference()
	c.CheckSum = nil
	return c
}

func getResponseReference() *WrapToken {
	response, _ := hex.DecodeString(testChallengeReplyFromInitiator)
	return &WrapToken{
		Flags:     0x00,
		EC:        12,
		RRC:       0,
		SndSeqNum: 0,
		Payload:   []byte{0x01, 0x01, 0x00, 0x00},
		CheckSum:  response[20:32],
	}
}

func getResponseReferenceNoChkSum() *WrapToken {
	r := getResponseReference()
	r.CheckSum = nil
	return r
}

func TestUnmarshal_Challenge(t *testing.T) {
	t.Parallel()
	challenge, _ := hex.DecodeString(testChallengeFromAcceptor)
	var wt WrapToken
	err := wt.Unmarshal(challenge, true)
	assert.Nil(t, err, "Unexpected error occurred.")
	assert.Equal(t, getChallengeReference(), &wt, "Token not decoded as expected.")
}

func TestUnmarshalFailure_Challenge(t *testing.T) {
	t.Parallel()
	challenge, _ := hex.DecodeString(testChallengeFromAcceptor)
	var wt WrapToken
	err := wt.Unmarshal(challenge, false)
	assert.NotNil(t, err, "Expected error did not occur: a message from the acceptor cannot be expected to be sent from the initiator.")
	assert.Nil(t, wt.Payload, "Token fields should not have been initialised")
	assert.Nil(t, wt.CheckSum, "Token fields should not have been initialised")
	assert.Equal(t, byte(0x00), wt.Flags, "Token fields should not have been initialised")
	assert.Equal(t, uint16(0), wt.EC, "Token fields should not have been initialised")
	assert.Equal(t, uint16(0), wt.RRC, "Token fields should not have been initialised")
	assert.Equal(t, uint64(0), wt.SndSeqNum, "Token fields should not have been initialised")
}

func TestUnmarshal_ChallengeReply(t *testing.T) {
	t.Parallel()
	response, _ := hex.DecodeString(testChallengeReplyFromInitiator)
	var wt WrapToken
	err := wt.Unmarshal(response, false)
	assert.Nil(t, err, "Unexpected error occurred.")
	assert.Equal(t, getResponseReference(), &wt, "Token not decoded as expected.")
}

func TestUnmarshalFailure_ChallengeReply(t *testing.T) {
	t.Parallel()
	response, _ := hex.DecodeString(testChallengeReplyFromInitiator)
	var wt WrapToken
	err := wt.Unmarshal(response, true)
	assert.NotNil(t, err, "Expected error did not occur: a message from the initiator cannot be expected to be sent from the acceptor.")
	assert.Nil(t, wt.Payload, "Token fields should not have been initialised")
	assert.Nil(t, wt.CheckSum, "Token fields should not have been initialised")
	assert.Equal(t, byte(0x00), wt.Flags, "Token fields should not have been initialised")
	assert.Equal(t, uint16(0), wt.EC, "Token fields should not have been initialised")
	assert.Equal(t, uint16(0), wt.RRC, "Token fields should not have been initialised")
	assert.Equal(t, uint64(0), wt.SndSeqNum, "Token fields should not have been initialised")
}

func TestChallengeChecksumVerification(t *testing.T) {
	t.Parallel()
	challenge, _ := hex.DecodeString(testChallengeFromAcceptor)
	var wt WrapToken
	wt.Unmarshal(challenge, true)
	challengeOk, cErr := wt.Verify(getSessionKey(), acceptorSeal)
	assert.Nil(t, cErr, "Error occurred during checksum verification.")
	assert.True(t, challengeOk, "Checksum verification failed.")
}

func TestResponseChecksumVerification(t *testing.T) {
	t.Parallel()
	reply, _ := hex.DecodeString(testChallengeReplyFromInitiator)
	var wt WrapToken
	wt.Unmarshal(reply, false)
	replyOk, rErr := wt.Verify(getSessionKey(), initiatorSeal)
	assert.Nil(t, rErr, "Error occurred during checksum verification.")
	assert.True(t, replyOk, "Checksum verification failed.")
}

func TestChecksumVerificationFailure(t *testing.T) {
	t.Parallel()
	challenge, _ := hex.DecodeString(testChallengeFromAcceptor)
	var wt WrapToken
	wt.Unmarshal(challenge, true)

	// Test a failure with the correct key but wrong keyusage:
	challengeOk, cErr := wt.Verify(getSessionKey(), initiatorSeal)
	assert.NotNil(t, cErr, "Expected error did not occur.")
	assert.False(t, challengeOk, "Checksum verification succeeded when it should have failed.")

	wrongKeyVal, _ := hex.DecodeString("14f9bde6b50ec508201a97f74c4effff")
	badKey := types.EncryptionKey{
		KeyType:  sessionKeyType,
		KeyValue: wrongKeyVal,
	}
	// Test a failure with the wrong key but correct keyusage:
	wrongKeyOk, wkErr := wt.Verify(badKey, acceptorSeal)
	assert.NotNil(t, wkErr, "Expected error did not occur.")
	assert.False(t, wrongKeyOk, "Checksum verification succeeded when it should have failed.")
}

func TestMarshal_Challenge(t *testing.T) {
	t.Parallel()
	bytes, _ := getChallengeReference().Marshal()
	assert.Equal(t, testChallengeFromAcceptor, hex.EncodeToString(bytes),
		"Marshalling did not yield the expected result.")
}

func TestMarshal_ChallengeReply(t *testing.T) {
	t.Parallel()
	bytes, _ := getResponseReference().Marshal()
	assert.Equal(t, testChallengeReplyFromInitiator, hex.EncodeToString(bytes),
		"Marshalling did not yield the expected result.")
}

func TestMarshal_Failures(t *testing.T) {
	t.Parallel()
	noChkSum := getResponseReferenceNoChkSum()
	chkBytes, chkErr := noChkSum.Marshal()
	assert.Nil(t, chkBytes, "No bytes should be returned.")
	assert.NotNil(t, chkErr, "Expected an error as no checksum was set")

	noPayload := getResponseReference()
	noPayload.Payload = nil
	pldBytes, pldErr := noPayload.Marshal()
	assert.Nil(t, pldBytes, "No bytes should be returned.")
	assert.NotNil(t, pldErr, "Expected an error as no checksum was set")
}

func TestNewInitiatorTokenSignatureAndMarshalling(t *testing.T) {
	t.Parallel()
	token, tErr := NewInitiatorWrapToken([]byte{0x01, 0x01, 0x00, 0x00}, getSessionKey())
	assert.Nil(t, tErr, "Unexpected error.")
	assert.Equal(t, getResponseReference(), token, "Token failed to be marshalled to the expected bytes.")
}

// TestUnmarshal_WithRRC tests that tokens with non-zero RRC (Right Rotation Count)
// are correctly un-rotated during unmarshalling per RFC 4121 Section 4.2.5.
// Microsoft Kerberos/SSPI typically uses:
//   - RRC=12 for integrity-only tokens (no encryption requested)
//   - RRC=28 for confidentiality tokens (encryption requested)
func TestUnmarshal_WithRRC(t *testing.T) {
	t.Parallel()

	// Start with the known good challenge token (RRC=0)
	originalToken, _ := hex.DecodeString(testChallengeFromAcceptor)

	// The token has:
	// - Header: bytes 0-15
	// - Payload: bytes 16-19 (4 bytes: 0x01, 0x01, 0x00, 0x00)
	// - Checksum: bytes 20-31 (12 bytes)
	// Data after header = Payload (4) + Checksum (12) = 16 bytes

	// Simulate Microsoft SSPI rotation: RRC=12 means rotate right by 12 bytes
	// Right rotation by 12: last 12 bytes (checksum) move to the front
	// Wire format becomes: Header | Checksum | Payload

	rotatedToken := make([]byte, len(originalToken))
	copy(rotatedToken[0:16], originalToken[0:16]) // Copy header

	// Set RRC = 12 in header (bytes 6-7, big-endian)
	binary.BigEndian.PutUint16(rotatedToken[6:8], 12)

	// Data after header in original: Payload (4) | Checksum (12)
	// After right rotation by 12: Checksum (12) | Payload (4)
	data := originalToken[16:]        // Payload | Checksum
	payload := data[:4]               // 4 bytes
	checksum := data[4:]              // 12 bytes
	copy(rotatedToken[16:], checksum) // Checksum first
	copy(rotatedToken[28:], payload)  // Then payload

	// Unmarshal the rotated token
	var wt WrapToken
	err := wt.Unmarshal(rotatedToken, true)
	assert.Nil(t, err, "Unexpected error unmarshalling rotated token")

	// The unmarshalled token should have correct payload and checksum
	// (same as the original, un-rotated token)
	assert.Equal(t, []byte{0x01, 0x01, 0x00, 0x00}, wt.Payload, "Payload not correctly recovered after un-rotation")
	assert.Equal(t, checksum, wt.CheckSum, "Checksum not correctly recovered after un-rotation")
	assert.Equal(t, uint16(12), wt.RRC, "RRC should be preserved in token")
	assert.Equal(t, uint16(12), wt.EC, "EC should be 12")

	// Verify checksum still validates
	ok, verifyErr := wt.Verify(getSessionKey(), acceptorSeal)
	assert.Nil(t, verifyErr, "Error during checksum verification")
	assert.True(t, ok, "Checksum verification failed after un-rotation")
}

// TestUnmarshal_RRCGreaterThanDataLength tests that RRC values larger than
// the data length are handled correctly per RFC 4121 requirement.
// Microsoft SSPI uses RRC=28 for confidentiality tokens, which may exceed
// the data length for small payloads.
func TestUnmarshal_RRCGreaterThanDataLength(t *testing.T) {
	t.Parallel()

	// Start with the known good challenge token
	originalToken, _ := hex.DecodeString(testChallengeFromAcceptor)
	data := originalToken[16:] // 16 bytes (Payload 4 + Checksum 12)

	// Test with RRC = 28 (greater than data length of 16)
	// Per RFC: RRC mod len(data) = 28 mod 16 = 12
	// This should be equivalent to RRC=12
	rotatedToken := make([]byte, len(originalToken))
	copy(rotatedToken[0:16], originalToken[0:16]) // Copy header

	// Set RRC = 28 in header
	binary.BigEndian.PutUint16(rotatedToken[6:8], 28)

	// Apply rotation equivalent to RRC=12 (28 mod 16)
	payload := data[:4]
	checksum := data[4:]
	copy(rotatedToken[16:], checksum)
	copy(rotatedToken[28:], payload)

	var wt WrapToken
	err := wt.Unmarshal(rotatedToken, true)
	assert.Nil(t, err, "Unexpected error unmarshalling token with RRC > data length")
	assert.Equal(t, []byte{0x01, 0x01, 0x00, 0x00}, wt.Payload, "Payload not correctly recovered")
	assert.Equal(t, uint16(28), wt.RRC, "RRC should be preserved as 28")

	// Verify checksum still validates
	ok, verifyErr := wt.Verify(getSessionKey(), acceptorSeal)
	assert.Nil(t, verifyErr, "Verification error")
	assert.True(t, ok, "Checksum verification failed")
}

// TestUnmarshal_RRCZero confirms that RRC=0 tokens work unchanged.
// MIT Kerberos typically uses RRC=0.
func TestUnmarshal_RRCZero(t *testing.T) {
	t.Parallel()

	// The original test token has RRC=0
	token, _ := hex.DecodeString(testChallengeFromAcceptor)

	var wt WrapToken
	err := wt.Unmarshal(token, true)
	assert.Nil(t, err, "Unexpected error")
	assert.Equal(t, uint16(0), wt.RRC, "RRC should be 0")
	assert.Equal(t, []byte{0x01, 0x01, 0x00, 0x00}, wt.Payload, "Payload incorrect")

	ok, verifyErr := wt.Verify(getSessionKey(), acceptorSeal)
	assert.Nil(t, verifyErr, "Verification error")
	assert.True(t, ok, "Checksum verification failed")
}

// TestUnmarshal_CallerBufferMutationDoesNotAffectToken verifies that
// Unmarshal copies the post-header data so Payload and CheckSum do not
// alias the caller's input buffer. Without the copy, a SASL receive loop
// that reuses a buffer would silently corrupt an already-parsed token.
func TestUnmarshal_CallerBufferMutationDoesNotAffectToken(t *testing.T) {
	t.Parallel()

	// Use a fresh buffer (not a shared test fixture) so mutation below
	// cannot affect other tests.
	src, _ := hex.DecodeString(testChallengeFromAcceptor)
	buf := make([]byte, len(src))
	copy(buf, src)

	var wt WrapToken
	if err := wt.Unmarshal(buf, true); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	// Snapshot what the token currently reports.
	payloadBefore := append([]byte(nil), wt.Payload...)
	checksumBefore := append([]byte(nil), wt.CheckSum...)

	// Scribble over the entire source buffer as if the caller's
	// receive loop reused it for the next incoming message.
	for i := range buf {
		buf[i] = 0xAA
	}

	assert.Equal(t, payloadBefore, wt.Payload, "Payload must not alias caller buffer")
	assert.Equal(t, checksumBefore, wt.CheckSum, "CheckSum must not alias caller buffer")
}

// TestSealUnsealRoundTripAES256 exercises the RFC 4121 §4.2.4 confidential
// WrapToken path end-to-end with AES256-CTS-HMAC-SHA1-96 (the etype used by
// the other tests in this file). This replaces the older
// TestUnmarshal_SealedTokenRejected test, which asserted that sealed tokens
// were rejected — they are now supported.
func TestSealUnsealRoundTripAES256(t *testing.T) {
	t.Parallel()
	key := getSessionKey()
	plain := []byte("confidential payload round trip")

	wt := &WrapToken{
		Flags:     SealedFlag,                            // initiator-direction
		EC:        16,                                    // one AES block of filler per MS-KILE §3.4.5.4.1
		RRC:       0,                                     // MIT-style on send
		SndSeqNum: 0x0102030405060708,
		Payload:   plain,
	}
	if err := wt.SealPayload(key, keyusage.GSSAPI_INITIATOR_SEAL); err != nil {
		t.Fatalf("SealPayload: %v", err)
	}
	wire, err := wt.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	// Unmarshal as the acceptor would and open the blob.
	var got WrapToken
	if err := got.Unmarshal(wire, false); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if got.Flags&SealedFlag == 0 {
		t.Fatalf("SealedFlag lost in round-trip")
	}
	if got.CheckSum != nil {
		t.Fatalf("sealed token should not carry a separate checksum, got %d bytes", len(got.CheckSum))
	}
	recovered, err := got.OpenSealed(key, keyusage.GSSAPI_INITIATOR_SEAL)
	if err != nil {
		t.Fatalf("OpenSealed: %v", err)
	}
	assert.Equal(t, plain, recovered)
	assert.Equal(t, uint64(0x0102030405060708), got.SndSeqNum)
	assert.Equal(t, uint16(16), got.EC)
}

// TestSealedTokenRoundTripMITStyle exercises SealPayload in its
// production configuration: emit RRC=0 and apply no rotation, matching
// MIT k5sealv3.c. The round-trip through Marshal/Unmarshal/OpenSealed
// must still recover the original plaintext.
func TestSealedTokenRoundTripMITStyle(t *testing.T) {
	t.Parallel()
	key := getSessionKey()
	plain := []byte("sealed payload, MIT-style RRC=0")

	wt := &WrapToken{
		Flags:     SealedFlag | SentByAcceptorFlag,
		EC:        0,
		RRC:       0,
		SndSeqNum: 42,
		Payload:   plain,
	}
	if err := wt.SealPayload(key, keyusage.GSSAPI_ACCEPTOR_SEAL); err != nil {
		t.Fatalf("SealPayload: %v", err)
	}
	if wt.RRC != 0 {
		t.Fatalf("SealPayload: RRC = %d, want 0 (MIT-style)", wt.RRC)
	}
	wire, err := wt.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if got := binary.BigEndian.Uint16(wire[6:8]); got != 0 {
		t.Fatalf("outer header RRC = %d, want 0", got)
	}

	var got WrapToken
	if err := got.Unmarshal(wire, true); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	recovered, err := got.OpenSealed(key, keyusage.GSSAPI_ACCEPTOR_SEAL)
	if err != nil {
		t.Fatalf("OpenSealed: %v", err)
	}
	assert.Equal(t, plain, recovered)
}

// TestSealedTokenAcceptsHeimdalSSPIStyleRRC verifies the receive path
// honours RFC 4121 §4.2.5: a peer (Heimdal, Windows SSPI) that emits a
// non-zero rotation count must still decrypt cleanly. The token here is
// built MIT-style and then post-rotated to the value Heimdal's
// _gssapi_wrap_cfx (cfx.c:1310) would emit for AES-SHA1: header_size +
// cksumsize = 16 + 12 = 28.
func TestSealedTokenAcceptsHeimdalSSPIStyleRRC(t *testing.T) {
	t.Parallel()
	key := getSessionKey()
	plain := []byte("sealed payload from a Heimdal/SSPI peer")

	wt := &WrapToken{
		Flags:     SealedFlag | SentByAcceptorFlag,
		EC:        0,
		RRC:       0,
		SndSeqNum: 7,
		Payload:   plain,
	}
	if err := wt.SealPayload(key, keyusage.GSSAPI_ACCEPTOR_SEAL); err != nil {
		t.Fatalf("SealPayload: %v", err)
	}
	wire, err := wt.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	const heimdalRRC = 28
	rotated := rotateRight(t, wire, heimdalRRC)

	var got WrapToken
	if err := got.Unmarshal(rotated, true); err != nil {
		t.Fatalf("Unmarshal of Heimdal-style token: %v", err)
	}
	if got.RRC != heimdalRRC {
		t.Fatalf("post-rotation RRC = %d, want %d", got.RRC, heimdalRRC)
	}
	recovered, err := got.OpenSealed(key, keyusage.GSSAPI_ACCEPTOR_SEAL)
	if err != nil {
		t.Fatalf("OpenSealed of Heimdal-style token: %v", err)
	}
	assert.Equal(t, plain, recovered)
}
