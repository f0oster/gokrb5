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
	testMICPayload = "deadbeef"
	// What a kerberized server might send
	testMICChallengeFromAcceptor = "040401ffffffffff00000000575e85d6c34d12ba3e5b1b1310cd9cb3"
	// What an initiator client could reply
	testMICChallengeReplyFromInitiator = "040400ffffffffff00000000000000009649ca09d2f1bc51ff6e5ca3"

	acceptorSign  = keyusage.GSSAPI_ACCEPTOR_SIGN
	initiatorSign = keyusage.GSSAPI_INITIATOR_SIGN
)

func getMICChallengeReference() *MICToken {
	challenge, _ := hex.DecodeString(testMICChallengeFromAcceptor)
	return &MICToken{
		Flags:     MICTokenFlagSentByAcceptor,
		SndSeqNum: binary.BigEndian.Uint64(challenge[8:16]),
		Payload:   nil,
		Checksum:  challenge[16:],
	}
}

func getMICChallengeReferenceNoChksum() *MICToken {
	c := getMICChallengeReference()
	c.Checksum = nil
	return c
}

func getMICResponseReference() *MICToken {
	response, _ := hex.DecodeString(testMICChallengeReplyFromInitiator)
	return &MICToken{
		Flags:     0x00,
		SndSeqNum: 0,
		Payload:   nil,
		Checksum:  response[16:],
	}
}

func getMICResponseReferenceNoChkSum() *MICToken {
	r := getMICResponseReference()
	r.Checksum = nil
	return r
}

func TestUnmarshal_MICChallenge(t *testing.T) {
	t.Parallel()
	challenge, _ := hex.DecodeString(testMICChallengeFromAcceptor)
	var mt MICToken
	err := mt.Unmarshal(challenge, true)
	assert.Nil(t, err, "Unexpected error occurred.")
	assert.Equal(t, getMICChallengeReference(), &mt, "Token not decoded as expected.")
}

func TestUnmarshalFailure_MICChallenge(t *testing.T) {
	t.Parallel()
	challenge, _ := hex.DecodeString(testMICChallengeFromAcceptor)
	var mt MICToken
	err := mt.Unmarshal(challenge, false)
	assert.NotNil(t, err, "Expected error did not occur: a message from the acceptor cannot be expected to be sent from the initiator.")
	assert.Nil(t, mt.Payload, "Token fields should not have been initialised")
	assert.Nil(t, mt.Checksum, "Token fields should not have been initialised")
	assert.Equal(t, byte(0x00), mt.Flags, "Token fields should not have been initialised")
	assert.Equal(t, uint64(0), mt.SndSeqNum, "Token fields should not have been initialised")
}

func TestUnmarshal_MICChallengeReply(t *testing.T) {
	t.Parallel()
	response, _ := hex.DecodeString(testMICChallengeReplyFromInitiator)
	var mt MICToken
	err := mt.Unmarshal(response, false)
	assert.Nil(t, err, "Unexpected error occurred.")
	assert.Equal(t, getMICResponseReference(), &mt, "Token not decoded as expected.")
}

func TestUnmarshalFailure_MICChallengeReply(t *testing.T) {
	t.Parallel()
	response, _ := hex.DecodeString(testMICChallengeReplyFromInitiator)
	var mt MICToken
	err := mt.Unmarshal(response, true)
	assert.NotNil(t, err, "Expected error did not occur: a message from the initiator cannot be expected to be sent from the acceptor.")
	assert.Nil(t, mt.Payload, "Token fields should not have been initialised")
	assert.Nil(t, mt.Checksum, "Token fields should not have been initialised")
	assert.Equal(t, byte(0x00), mt.Flags, "Token fields should not have been initialised")
	assert.Equal(t, uint64(0), mt.SndSeqNum, "Token fields should not have been initialised")
}

func TestMICChallengeChecksumVerification(t *testing.T) {
	t.Parallel()
	challenge, _ := hex.DecodeString(testMICChallengeFromAcceptor)
	var mt MICToken
	mt.Unmarshal(challenge, true)
	mt.Payload, _ = hex.DecodeString(testMICPayload)
	challengeOk, cErr := mt.Verify(getSessionKey(), acceptorSign)
	assert.Nil(t, cErr, "Error occurred during checksum verification.")
	assert.True(t, challengeOk, "Checksum verification failed.")
}

func TestMICResponseChecksumVerification(t *testing.T) {
	t.Parallel()
	reply, _ := hex.DecodeString(testMICChallengeReplyFromInitiator)
	var mt MICToken
	mt.Unmarshal(reply, false)
	mt.Payload, _ = hex.DecodeString(testMICPayload)
	replyOk, rErr := mt.Verify(getSessionKey(), initiatorSign)
	assert.Nil(t, rErr, "Error occurred during checksum verification.")
	assert.True(t, replyOk, "Checksum verification failed.")
}

func TestMICChecksumVerificationFailure(t *testing.T) {
	t.Parallel()
	challenge, _ := hex.DecodeString(testMICChallengeFromAcceptor)
	var mt MICToken
	mt.Unmarshal(challenge, true)

	// Test a failure with the correct key but wrong keyusage:
	challengeOk, cErr := mt.Verify(getSessionKey(), initiatorSign)
	assert.NotNil(t, cErr, "Expected error did not occur.")
	assert.False(t, challengeOk, "Checksum verification succeeded when it should have failed.")

	wrongKeyVal, _ := hex.DecodeString("14f9bde6b50ec508201a97f74c4effff")
	badKey := types.EncryptionKey{
		KeyType:  sessionKeyType,
		KeyValue: wrongKeyVal,
	}
	// Test a failure with the wrong key but correct keyusage:
	wrongKeyOk, wkErr := mt.Verify(badKey, acceptorSign)
	assert.NotNil(t, wkErr, "Expected error did not occur.")
	assert.False(t, wrongKeyOk, "Checksum verification succeeded when it should have failed.")
}

func TestMarshal_MICChallenge(t *testing.T) {
	t.Parallel()
	bytes, _ := getMICChallengeReference().Marshal()
	assert.Equal(t, testMICChallengeFromAcceptor, hex.EncodeToString(bytes),
		"Marshalling did not yield the expected result.")
}

func TestMarshal_MICChallengeReply(t *testing.T) {
	t.Parallel()
	bytes, _ := getMICResponseReference().Marshal()
	assert.Equal(t, testMICChallengeReplyFromInitiator, hex.EncodeToString(bytes),
		"Marshalling did not yield the expected result.")
}

func TestMarshal_MICFailures(t *testing.T) {
	t.Parallel()
	noChkSum := getMICResponseReferenceNoChkSum()
	chkBytes, chkErr := noChkSum.Marshal()
	assert.Nil(t, chkBytes, "No bytes should be returned.")
	assert.NotNil(t, chkErr, "Expected an error as no checksum was set")
}

// TestMICToken_CallerBufferMutationDoesNotAffectToken verifies that
// MICToken.Unmarshal copies the trailing checksum out of the caller's
// input buffer, matching the equivalent WrapToken fix. Without the
// copy, a long-lived SASL receive loop that reuses a buffer could
// silently corrupt an already-parsed MIC token.
func TestMICToken_CallerBufferMutationDoesNotAffectToken(t *testing.T) {
	t.Parallel()
	src, _ := hex.DecodeString(testMICChallengeFromAcceptor)
	buf := make([]byte, len(src))
	copy(buf, src)

	var mt MICToken
	if err := mt.Unmarshal(buf, true); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	checksumBefore := append([]byte(nil), mt.Checksum...)
	for i := range buf {
		buf[i] = 0xAA
	}
	assert.Equal(t, checksumBefore, mt.Checksum, "Checksum must not alias caller buffer")
}

// TestMICToken_AcceptorSubkeyFlagRoundTrip confirms the flag bit that
// selects the acceptor subkey (0x04) is preserved through
// Unmarshal/Marshal. SecurityContext.VerifySignature relies on this
// flag to pick the correct verification key per MS-KILE §3.1.1.2.
func TestMICToken_AcceptorSubkeyFlagRoundTrip(t *testing.T) {
	t.Parallel()
	key := getSessionKey()
	original := &MICToken{
		Flags:     MICTokenFlagSentByAcceptor | MICTokenFlagAcceptorSubkey,
		SndSeqNum: 42,
		Payload:   []byte("sign me"),
	}
	if err := original.SetChecksum(key, keyusage.GSSAPI_ACCEPTOR_SIGN); err != nil {
		t.Fatalf("SetChecksum: %v", err)
	}
	wire, err := original.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var parsed MICToken
	if err := parsed.Unmarshal(wire, true); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	assert.NotZero(t, parsed.Flags&MICTokenFlagAcceptorSubkey, "AcceptorSubkey flag lost in round-trip")
	assert.Equal(t, uint64(42), parsed.SndSeqNum)

	// Verify with the same key to confirm key selection logic works.
	parsed.Payload = []byte("sign me")
	ok, err := parsed.Verify(key, keyusage.GSSAPI_ACCEPTOR_SIGN)
	assert.NoError(t, err)
	assert.True(t, ok)
}

func TestNewInitiatorMICTokenSignatureAndMarshalling(t *testing.T) {
	t.Parallel()
	bytes, _ := hex.DecodeString(testMICPayload)
	token, tErr := NewInitiatorMICToken(bytes, getSessionKey())
	token.Payload = nil
	assert.Nil(t, tErr, "Unexpected error.")
	assert.Equal(t, getMICResponseReference(), token, "Token failed to be marshalled to the expected bytes.")
}
