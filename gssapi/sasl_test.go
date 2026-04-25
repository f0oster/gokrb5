package gssapi

import (
	"testing"

	"github.com/f0oster/gokrb5/iana/keyusage"
	"github.com/f0oster/gokrb5/types"
	"github.com/stretchr/testify/assert"
)

func TestSASLSecurityLayerConstants(t *testing.T) {
	// Verify RFC 4752 values
	assert.Equal(t, byte(0x01), SASLSecurityNone)
	assert.Equal(t, byte(0x02), SASLSecurityIntegrity)
	assert.Equal(t, byte(0x04), SASLSecurityConfidential)
}

func TestSASLServerOffer_SupportsLayer(t *testing.T) {
	tests := []struct {
		name      string
		supported byte
		check     byte
		want      bool
	}{
		{"none only supports none", SASLSecurityNone, SASLSecurityNone, true},
		{"none only does not support integrity", SASLSecurityNone, SASLSecurityIntegrity, false},
		{"all layers supports none", SASLSecurityNone | SASLSecurityIntegrity | SASLSecurityConfidential, SASLSecurityNone, true},
		{"all layers supports integrity", SASLSecurityNone | SASLSecurityIntegrity | SASLSecurityConfidential, SASLSecurityIntegrity, true},
		{"all layers supports confidential", SASLSecurityNone | SASLSecurityIntegrity | SASLSecurityConfidential, SASLSecurityConfidential, true},
		{"integrity+confidential supports integrity", SASLSecurityIntegrity | SASLSecurityConfidential, SASLSecurityIntegrity, true},
		{"integrity+confidential does not support none", SASLSecurityIntegrity | SASLSecurityConfidential, SASLSecurityNone, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			offer := &SASLServerOffer{SupportedLayers: tt.supported}
			assert.Equal(t, tt.want, offer.SupportsLayer(tt.check))
		})
	}
}

// newSASLContext builds a SecurityContext aligned with an imagined
// AP-REQ/AP-REP exchange so ParseSASLServerToken and BuildSASLClientToken
// have somewhere to pull sequence numbers and keys from.
func newSASLContext(t *testing.T) *SecurityContext {
	t.Helper()
	return NewInitiatorContext(getSessionKey(), types.EncryptionKey{}, types.EncryptionKey{}, 10, 0)
}

func TestBuildSASLClientToken_AuthOnly(t *testing.T) {
	t.Parallel()
	ctx := newSASLContext(t)

	resp := SASLClientResponse{
		ChosenLayer:   SASLSecurityNone,
		MaxBufferSize: 0,
	}
	token, err := BuildSASLClientToken(ctx, resp)
	assert.NoError(t, err)
	if len(token) < 16 {
		t.Fatalf("token too short: %d", len(token))
	}
	assert.Equal(t, byte(0x05), token[0])
	assert.Equal(t, byte(0x04), token[1])

	// Parse back and check payload structure.
	wt := &WrapToken{}
	assert.NoError(t, wt.Unmarshal(token, false))
	assert.GreaterOrEqual(t, len(wt.Payload), 4)
	assert.Equal(t, SASLSecurityNone, wt.Payload[0])
	assert.Equal(t, uint64(10), wt.SndSeqNum, "sendSeq sourced from context")
	assert.Equal(t, uint64(11), ctx.SendSeq(), "context advances after wrap")
}

func TestBuildSASLClientToken_WithAuthzID(t *testing.T) {
	t.Parallel()
	ctx := newSASLContext(t)
	authzID := "user@REALM"
	resp := SASLClientResponse{
		ChosenLayer:   SASLSecurityIntegrity,
		MaxBufferSize: 65536,
		AuthzID:       authzID,
	}

	token, err := BuildSASLClientToken(ctx, resp)
	assert.NoError(t, err)

	wt := &WrapToken{}
	assert.NoError(t, wt.Unmarshal(token, false))
	assert.Equal(t, 4+len(authzID), len(wt.Payload))
	assert.Equal(t, authzID, string(wt.Payload[4:]))
	maxBuf := uint32(wt.Payload[1])<<16 | uint32(wt.Payload[2])<<8 | uint32(wt.Payload[3])
	assert.Equal(t, uint32(65536), maxBuf)
	assert.Equal(t, SASLSecurityIntegrity, wt.Payload[0])
}

func TestBuildSASLClientToken_RejectsLayerNoneWithNonZeroBuffer(t *testing.T) {
	t.Parallel()
	ctx := newSASLContext(t)
	resp := SASLClientResponse{
		ChosenLayer:   SASLSecurityNone,
		MaxBufferSize: 1024,
	}
	_, err := BuildSASLClientToken(ctx, resp)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "MaxBufferSize=0")
}

func TestBuildSASLClientToken_RejectsOversizedBuffer(t *testing.T) {
	t.Parallel()
	ctx := newSASLContext(t)
	resp := SASLClientResponse{
		ChosenLayer:   SASLSecurityIntegrity,
		MaxBufferSize: 1 << 24, // one past the 3-octet limit
	}
	_, err := BuildSASLClientToken(ctx, resp)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "3-octet")
}

func TestBuildSASLClientToken_RejectsInvalidLayer(t *testing.T) {
	t.Parallel()
	ctx := newSASLContext(t)
	resp := SASLClientResponse{
		ChosenLayer: 0x07, // combination, not a single valid layer
	}
	_, err := BuildSASLClientToken(ctx, resp)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "ChosenLayer")
}

func TestBuildSASLClientToken_SubkeyFlagFromContext(t *testing.T) {
	t.Parallel()
	session := getSessionKey()
	apRepSubkey := types.EncryptionKey{
		KeyType:  sessionKeyType,
		KeyValue: []byte("abcdef0123456789"),
	}
	ctx := NewInitiatorContext(session, types.EncryptionKey{}, apRepSubkey, 0, 0)

	token, err := BuildSASLClientToken(ctx, SASLClientResponse{ChosenLayer: SASLSecurityNone})
	assert.NoError(t, err)

	wt := &WrapToken{}
	assert.NoError(t, wt.Unmarshal(token, false))
	assert.NotZero(t, wt.Flags&AcceptorSubkeyFlag, "subkey flag must be set when context has a subkey")
}

func TestParseSASLServerToken_RoundTrip(t *testing.T) {
	t.Parallel()
	key := getSessionKey()
	ctx := NewInitiatorContext(key, types.EncryptionKey{}, types.EncryptionKey{}, 0, 0)

	// Craft a server offer token as if the acceptor had wrapped it.
	payload := []byte{
		SASLSecurityNone | SASLSecurityIntegrity, // SupportedLayers
		0x00, 0x10, 0x00,                         // MaxBufferSize = 4096
	}
	serverWrap := &WrapToken{
		Flags:     SentByAcceptorFlag,
		EC:        12,
		RRC:       0,
		SndSeqNum: 0,
		Payload:   payload,
	}
	assert.NoError(t, serverWrap.SetCheckSum(key, keyusage.GSSAPI_ACCEPTOR_SEAL))
	bytes, err := serverWrap.Marshal()
	assert.NoError(t, err)

	offer, err := ParseSASLServerToken(ctx, bytes)
	assert.NoError(t, err)
	if assert.NotNil(t, offer) {
		assert.True(t, offer.SupportsLayer(SASLSecurityNone))
		assert.True(t, offer.SupportsLayer(SASLSecurityIntegrity))
		assert.False(t, offer.SupportsLayer(SASLSecurityConfidential))
		assert.Equal(t, uint32(4096), offer.MaxBufferSize)
	}
	assert.Equal(t, uint64(1), ctx.NextRecvSeq(), "context recvSeq advanced after parse")
}

func TestParseSASLServerToken_InvalidToken(t *testing.T) {
	t.Parallel()
	ctx := newSASLContext(t)

	_, err := ParseSASLServerToken(ctx, []byte{})
	assert.Error(t, err, "empty token rejected")

	_, err = ParseSASLServerToken(ctx, []byte{0x05, 0x04})
	assert.Error(t, err, "short token rejected")

	badToken := make([]byte, 32)
	badToken[0] = 0x01 // wrong token ID
	_, err = ParseSASLServerToken(ctx, badToken)
	assert.Error(t, err, "wrong token ID rejected")
}
