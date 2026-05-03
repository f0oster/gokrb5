package gssapi

import (
	"encoding/binary"
	"slices"
	"sync"
	"testing"

	"github.com/f0oster/gokrb5/iana/keyusage"
	"github.com/f0oster/gokrb5/types"
	"github.com/stretchr/testify/assert"
)

// acceptorWrapToken builds a wrap token as if the acceptor had sent it:
// flips SentByAcceptorFlag on and checksums with GSSAPI_ACCEPTOR_SEAL so
// the initiator SecurityContext can verify it on the Unwrap path.
func acceptorWrapToken(t *testing.T, key types.EncryptionKey, seq uint64, payload []byte, withSubkeyFlag bool) []byte {
	t.Helper()
	flags := byte(SentByAcceptorFlag)
	if withSubkeyFlag {
		flags |= AcceptorSubkeyFlag
	}
	wt := &WrapToken{
		Flags:     flags,
		EC:        12, // AES128/256-CTS-HMAC-SHA1-96 HMAC output length
		RRC:       0,
		SndSeqNum: seq,
		Payload:   payload,
	}
	if err := wt.SetCheckSum(key, keyusage.GSSAPI_ACCEPTOR_SEAL); err != nil {
		t.Fatalf("set acceptor checksum: %v", err)
	}
	b, err := wt.Marshal()
	if err != nil {
		t.Fatalf("marshal acceptor token: %v", err)
	}
	return b
}

// acceptorMICToken builds a MIC token from the acceptor side so the
// initiator SecurityContext can verify it on the VerifySignature path.
func acceptorMICToken(t *testing.T, key types.EncryptionKey, seq uint64, payload []byte, withSubkeyFlag bool) []byte {
	t.Helper()
	flags := byte(MICTokenFlagSentByAcceptor)
	if withSubkeyFlag {
		flags |= MICTokenFlagAcceptorSubkey
	}
	mt := &MICToken{
		Flags:     flags,
		SndSeqNum: seq,
		Payload:   payload,
	}
	if err := mt.SetChecksum(key, keyusage.GSSAPI_ACCEPTOR_SIGN); err != nil {
		t.Fatalf("set acceptor MIC checksum: %v", err)
	}
	b, err := mt.Marshal()
	if err != nil {
		t.Fatalf("marshal acceptor MIC: %v", err)
	}
	return b
}

// rotateRight produces a wire-format WrapToken where the post-header
// payload|checksum region has been right-rotated by rrc bytes, matching
// what SSPI emits per MS-KILE §3.4.5.4.1 (RRC=12 for integrity-only
// AES-SHA1 WrapTokens).
func rotateRight(t *testing.T, unrotated []byte, rrc int) []byte {
	t.Helper()
	out := make([]byte, len(unrotated))
	copy(out[:HdrLen], unrotated[:HdrLen])
	binary.BigEndian.PutUint16(out[6:8], uint16(rrc))
	data := unrotated[HdrLen:]
	if len(data) == 0 {
		return out
	}
	r := rrc % len(data)
	copy(out[HdrLen:], data[len(data)-r:])
	copy(out[HdrLen+r:], data[:len(data)-r])
	return out
}

// newInitiator builds a SecurityContext for tests using the session key
// constants defined in wrapToken_test.go. apRepSeq seeds the sliding
// window anchor.
func newInitiator(sendSeq, apRepSeq uint64) *SecurityContext {
	return NewInitiatorContext(getSessionKey(), types.EncryptionKey{}, types.EncryptionKey{}, sendSeq, apRepSeq)
}

func TestNewInitiatorContext_SeedsSendAndRecv(t *testing.T) {
	t.Parallel()
	ctx := NewInitiatorContext(getSessionKey(), types.EncryptionKey{}, types.EncryptionKey{}, 100, 200)
	assert.Equal(t, uint64(100), ctx.SendSeq(), "sendSeq initialized from authenticator")
	assert.Equal(t, uint64(200), ctx.NextRecvSeq(), "recvSeq baseline from apRepSeq")
}

func TestSecurityContext_WrapUnwrapRoundTripMITStyle(t *testing.T) {
	t.Parallel()
	// MIT-style: both sides start at a non-zero value that they
	// coordinate through Authenticator.SeqNumber and EncAPRepPart.
	key := getSessionKey()
	ctx := newInitiator(5, 7)

	plaintext := []byte("hello world")
	token, err := ctx.Wrap(plaintext)
	assert.NoError(t, err)

	wt := &WrapToken{}
	assert.NoError(t, wt.Unmarshal(token, false))
	assert.Equal(t, uint64(5), wt.SndSeqNum)
	assert.Equal(t, uint64(6), ctx.SendSeq())
	assert.Equal(t, byte(0x00), wt.Flags, "no acceptor, no sealed, no subkey bits")
	assert.Equal(t, uint16(0), wt.RRC, "initiator emits RRC=0 (MIT-style)")

	reply := []byte("world hello")
	replyToken := acceptorWrapToken(t, key, 7, reply, false)
	got, err := ctx.Unwrap(replyToken)
	assert.NoError(t, err)
	assert.Equal(t, reply, got)
	assert.Equal(t, SeqStatusOK, ctx.LastRecvStatus())
	assert.Equal(t, uint64(8), ctx.NextRecvSeq())
}

func TestSecurityContext_UnwrapWithSSPIStyleRRC12(t *testing.T) {
	t.Parallel()
	key := getSessionKey()
	ctx := newInitiator(0, 0)

	reply := []byte("from windows")
	unrotated := acceptorWrapToken(t, key, 0, reply, false)
	rotated := rotateRight(t, unrotated, 12)

	got, err := ctx.Unwrap(rotated)
	assert.NoError(t, err)
	assert.Equal(t, reply, got)
	// TODO(testdata): replace with a real captured Windows token
	// when an AD test environment is available.
}

func TestSecurityContext_SendSeqMonotonic(t *testing.T) {
	t.Parallel()
	ctx := newInitiator(10, 0)
	for i := uint64(0); i < 3; i++ {
		token, err := ctx.Wrap([]byte("msg"))
		assert.NoError(t, err)
		wt := &WrapToken{}
		assert.NoError(t, wt.Unmarshal(token, false))
		assert.Equal(t, 10+i, wt.SndSeqNum)
	}
	assert.Equal(t, uint64(13), ctx.SendSeq())
}

func TestSecurityContext_ConfidentialRoundTripAES(t *testing.T) {
	t.Parallel()
	// Round-trip a sealed WrapToken through the same context: encrypt
	// on the initiator side, then fake the acceptor flip and decrypt
	// as if we were an AD-style peer. This exercises the RFC 4121
	// §4.2.4 / MS-KILE §3.4.5.4.1 sealed layout end-to-end.
	key := getSessionKey()
	ctx := newInitiator(0, 0)
	ctx.Confidential = true

	plaintext := []byte("secret payload for sealed wrap")
	token, err := ctx.Wrap(plaintext)
	assert.NoError(t, err)

	// Parse the sealed token back via raw WrapToken API (simulating
	// the acceptor receiving it). The enctype's own HMAC covers
	// integrity; OpenSealed verifies the inner header copy.
	wt := &WrapToken{}
	assert.NoError(t, wt.Unmarshal(token, false))
	assert.NotZero(t, wt.Flags&SealedFlag, "SealedFlag must be set in marshaled token")
	assert.Nil(t, wt.CheckSum, "sealed tokens do not carry a trailing checksum")
	recovered, err := wt.OpenSealed(key, keyusage.GSSAPI_INITIATOR_SEAL)
	assert.NoError(t, err)
	assert.Equal(t, plaintext, recovered)
}

func TestSecurityContext_ConfidentialUnwrapFromAcceptorSide(t *testing.T) {
	t.Parallel()
	// Build a sealed token as if the acceptor had sent it, then pass
	// it through SecurityContext.Unwrap on the initiator side.
	key := getSessionKey()
	plaintext := []byte("from acceptor sealed")

	wt := &WrapToken{
		Flags:     SentByAcceptorFlag | SealedFlag,
		EC:        16, // one AES block of filler per MS-KILE §3.4.5.4.1
		RRC:       0,
		SndSeqNum: 5,
		Payload:   plaintext,
	}
	assert.NoError(t, wt.SealPayload(key, keyusage.GSSAPI_ACCEPTOR_SEAL))
	bytes, err := wt.Marshal()
	assert.NoError(t, err)

	ctx := newInitiator(0, 5)
	ctx.Confidential = true // only affects send direction; unwrap detects Sealed via the flag
	got, err := ctx.Unwrap(bytes)
	assert.NoError(t, err)
	assert.Equal(t, plaintext, got)
}

func TestSecurityContext_ADStyleRepeatedZeroTolerated(t *testing.T) {
	t.Parallel()
	// Active Directory emits every server→client WrapToken with
	// SND_SEQ=0. The sliding window accepts the first as in-order and
	// returns SeqStatusDuplicate (non-fatal) for subsequent ones; the
	// payload is returned in both cases so application-layer code
	// that ignores supplementary status sees a continuous stream.
	key := getSessionKey()
	ctx := newInitiator(0, 0)

	for i := 0; i < 3; i++ {
		tok := acceptorWrapToken(t, key, 0, []byte("ad response"), false)
		got, err := ctx.Unwrap(tok)
		assert.NoError(t, err, "AD-style duplicate seq must not produce an error")
		assert.Equal(t, []byte("ad response"), got)
	}
	// After the first, subsequent tokens are flagged as duplicates.
	assert.Equal(t, SeqStatusDuplicate, ctx.LastRecvStatus())
}

func TestSecurityContext_StrictSequenceRejectsDuplicate(t *testing.T) {
	t.Parallel()
	key := getSessionKey()
	ctx := newInitiator(0, 0)
	ctx.StrictSequence = true

	// First token accepted.
	tok := acceptorWrapToken(t, key, 0, []byte("a"), false)
	_, err := ctx.Unwrap(tok)
	assert.NoError(t, err)

	// Second at same seq → duplicate → strict mode errors.
	tok2 := acceptorWrapToken(t, key, 0, []byte("b"), false)
	_, err = ctx.Unwrap(tok2)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "supplementary")
}

func TestSecurityContext_OutOfOrderNonStrict(t *testing.T) {
	t.Parallel()
	key := getSessionKey()
	ctx := newInitiator(0, 0)

	// Accept a token at seq=5 (forward gap). Non-strict: succeeds,
	// status is Gap.
	tok := acceptorWrapToken(t, key, 5, []byte("later"), false)
	got, err := ctx.Unwrap(tok)
	assert.NoError(t, err)
	assert.Equal(t, []byte("later"), got)
	assert.Equal(t, SeqStatusGap, ctx.LastRecvStatus())

	// Then accept a token at seq=3 (past, within window). Non-strict:
	// succeeds, status is Unsequenced.
	tok2 := acceptorWrapToken(t, key, 3, []byte("earlier"), false)
	got, err = ctx.Unwrap(tok2)
	assert.NoError(t, err)
	assert.Equal(t, []byte("earlier"), got)
	assert.Equal(t, SeqStatusUnsequenced, ctx.LastRecvStatus())
}

func TestSecurityContext_MICRoundTrip(t *testing.T) {
	t.Parallel()
	key := getSessionKey()
	ctx := newInitiator(20, 20)

	msg := []byte("message to sign")
	sig, err := ctx.MakeSignature(msg)
	assert.NoError(t, err)
	assert.Equal(t, uint64(21), ctx.SendSeq(), "MIC advances sendSeq like Wrap does")

	parsed := &MICToken{}
	assert.NoError(t, parsed.Unmarshal(sig, false))
	parsed.Payload = msg
	ok, err := parsed.Verify(key, keyusage.GSSAPI_INITIATOR_SIGN)
	assert.NoError(t, err)
	assert.True(t, ok)
	assert.Equal(t, uint64(20), parsed.SndSeqNum)

	replyMsg := []byte("reply to sign")
	replyMIC := acceptorMICToken(t, key, 20, replyMsg, false)
	err = ctx.VerifySignature(replyMsg, replyMIC)
	assert.NoError(t, err)
	assert.Equal(t, uint64(21), ctx.NextRecvSeq())
}

func TestSecurityContext_MICAndWrapShareSendSeq(t *testing.T) {
	t.Parallel()
	// Per RFC 4121 §4.2.3 a single sendSeq counter covers both Wrap
	// and MIC tokens emitted by one side.
	ctx := newInitiator(100, 0)

	wt1, err := ctx.Wrap([]byte("one"))
	assert.NoError(t, err)
	mic, err := ctx.MakeSignature([]byte("two"))
	assert.NoError(t, err)
	wt2, err := ctx.Wrap([]byte("three"))
	assert.NoError(t, err)
	assert.Equal(t, uint64(103), ctx.SendSeq())

	parsedWrap1 := &WrapToken{}
	assert.NoError(t, parsedWrap1.Unmarshal(wt1, false))
	assert.Equal(t, uint64(100), parsedWrap1.SndSeqNum)

	parsedMIC := &MICToken{}
	assert.NoError(t, parsedMIC.Unmarshal(mic, false))
	assert.Equal(t, uint64(101), parsedMIC.SndSeqNum)

	parsedWrap2 := &WrapToken{}
	assert.NoError(t, parsedWrap2.Unmarshal(wt2, false))
	assert.Equal(t, uint64(102), parsedWrap2.SndSeqNum)
}

func TestSecurityContext_APRepSubkeyFlagSetOnOutgoingWrap(t *testing.T) {
	t.Parallel()
	session := getSessionKey()
	apRepSubkey := types.EncryptionKey{
		KeyType:  sessionKeyType,
		KeyValue: []byte("abcdef0123456789"),
	}
	ctx := NewInitiatorContext(session, types.EncryptionKey{}, apRepSubkey, 0, 0)

	token, err := ctx.Wrap([]byte("msg"))
	assert.NoError(t, err)

	wt := &WrapToken{}
	assert.NoError(t, wt.Unmarshal(token, false))
	assert.NotZero(t, wt.Flags&AcceptorSubkeyFlag, "AcceptorSubkeyFlag must be set when APRepSubkey is present")

	okSubkey, err := wt.Verify(apRepSubkey, keyusage.GSSAPI_INITIATOR_SEAL)
	assert.NoError(t, err)
	assert.True(t, okSubkey, "checksum verifies with APRepSubkey")

	okSession, err := wt.Verify(session, keyusage.GSSAPI_INITIATOR_SEAL)
	assert.Error(t, err, "checksum must NOT verify with session key when APRepSubkey was used")
	assert.False(t, okSession)
}

func TestSecurityContext_AuthenticatorSubkeyUsedWhenNoAPRepSubkey(t *testing.T) {
	t.Parallel()
	// When EncAPRepPart does not carry a subkey, MIT/Heimdal GSS
	// implementations fall back to the Authenticator subkey for
	// per-message tokens. The outgoing flag bit is NOT set in this
	// case (the flag means "acceptor subkey in use", which this isn't).
	session := getSessionKey()
	authSubkey := types.EncryptionKey{
		KeyType:  sessionKeyType,
		KeyValue: []byte("fedcba9876543210"),
	}
	ctx := NewInitiatorContext(session, authSubkey, types.EncryptionKey{}, 0, 0)

	token, err := ctx.Wrap([]byte("msg"))
	assert.NoError(t, err)

	wt := &WrapToken{}
	assert.NoError(t, wt.Unmarshal(token, false))
	assert.Zero(t, wt.Flags&AcceptorSubkeyFlag, "Authenticator subkey path must not set AcceptorSubkeyFlag")

	ok, err := wt.Verify(authSubkey, keyusage.GSSAPI_INITIATOR_SEAL)
	assert.NoError(t, err)
	assert.True(t, ok, "checksum verifies with AuthenticatorSubkey")
}

func TestSecurityContext_SubkeyFlagClearWhenNoSubkey(t *testing.T) {
	t.Parallel()
	ctx := newInitiator(0, 0)

	token, err := ctx.Wrap([]byte("msg"))
	assert.NoError(t, err)

	wt := &WrapToken{}
	assert.NoError(t, wt.Unmarshal(token, false))
	assert.Zero(t, wt.Flags&AcceptorSubkeyFlag)
}

func TestSecurityContext_UnwrapErrorsWhenSubkeyFlagSetButNoAPRepSubkey(t *testing.T) {
	t.Parallel()
	// Peer asserts AcceptorSubkeyFlag but our context never received an
	// AP-REP subkey. Falling back to a different key would only produce
	// "checksum invalid" downstream; surface the actual cause instead.
	key := getSessionKey()
	ctx := newInitiator(0, 0)

	tok := acceptorWrapToken(t, key, 0, []byte("payload"), true /* withSubkeyFlag */)
	_, err := ctx.Unwrap(tok)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "AcceptorSubkeyFlag")
}

func TestSecurityContext_VerifySignatureErrorsWhenSubkeyFlagSetButNoAPRepSubkey(t *testing.T) {
	t.Parallel()
	key := getSessionKey()
	ctx := newInitiator(0, 0)

	msg := []byte("signed payload")
	mic := acceptorMICToken(t, key, 0, msg, true /* withSubkeyFlag */)
	err := ctx.VerifySignature(msg, mic)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "AcceptorSubkeyFlag")
}

func TestSecurityContext_UnwrapSelectsSubkeyWhenFlagSet(t *testing.T) {
	t.Parallel()
	session := getSessionKey()
	apRepSubkey := types.EncryptionKey{
		KeyType:  sessionKeyType,
		KeyValue: []byte("abcdef0123456789"),
	}
	ctx := NewInitiatorContext(session, types.EncryptionKey{}, apRepSubkey, 0, 0)

	reply := acceptorWrapToken(t, apRepSubkey, 0, []byte("from acceptor"), true)
	got, err := ctx.Unwrap(reply)
	assert.NoError(t, err)
	assert.Equal(t, []byte("from acceptor"), got)
}

// TestSecurityContext_AES256SHA384RoundTrip exercises the AES256-CTS-HMAC-SHA384-192
// enctype (RFC 8009, etypeID 20) end-to-end. This is the default enctype
// negotiated by recent Windows Server releases and MIT krb5 versions, and
// MS-KILE §3.4.5.4.1 uses it for GSS_WrapEx. Integrity-only HMAC is
// truncated to 192 bits = 24 bytes, so EC on the wire is 24.
func TestSecurityContext_AES256SHA384RoundTrip(t *testing.T) {
	t.Parallel()
	key := types.EncryptionKey{
		KeyType: 20, // AES256-CTS-HMAC-SHA384-192
		// 32-byte AES256 key (deterministic for test reproducibility)
		KeyValue: []byte("0123456789abcdef0123456789abcdef"),
	}
	ctx := NewInitiatorContext(key, types.EncryptionKey{}, types.EncryptionKey{}, 100, 200)

	// Integrity-only wrap.
	plain := []byte("rfc 8009 round trip payload")
	token, err := ctx.Wrap(plain)
	assert.NoError(t, err)

	wt := &WrapToken{}
	assert.NoError(t, wt.Unmarshal(token, false))
	assert.Equal(t, uint16(24), wt.EC, "AES-SHA384-192 integrity EC must be 24 bytes")
	assert.Equal(t, uint64(100), wt.SndSeqNum)
	// Verify the checksum round-trips under the correct key+usage.
	ok, err := wt.Verify(key, keyusage.GSSAPI_INITIATOR_SEAL)
	assert.NoError(t, err)
	assert.True(t, ok)

	// Confidential round-trip with the same enctype.
	ctx.Confidential = true
	sealed, err := ctx.Wrap([]byte("sealed rfc 8009 payload"))
	assert.NoError(t, err)
	sealedWT := &WrapToken{}
	assert.NoError(t, sealedWT.Unmarshal(sealed, false))
	assert.NotZero(t, sealedWT.Flags&SealedFlag)
	recovered, err := sealedWT.OpenSealed(key, keyusage.GSSAPI_INITIATOR_SEAL)
	assert.NoError(t, err)
	assert.Equal(t, []byte("sealed rfc 8009 payload"), recovered)
}

// TestSecurityContext_ConcurrentWrap_AllocatesUniqueSeq exercises the
// send-side mutex. N goroutines each call Wrap once; the produced tokens
// must carry a contiguous, unique 0..N-1 set of sequence numbers.
func TestSecurityContext_ConcurrentWrap_AllocatesUniqueSeq(t *testing.T) {
	t.Parallel()
	const N = 64
	ctx := newInitiator(0, 0)

	tokens := make([][]byte, N)
	var wg sync.WaitGroup
	wg.Add(N)
	for i := 0; i < N; i++ {
		go func(i int) {
			defer wg.Done()
			tok, err := ctx.Wrap([]byte("payload"))
			if err != nil {
				t.Errorf("Wrap %d: %v", i, err)
				return
			}
			tokens[i] = tok
		}(i)
	}
	wg.Wait()

	seqs := make([]uint64, 0, N)
	for i, tok := range tokens {
		if tok == nil {
			t.Fatalf("token %d nil", i)
		}
		wt := &WrapToken{}
		if err := wt.Unmarshal(tok, false); err != nil {
			t.Fatalf("unmarshal %d: %v", i, err)
		}
		seqs = append(seqs, wt.SndSeqNum)
	}
	slices.Sort(seqs)
	for i := 0; i < N; i++ {
		assert.Equal(t, uint64(i), seqs[i], "seq %d", i)
	}
	assert.Equal(t, uint64(N), ctx.SendSeq())
}

// TestSecurityContext_ConcurrentWrapUnwrap_DirectionsIndependent exercises
// the RFC 2743 §1.1.3 contract: protect operations in opposite directions
// on a single context must not interfere. A sender goroutine drives Wrap
// while a receiver goroutine consumes acceptor-side tokens through Unwrap.
func TestSecurityContext_ConcurrentWrapUnwrap_DirectionsIndependent(t *testing.T) {
	t.Parallel()
	const N = 64
	key := getSessionKey()
	ctx := newInitiator(0, 0)

	prebuilt := make([][]byte, N)
	for i := 0; i < N; i++ {
		prebuilt[i] = acceptorWrapToken(t, key, uint64(i), []byte("payload"), false)
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < N; i++ {
			if _, err := ctx.Wrap([]byte("send")); err != nil {
				t.Errorf("Wrap %d: %v", i, err)
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < N; i++ {
			if _, err := ctx.Unwrap(prebuilt[i]); err != nil {
				t.Errorf("Unwrap %d: %v", i, err)
				return
			}
		}
	}()
	wg.Wait()

	assert.Equal(t, uint64(N), ctx.SendSeq())
	assert.Equal(t, uint64(N), ctx.NextRecvSeq())
}

// pairContexts builds matched initiator/acceptor contexts with seeds
// coordinated as if they had completed an AP-REQ/AP-REP exchange:
// initiator's send seed = acceptor's recv anchor (Authenticator.SeqNumber);
// acceptor's send seed = initiator's recv anchor (EncAPRepPart.SequenceNumber).
func pairContexts(t *testing.T, initSendSeed, accSendSeed uint64, authSubkey, apRepSubkey types.EncryptionKey) (*SecurityContext, *SecurityContext) {
	t.Helper()
	initiator := NewInitiatorContext(getSessionKey(), authSubkey, apRepSubkey, initSendSeed, accSendSeed)
	acceptor := NewAcceptorContext(getSessionKey(), authSubkey, apRepSubkey, accSendSeed, initSendSeed)
	return initiator, acceptor
}

func TestNewAcceptorContext_SeedsSendAndRecv(t *testing.T) {
	t.Parallel()
	ctx := NewAcceptorContext(getSessionKey(), types.EncryptionKey{}, types.EncryptionKey{}, 100, 200)
	assert.False(t, ctx.IsInitiator, "acceptor-side context")
	assert.Equal(t, uint64(100), ctx.SendSeq(), "sendSeq seeded from EncAPRepPart")
	assert.Equal(t, uint64(200), ctx.NextRecvSeq(), "recvSeq seeded from initiator's Authenticator")
}

func TestSecurityContext_BidirectionalWrap_Integrity(t *testing.T) {
	t.Parallel()
	initiator, acceptor := pairContexts(t, 50, 100, types.EncryptionKey{}, types.EncryptionKey{})

	// Initiator → acceptor.
	plain := []byte("from initiator")
	tok, err := initiator.Wrap(plain)
	assert.NoError(t, err)

	// Outgoing initiator token must NOT set SentByAcceptorFlag.
	parsed := &WrapToken{}
	assert.NoError(t, parsed.Unmarshal(tok, false))
	assert.Zero(t, parsed.Flags&SentByAcceptorFlag, "initiator outbound has acceptor flag clear")
	assert.Equal(t, uint64(50), parsed.SndSeqNum)

	got, err := acceptor.Unwrap(tok)
	assert.NoError(t, err)
	assert.Equal(t, plain, got)
	assert.Equal(t, SeqStatusOK, acceptor.LastRecvStatus())
	assert.Equal(t, uint64(51), acceptor.NextRecvSeq())

	// Acceptor → initiator.
	reply := []byte("from acceptor")
	tok, err = acceptor.Wrap(reply)
	assert.NoError(t, err)

	// Outgoing acceptor token MUST set SentByAcceptorFlag.
	parsed = &WrapToken{}
	assert.NoError(t, parsed.Unmarshal(tok, true))
	assert.NotZero(t, parsed.Flags&SentByAcceptorFlag, "acceptor outbound has acceptor flag set")
	assert.Equal(t, uint64(100), parsed.SndSeqNum)

	got, err = initiator.Unwrap(tok)
	assert.NoError(t, err)
	assert.Equal(t, reply, got)
	assert.Equal(t, SeqStatusOK, initiator.LastRecvStatus())
	assert.Equal(t, uint64(101), initiator.NextRecvSeq())

	// Sequence advances independently per direction across multiple exchanges.
	for i := uint64(0); i < 3; i++ {
		t1, err := initiator.Wrap([]byte("ping"))
		assert.NoError(t, err)
		_, err = acceptor.Unwrap(t1)
		assert.NoError(t, err)
		t2, err := acceptor.Wrap([]byte("pong"))
		assert.NoError(t, err)
		_, err = initiator.Unwrap(t2)
		assert.NoError(t, err)
	}
	assert.Equal(t, uint64(54), initiator.SendSeq())
	assert.Equal(t, uint64(54), acceptor.NextRecvSeq())
	assert.Equal(t, uint64(104), acceptor.SendSeq())
	assert.Equal(t, uint64(104), initiator.NextRecvSeq())
}

func TestSecurityContext_BidirectionalWrap_Sealed(t *testing.T) {
	t.Parallel()
	initiator, acceptor := pairContexts(t, 0, 0, types.EncryptionKey{}, types.EncryptionKey{})
	initiator.Confidential = true
	acceptor.Confidential = true

	// Initiator sealed → acceptor opens.
	plain := []byte("sealed from initiator")
	tok, err := initiator.Wrap(plain)
	assert.NoError(t, err)
	parsed := &WrapToken{}
	assert.NoError(t, parsed.Unmarshal(tok, false))
	assert.NotZero(t, parsed.Flags&SealedFlag, "SealedFlag set on initiator outbound")

	got, err := acceptor.Unwrap(tok)
	assert.NoError(t, err)
	assert.Equal(t, plain, got)

	// Acceptor sealed → initiator opens.
	reply := []byte("sealed from acceptor")
	tok, err = acceptor.Wrap(reply)
	assert.NoError(t, err)
	parsed = &WrapToken{}
	assert.NoError(t, parsed.Unmarshal(tok, true))
	assert.NotZero(t, parsed.Flags&SealedFlag, "SealedFlag set on acceptor outbound")
	assert.NotZero(t, parsed.Flags&SentByAcceptorFlag, "SentByAcceptorFlag set on acceptor outbound")

	got, err = initiator.Unwrap(tok)
	assert.NoError(t, err)
	assert.Equal(t, reply, got)
}

func TestSecurityContext_BidirectionalMIC(t *testing.T) {
	t.Parallel()
	initiator, acceptor := pairContexts(t, 20, 40, types.EncryptionKey{}, types.EncryptionKey{})

	// Initiator → acceptor MIC.
	msg := []byte("message from initiator")
	sig, err := initiator.MakeSignature(msg)
	assert.NoError(t, err)
	parsed := &MICToken{}
	assert.NoError(t, parsed.Unmarshal(sig, false))
	assert.Zero(t, parsed.Flags&MICTokenFlagSentByAcceptor, "initiator MIC has acceptor flag clear")

	err = acceptor.VerifySignature(msg, sig)
	assert.NoError(t, err)

	// Acceptor → initiator MIC.
	reply := []byte("reply from acceptor")
	sig, err = acceptor.MakeSignature(reply)
	assert.NoError(t, err)
	parsed = &MICToken{}
	assert.NoError(t, parsed.Unmarshal(sig, true))
	assert.NotZero(t, parsed.Flags&MICTokenFlagSentByAcceptor, "acceptor MIC has acceptor flag set")

	err = initiator.VerifySignature(reply, sig)
	assert.NoError(t, err)
}

func TestSecurityContext_BidirectionalAPRepSubkey(t *testing.T) {
	t.Parallel()
	// MS-KILE §3.1.1.2: when AP-REP subkey is present, both sides use it
	// as the per-message session key and set AcceptorSubkeyFlag on
	// outgoing tokens regardless of role.
	apRepSubkey := types.EncryptionKey{
		KeyType:  sessionKeyType,
		KeyValue: []byte("abcdef0123456789"),
	}
	initiator, acceptor := pairContexts(t, 0, 0, types.EncryptionKey{}, apRepSubkey)

	// Initiator → acceptor: flag set, acceptor opens with APRepSubkey.
	plain := []byte("with subkey from initiator")
	tok, err := initiator.Wrap(plain)
	assert.NoError(t, err)
	parsed := &WrapToken{}
	assert.NoError(t, parsed.Unmarshal(tok, false))
	assert.NotZero(t, parsed.Flags&AcceptorSubkeyFlag, "initiator outbound sets AcceptorSubkeyFlag when APRepSubkey is in use")

	got, err := acceptor.Unwrap(tok)
	assert.NoError(t, err)
	assert.Equal(t, plain, got)

	// Acceptor → initiator: flag set, initiator opens with APRepSubkey.
	reply := []byte("with subkey from acceptor")
	tok, err = acceptor.Wrap(reply)
	assert.NoError(t, err)
	parsed = &WrapToken{}
	assert.NoError(t, parsed.Unmarshal(tok, true))
	assert.NotZero(t, parsed.Flags&AcceptorSubkeyFlag, "acceptor outbound sets AcceptorSubkeyFlag")
	assert.NotZero(t, parsed.Flags&SentByAcceptorFlag, "acceptor outbound sets SentByAcceptorFlag")

	got, err = initiator.Unwrap(tok)
	assert.NoError(t, err)
	assert.Equal(t, reply, got)
}

func TestSecurityContext_AntiReflection(t *testing.T) {
	t.Parallel()
	// RFC 4121 §4.2.2: a context must reject its own outbound tokens
	// reflected back. Initiator-emitted tokens have SentByAcceptorFlag
	// clear; acceptor-emitted have it set. Each side rejects the wrong
	// direction at Unmarshal time.
	initiator, acceptor := pairContexts(t, 0, 0, types.EncryptionKey{}, types.EncryptionKey{})

	// Acceptor's own outbound reflected back to itself.
	accTok, err := acceptor.Wrap([]byte("from acceptor"))
	assert.NoError(t, err)
	_, err = acceptor.Unwrap(accTok)
	assert.Error(t, err, "acceptor must reject its own outbound (anti-reflection)")

	// Initiator's own outbound reflected back to itself.
	initTok, err := initiator.Wrap([]byte("from initiator"))
	assert.NoError(t, err)
	_, err = initiator.Unwrap(initTok)
	assert.Error(t, err, "initiator must reject its own outbound (anti-reflection)")
}

// TestSecurityContext_ConcurrentMakeSignature_AllocatesUniqueSeq is the
// MIC-token counterpart to ConcurrentWrap. Same invariant: every produced
// MIC carries a unique sequence number.
func TestSecurityContext_ConcurrentMakeSignature_AllocatesUniqueSeq(t *testing.T) {
	t.Parallel()
	const N = 32
	ctx := newInitiator(0, 0)

	mics := make([][]byte, N)
	var wg sync.WaitGroup
	wg.Add(N)
	for i := 0; i < N; i++ {
		go func(i int) {
			defer wg.Done()
			m, err := ctx.MakeSignature([]byte("msg"))
			if err != nil {
				t.Errorf("MakeSignature %d: %v", i, err)
				return
			}
			mics[i] = m
		}(i)
	}
	wg.Wait()

	seen := make(map[uint64]struct{}, N)
	for i, m := range mics {
		if m == nil {
			t.Fatalf("mic %d nil", i)
		}
		mt := &MICToken{}
		if err := mt.Unmarshal(m, false); err != nil {
			t.Fatalf("unmarshal %d: %v", i, err)
		}
		if _, dup := seen[mt.SndSeqNum]; dup {
			t.Fatalf("duplicate seq %d", mt.SndSeqNum)
		}
		seen[mt.SndSeqNum] = struct{}{}
	}
	assert.Len(t, seen, N)
}
