package gssapi

import (
	"errors"
	"fmt"
	"sync"

	"github.com/f0oster/gokrb5/crypto"
	"github.com/f0oster/gokrb5/iana/keyusage"
	"github.com/f0oster/gokrb5/types"
)

// SecurityContext is an established Kerberos GSS security context. It
// owns the per-message send/receive sequence state and the key-selection
// rules for Wrap and MIC tokens per RFC 4121 §4.2. Both initiator-side
// and acceptor-side contexts are supported; use NewInitiatorContext or
// NewAcceptorContext to construct.
//
// Incoming sequence numbers flow through a 64-slot sliding window
// matching MIT krb5 (src/lib/gssapi/generic/util_seqstate.c:81-113);
// Heimdal uses a 20-slot jitter window with the same supplementary
// status semantics (third_party/heimdal/lib/gssapi/krb5/sequence.c:140-198).
// Per RFC 2743 §1.2.3 the supplementary statuses (Gap, Unsequenced,
// Old, Duplicate) are non-fatal, so Unwrap and VerifySignature return
// the payload regardless; LastRecvStatus exposes the outcome of the
// most recent check. Set StrictSequence to promote any non-OK status
// to an error.
//
// The permissive default is required for Active Directory interop on
// initiator contexts: AD emits every server-to-client WrapToken with
// SND_SEQ=0 (observed against a live DC), so after the first token
// every subsequent one is flagged Duplicate. The window therefore
// provides no in-band replay protection on the receive direction
// against AD; callers that need replay protection there must rely on
// the underlying transport (e.g. TLS) or enable StrictSequence and
// accept the loss of AD interop. Acceptor contexts receive tokens
// from initiators, where this AD quirk does not apply.
//
// Key selection follows RFC 4121 §4.2.2 and MS-KILE §3.1.1.2: outgoing
// tokens use the highest-precedence non-empty key (APRepSubkey >
// AuthenticatorSubkey > SessionKey) and set AcceptorSubkeyFlag when the
// AP-REP subkey is in use. Incoming tokens are verified with the key
// indicated by their own flag bit. The same precedence applies to
// both roles.
//
// Per RFC 2743 §1.1.3, Wrap/MakeSignature may run concurrently with
// Unwrap/VerifySignature on the same context. Same-direction concurrency
// is serialised internally on independent send and receive mutexes, so
// the two directions never block each other. Configuration fields must
// not be modified after the first protect operation.
type SecurityContext struct {
	// SessionKey is the session key from the service ticket. Required.
	SessionKey types.EncryptionKey

	// AuthenticatorSubkey is the subkey the client placed in its AP-REQ
	// Authenticator. When non-empty it takes precedence over SessionKey;
	// superseded by APRepSubkey when that field is also set.
	AuthenticatorSubkey types.EncryptionKey

	// APRepSubkey is the subkey from the decrypted EncAPRepPart. When
	// non-empty it is the authoritative key and sets AcceptorSubkeyFlag
	// on outgoing tokens. Mandatory-to-use for AES enctypes per
	// MS-KILE §3.1.1.2 when the server supplied one.
	APRepSubkey types.EncryptionKey

	// IsInitiator selects which side this context represents. Set by
	// NewInitiatorContext (true) or NewAcceptorContext (false); affects
	// outgoing/incoming token direction flags and key-usage constants.
	IsInitiator bool

	// Confidential enables sealed (encrypted) WrapTokens per RFC 4121
	// §4.2.4. Default false (integrity-only).
	Confidential bool

	// StrictSequence promotes non-OK SeqStatus values to fatal errors on
	// Unwrap and VerifySignature. Default false; must stay false for AD
	// interop because AD reuses SND_SEQ=0 for every server wrap.
	StrictSequence bool

	// ReplayDetect enables the replay-detection component of the sliding
	// window. Default true.
	ReplayDetect bool

	// SequenceDetect enables the sequence-ordering component of the
	// sliding window. Default true. Affects only how supplementary
	// statuses are reported unless StrictSequence is also set.
	SequenceDetect bool

	sendMu  sync.Mutex
	sendSeq uint64

	recvMu         sync.Mutex
	recvState      *seqState
	lastRecvStatus SeqStatus
}

// NewInitiatorContext builds an initiator-side SecurityContext.
// sentAuthSeq is the SeqNumber from the client's AP-REQ Authenticator
// and seeds sendSeq. apRepSeq is the SequenceNumber from the decrypted
// EncAPRepPart and anchors the receive sliding window; pass 0 when the
// AP-REP did not carry one. authSubkey and apRepSubkey may be zero
// EncryptionKey values when absent.
func NewInitiatorContext(sessionKey, authSubkey, apRepSubkey types.EncryptionKey, sentAuthSeq, apRepSeq uint64) *SecurityContext {
	c := &SecurityContext{
		SessionKey:          sessionKey,
		AuthenticatorSubkey: authSubkey,
		APRepSubkey:         apRepSubkey,
		IsInitiator:         true,
		ReplayDetect:        true,
		SequenceDetect:      true,
		sendSeq:             sentAuthSeq,
	}
	c.recvState = newSeqState(apRepSeq, c.ReplayDetect, c.SequenceDetect)
	return c
}

// NewAcceptorContext builds an acceptor-side SecurityContext.
// sentAPRepSeq is the SequenceNumber the acceptor placed in its
// EncAPRepPart and seeds sendSeq. recvAuthSeq is the SeqNumber from
// the initiator's AP-REQ Authenticator and anchors the receive sliding
// window. authSubkey carries the initiator's Authenticator subkey;
// apRepSubkey carries the subkey the acceptor placed in EncAPRepPart.
// Either may be a zero EncryptionKey when absent.
func NewAcceptorContext(sessionKey, authSubkey, apRepSubkey types.EncryptionKey, sentAPRepSeq, recvAuthSeq uint64) *SecurityContext {
	c := &SecurityContext{
		SessionKey:          sessionKey,
		AuthenticatorSubkey: authSubkey,
		APRepSubkey:         apRepSubkey,
		IsInitiator:         false,
		ReplayDetect:        true,
		SequenceDetect:      true,
		sendSeq:             sentAPRepSeq,
	}
	c.recvState = newSeqState(recvAuthSeq, c.ReplayDetect, c.SequenceDetect)
	return c
}

// SendSeq returns the next sequence number that Wrap or MakeSignature
// will place in an outgoing token. Exposed for tests and diagnostics.
func (c *SecurityContext) SendSeq() uint64 {
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	return c.sendSeq
}

// NextRecvSeq returns the sequence number the sliding window currently
// expects next from the peer. Exposed for tests and diagnostics.
func (c *SecurityContext) NextRecvSeq() uint64 {
	c.recvMu.Lock()
	defer c.recvMu.Unlock()
	return c.recvState.nextExpected()
}

// LastRecvStatus returns the SeqStatus produced by the most recent
// Unwrap or VerifySignature call. Useful for callers that want to log
// or act on non-fatal supplementary statuses without enabling
// StrictSequence.
func (c *SecurityContext) LastRecvStatus() SeqStatus {
	c.recvMu.Lock()
	defer c.recvMu.Unlock()
	return c.lastRecvStatus
}

// activeKey returns the key currently used for outgoing per-message
// tokens, honouring the precedence APRepSubkey > AuthenticatorSubkey >
// SessionKey.
func (c *SecurityContext) activeKey() types.EncryptionKey {
	if c.APRepSubkey.KeyValue != nil {
		return c.APRepSubkey
	}
	if c.AuthenticatorSubkey.KeyValue != nil {
		return c.AuthenticatorSubkey
	}
	return c.SessionKey
}

// outgoingFlags builds the Flags byte for an outgoing WrapToken or
// MICToken. AcceptorSubkeyFlag is set when the APRepSubkey is in use;
// the Authenticator subkey path does not set the flag because it is
// the client's own subkey, not the acceptor's.
func (c *SecurityContext) outgoingFlags(base byte) byte {
	if !c.IsInitiator {
		base |= SentByAcceptorFlag
	}
	if c.APRepSubkey.KeyValue != nil {
		base |= AcceptorSubkeyFlag
	}
	return base
}

// outgoingMICFlags is the MICToken counterpart to outgoingFlags, using
// the MICTokenFlag* constants.
func (c *SecurityContext) outgoingMICFlags() byte {
	var flags byte
	if !c.IsInitiator {
		flags |= MICTokenFlagSentByAcceptor
	}
	if c.APRepSubkey.KeyValue != nil {
		flags |= MICTokenFlagAcceptorSubkey
	}
	return flags
}

// incomingKey selects the verification key for a received token based
// on its AcceptorSubkeyFlag. When the flag is set the peer is asserting
// it used the acceptor subkey from the AP-REP; if no APRepSubkey is
// held an error is returned because falling back to a different key
// would only produce an opaque "checksum invalid" downstream. When the
// flag is clear the AuthenticatorSubkey takes precedence over the
// session key.
func (c *SecurityContext) incomingKey(acceptorSubkeyFlagSet bool) (types.EncryptionKey, error) {
	if acceptorSubkeyFlagSet {
		if c.APRepSubkey.KeyValue == nil {
			return types.EncryptionKey{}, errors.New("token sets AcceptorSubkeyFlag but no AP-REP subkey is held on this SecurityContext")
		}
		return c.APRepSubkey, nil
	}
	if c.AuthenticatorSubkey.KeyValue != nil {
		return c.AuthenticatorSubkey, nil
	}
	return c.SessionKey, nil
}

func (c *SecurityContext) sendSealUsage() uint32 {
	if c.IsInitiator {
		return keyusage.GSSAPI_INITIATOR_SEAL
	}
	return keyusage.GSSAPI_ACCEPTOR_SEAL
}

func (c *SecurityContext) recvSealUsage() uint32 {
	if c.IsInitiator {
		return keyusage.GSSAPI_ACCEPTOR_SEAL
	}
	return keyusage.GSSAPI_INITIATOR_SEAL
}

func (c *SecurityContext) sendSignUsage() uint32 {
	if c.IsInitiator {
		return keyusage.GSSAPI_INITIATOR_SIGN
	}
	return keyusage.GSSAPI_ACCEPTOR_SIGN
}

func (c *SecurityContext) recvSignUsage() uint32 {
	if c.IsInitiator {
		return keyusage.GSSAPI_ACCEPTOR_SIGN
	}
	return keyusage.GSSAPI_INITIATOR_SIGN
}

// Wrap builds a WrapToken carrying plaintext, increments the send
// sequence counter, and returns the marshaled bytes ready to hand to
// the transport. When Confidential is false the token is integrity-only;
// when true it is encrypted per RFC 4121 §4.2.4 (see wrapToken.go for
// the sealed format details).
func (c *SecurityContext) Wrap(plaintext []byte) ([]byte, error) {
	c.sendMu.Lock()
	defer c.sendMu.Unlock()

	key := c.activeKey()
	encType, err := crypto.GetEtype(key.KeyType)
	if err != nil {
		return nil, fmt.Errorf("get etype: %w", err)
	}

	flags := c.outgoingFlags(0x00)
	var wt *WrapToken
	if c.Confidential {
		flags |= SealedFlag
		// EC=0 for AES enctypes. Per RFC 4121 §4.2.3/§4.2.4 the
		// filler exists to absorb crypto-system residue after
		// decryption; AES-CTS produces no residue for any plaintext
		// length, so no filler is needed. MIT krb5, Heimdal, and
		// Windows SSPI all emit EC=0 here and their receivers
		// enforce it.
		wt = &WrapToken{
			Flags:     flags,
			EC:        0,
			RRC:       0,
			SndSeqNum: c.sendSeq,
			Payload:   plaintext,
		}
		if err := wt.SealPayload(key, c.sendSealUsage()); err != nil {
			return nil, fmt.Errorf("seal wrap token: %w", err)
		}
	} else {
		wt = &WrapToken{
			Flags:     flags,
			EC:        uint16(encType.GetHMACBitLength() / 8),
			RRC:       0,
			SndSeqNum: c.sendSeq,
			Payload:   plaintext,
		}
		if err := wt.SetCheckSum(key, c.sendSealUsage()); err != nil {
			return nil, fmt.Errorf("sign wrap token: %w", err)
		}
	}
	b, err := wt.Marshal()
	if err != nil {
		return nil, err
	}
	c.sendSeq++
	return b, nil
}

// Unwrap parses an incoming WrapToken, verifies its checksum (or
// decrypts it, for sealed tokens), enforces the configured
// replay/sequence policy through the sliding window, and returns the
// carried payload. Non-fatal supplementary statuses (gap, out-of-order,
// old, duplicate) are recorded on c.LastRecvStatus() and do not
// produce an error unless StrictSequence is set.
func (c *SecurityContext) Unwrap(token []byte) ([]byte, error) {
	wt := &WrapToken{}
	if err := wt.Unmarshal(token, c.IsInitiator); err != nil {
		return nil, fmt.Errorf("unmarshal wrap token: %w", err)
	}
	key, err := c.incomingKey(wt.Flags&AcceptorSubkeyFlag != 0)
	if err != nil {
		return nil, fmt.Errorf("select wrap token verification key: %w", err)
	}

	var payload []byte
	if wt.Flags&SealedFlag != 0 {
		pt, err := wt.OpenSealed(key, c.recvSealUsage())
		if err != nil {
			return nil, fmt.Errorf("open sealed wrap token: %w", err)
		}
		payload = pt
	} else {
		ok, err := wt.Verify(key, c.recvSealUsage())
		if err != nil {
			return nil, fmt.Errorf("verify wrap token: %w", err)
		}
		if !ok {
			return nil, errors.New("wrap token checksum invalid")
		}
		payload = wt.Payload
	}

	if err := c.evaluateRecvStatus(wt.SndSeqNum); err != nil {
		return nil, err
	}
	return payload, nil
}

// MakeSignature builds a detached MICToken over msg, increments the send
// sequence counter, and returns the marshaled bytes. The message is not
// carried in the token; the peer must already have it to call
// VerifySignature.
func (c *SecurityContext) MakeSignature(msg []byte) ([]byte, error) {
	c.sendMu.Lock()
	defer c.sendMu.Unlock()

	mt := &MICToken{
		Flags:     c.outgoingMICFlags(),
		SndSeqNum: c.sendSeq,
		Payload:   msg,
	}
	if err := mt.SetChecksum(c.activeKey(), c.sendSignUsage()); err != nil {
		return nil, fmt.Errorf("sign MIC token: %w", err)
	}
	b, err := mt.Marshal()
	if err != nil {
		return nil, err
	}
	c.sendSeq++
	return b, nil
}

// VerifySignature verifies a detached MICToken over msg. The token's
// AcceptorSubkey flag selects the verification key; the sequence number
// flows through the sliding window with the same supplementary-status
// semantics as Unwrap.
func (c *SecurityContext) VerifySignature(msg, token []byte) error {
	mt := &MICToken{}
	if err := mt.Unmarshal(token, c.IsInitiator); err != nil {
		return fmt.Errorf("unmarshal MIC token: %w", err)
	}
	mt.Payload = msg
	key, err := c.incomingKey(mt.Flags&MICTokenFlagAcceptorSubkey != 0)
	if err != nil {
		return fmt.Errorf("select MIC token verification key: %w", err)
	}
	ok, err := mt.Verify(key, c.recvSignUsage())
	if err != nil {
		return fmt.Errorf("verify MIC token: %w", err)
	}
	if !ok {
		return errors.New("MIC token checksum invalid")
	}
	return c.evaluateRecvStatus(mt.SndSeqNum)
}

// evaluateRecvStatus runs the sliding-window check and records the
// resulting status on the context. When StrictSequence is true, any
// non-OK status becomes a fatal error.
func (c *SecurityContext) evaluateRecvStatus(seq uint64) error {
	status := c.recvState.check(seq)
	c.lastRecvStatus = status
	if c.StrictSequence && status != SeqStatusOK {
		return fmt.Errorf("sequence supplementary status %v for seq %d (StrictSequence=true)", status, seq)
	}
	return nil
}
