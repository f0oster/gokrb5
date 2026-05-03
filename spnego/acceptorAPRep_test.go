package spnego

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/f0oster/gokrb5/gssapi"
	"github.com/f0oster/gokrb5/iana/msgtype"
	"github.com/f0oster/gokrb5/messages"
	"github.com/f0oster/gokrb5/test/testdata"
	"github.com/f0oster/gokrb5/types"
	"github.com/stretchr/testify/assert"
)

func TestKRB5Token_BuildAPRep(t *testing.T) {
	t.Parallel()
	// AES128-CTS-HMAC-SHA1-96 ticket session key.
	sessionKey := types.EncryptionKey{
		KeyType:  17,
		KeyValue: []byte("0123456789abcdef"),
	}
	tt, _ := time.Parse(testdata.TEST_TIME_FORMAT, testdata.TEST_TIME)
	tok := &KRB5Token{
		APReq: messages.APReq{
			Ticket: messages.Ticket{
				DecryptedEncPart: messages.EncTicketPart{Key: sessionKey},
			},
			Authenticator: types.Authenticator{CTime: tt, Cusec: 123456},
		},
	}

	if err := tok.buildAPRep(); err != nil {
		t.Fatalf("buildAPRep: %v", err)
	}

	// Acceptor subkey: same enctype as session key, fresh random bytes.
	assert.Equal(t, sessionKey.KeyType, tok.AcceptorSubkey.KeyType, "acceptor subkey enctype matches ticket session key")
	assert.Len(t, tok.AcceptorSubkey.KeyValue, 16, "acceptor subkey length matches enctype 17")
	assert.NotEqual(t, sessionKey.KeyValue, tok.AcceptorSubkey.KeyValue, "acceptor subkey is distinct from ticket session key")
	assert.NotZero(t, tok.AcceptorSeqNumber, "fresh acceptor sequence number generated")

	// MechToken bytes round-trip back to a KRB5 AP-REP.
	assert.NotEmpty(t, tok.ResponseToken(), "response MechToken populated")
	var rt KRB5Token
	if err := rt.Unmarshal(tok.ResponseToken()); err != nil {
		t.Fatalf("unmarshal MechToken: %v", err)
	}
	assert.True(t, rt.IsAPRep(), "round-tripped MechToken is AP-REP")
	assert.Equal(t, msgtype.KRB_AP_REP, rt.APRep.MsgType)
	assert.Equal(t, tok.APRep.EncPart.EType, rt.APRep.EncPart.EType)
	assert.Equal(t, tok.APRep.EncPart.Cipher, rt.APRep.EncPart.Cipher)
}

func TestAcceptCompletedResponseHeader_NoMutualAuth(t *testing.T) {
	t.Parallel()
	h, err := acceptCompletedResponseHeader(nil)
	if err != nil {
		t.Fatalf("acceptCompletedResponseHeader: %v", err)
	}
	assert.Equal(t, spnegoNegTokenRespKRBAcceptCompleted, h, "nil response token uses the static accept-completed constant")
}

func TestKRB5Token_SecurityContext(t *testing.T) {
	t.Parallel()
	sessionKey := types.EncryptionKey{
		KeyType:  17,
		KeyValue: []byte("0123456789abcdef"),
	}
	authSubkey := types.EncryptionKey{
		KeyType:  17,
		KeyValue: []byte("authsubkey5678ab"),
	}
	tt, _ := time.Parse(testdata.TEST_TIME_FORMAT, testdata.TEST_TIME)

	// Construct a KRB5Token in the shape Verify leaves it after a
	// successful mutual-auth AP-REQ: ticket session key, initiator's
	// authenticator subkey + seq, and acceptor subkey + seq populated by
	// buildAPRep.
	tok := &KRB5Token{
		tokID: []byte{0x01, 0x00}, // AP-REQ
		APReq: messages.APReq{
			Ticket: messages.Ticket{
				DecryptedEncPart: messages.EncTicketPart{Key: sessionKey},
			},
			Authenticator: types.Authenticator{
				CTime:     tt,
				Cusec:     123456,
				SubKey:    authSubkey,
				SeqNumber: 42,
			},
		},
	}
	if err := tok.buildAPRep(); err != nil {
		t.Fatalf("buildAPRep: %v", err)
	}

	sc := tok.SecurityContext()
	if sc == nil {
		t.Fatal("SecurityContext returned nil for mutual-auth AP-REQ")
	}
	assert.False(t, sc.IsInitiator)
	assert.Equal(t, uint64(tok.AcceptorSeqNumber), sc.SendSeq())
	assert.Equal(t, uint64(42), sc.NextRecvSeq())

	// Pair with an initiator context built from the same key material and
	// exchange tokens both directions.
	initiator := gssapi.NewInitiatorContext(
		sessionKey,
		authSubkey,
		tok.AcceptorSubkey,
		42,                            // initiator's send seed = Authenticator.SeqNumber
		uint64(tok.AcceptorSeqNumber), // initiator's recv anchor = EncAPRepPart.SequenceNumber
	)

	plain := []byte("from acceptor via SecurityContext()")
	wrapped, err := sc.Wrap(plain)
	if err != nil {
		t.Fatalf("acceptor Wrap: %v", err)
	}
	got, err := initiator.Unwrap(wrapped)
	if err != nil {
		t.Fatalf("initiator Unwrap: %v", err)
	}
	assert.Equal(t, plain, got)

	reply := []byte("from initiator")
	wrapped, err = initiator.Wrap(reply)
	if err != nil {
		t.Fatalf("initiator Wrap: %v", err)
	}
	got, err = sc.Unwrap(wrapped)
	if err != nil {
		t.Fatalf("acceptor Unwrap: %v", err)
	}
	assert.Equal(t, reply, got)
}

func TestKRB5Token_SecurityContext_NilWithoutMutualAuth(t *testing.T) {
	t.Parallel()
	tok := &KRB5Token{
		tokID: []byte{0x01, 0x00}, // AP-REQ, but buildAPRep never called
	}
	assert.Nil(t, tok.SecurityContext(), "no AcceptorSubkey, no SecurityContext")
}

func TestKRB5Token_SecurityContext_NilForNonAPReq(t *testing.T) {
	t.Parallel()
	tok := &KRB5Token{
		tokID:          []byte{0x02, 0x00}, // AP-REP, not AP-REQ
		AcceptorSubkey: types.EncryptionKey{KeyType: 17, KeyValue: []byte("0123456789abcdef")},
	}
	assert.Nil(t, tok.SecurityContext(), "AP-REP token type yields no acceptor context")
}

func TestSPNEGOToken_SecurityContext(t *testing.T) {
	t.Parallel()
	// Resp-side tokens never produce an acceptor context.
	s := &SPNEGOToken{Resp: true}
	assert.Nil(t, s.SecurityContext())

	// Init token without a mechToken returns nil.
	s = &SPNEGOToken{Init: true}
	assert.Nil(t, s.SecurityContext())

	// Init token wrapping a verified mutual-auth AP-REQ KRB5Token delegates.
	sessionKey := types.EncryptionKey{KeyType: 17, KeyValue: []byte("0123456789abcdef")}
	tt, _ := time.Parse(testdata.TEST_TIME_FORMAT, testdata.TEST_TIME)
	krb5 := &KRB5Token{
		tokID: []byte{0x01, 0x00},
		APReq: messages.APReq{
			Ticket:        messages.Ticket{DecryptedEncPart: messages.EncTicketPart{Key: sessionKey}},
			Authenticator: types.Authenticator{CTime: tt, Cusec: 1, SeqNumber: 7},
		},
	}
	if err := krb5.buildAPRep(); err != nil {
		t.Fatalf("buildAPRep: %v", err)
	}
	s = &SPNEGOToken{
		Init:         true,
		NegTokenInit: NegTokenInit{mechToken: krb5},
	}
	sc := s.SecurityContext()
	if sc == nil {
		t.Fatal("SPNEGOToken.SecurityContext returned nil for valid mutual-auth token")
	}
	assert.False(t, sc.IsInitiator)
}

func TestAcceptCompletedResponseHeader_MutualAuth(t *testing.T) {
	t.Parallel()
	payload := []byte{0xde, 0xad, 0xbe, 0xef}
	h, err := acceptCompletedResponseHeader(payload)
	if err != nil {
		t.Fatalf("acceptCompletedResponseHeader: %v", err)
	}
	assert.NotEqual(t, spnegoNegTokenRespKRBAcceptCompleted, h, "header differs from the static constant when a response token is supplied")
	assert.True(t, strings.HasPrefix(h, "Negotiate "), "header carries the Negotiate scheme")

	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(h, "Negotiate "))
	if err != nil {
		t.Fatalf("base64 decode: %v", err)
	}
	var resp NegTokenResp
	if err := resp.Unmarshal(raw); err != nil {
		t.Fatalf("NegTokenResp.Unmarshal: %v", err)
	}
	assert.Equal(t, asn1.Enumerated(NegStateAcceptCompleted), resp.NegState, "NegState=accept-completed")
	assert.True(t, resp.SupportedMech.Equal(gssapi.OIDKRB5.OID()), "SupportedMech=KRB5")
	assert.Equal(t, payload, resp.ResponseToken, "ResponseToken carries the AP-REP MechToken bytes")
}
