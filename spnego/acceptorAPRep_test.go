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
