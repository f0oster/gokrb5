package messages

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/f0oster/gokrb5/crypto"
	"github.com/f0oster/gokrb5/iana"
	"github.com/f0oster/gokrb5/iana/keyusage"
	"github.com/f0oster/gokrb5/iana/msgtype"
	"github.com/f0oster/gokrb5/test/testdata"
	"github.com/f0oster/gokrb5/types"
	"github.com/stretchr/testify/assert"
)

func TestUnmarshalAPRep(t *testing.T) {
	t.Parallel()
	var a APRep
	b, err := hex.DecodeString(testdata.MarshaledKRB5ap_rep)
	if err != nil {
		t.Fatalf("Test vector read error: %v", err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}
	assert.Equal(t, iana.PVNO, a.PVNO, "PVNO not as expected")
	assert.Equal(t, msgtype.KRB_AP_REP, a.MsgType, "MsgType is not as expected")
	assert.Equal(t, testdata.TEST_ETYPE, a.EncPart.EType, "Ticket encPart etype not as expected")
	assert.Equal(t, iana.PVNO, a.EncPart.KVNO, "Ticket encPart KVNO not as expected")
	assert.Equal(t, []byte(testdata.TEST_CIPHERTEXT), a.EncPart.Cipher, "Ticket encPart cipher not as expected")
}

func TestUnmarshalEncAPRepPart(t *testing.T) {
	t.Parallel()
	var a EncAPRepPart
	b, err := hex.DecodeString(testdata.MarshaledKRB5ap_rep_enc_part)
	if err != nil {
		t.Fatalf("Test vector read error: %v", err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}
	//Parse the test time value into a time.Time type
	tt, _ := time.Parse(testdata.TEST_TIME_FORMAT, testdata.TEST_TIME)

	assert.Equal(t, tt, a.CTime, "CTime not as expected")
	assert.Equal(t, 123456, a.Cusec, "Client microseconds not as expected")
	assert.Equal(t, int32(1), a.Subkey.KeyType, "Subkey type not as expected")
	assert.Equal(t, []byte("12345678"), a.Subkey.KeyValue, "Subkey value not as expected")
	assert.Equal(t, int64(17), a.SequenceNumber, "Sequence number not as expected")
}

func TestUnmarshalEncAPRepPart_optionalsNULL(t *testing.T) {
	t.Parallel()
	var a EncAPRepPart
	b, err := hex.DecodeString(testdata.MarshaledKRB5ap_rep_enc_partOptionalsNULL)
	if err != nil {
		t.Fatalf("Test vector read error: %v", err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}
	//Parse the test time value into a time.Time type
	tt, _ := time.Parse(testdata.TEST_TIME_FORMAT, testdata.TEST_TIME)

	assert.Equal(t, tt, a.CTime, "CTime not as expected")
	assert.Equal(t, 123456, a.Cusec, "Client microseconds not as expected")
}

func TestAPRepMarshalRoundTrip(t *testing.T) {
	t.Parallel()
	var a APRep
	b, err := hex.DecodeString(testdata.MarshaledKRB5ap_rep)
	if err != nil {
		t.Fatalf("Test vector read error: %v", err)
	}
	if err := a.Unmarshal(b); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}
	mb, err := a.Marshal()
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}
	var b2 APRep
	if err := b2.Unmarshal(mb); err != nil {
		t.Fatalf("Unmarshal of remarshaled APRep error: %v", err)
	}
	assert.Equal(t, a.PVNO, b2.PVNO)
	assert.Equal(t, a.MsgType, b2.MsgType)
	assert.Equal(t, a.EncPart.EType, b2.EncPart.EType)
	assert.Equal(t, a.EncPart.KVNO, b2.EncPart.KVNO)
	assert.Equal(t, a.EncPart.Cipher, b2.EncPart.Cipher)
}

func TestEncAPRepPartMarshalRoundTrip(t *testing.T) {
	t.Parallel()
	var a EncAPRepPart
	b, err := hex.DecodeString(testdata.MarshaledKRB5ap_rep_enc_part)
	if err != nil {
		t.Fatalf("Test vector read error: %v", err)
	}
	if err := a.Unmarshal(b); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}
	mb, err := a.Marshal()
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}
	var b2 EncAPRepPart
	if err := b2.Unmarshal(mb); err != nil {
		t.Fatalf("Unmarshal of remarshaled EncAPRepPart error: %v", err)
	}
	assert.True(t, a.CTime.Equal(b2.CTime), "CTime not preserved")
	assert.Equal(t, a.Cusec, b2.Cusec)
	assert.Equal(t, a.Subkey.KeyType, b2.Subkey.KeyType)
	assert.Equal(t, a.Subkey.KeyValue, b2.Subkey.KeyValue)
	assert.Equal(t, a.SequenceNumber, b2.SequenceNumber)
}

func TestNewAPRep(t *testing.T) {
	t.Parallel()
	// AES128-CTS-HMAC-SHA1-96 session key (etype 17, 16 bytes).
	sessionKey := types.EncryptionKey{
		KeyType:  17,
		KeyValue: []byte("0123456789abcdef"),
	}
	tt, _ := time.Parse(testdata.TEST_TIME_FORMAT, testdata.TEST_TIME)
	auth := types.Authenticator{
		CTime: tt,
		Cusec: 123456,
	}

	rep, enc, err := NewAPRep(sessionKey, auth)
	if err != nil {
		t.Fatalf("NewAPRep error: %v", err)
	}

	assert.Equal(t, iana.PVNO, rep.PVNO)
	assert.Equal(t, msgtype.KRB_AP_REP, rep.MsgType)
	assert.Equal(t, sessionKey.KeyType, enc.Subkey.KeyType, "acceptor subkey enctype matches session key")
	assert.Len(t, enc.Subkey.KeyValue, 16, "acceptor subkey has correct length for etype 17")
	assert.NotZero(t, enc.SequenceNumber, "sequence number generated")
	assert.True(t, auth.CTime.Equal(enc.CTime))
	assert.Equal(t, auth.Cusec, enc.Cusec)

	// EncAPRepPart decrypts under the session key with key usage 12 and
	// round-trips to the same plaintext fields.
	plain, err := crypto.DecryptEncPart(rep.EncPart, sessionKey, keyusage.AP_REP_ENCPART)
	if err != nil {
		t.Fatalf("DecryptEncPart: %v", err)
	}
	var decoded EncAPRepPart
	if err := decoded.Unmarshal(plain); err != nil {
		t.Fatalf("Unmarshal decrypted EncAPRepPart: %v", err)
	}
	assert.True(t, enc.CTime.Equal(decoded.CTime))
	assert.Equal(t, enc.Cusec, decoded.Cusec)
	assert.Equal(t, enc.Subkey.KeyType, decoded.Subkey.KeyType)
	assert.Equal(t, enc.Subkey.KeyValue, decoded.Subkey.KeyValue)
	assert.Equal(t, enc.SequenceNumber, decoded.SequenceNumber)
}

func TestNewAPRep_freshSubkeyAndSeqEachCall(t *testing.T) {
	t.Parallel()
	sessionKey := types.EncryptionKey{
		KeyType:  17,
		KeyValue: []byte("0123456789abcdef"),
	}
	tt, _ := time.Parse(testdata.TEST_TIME_FORMAT, testdata.TEST_TIME)
	auth := types.Authenticator{CTime: tt, Cusec: 1}

	_, e1, err := NewAPRep(sessionKey, auth)
	if err != nil {
		t.Fatalf("first NewAPRep: %v", err)
	}
	_, e2, err := NewAPRep(sessionKey, auth)
	if err != nil {
		t.Fatalf("second NewAPRep: %v", err)
	}
	assert.NotEqual(t, e1.Subkey.KeyValue, e2.Subkey.KeyValue, "acceptor subkey is fresh per call")
	assert.NotEqual(t, e1.SequenceNumber, e2.SequenceNumber, "sequence number is fresh per call")
}

func TestEncAPRepPartMarshalRoundTrip_optionalsNULL(t *testing.T) {
	t.Parallel()
	var a EncAPRepPart
	b, err := hex.DecodeString(testdata.MarshaledKRB5ap_rep_enc_partOptionalsNULL)
	if err != nil {
		t.Fatalf("Test vector read error: %v", err)
	}
	if err := a.Unmarshal(b); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}
	mb, err := a.Marshal()
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}
	var b2 EncAPRepPart
	if err := b2.Unmarshal(mb); err != nil {
		t.Fatalf("Unmarshal of remarshaled EncAPRepPart error: %v", err)
	}
	assert.True(t, a.CTime.Equal(b2.CTime), "CTime not preserved")
	assert.Equal(t, a.Cusec, b2.Cusec)
	assert.Equal(t, int32(0), b2.Subkey.KeyType, "Subkey should be omitted")
	assert.Empty(t, b2.Subkey.KeyValue, "Subkey value should be empty")
	assert.Equal(t, int64(0), b2.SequenceNumber, "SequenceNumber should be omitted")
}
