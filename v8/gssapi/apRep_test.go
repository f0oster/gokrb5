package gssapi

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/test/testdata"
	"github.com/jcmturner/gokrb5/v8/types"
	"github.com/stretchr/testify/assert"
)

const (
	testAPRepCusec       = 123456
	testAPRepSeqNumber   = int64(17)
	testAPRepSubkeyType  = int32(1)
	testAPRepSubkeyValue = "12345678"
)

var testAPRepKey = types.EncryptionKey{
	KeyType:  17,
	KeyValue: []byte("0123456789abcdef"),
}

func buildTestAPRep(t *testing.T, encPartHex string) messages.APRep {
	t.Helper()
	plain, err := hex.DecodeString(encPartHex)
	if err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	ed, err := crypto.GetEncryptedData(plain, testAPRepKey, keyusage.AP_REP_ENCPART, 1)
	if err != nil {
		t.Fatalf("encrypt fixture: %v", err)
	}
	return messages.APRep{
		PVNO:    5,
		MsgType: 15,
		EncPart: ed,
	}
}

func matchingAuthenticator(t *testing.T) types.Authenticator {
	t.Helper()
	ct, err := time.Parse(testdata.TEST_TIME_FORMAT, testdata.TEST_TIME)
	if err != nil {
		t.Fatalf("parse test time: %v", err)
	}
	return types.Authenticator{
		CTime: ct,
		Cusec: testAPRepCusec,
	}
}

func TestVerifyAPRep_HappyPathWithSubkey(t *testing.T) {
	t.Parallel()
	apRep := buildTestAPRep(t, testdata.MarshaledKRB5ap_rep_enc_part)
	auth := matchingAuthenticator(t)

	encPart, err := VerifyAPRep(apRep, testAPRepKey, auth)
	assert.NoError(t, err)
	if !assert.NotNil(t, encPart) {
		return
	}
	assert.Equal(t, testAPRepCusec, encPart.Cusec)
	assert.Equal(t, testAPRepSubkeyType, encPart.Subkey.KeyType)
	assert.Equal(t, []byte(testAPRepSubkeyValue), encPart.Subkey.KeyValue)
	assert.Equal(t, testAPRepSeqNumber, encPart.SequenceNumber)
}

func TestVerifyAPRep_HappyPathWithoutSubkey(t *testing.T) {
	t.Parallel()
	apRep := buildTestAPRep(t, testdata.MarshaledKRB5ap_rep_enc_partOptionalsNULL)
	auth := matchingAuthenticator(t)

	encPart, err := VerifyAPRep(apRep, testAPRepKey, auth)
	assert.NoError(t, err)
	if !assert.NotNil(t, encPart) {
		return
	}
	assert.Zero(t, encPart.Subkey.KeyType)
	assert.Zero(t, encPart.SequenceNumber)
}

func TestVerifyAPRep_CTimeMismatch(t *testing.T) {
	t.Parallel()
	apRep := buildTestAPRep(t, testdata.MarshaledKRB5ap_rep_enc_part)
	auth := matchingAuthenticator(t)
	auth.CTime = auth.CTime.Add(time.Second)

	_, err := VerifyAPRep(apRep, testAPRepKey, auth)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "ctime")
}

func TestVerifyAPRep_CusecMismatch(t *testing.T) {
	t.Parallel()
	apRep := buildTestAPRep(t, testdata.MarshaledKRB5ap_rep_enc_part)
	auth := matchingAuthenticator(t)
	auth.Cusec = testAPRepCusec + 1

	_, err := VerifyAPRep(apRep, testAPRepKey, auth)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cusec")
}

func TestVerifyAPRep_WrongSessionKey(t *testing.T) {
	t.Parallel()
	apRep := buildTestAPRep(t, testdata.MarshaledKRB5ap_rep_enc_part)
	auth := matchingAuthenticator(t)

	wrongKey := types.EncryptionKey{
		KeyType:  testAPRepKey.KeyType,
		KeyValue: []byte("fedcba9876543210"),
	}
	_, err := VerifyAPRep(apRep, wrongKey, auth)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "decrypt")
}

func TestVerifyAPRep_TamperedCiphertext(t *testing.T) {
	t.Parallel()
	apRep := buildTestAPRep(t, testdata.MarshaledKRB5ap_rep_enc_part)
	if len(apRep.EncPart.Cipher) == 0 {
		t.Fatal("fixture ciphertext empty")
	}
	apRep.EncPart.Cipher[0] ^= 0xFF
	auth := matchingAuthenticator(t)

	_, err := VerifyAPRep(apRep, testAPRepKey, auth)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "decrypt")
}

func TestVerifyAPRep_CTimeSubSecondTolerance(t *testing.T) {
	t.Parallel()
	apRep := buildTestAPRep(t, testdata.MarshaledKRB5ap_rep_enc_part)

	base, err := time.Parse(testdata.TEST_TIME_FORMAT, testdata.TEST_TIME)
	if err != nil {
		t.Fatalf("parse test time: %v", err)
	}
	auth := types.Authenticator{
		CTime: base.Add(52 * time.Millisecond),
		Cusec: testAPRepCusec,
	}

	encPart, err := VerifyAPRep(apRep, testAPRepKey, auth)
	assert.NoError(t, err)
	assert.NotNil(t, encPart)
}

func TestVerifyAPRep_SeqNumberNotCompared(t *testing.T) {
	t.Parallel()
	apRep := buildTestAPRep(t, testdata.MarshaledKRB5ap_rep_enc_part)
	auth := matchingAuthenticator(t)
	auth.SeqNumber = 9999

	encPart, err := VerifyAPRep(apRep, testAPRepKey, auth)
	assert.NoError(t, err)
	if assert.NotNil(t, encPart) {
		assert.Equal(t, testAPRepSeqNumber, encPart.SequenceNumber)
	}
}
