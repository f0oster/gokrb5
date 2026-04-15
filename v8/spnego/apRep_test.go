package spnego

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

// The testdata fixtures encode EncAPRepPart values whose ctime is TEST_TIME
// and whose cusec is 123456. The "full" fixture additionally carries a
// subkey (type 1, "12345678") and sequence number 17; the "OptionalsNULL"
// fixture omits both.
const (
	testAPRepCusec       = 123456
	testAPRepSeqNumber   = int64(17)
	testAPRepSubkeyType  = int32(1)
	testAPRepSubkeyValue = "12345678"
)

// testKey is an arbitrary 16-byte key used to encrypt AP-REP fixtures for
// decryption round-trips. AES128-CTS-HMAC-SHA1-96 (etype 17) is a KILE
// default and keeps the fixture compact.
var testAPRepKey = types.EncryptionKey{
	KeyType:  17,
	KeyValue: []byte("0123456789abcdef"),
}

// buildTestAPRep encrypts the supplied EncAPRepPart plaintext bytes with
// testAPRepKey and returns an APRep wrapping the ciphertext.
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

// matchingAuthenticator builds an Authenticator whose ctime/cusec align
// with the fixtures, so VerifyAPRep's mutual-auth check passes.
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
	assert.Equal(t, testAPRepCusec, encPart.Cusec, "Cusec passed through")
	assert.Equal(t, testAPRepSubkeyType, encPart.Subkey.KeyType, "Subkey type passed through")
	assert.Equal(t, []byte(testAPRepSubkeyValue), encPart.Subkey.KeyValue, "Subkey value passed through")
	assert.Equal(t, testAPRepSeqNumber, encPart.SequenceNumber, "SequenceNumber passed through (adopted, not compared)")
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
	assert.Zero(t, encPart.Subkey.KeyType, "Subkey absent in OptionalsNULL fixture")
	assert.Zero(t, encPart.SequenceNumber, "SequenceNumber absent in OptionalsNULL fixture")
}

func TestVerifyAPRep_CTimeMismatch(t *testing.T) {
	t.Parallel()
	apRep := buildTestAPRep(t, testdata.MarshaledKRB5ap_rep_enc_part)
	auth := matchingAuthenticator(t)
	auth.CTime = auth.CTime.Add(time.Second) // drift past the second-precision floor

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

// TestVerifyAPRep_CTimeSubSecondTolerance exercises the real-world case
// that unit fixtures miss: the Authenticator carries nanosecond-precision
// time.Now() in memory, but ASN.1 GeneralizedTime rounds ctime to the
// second on the wire, so the server's echoed EncAPRepPart.CTime is always
// second-precision. Comparing the two directly with .Equal() would
// always fail. VerifyAPRep must truncate the sent-side ctime before
// comparing; this test ensures that stays true.
func TestVerifyAPRep_CTimeSubSecondTolerance(t *testing.T) {
	t.Parallel()
	apRep := buildTestAPRep(t, testdata.MarshaledKRB5ap_rep_enc_part)

	// Build an Authenticator whose CTime has a non-zero sub-second
	// component. The fixture encodes 1994-06-10 06:03:17 UTC exactly,
	// so we add a stray 52ms to exercise the truncation path.
	base, err := time.Parse(testdata.TEST_TIME_FORMAT, testdata.TEST_TIME)
	if err != nil {
		t.Fatalf("parse test time: %v", err)
	}
	auth := types.Authenticator{
		CTime: base.Add(52 * time.Millisecond),
		Cusec: testAPRepCusec,
	}

	encPart, err := VerifyAPRep(apRep, testAPRepKey, auth)
	assert.NoError(t, err, "nanosecond precision on sent-side ctime must not cause rejection")
	assert.NotNil(t, encPart)
}

// TestVerifyAPRep_SeqNumberNotCompared exercises the specific correction
// made during the plan review: EncAPRepPart.SequenceNumber is the server's
// chosen initial send-sequence and must NOT be compared against anything
// the client sent. A caller that constructs a matching Authenticator with
// a completely unrelated SeqNumber value should still succeed — the server
// picked 17, the client sent 9999, both are legitimate.
func TestVerifyAPRep_SeqNumberNotCompared(t *testing.T) {
	t.Parallel()
	apRep := buildTestAPRep(t, testdata.MarshaledKRB5ap_rep_enc_part)
	auth := matchingAuthenticator(t)
	auth.SeqNumber = 9999

	encPart, err := VerifyAPRep(apRep, testAPRepKey, auth)
	assert.NoError(t, err, "SequenceNumber is adopted, not compared; the mismatch must not cause failure")
	if assert.NotNil(t, encPart) {
		assert.Equal(t, testAPRepSeqNumber, encPart.SequenceNumber, "caller adopts the server's chosen seq")
	}
}
