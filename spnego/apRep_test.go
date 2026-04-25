package spnego

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/f0oster/gokrb5/crypto"
	"github.com/f0oster/gokrb5/iana/keyusage"
	"github.com/f0oster/gokrb5/messages"
	"github.com/f0oster/gokrb5/test/testdata"
	"github.com/f0oster/gokrb5/types"
)

const (
	testAPRepCusec     = 123456
	testAPRepSeqNumber = int64(17)
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
