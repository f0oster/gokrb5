package gssapi

import (
	"fmt"
	"time"

	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

// VerifyAPRep decrypts an AP-REP with sessionKey and verifies the
// server's mutual-authentication proof per RFC 4120 §3.2.4: the
// decrypted ctime and cusec must match those of sentAuth, the
// Authenticator the client placed in its AP-REQ. The returned
// EncAPRepPart carries the optional Subkey (per MS-KILE §3.1.1.2,
// mandatory-to-use for AES when present) and SequenceNumber (the
// server's initial send-sequence for subsequent per-message tokens).
func VerifyAPRep(apRep messages.APRep, sessionKey types.EncryptionKey, sentAuth types.Authenticator) (*messages.EncAPRepPart, error) {
	decrypted, err := crypto.DecryptEncPart(apRep.EncPart, sessionKey, keyusage.AP_REP_ENCPART)
	if err != nil {
		return nil, fmt.Errorf("decrypt AP-REP: %w", err)
	}

	var encPart messages.EncAPRepPart
	if err := encPart.Unmarshal(decrypted); err != nil {
		return nil, fmt.Errorf("unmarshal EncAPRepPart: %w", err)
	}

	sentCTime := sentAuth.CTime.Truncate(time.Second)
	if !encPart.CTime.Equal(sentCTime) {
		return nil, fmt.Errorf("AP-REP ctime %v does not match authenticator ctime %v",
			encPart.CTime, sentCTime)
	}
	if encPart.Cusec != sentAuth.Cusec {
		return nil, fmt.Errorf("AP-REP cusec %d does not match authenticator cusec %d",
			encPart.Cusec, sentAuth.Cusec)
	}

	return &encPart, nil
}
