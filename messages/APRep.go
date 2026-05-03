package messages

import (
	"crypto/rand"
	"fmt"
	"math"
	"math/big"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/f0oster/gokrb5/asn1tools"
	"github.com/f0oster/gokrb5/crypto"
	"github.com/f0oster/gokrb5/iana"
	"github.com/f0oster/gokrb5/iana/asnAppTag"
	"github.com/f0oster/gokrb5/iana/keyusage"
	"github.com/f0oster/gokrb5/iana/msgtype"
	"github.com/f0oster/gokrb5/krberror"
	"github.com/f0oster/gokrb5/types"
)

// APRep implements RFC 4120 KRB_AP_REP: https://tools.ietf.org/html/rfc4120#section-5.5.2.
type APRep struct {
	PVNO    int                 `asn1:"explicit,tag:0"`
	MsgType int                 `asn1:"explicit,tag:1"`
	EncPart types.EncryptedData `asn1:"explicit,tag:2"`
}

// EncAPRepPart is the encrypted part of KRB_AP_REP.
type EncAPRepPart struct {
	CTime          time.Time           `asn1:"generalized,explicit,tag:0"`
	Cusec          int                 `asn1:"explicit,tag:1"`
	Subkey         types.EncryptionKey `asn1:"optional,explicit,tag:2"`
	SequenceNumber int64               `asn1:"optional,explicit,tag:3"`
}

// Unmarshal bytes b into the APRep struct.
func (a *APRep) Unmarshal(b []byte) error {
	_, err := asn1.UnmarshalWithParams(b, a, fmt.Sprintf("application,explicit,tag:%v", asnAppTag.APREP))
	if err != nil {
		return processUnmarshalReplyError(b, err)
	}
	expectedMsgType := msgtype.KRB_AP_REP
	if a.MsgType != expectedMsgType {
		return krberror.NewErrorf(krberror.KRBMsgError, "message ID does not indicate a KRB_AP_REP. Expected: %v; Actual: %v", expectedMsgType, a.MsgType)
	}
	return nil
}

// Unmarshal bytes b into the APRep encrypted part struct.
func (a *EncAPRepPart) Unmarshal(b []byte) error {
	_, err := asn1.UnmarshalWithParams(b, a, fmt.Sprintf("application,explicit,tag:%v", asnAppTag.EncAPRepPart))
	if err != nil {
		return krberror.Errorf(err, krberror.EncodingError, "AP_REP unmarshal error")
	}
	return nil
}

// Marshal APRep to ASN.1 DER bytes wrapped in the KRB_AP_REP application tag.
func (a *APRep) Marshal() ([]byte, error) {
	b, err := asn1.Marshal(*a)
	if err != nil {
		return nil, krberror.Errorf(err, krberror.EncodingError, "marshaling error of AP_REP")
	}
	return asn1tools.AddASNAppTag(b, asnAppTag.APREP), nil
}

// Marshal EncAPRepPart to ASN.1 DER bytes wrapped in the EncAPRepPart application tag.
func (a *EncAPRepPart) Marshal() ([]byte, error) {
	b, err := asn1.Marshal(*a)
	if err != nil {
		return nil, krberror.Errorf(err, krberror.EncodingError, "marshaling error of EncAPRepPart")
	}
	return asn1tools.AddASNAppTag(b, asnAppTag.EncAPRepPart), nil
}

// NewAPRep builds a KRB_AP_REP responding to the client's AP-REQ.
//
// A fresh acceptor subkey of the same enctype as sessionKey and a fresh
// random sequence number are generated. The Authenticator's CTime and
// Cusec are echoed in EncAPRepPart so the initiator can verify the
// reply per RFC 4120 §3.2.4. EncAPRepPart is encrypted under sessionKey
// with key usage 12 (AP_REP_ENCPART).
//
// The returned EncAPRepPart carries the plaintext subkey and sequence
// number; callers building a gssapi.SecurityContext use them as the
// acceptor subkey and the seed for seq_send.
func NewAPRep(sessionKey types.EncryptionKey, auth types.Authenticator) (APRep, EncAPRepPart, error) {
	var rep APRep
	encType, err := crypto.GetEtype(sessionKey.KeyType)
	if err != nil {
		return rep, EncAPRepPart{}, krberror.Errorf(err, krberror.EncryptingError, "error getting etype for AP_REP subkey")
	}
	sk := make([]byte, encType.GetKeyByteSize())
	if _, err := rand.Read(sk); err != nil {
		return rep, EncAPRepPart{}, krberror.Errorf(err, krberror.EncryptingError, "error generating AP_REP subkey")
	}
	seq, err := rand.Int(rand.Reader, big.NewInt(math.MaxUint32))
	if err != nil {
		return rep, EncAPRepPart{}, krberror.Errorf(err, krberror.EncryptingError, "error generating AP_REP sequence number")
	}
	enc := EncAPRepPart{
		CTime: auth.CTime,
		Cusec: auth.Cusec,
		Subkey: types.EncryptionKey{
			KeyType:  sessionKey.KeyType,
			KeyValue: sk,
		},
		SequenceNumber: seq.Int64() & 0x3fffffff,
	}
	plain, err := enc.Marshal()
	if err != nil {
		return rep, EncAPRepPart{}, krberror.Errorf(err, krberror.EncodingError, "error marshaling EncAPRepPart")
	}
	ed, err := crypto.GetEncryptedData(plain, sessionKey, keyusage.AP_REP_ENCPART, iana.PVNO)
	if err != nil {
		return rep, EncAPRepPart{}, krberror.Errorf(err, krberror.EncryptingError, "error encrypting EncAPRepPart")
	}
	rep = APRep{
		PVNO:    iana.PVNO,
		MsgType: msgtype.KRB_AP_REP,
		EncPart: ed,
	}
	return rep, enc, nil
}
