package client

import (
	"slices"

	"github.com/f0oster/gokrb5/crypto"
	"github.com/f0oster/gokrb5/crypto/etype"
	"github.com/f0oster/gokrb5/iana/errorcode"
	"github.com/f0oster/gokrb5/iana/keyusage"
	"github.com/f0oster/gokrb5/iana/patype"
	"github.com/f0oster/gokrb5/krberror"
	"github.com/f0oster/gokrb5/messages"
	"github.com/f0oster/gokrb5/types"
)

// ASExchange performs an AS exchange for the client to retrieve a TGT.
func (cl *Client) ASExchange(realm string, ASReq messages.ASReq, referral int) (messages.ASRep, error) {
	if ok, err := cl.IsConfigured(); !ok {
		return messages.ASRep{}, krberror.Errorf(err, krberror.ConfigError, "AS Exchange cannot be performed")
	}

	// Set PAData if required
	err := setPAData(cl, nil, &ASReq)
	if err != nil {
		return messages.ASRep{}, krberror.Errorf(err, krberror.KRBMsgError, "AS Exchange Error: issue with setting PAData on AS_REQ")
	}

	b, err := ASReq.Marshal()
	if err != nil {
		return messages.ASRep{}, krberror.Errorf(err, krberror.EncodingError, "AS Exchange Error: failed marshaling AS_REQ")
	}
	var ASRep messages.ASRep

	rb, err := cl.sendToKDC(b, realm)
	if err != nil {
		if e, ok := err.(messages.KRBError); ok {
			switch e.ErrorCode {
			case errorcode.KDC_ERR_PREAUTH_REQUIRED, errorcode.KDC_ERR_PREAUTH_FAILED:
				// From now on assume this client will need to do this pre-auth and set the PAData
				cl.settings.assumePreAuthentication.Store(true)
				err = setPAData(cl, &e, &ASReq)
				if err != nil {
					return messages.ASRep{}, krberror.Errorf(err, krberror.KRBMsgError, "AS Exchange Error: failed setting AS_REQ PAData for pre-authentication required")
				}
				b, err := ASReq.Marshal()
				if err != nil {
					return messages.ASRep{}, krberror.Errorf(err, krberror.EncodingError, "AS Exchange Error: failed marshaling AS_REQ with PAData")
				}
				rb, err = cl.sendToKDC(b, realm)
				if err != nil {
					if _, ok := err.(messages.KRBError); ok {
						return messages.ASRep{}, krberror.Errorf(err, krberror.KDCError, "AS Exchange Error: kerberos error response from KDC")
					}
					return messages.ASRep{}, krberror.Errorf(err, krberror.NetworkingError, "AS Exchange Error: failed sending AS_REQ to KDC")
				}
			case errorcode.KDC_ERR_WRONG_REALM:
				// Client referral https://tools.ietf.org/html/rfc6806.html#section-7
				if referral > 5 {
					return messages.ASRep{}, krberror.Errorf(err, krberror.KRBMsgError, "maximum number of client referrals exceeded")
				}
				cl.Log("AS-REQ referral: from-realm=%q crealm=%q realm=%q sname=%v edata=%x", ASReq.ReqBody.Realm, e.CRealm, e.Realm, e.SName.NameString, e.EData)
				referral++
				ASReq.ReqBody.Realm = e.CRealm
				if len(ASReq.ReqBody.SName.NameString) >= 2 && ASReq.ReqBody.SName.NameString[0] == "krbtgt" {
					ASReq.ReqBody.SName.NameString = []string{"krbtgt", e.CRealm}
				}
				// PA-ENC-TIMESTAMP from the previous realm was encrypted under
				// that realm's key salt; drop it so the recursive call redoes
				// preauth fresh against the new realm.
				filtered := ASReq.PAData[:0]
				for _, pa := range ASReq.PAData {
					if pa.PADataType != patype.PA_ENC_TIMESTAMP {
						filtered = append(filtered, pa)
					}
				}
				ASReq.PAData = filtered
				return cl.ASExchange(e.CRealm, ASReq, referral)
			default:
				return messages.ASRep{}, krberror.Errorf(err, krberror.KDCError, "AS Exchange Error: kerberos error response from KDC")
			}
		} else {
			return messages.ASRep{}, krberror.Errorf(err, krberror.NetworkingError, "AS Exchange Error: failed sending AS_REQ to KDC")
		}
	}
	err = ASRep.Unmarshal(rb)
	if err != nil {
		return messages.ASRep{}, krberror.Errorf(err, krberror.EncodingError, "AS Exchange Error: failed to process the AS_REP")
	}
	if ok, err := ASRep.Verify(cl.Config, cl.Credentials, ASReq); !ok {
		return messages.ASRep{}, krberror.Errorf(err, krberror.KRBMsgError, "AS Exchange Error: AS_REP is not valid or client password/keytab incorrect")
	}
	return ASRep, nil
}

// setPAData adds the PA-ENC-TIMESTAMP encrypted-timestamp pre-authentication
// padata (RFC 4120 §5.2.7.2) to the AS-REQ when pre-authentication is in play.
// PA-REQ-ENC-PA-REP (RFC 6806 §11) is set on every AS-REQ at construction time
// in NewASReq, not here, so retries and referrals don't duplicate it.
func setPAData(cl *Client, krberr *messages.KRBError, ASReq *messages.ASReq) error {
	if cl.settings.AssumePreAuthentication() {
		// Identify the etype to use to encrypt the PA Data
		var et etype.EType
		var err error
		var key types.EncryptionKey
		var kvno int
		if krberr == nil {
			// This is not in response to an error from the KDC. It is preemptive or renewal
			// There is no KRB Error that tells us the etype to use
			permitted := cl.Config.LibDefaults.PermittedEnctypeIDs
			etn := cl.settings.preAuthEType.Load() // Use the etype that may have previously been negotiated
			if etn != 0 && !etypePermitted(etn, permitted) {
				etn = 0
			}
			if etn == 0 {
				etn = int32(cl.Config.LibDefaults.PreferredPreauthTypes[0]) // Resort to config
			}
			if !etypePermitted(etn, permitted) {
				return krberror.NewErrorf(krberror.EncryptingError, "preferred pre-auth etype %d is not permitted by client policy", etn)
			}
			et, err = crypto.GetEtype(etn)
			if err != nil {
				return krberror.Errorf(err, krberror.EncryptingError, "error getting etype for pre-auth encryption")
			}
			key, kvno, err = cl.Key(et, 0, nil)
			if err != nil {
				return krberror.Errorf(err, krberror.EncryptingError, "error getting key from credentials")
			}
		} else {
			// Get the etype to use from the PA data in the KRBError e-data
			et, err = preAuthEType(krberr, cl.Config.LibDefaults.PermittedEnctypeIDs)
			if err != nil {
				return krberror.Errorf(err, krberror.EncryptingError, "error getting etype for pre-auth encryption")
			}
			cl.settings.preAuthEType.Store(et.GetETypeID()) // Set the etype that has been defined for potential future use
			key, kvno, err = cl.Key(et, 0, krberr)
			if err != nil {
				return krberror.Errorf(err, krberror.EncryptingError, "error getting key from credentials")
			}
		}
		// Generate the PA data
		paTSb, err := types.GetPAEncTSEncAsnMarshalled()
		if err != nil {
			return krberror.Errorf(err, krberror.KRBMsgError, "error creating PAEncTSEnc for Pre-Authentication")
		}
		paEncTS, err := crypto.GetEncryptedData(paTSb, key, keyusage.AS_REQ_PA_ENC_TIMESTAMP, kvno)
		if err != nil {
			return krberror.Errorf(err, krberror.EncryptingError, "error encrypting pre-authentication timestamp")
		}
		pb, err := paEncTS.Marshal()
		if err != nil {
			return krberror.Errorf(err, krberror.EncodingError, "error marshaling the PAEncTSEnc encrypted data")
		}
		pa := types.PAData{
			PADataType:  patype.PA_ENC_TIMESTAMP,
			PADataValue: pb,
		}
		// Look for and delete any exiting patype.PA_ENC_TIMESTAMP
		for i, pa := range ASReq.PAData {
			if pa.PADataType == patype.PA_ENC_TIMESTAMP {
				ASReq.PAData[i] = ASReq.PAData[len(ASReq.PAData)-1]
				ASReq.PAData = ASReq.PAData[:len(ASReq.PAData)-1]
			}
		}
		ASReq.PAData = append(ASReq.PAData, pa)
	}
	return nil
}

// preAuthEType picks an etype for pre-authentication from the KDC's
// KRBError hints, constrained to those in permitted.
func preAuthEType(krberr *messages.KRBError, permitted []int32) (etype.EType, error) {
	var pas types.PADataSequence
	if err := pas.Unmarshal(krberr.EData); err != nil {
		return nil, krberror.Errorf(err, krberror.EncodingError, "error unmarshaling KRBError data")
	}
	var info2 types.ETypeInfo2
	var info1 types.ETypeInfo
	for _, pa := range pas {
		switch pa.PADataType {
		case patype.PA_ETYPE_INFO2:
			entries, err := pa.GetETypeInfo2()
			if err != nil {
				return nil, krberror.Errorf(err, krberror.EncodingError, "error unmarshaling ETYPE-INFO2 data")
			}
			if info2 == nil {
				info2 = entries
			}
		case patype.PA_ETYPE_INFO:
			entries, err := pa.GetETypeInfo()
			if err != nil {
				return nil, krberror.Errorf(err, krberror.EncodingError, "error unmarshaling ETYPE-INFO data")
			}
			if info1 == nil {
				info1 = entries
			}
		}
	}
	// RFC 4120 §5.2.7.5: ETYPE-INFO2 is preferred over ETYPE-INFO.
	candidates := make([]int32, 0, len(info2)+len(info1))
	for _, e := range info2 {
		candidates = append(candidates, e.EType)
	}
	if len(info2) == 0 {
		for _, e := range info1 {
			candidates = append(candidates, e.EType)
		}
	}
	for _, id := range candidates {
		if !etypePermitted(id, permitted) {
			continue
		}
		et, err := crypto.GetEtype(id)
		if err != nil {
			continue
		}
		return et, nil
	}
	return nil, krberror.NewErrorf(krberror.EncryptingError, "KDC offered no etype permitted by client policy")
}

func etypePermitted(id int32, permitted []int32) bool {
	if len(permitted) == 0 {
		return true
	}
	return slices.Contains(permitted, id)
}
