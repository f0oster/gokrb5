package framework

import (
	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/f0oster/gokrb5/gssapi"
	"github.com/f0oster/gokrb5/spnego"
)

// WrapSPNEGOInit wraps an inner GSS-API mech token in a marshaled
// SPNEGO NegTokenInit identifying KRB5 as the mechanism.
func WrapSPNEGOInit(mechBytes []byte) ([]byte, error) {
	spt := &spnego.SPNEGOToken{
		Init: true,
		NegTokenInit: spnego.NegTokenInit{
			MechTypes:      []asn1.ObjectIdentifier{gssapi.OIDKRB5.OID()},
			MechTokenBytes: mechBytes,
		},
	}
	return spt.Marshal()
}

// UnwrapSPNEGOResp returns the inner mech token bytes carried in a
// marshaled SPNEGO NegTokenResp.
func UnwrapSPNEGOResp(respBytes []byte) ([]byte, error) {
	var resp spnego.NegTokenResp
	if err := resp.Unmarshal(respBytes); err != nil {
		return nil, err
	}
	return resp.ResponseToken, nil
}
