package gssapi

import (
	"fmt"
	"time"

	"github.com/f0oster/gokrb5/credentials"
	"github.com/f0oster/gokrb5/iana/errorcode"
	"github.com/f0oster/gokrb5/messages"
)

// verifyAPREQ runs the RFC 4120 §3.2.3 acceptor-side checks against an
// AP-REQ already parsed from a mech token, plus the MS-PAC ClientInfo
// cross-check (§2.7) when a PAC is present. It returns the verified
// client credentials on success.
//
// Verification order (security-relevant; fail before producing any
// response that could leak information):
//  1. Decrypt and validate the AP-REQ (ticket, authenticator)
//  2. RequireHostAddress check (if enabled)
//  3. Replay-cache check
//  4. PAC decode + ClientInfo cross-check (if PAC present)
//  5. Build *credentials.Credentials
//
// Channel-bindings checks are layered on top by Acceptor.Accept after
// verifyAPREQ returns.
func verifyAPREQ(apReq *messages.APReq, a *Acceptor, call *acceptCall) (*credentials.Credentials, error) {
	ok, err := apReq.Verify(a.keytab, a.maxClockSkew, call.remoteAddr, a.keytabPrincipal, a.permittedEnctypes)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("AP-REQ verification failed without a typed error")
	}

	if a.requireHostAddr && len(apReq.Ticket.DecryptedEncPart.CAddr) < 1 {
		return nil, messages.NewKRBError(apReq.Ticket.SName, apReq.Ticket.Realm,
			errorcode.KRB_AP_ERR_BADADDR, "ticket does not contain HostAddress values required")
	}

	if a.replayCache.IsReplay(apReq.Ticket.SName, apReq.Authenticator, apReq.EncryptedAuthenticator.Cipher) {
		return nil, messages.NewKRBError(apReq.Ticket.SName, apReq.Ticket.Realm,
			errorcode.KRB_AP_ERR_REPEAT, "replay detected")
	}

	// Build credentials from the ticket's identity. APReq.Verify has
	// confirmed Authenticator.CName/CRealm match the ticket, so either
	// is correct; the ticket-side fields are the authoritative source.
	creds := credentials.NewFromPrincipalName(apReq.Ticket.DecryptedEncPart.CName, apReq.Ticket.DecryptedEncPart.CRealm)
	creds.SetAuthTime(time.Now().UTC())
	creds.SetAuthenticated(true)
	creds.SetValidUntil(apReq.Ticket.DecryptedEncPart.EndTime)

	if a.decodePAC {
		isPAC, pac, err := apReq.Ticket.GetPACType(a.keytab, a.keytabPrincipal, a.logger)
		if isPAC && err != nil {
			return nil, err
		}
		if isPAC && pac.ClientInfo != nil {
			// MS-PAC §2.7: PAC_CLIENT_INFO.Name must match the
			// ticket's CName so a cross-realm KDC cannot graft a PAC
			// minted for one principal onto a ticket for another.
			expected := apReq.Ticket.DecryptedEncPart.CName.PrincipalNameString()
			if pac.ClientInfo.Name != expected {
				return nil, messages.NewKRBError(
					apReq.Ticket.SName, apReq.Ticket.Realm,
					errorcode.KRB_AP_ERR_BADMATCH,
					fmt.Sprintf("PAC ClientInfo name %q does not match ticket CName %q", pac.ClientInfo.Name, expected),
				)
			}
		}
		if isPAC && pac.KerbValidationInfo != nil {
			creds.SetADCredentials(credentials.ADCredentials{
				GroupMembershipSIDs: pac.KerbValidationInfo.GetGroupMembershipSIDs(),
				LogOnTime:           pac.KerbValidationInfo.LogOnTime.Time(),
				LogOffTime:          pac.KerbValidationInfo.LogOffTime.Time(),
				PasswordLastSet:     pac.KerbValidationInfo.PasswordLastSet.Time(),
				EffectiveName:       pac.KerbValidationInfo.EffectiveName.Value,
				FullName:            pac.KerbValidationInfo.FullName.Value,
				UserID:              int(pac.KerbValidationInfo.UserID),
				PrimaryGroupID:      int(pac.KerbValidationInfo.PrimaryGroupID),
				LogonServer:         pac.KerbValidationInfo.LogonServer.Value,
				LogonDomainName:     pac.KerbValidationInfo.LogonDomainName.Value,
				LogonDomainID:       pac.KerbValidationInfo.LogonDomainID.String(),
			})
		}
	}
	return creds, nil
}
