package spnego

import (
	"encoding/base64"
	"fmt"
	"log"
	"strings"
	"time"

	goidentity "github.com/jcmturner/goidentity/v6"
	"github.com/f0oster/gokrb5/client"
	"github.com/f0oster/gokrb5/config"
	"github.com/f0oster/gokrb5/credentials"
	"github.com/f0oster/gokrb5/keytab"
	"github.com/f0oster/gokrb5/types"
)

// BasicAuthOption configures a KRB5BasicAuthenticator.
type BasicAuthOption func(*KRB5BasicAuthenticator)

// WithBasicAuthKeytabPrincipal overrides the principal name used to
// look up the service key in the keytab.
func WithBasicAuthKeytabPrincipal(name string) BasicAuthOption {
	return func(a *KRB5BasicAuthenticator) {
		pn, _ := types.ParseSPNString(name)
		a.keytabPrincipal = &pn
	}
}

// WithBasicAuthLogger sets the logger used during PAC processing.
func WithBasicAuthLogger(l *log.Logger) BasicAuthOption {
	return func(a *KRB5BasicAuthenticator) { a.logger = l }
}

// KRB5BasicAuthenticator authenticates an HTTP Basic header by running
// an AS-REQ + TGS-REQ for the supplied credentials and decrypting the
// resulting service ticket locally against kt.
type KRB5BasicAuthenticator struct {
	BasicHeaderValue string
	krb5Conf         *config.Config
	clientSettings   *client.Settings
	keytab           *keytab.Keytab
	keytabPrincipal  *types.PrincipalName
	spn              string
	logger           *log.Logger
	realm            string
	username         string
	password         string
}

// NewKRB5BasicAuthenticator constructs a KRB5BasicAuthenticator.
func NewKRB5BasicAuthenticator(headerVal string, krb5Conf *config.Config, clientSettings *client.Settings, kt *keytab.Keytab, spn string, opts ...BasicAuthOption) KRB5BasicAuthenticator {
	a := KRB5BasicAuthenticator{
		BasicHeaderValue: headerVal,
		krb5Conf:         krb5Conf,
		clientSettings:   clientSettings,
		keytab:           kt,
		spn:              spn,
	}
	for _, o := range opts {
		o(&a)
	}
	return a
}

// Authenticate parses the Basic header and exercises the full Kerberos
// flow against the configured KDC. The returned identity carries any
// PAC-derived ADCredentials.
func (a KRB5BasicAuthenticator) Authenticate() (i goidentity.Identity, ok bool, err error) {
	a.realm, a.username, a.password, err = parseBasicHeaderValue(a.BasicHeaderValue)
	if err != nil {
		err = fmt.Errorf("could not parse basic authentication header: %v", err)
		return
	}
	cl := client.NewWithPassword(a.username, a.realm, a.password, a.krb5Conf)
	err = cl.Login()
	if err != nil {
		err = fmt.Errorf("error with user credentials during login: %v", err)
		return
	}
	tkt, _, err := cl.GetServiceTicket(a.spn)
	if err != nil {
		err = fmt.Errorf("could not get service ticket: %v", err)
		return
	}
	err = tkt.DecryptEncPart(a.keytab, a.keytabPrincipal)
	if err != nil {
		err = fmt.Errorf("could not decrypt service ticket: %v", err)
		return
	}
	cl.Credentials.SetAuthTime(time.Now().UTC())
	cl.Credentials.SetAuthenticated(true)
	isPAC, pac, err := tkt.GetPACType(a.keytab, a.keytabPrincipal, a.logger)
	if isPAC && err != nil {
		err = fmt.Errorf("error processing PAC: %v", err)
		return
	}
	if isPAC && pac.ClientInfo != nil {
		// MS-PAC §2.7: PAC_CLIENT_INFO.Name must match the ticket's
		// CName so a cross-realm KDC cannot graft a PAC minted for one
		// principal onto a ticket for another.
		expected := tkt.DecryptedEncPart.CName.PrincipalNameString()
		if pac.ClientInfo.Name != expected {
			err = fmt.Errorf("PAC ClientInfo name %q does not match ticket CName %q", pac.ClientInfo.Name, expected)
			return
		}
	}
	if isPAC && pac.KerbValidationInfo != nil {
		cl.Credentials.SetADCredentials(credentials.ADCredentials{
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
	ok = true
	i = cl.Credentials
	return
}

// Mechanism returns the authentication mechanism.
func (a KRB5BasicAuthenticator) Mechanism() string {
	return "Kerberos Basic"
}

func parseBasicHeaderValue(s string) (domain, username, password string, err error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return
	}
	v := string(b)
	vc := strings.SplitN(v, ":", 2)
	password = vc[1]
	// Accept <Username>, <Domain>\<Username>, and <Username>@<Domain>.
	if strings.Contains(vc[0], `\`) {
		u := strings.SplitN(vc[0], `\`, 2)
		domain = u[0]
		username = u[1]
	} else if strings.Contains(vc[0], `@`) {
		u := strings.SplitN(vc[0], `@`, 2)
		domain = u[1]
		username = u[0]
	} else {
		username = vc[0]
	}
	return
}
