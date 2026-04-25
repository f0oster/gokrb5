//go:build ignore

/*
ldap_with_cbt.go demonstrates GSSAPI authentication over LDAP with
TLS channel bindings using the go-ldap/v3 library and the low-level
gokrb5 APIs. Defaults target the public FreeIPA demo.

Usage:

	go run ldap_with_cbt.go
	go run ldap_with_cbt.go -server dc.example.com -realm EXAMPLE.COM -user testuser -password secret
*/
package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/f0oster/gokrb5/client"
	"github.com/f0oster/gokrb5/config"
	"github.com/f0oster/gokrb5/gssapi"
	"github.com/f0oster/gokrb5/iana/flags"
	"github.com/f0oster/gokrb5/spnego"
	"github.com/f0oster/gokrb5/types"
)

func main() {
	server := flag.String("server", "ipa.demo1.freeipa.org", "LDAP server hostname")
	realm := flag.String("realm", "DEMO1.FREEIPA.ORG", "Kerberos realm")
	user := flag.String("user", "admin", "Username without realm")
	password := flag.String("password", "Secret123", "Password")
	insecure := flag.Bool("insecure", true, "Skip TLS certificate verification")
	timeout := flag.Duration("timeout", 30*time.Second, "TCP dial timeout")
	flag.Parse()

	// Authenticate and acquire a TGT.
	fmt.Println("\n" + header("Kerberos (RFC 4120)"))

	krb5Conf, err := config.NewFromString(fmt.Sprintf(`
[libdefaults]
  default_realm = %s
  udp_preference_limit = 1
[realms]
  %s = {
    kdc = %s
  }
`, *realm, *realm, *server))
	if err != nil {
		log.Fatalf("ERROR: %v", err)
	}

	krb5Client := client.NewWithPassword(*user, *realm, *password, krb5Conf)
	if err := krb5Client.Login(); err != nil {
		log.Fatalf("ERROR: AS-REQ failed: %v", err)
	}
	defer krb5Client.Destroy()
	fmt.Printf("[+] AS-REP: TGT for %s@%s\n", *user, *realm)

	// Connect and upgrade to TLS, then derive the channel binding.
	fmt.Println("\n" + header("TLS + channel bindings (RFC 5929)"))

	conn, err := ldap.DialURL("ldap://"+*server+":389", ldap.DialWithDialer(&net.Dialer{Timeout: *timeout}))
	if err != nil {
		log.Fatalf("ERROR: dial: %v", err)
	}
	defer conn.Close()
	fmt.Printf("[+] TCP %s:389\n", *server)

	tlsConfig := &tls.Config{ServerName: *server, InsecureSkipVerify: *insecure}
	if err := conn.StartTLS(tlsConfig); err != nil {
		log.Fatalf("ERROR: StartTLS: %v", err)
	}
	fmt.Println("[+] StartTLS complete")

	tlsState, ok := conn.TLSConnectionState()
	if !ok {
		log.Fatal("ERROR: TLSConnectionState unavailable; StartTLS may have failed")
	}
	channelBindings, err := gssapi.NewTLSChannelBindingsFromState(&tlsState)
	if err != nil {
		log.Fatalf("ERROR: build channel bindings: %v", err)
	}
	hashStart := len(gssapi.TLSServerEndPointPrefix)
	hashPreview := channelBindings.ApplicationData[hashStart:]
	if len(hashPreview) > 16 {
		hashPreview = hashPreview[:16]
	}
	fmt.Printf("[+] tls-server-end-point binding: %x...  (first %d bytes of leaf cert hash)\n",
		hashPreview, len(hashPreview))

	// SASL/GSSAPI bind with channel bindings.
	fmt.Println("\n" + header("SASL/GSSAPI bind (RFC 4752, RFC 4121)"))

	gssClient := &RawGSSAPIClient{
		krb5Client: krb5Client,
		bindings:   channelBindings,
	}

	spn := "ldap/" + *server
	if err := conn.GSSAPIBind(gssClient, spn, ""); err != nil {
		log.Fatalf("ERROR: bind: %v", err)
	}
	fmt.Println("[+] bind complete")

	fmt.Println("\n" + header("LDAP Query Results"))

	result, err := conn.Search(ldap.NewSearchRequest(
		"", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)", []string{"defaultNamingContext"}, nil,
	))
	if err != nil {
		log.Fatalf("ERROR: search: %v", err)
	}

	if len(result.Entries) > 0 {
		fmt.Printf("[+] defaultNamingContext = %s\n",
			result.Entries[0].GetAttributeValue("defaultNamingContext"))
	}
}

// header formats a top-level section banner.
func header(s string) string {
	return fmt.Sprintf("=== %s ===", s)
}

// RawGSSAPIClient implements go-ldap's GSSAPIClient interface on top of
// the raw gokrb5 APIs.
type RawGSSAPIClient struct {
	krb5Client *client.Client
	bindings   *gssapi.ChannelBindings

	sessionKey types.EncryptionKey
	sentAuth   types.Authenticator
	secCtx     *gssapi.SecurityContext
}

// InitSecContext is the older two-arg form of the GSSAPIClient interface.
func (c *RawGSSAPIClient) InitSecContext(target string, token []byte) ([]byte, bool, error) {
	return c.InitSecContextWithOptions(target, token, nil)
}

// InitSecContextWithOptions is called twice by go-ldap: first with
// token==nil to produce the AP-REQ, and again with the server's AP-REP
// bytes to verify mutual auth.
func (c *RawGSSAPIClient) InitSecContextWithOptions(target string, token []byte, _ []int) ([]byte, bool, error) {
	if token == nil {
		// Build the AP-REQ.
		tkt, key, err := c.krb5Client.GetServiceTicket(target)
		if err != nil {
			return nil, false, fmt.Errorf("GetServiceTicket: %w", err)
		}
		c.sessionKey = key

		// Build the AP-REQ with the TLS channel bindings embedded in
		// the authenticator checksum per RFC 4121 §4.1.1.
		krb5Token, err := spnego.NewKRB5TokenAPREQWithBindings(
			c.krb5Client,
			tkt,
			key,
			[]int{gssapi.ContextFlagInteg, gssapi.ContextFlagMutual},
			[]int{flags.APOptionMutualRequired},
			c.bindings,
			nil, // no credential delegation
		)
		if err != nil {
			return nil, false, fmt.Errorf("NewKRB5TokenAPREQWithBindings: %w", err)
		}
		c.sentAuth = krb5Token.Authenticator

		output, _ := krb5Token.Marshal()
		fmt.Printf("[>] AP-REQ (%d bytes), ticket %s (etype %d)\n", len(output), target, key.KeyType)
		return output, true, nil
	}

	// Verify the server's mutual auth proof and build SecurityContext.
	var krb5Token spnego.KRB5Token
	if err := krb5Token.Unmarshal(token); err != nil {
		return nil, false, fmt.Errorf("unmarshal AP-REP: %w", err)
	}
	if !krb5Token.IsAPRep() {
		return nil, false, nil
	}
	fmt.Printf("[<] AP-REP (%d bytes)\n", len(token))

	krb5Token.SetAPRepVerification(c.sentAuth, c.sessionKey)
	ok, status := krb5Token.Verify()
	if !ok {
		return nil, false, fmt.Errorf("AP-REP verify: %s", status.Message)
	}
	fmt.Println("    mutual auth verified (RFC 4120 §3.2.4)")

	var apRepSubkey types.EncryptionKey
	var apRepSeq uint64
	if krb5Token.EncAPRepPart != nil {
		if krb5Token.EncAPRepPart.Subkey.KeyValue != nil {
			apRepSubkey = krb5Token.EncAPRepPart.Subkey
			fmt.Printf("    AP-REP subkey: etype %d, %d bytes  [acceptor subkey in use]\n",
				apRepSubkey.KeyType, len(apRepSubkey.KeyValue))
		}
		apRepSeq = uint64(krb5Token.EncAPRepPart.SequenceNumber)
	}
	c.secCtx = gssapi.NewInitiatorContext(
		c.sessionKey,
		c.sentAuth.SubKey,
		apRepSubkey,
		uint64(c.sentAuth.SeqNumber),
		apRepSeq,
	)
	return nil, false, nil
}

// NegotiateSaslAuth handles the RFC 4752 §3.1 SASL layer negotiation.
func (c *RawGSSAPIClient) NegotiateSaslAuth(token []byte, authzid string) ([]byte, error) {
	if c.secCtx == nil {
		return nil, fmt.Errorf("SecurityContext not initialised; AP-REP was never verified")
	}

	fmt.Printf("[<] wrapped server offer (%d bytes)\n", len(token))
	offer, err := gssapi.ParseSASLServerToken(c.secCtx, token)
	if err != nil {
		return nil, fmt.Errorf("ParseSASLServerToken: %w", err)
	}
	fmt.Printf("    server offers: %s, max-buffer %d\n",
		gssapi.DescribeSASLLayers(offer.SupportedLayers), offer.MaxBufferSize)

	response, err := gssapi.BuildSASLClientToken(c.secCtx, gssapi.SASLClientResponse{
		ChosenLayer: gssapi.SASLSecurityNone,
		AuthzID:     authzid,
	})
	if err != nil {
		return nil, fmt.Errorf("BuildSASLClientToken: %w", err)
	}
	fmt.Println("    client selects: none")
	return response, nil
}

// DeleteSecContext is called by go-ldap on connection teardown.
func (c *RawGSSAPIClient) DeleteSecContext() error {
	c.sessionKey = types.EncryptionKey{}
	c.secCtx = nil
	return nil
}
