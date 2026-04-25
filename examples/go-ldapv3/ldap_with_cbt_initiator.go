//go:build ignore

/*
ldap_with_cbt_initiator.go demonstrates GSSAPI authentication over
LDAP with TLS channel bindings using the gssapi.Initiator API and
the go-ldap/v3 library. Defaults target the public FreeIPA demo.

See ldap_with_cbt.go for the equivalent low-level flow.

Usage:

	go run ldap_with_cbt_initiator.go
	go run ldap_with_cbt_initiator.go -server dc.example.com -realm EXAMPLE.COM \
	    -user testuser -password secret
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
)

func main() {
	server := flag.String("server", "ipa.demo1.freeipa.org", "LDAP server hostname")
	realm := flag.String("realm", "DEMO1.FREEIPA.ORG", "Kerberos realm")
	user := flag.String("user", "admin", "Username without realm")
	password := flag.String("password", "Secret123", "Password")
	insecure := flag.Bool("insecure", true, "Skip TLS certificate verification")
	timeout := flag.Duration("timeout", 30*time.Second, "TCP dial timeout")
	flag.Parse()

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
		log.Fatal("ERROR: TLSConnectionState unavailable")
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

	fmt.Println("\n" + header("SASL/GSSAPI bind (RFC 4752, RFC 4121)"))

	gssClient := &InitiatorGSSAPIClient{
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

func header(s string) string {
	return fmt.Sprintf("=== %s ===", s)
}

// InitiatorGSSAPIClient implements go-ldap's GSSAPIClient interface
// using gssapi.Initiator.
type InitiatorGSSAPIClient struct {
	krb5Client *client.Client
	bindings   *gssapi.ChannelBindings
	init       *gssapi.Initiator
	secCtx     *gssapi.SecurityContext
}

func (c *InitiatorGSSAPIClient) InitSecContext(target string, token []byte) ([]byte, bool, error) {
	return c.InitSecContextWithOptions(target, token, nil)
}

func (c *InitiatorGSSAPIClient) InitSecContextWithOptions(target string, token []byte, _ []int) ([]byte, bool, error) {
	if token == nil {
		init, err := gssapi.NewInitiator(c.krb5Client, target,
			gssapi.WithMutualAuth(),
			gssapi.WithChannelBindings(c.bindings),
		)
		if err != nil {
			return nil, false, fmt.Errorf("NewInitiator: %w", err)
		}
		c.init = init

		out, err := c.init.Step(nil)
		if err != nil {
			return nil, false, fmt.Errorf("Step(nil): %w", err)
		}
		fmt.Printf("[>] AP-REQ (%d bytes), ticket %s (etype %d)\n", len(out), target, c.init.SessionKeyEtype())
		return out, true, nil
	}

	if _, err := c.init.Step(token); err != nil {
		return nil, false, fmt.Errorf("Step(AP-REP): %w", err)
	}
	fmt.Printf("[<] AP-REP: mutual auth verified\n")

	ctx, err := c.init.SecurityContext()
	if err != nil {
		return nil, false, err
	}
	c.secCtx = ctx
	return nil, false, nil
}

func (c *InitiatorGSSAPIClient) NegotiateSaslAuth(token []byte, authzid string) ([]byte, error) {
	if c.secCtx == nil {
		return nil, fmt.Errorf("SecurityContext not established")
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

func (c *InitiatorGSSAPIClient) DeleteSecContext() error {
	c.secCtx = nil
	c.init = nil
	return nil
}
