//go:build initiator

/*
sasl_initiator.go demonstrates SASL/GSSAPI authentication and
per-message protection over a raw TCP LDAP connection using the
gssapi.Initiator API.

Run: go run -tags initiator . [flags]
*/
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/gssapi"
)

func main() {
	server := flag.String("server", "ipa.demo1.freeipa.org", "LDAP server FQDN")
	realm := flag.String("realm", "DEMO1.FREEIPA.ORG", "Kerberos realm")
	user := flag.String("user", "admin", "Username without realm")
	password := flag.String("password", "Secret123", "Password")
	layer := flag.String("layer", "integrity", "SASL security layer: integrity or confidentiality")
	timeout := flag.Duration("timeout", 30*time.Second, "TCP dial timeout")
	flag.Parse()

	var chosenLayer byte
	var chosenLayerName string
	switch strings.ToLower(*layer) {
	case "none", "n":
		chosenLayer = gssapi.SASLSecurityNone
		chosenLayerName = "none"
	case "integrity", "integ", "i":
		chosenLayer = gssapi.SASLSecurityIntegrity
		chosenLayerName = "integrity"
	case "confidentiality", "conf", "c":
		chosenLayer = gssapi.SASLSecurityConfidential
		chosenLayerName = "confidentiality"
	default:
		log.Fatalf("ERROR: -layer must be none, integrity, or confidentiality, got %q", *layer)
	}

	// Authenticate and acquire a TGT.
	fmt.Println("\n" + Header("Kerberos (RFC 4120)"))

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

	// Establish a GSS context and run the SASL bind.
	fmt.Println("\n" + Header("SASL/GSSAPI bind (RFC 4752, RFC 4121)"))

	spn := "ldap/" + *server
	initOpts := []gssapi.InitiatorOption{gssapi.WithMutualAuth()}
	if chosenLayer == gssapi.SASLSecurityConfidential {
		initOpts = append(initOpts, gssapi.WithConfidentiality())
	}
	init, err := gssapi.NewInitiator(krb5Client, spn, initOpts...)
	if err != nil {
		log.Fatalf("ERROR: NewInitiator: %v", err)
	}
	fmt.Printf("[+] TGS-REP: ticket for %s (etype %d)\n", spn, init.SessionKeyEtype())

	conn, err := net.DialTimeout("tcp", *server+":389", *timeout)
	if err != nil {
		log.Fatalf("ERROR: dial: %v", err)
	}
	defer conn.Close()
	fmt.Printf("[+] TCP %s:389\n", *server)

	ldap := &LDAPConn{Conn: conn, MsgID: 1}

	apReqToken, err := init.Step(nil)
	if err != nil {
		log.Fatalf("ERROR: Step(nil): %v", err)
	}

	var ctx *gssapi.SecurityContext
	token := apReqToken
	firstStep := true

	for {
		label := "GSS token"
		switch {
		case firstStep:
			label = "GSSAPI initial context token"
		case token == nil:
			label = "empty GSS token (security-layer negotiation)"
		case ctx != nil:
			label = "wrapped client response"
		}
		fmt.Printf("[>] BindRequest: %s (%d bytes)\n", label, len(token))
		firstStep = false

		resultCode, serverCreds, err := ldap.SASLBind("GSSAPI", token)
		if err != nil {
			log.Fatalf("ERROR: SASL bind transport: %v", err)
		}

		if resultCode == LDAPResultSuccess {
			fmt.Println("[<] success: bind complete")
			break
		}
		if resultCode != LDAPResultSaslBindProgress {
			log.Fatalf("ERROR: BindResponse resultCode=%d (expected saslBindInProgress=14)", resultCode)
		}

		if len(serverCreds) == 0 {
			fmt.Println("[<] saslBindInProgress: no server token")
			token = nil
			continue
		}

		// Pass the server's reply to the Initiator to verify mutual auth.
		if !init.Done() {
			fmt.Printf("[<] saslBindInProgress: AP-REP (%d bytes)\n", len(serverCreds))
			if _, err := init.Step(serverCreds); err != nil {
				log.Fatalf("ERROR: Step(AP-REP): %v", err)
			}
			fmt.Println("    mutual auth verified (RFC 4120 §3.2.4)")
			ctx, err = init.SecurityContext()
			if err != nil {
				log.Fatalf("ERROR: SecurityContext: %v", err)
			}
			token = nil
			continue
		}

		// Parse the server's SASL offer and select a security layer.
		if ctx == nil {
			log.Fatalf("ERROR: server sent a SASL offer before the AP-REP")
		}
		fmt.Printf("[<] saslBindInProgress: wrapped server offer (%d bytes)\n", len(serverCreds))
		offer, err := gssapi.ParseSASLServerToken(ctx, serverCreds)
		if err != nil {
			log.Fatalf("ERROR: parse SASL server offer: %v", err)
		}
		fmt.Printf("    server offers: %s, max-buffer %d\n",
			gssapi.DescribeSASLLayers(offer.SupportedLayers), offer.MaxBufferSize)

		if !offer.SupportsLayer(chosenLayer) {
			log.Fatalf("ERROR: server does not advertise SASL %s (offer=0x%02x)",
				chosenLayerName, offer.SupportedLayers)
		}
		var maxBuf uint32
		if chosenLayer != gssapi.SASLSecurityNone {
			maxBuf = 65536
		}
		token, err = gssapi.BuildSASLClientToken(ctx, gssapi.SASLClientResponse{
			ChosenLayer:   chosenLayer,
			MaxBufferSize: maxBuf,
		})
		if err != nil {
			log.Fatalf("ERROR: build SASL client response: %v", err)
		}
		fmt.Printf("    client selects: %s, max-buffer %d\n", chosenLayerName, maxBuf)
	}

	if chosenLayer == gssapi.SASLSecurityNone {
		fmt.Println("\n" + Header("LDAP query (no security layer)"))
		searchReq := BuildRootDSESearchRequest(ldap.MsgID, []string{"defaultNamingContext"})
		fmt.Println("[>] SearchRequest rootDSE defaultNamingContext")
		if err := ldap.SendLDAP(searchReq); err != nil {
			log.Fatalf("ERROR: send: %v", err)
		}
		resp, err := ldap.RecvLDAP()
		if err != nil {
			log.Fatalf("ERROR: recv: %v", err)
		}
		fmt.Printf("[<] %d bytes\n", len(resp))
		fmt.Printf("[+] defaultNamingContext = %s\n", ParseSearchResult(resp))
		return
	}

	// Wrapped rootDSE search to verify per-message protection.
	fmt.Println("\n" + Header("Per-message protection (RFC 4121 §4.2)"))

	if ctx == nil {
		log.Fatal("ERROR: SASL bind finished without establishing a SecurityContext")
	}

	searchReq := BuildRootDSESearchRequest(ldap.MsgID, []string{"defaultNamingContext"})
	fmt.Println("[>] SearchRequest rootDSE defaultNamingContext")

	preWrapSend := ctx.SendSeq()
	wrappedReq, err := ctx.Wrap(searchReq)
	if err != nil {
		log.Fatalf("ERROR: ctx.Wrap: %v", err)
	}
	fmt.Printf("    plaintext %d B -> wrapped %d B   sendSeq %d -> %d\n",
		len(searchReq), len(wrappedReq), preWrapSend, ctx.SendSeq())
	fmt.Printf("    %s\n", DescribeWrapHeader(wrappedReq))

	if err := ldap.SendRaw(wrappedReq); err != nil {
		log.Fatalf("ERROR: send: %v", err)
	}

	wrappedResp, err := ldap.RecvRaw()
	if err != nil {
		log.Fatalf("ERROR: recv: %v", err)
	}

	unwrapped, err := ctx.Unwrap(wrappedResp)
	if err != nil {
		log.Fatalf("ERROR: ctx.Unwrap: %v", err)
	}
	recvSeq := ReadWrapSndSeq(wrappedResp)
	status := ctx.LastRecvStatus()
	fmt.Printf("[<] wrapped %d B -> plaintext %d B   recvSeq=%d  status=%v\n",
		len(wrappedResp), len(unwrapped), recvSeq, status)

	result := ParseSearchResult(unwrapped)
	fmt.Printf("[+] defaultNamingContext = %s\n", result)
}
