package spnego

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/goidentity/v6"
	"github.com/f0oster/gokrb5/client"
	"github.com/f0oster/gokrb5/credentials"
	"github.com/f0oster/gokrb5/gssapi"
	"github.com/f0oster/gokrb5/iana/nametype"
	"github.com/f0oster/gokrb5/krberror"
	"github.com/f0oster/gokrb5/types"
)

// Client side functionality //

// Client will negotiate authentication with a server using SPNEGO.
type Client struct {
	*http.Client
	krb5Client *client.Client
	spn        string
	reqs       []*http.Request
}

type redirectErr struct {
	reqTarget *http.Request
}

func (e redirectErr) Error() string {
	return fmt.Sprintf("redirect to %v", e.reqTarget.URL)
}

type teeReadCloser struct {
	io.Reader
	io.Closer
}

// NewClient returns a SPNEGO enabled HTTP client.
// Be careful when passing in the *http.Client if it is beginning reused in multiple calls to this function.
// Ensure reuse of the provided *http.Client is for the same user as a session cookie may have been added to
// http.Client's cookie jar.
// Incorrect reuse of the provided *http.Client could lead to access to the wrong user's session.
func NewClient(krb5Cl *client.Client, httpCl *http.Client, spn string) *Client {
	if httpCl == nil {
		httpCl = &http.Client{}
	}
	// Add a cookie jar if there isn't one
	if httpCl.Jar == nil {
		httpCl.Jar, _ = cookiejar.New(nil)
	}
	// Add a CheckRedirect function that will execute any functional already defined and then error with a redirectErr
	f := httpCl.CheckRedirect
	httpCl.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if f != nil {
			err := f(req, via)
			if err != nil {
				return err
			}
		}
		return redirectErr{reqTarget: req}
	}
	return &Client{
		Client:     httpCl,
		krb5Client: krb5Cl,
		spn:        spn,
	}
}

// Do is the SPNEGO enabled HTTP client's equivalent of the http.Client's Do method.
func (c *Client) Do(req *http.Request) (resp *http.Response, err error) {
	var body bytes.Buffer
	if req.Body != nil {
		// Use a tee reader to capture any body sent in case we have to replay it again
		teeR := io.TeeReader(req.Body, &body)
		teeRC := teeReadCloser{teeR, req.Body}
		req.Body = teeRC
	}
	resp, err = c.Client.Do(req)
	if err != nil {
		if ue, ok := err.(*url.Error); ok {
			if e, ok := ue.Err.(redirectErr); ok {
				// Picked up a redirect
				e.reqTarget.Header.Del(HTTPHeaderAuthRequest)
				c.reqs = append(c.reqs, e.reqTarget)
				if len(c.reqs) >= 10 {
					return resp, errors.New("stopped after 10 redirects")
				}
				if req.Body != nil {
					// Refresh the body reader so the body can be sent again
					e.reqTarget.Body = io.NopCloser(&body)
				}
				return c.Do(e.reqTarget)
			}
		}
		return resp, err
	}
	if respUnauthorizedNegotiate(resp) {
		err := SetSPNEGOHeader(c.krb5Client, req, c.spn)
		if err != nil {
			return resp, err
		}
		if req.Body != nil {
			// Refresh the body reader so the body can be sent again
			req.Body = io.NopCloser(&body)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return c.Do(req)
	}
	return resp, err
}

// Get is the SPNEGO enabled HTTP client's equivalent of the http.Client's Get method.
func (c *Client) Get(url string) (resp *http.Response, err error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	return c.Do(req)
}

// Post is the SPNEGO enabled HTTP client's equivalent of the http.Client's Post method.
func (c *Client) Post(url, contentType string, body io.Reader) (resp *http.Response, err error) {
	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", contentType)
	return c.Do(req)
}

// PostForm is the SPNEGO enabled HTTP client's equivalent of the http.Client's PostForm method.
func (c *Client) PostForm(url string, data url.Values) (resp *http.Response, err error) {
	return c.Post(url, "application/x-www-form-urlencoded", strings.NewReader(data.Encode()))
}

// Head is the SPNEGO enabled HTTP client's equivalent of the http.Client's Head method.
func (c *Client) Head(url string) (resp *http.Response, err error) {
	req, err := http.NewRequest("HEAD", url, nil)
	if err != nil {
		return nil, err
	}
	return c.Do(req)
}

func respUnauthorizedNegotiate(resp *http.Response) bool {
	if resp.StatusCode == http.StatusUnauthorized {
		if resp.Header.Get(HTTPHeaderAuthResponse) == HTTPHeaderAuthResponseValueKey {
			return true
		}
	}
	return false
}

func setRequestSPN(r *http.Request) (types.PrincipalName, error) {
	h := strings.TrimSuffix(r.URL.Host, ".")
	// This if statement checks if the host includes a port number
	if strings.LastIndex(r.URL.Host, ":") > strings.LastIndex(r.URL.Host, "]") {
		// There is a port number in the URL
		h, p, err := net.SplitHostPort(h)
		if err != nil {
			return types.PrincipalName{}, err
		}
		name, err := net.LookupCNAME(h)
		if name != "" && err == nil {
			// Underlyng canonical name should be used for SPN
			h = strings.ToLower(name)
		}
		h = strings.TrimSuffix(h, ".")
		r.Host = fmt.Sprintf("%s:%s", h, p)
		return types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "HTTP/"+h), nil
	}
	name, err := net.LookupCNAME(h)
	if name != "" && err == nil {
		// Underlyng canonical name should be used for SPN
		h = strings.ToLower(name)
	}
	h = strings.TrimSuffix(h, ".")
	r.Host = h
	return types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "HTTP/"+h), nil
}

// SetSPNEGOHeader gets the service ticket and sets it as the SPNEGO authorization header on HTTP request object.
// To auto generate the SPN from the request object pass a null string "".
func SetSPNEGOHeader(cl *client.Client, r *http.Request, spn string) error {
	if spn == "" {
		pn, err := setRequestSPN(r)
		if err != nil {
			return err
		}
		spn = pn.PrincipalNameString()
	}
	cl.Log("using SPN %s", spn)
	if err := cl.AffirmLogin(); err != nil {
		return fmt.Errorf("could not acquire client credential: %v", err)
	}
	init, err := gssapi.NewInitiator(cl, spn)
	if err != nil {
		return fmt.Errorf("could not initialize context: %v", err)
	}
	mechBytes, err := init.Step(nil)
	if err != nil {
		return fmt.Errorf("could not produce mech token: %v", err)
	}
	spt := SPNEGOToken{
		Init: true,
		NegTokenInit: NegTokenInit{
			MechTypes: []asn1.ObjectIdentifier{
				gssapi.OIDKRB5.OID(),
				gssapi.OIDMSLegacyKRB5.OID(),
			},
			MechTokenBytes: mechBytes,
		},
	}
	nb, err := spt.Marshal()
	if err != nil {
		return krberror.Errorf(err, krberror.EncodingError, "could not marshal SPNEGO")
	}
	hs := "Negotiate " + base64.StdEncoding.EncodeToString(nb)
	r.Header.Set(HTTPHeaderAuthRequest, hs)
	return nil
}

// Service side functionality //

const (
	// spnegoNegTokenRespReject is the WWW-Authenticate value sent on a
	// failed handshake.
	spnegoNegTokenRespReject = "Negotiate oQcwBaADCgEC"
	// spnegoNegTokenRespIncompleteKRB5 is the WWW-Authenticate value sent
	// when the acceptor wants the client to retry with a KRB5 mech token.
	spnegoNegTokenRespIncompleteKRB5 = "Negotiate oRQwEqADCgEBoQsGCSqGSIb3EgECAg=="
	// sessionCredentials is the session-store key for marshaled credentials.
	sessionCredentials = "github.com/f0oster/gokrb5/sessionCredentials"
	// HTTPHeaderAuthRequest is the header that will hold authn/z information.
	HTTPHeaderAuthRequest = "Authorization"
	// HTTPHeaderAuthResponse is the header that will hold SPNEGO data from the server.
	HTTPHeaderAuthResponse = "WWW-Authenticate"
	// HTTPHeaderAuthResponseValueKey is the key in the auth header for SPNEGO.
	HTTPHeaderAuthResponseValueKey = "Negotiate"
	// UnauthorizedMsg is the message returned in the body when authentication fails.
	UnauthorizedMsg = "Unauthorised.\n"
)

// HTTPOption configures the SPNEGO HTTP middleware.
type HTTPOption func(*httpConfig)

type httpConfig struct {
	sessionMgr SessionMgr
	logger     *log.Logger
}

// WithSessionManager attaches a session manager. The middleware stores
// the verified credentials in the session and bypasses the handshake
// on subsequent requests that present an established session.
func WithSessionManager(sm SessionMgr) HTTPOption {
	return func(c *httpConfig) { c.sessionMgr = sm }
}

// WithHTTPLogger sets the logger for middleware-level events.
func WithHTTPLogger(l *log.Logger) HTTPOption {
	return func(c *httpConfig) { c.logger = l }
}

// SPNEGOKRB5Authenticate wraps inner with an SPNEGO/Kerberos
// authentication handler.
func SPNEGOKRB5Authenticate(inner http.Handler, acc *Acceptor, opts ...HTTPOption) http.Handler {
	cfg := &httpConfig{}
	for _, o := range opts {
		o(cfg)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if cfg.sessionMgr != nil {
			if id, err := getSessionCredentials(cfg.sessionMgr, r); err == nil && id.Authenticated() {
				logHTTP(cfg.logger, "%s - SPNEGO request served under session %s", r.RemoteAddr, id.SessionID())
				inner.ServeHTTP(w, goidentity.AddToHTTPRequestContext(&id, r))
				return
			}
		}

		spnegoBytes, err := readNegotiateHeader(r, w, cfg.logger)
		if err != nil {
			return
		}

		var callOpts []gssapi.AcceptOption
		if h, hErr := types.GetHostAddress(r.RemoteAddr); hErr == nil {
			callOpts = append(callOpts, gssapi.WithRemoteAddress(h))
		} else {
			logHTTP(cfg.logger, "%s - SPNEGO could not parse client address: %v", r.RemoteAddr, hErr)
		}

		acceptance, err := acc.Accept(spnegoBytes, callOpts...)
		if err != nil {
			spnegoResponseReject(cfg.logger, w, "%s - SPNEGO validation error: %v", r.RemoteAddr, err)
			return
		}

		id := acceptance.Credentials
		if cfg.sessionMgr != nil {
			if err := newSession(cfg.sessionMgr, cfg.logger, w, r, id); err != nil {
				return
			}
		}

		header := "Negotiate " + base64.StdEncoding.EncodeToString(acceptance.ResponseToken)
		w.Header().Set(HTTPHeaderAuthResponse, header)
		logHTTP(cfg.logger, "%s %s@%s - SPNEGO authentication succeeded", r.RemoteAddr, id.UserName(), id.Domain())
		inner.ServeHTTP(w, goidentity.AddToHTTPRequestContext(id, r))
	})
}

// readNegotiateHeader extracts the SPNEGO bytes from the
// "Authorization: Negotiate <base64>" header. Issue #347: some clients
// send a bare KRB5 mech token instead of a SPNEGO-wrapped one; wrap it
// into a NegTokenInit before returning.
func readNegotiateHeader(r *http.Request, w http.ResponseWriter, logger *log.Logger) ([]byte, error) {
	s := strings.SplitN(r.Header.Get(HTTPHeaderAuthRequest), " ", 2)
	if len(s) != 2 || s[0] != HTTPHeaderAuthResponseValueKey {
		w.Header().Set(HTTPHeaderAuthResponse, HTTPHeaderAuthResponseValueKey)
		http.Error(w, UnauthorizedMsg, http.StatusUnauthorized)
		return nil, errors.New("client did not provide a negotiation authorization header")
	}
	b, err := base64.StdEncoding.DecodeString(s[1])
	if err != nil {
		err = fmt.Errorf("error in base64 decoding negotiation header: %v", err)
		spnegoNegotiateKRB5MechType(logger, w, "%s - SPNEGO %v", r.RemoteAddr, err)
		return nil, err
	}
	var probe SPNEGOToken
	if probe.Unmarshal(b) == nil {
		return b, nil
	}
	// Bare KRB5 token. Wrap it.
	oid, _, _, err := gssapi.UnmarshalMechToken(b)
	if err != nil {
		err = fmt.Errorf("error in unmarshaling SPNEGO token: %v", err)
		spnegoNegotiateKRB5MechType(logger, w, "%s - SPNEGO %v", r.RemoteAddr, err)
		return nil, err
	}
	wrapped := SPNEGOToken{
		Init: true,
		NegTokenInit: NegTokenInit{
			MechTypes:      []asn1.ObjectIdentifier{oid},
			MechTokenBytes: b,
		},
	}
	out, err := wrapped.Marshal()
	if err != nil {
		err = fmt.Errorf("error rewrapping bare KRB5 token as SPNEGO: %v", err)
		spnegoNegotiateKRB5MechType(logger, w, "%s - SPNEGO %v", r.RemoteAddr, err)
		return nil, err
	}
	return out, nil
}

func getSessionCredentials(sm SessionMgr, r *http.Request) (credentials.Credentials, error) {
	var creds credentials.Credentials
	cb, err := sm.Get(r, sessionCredentials)
	if err != nil || cb == nil || len(cb) < 1 {
		return creds, fmt.Errorf("%s - SPNEGO error getting session and credentials for request: %v", r.RemoteAddr, err)
	}
	if err := creds.Unmarshal(cb); err != nil {
		return creds, fmt.Errorf("%s - SPNEGO credentials malformed in session: %v", r.RemoteAddr, err)
	}
	return creds, nil
}

func newSession(sm SessionMgr, logger *log.Logger, w http.ResponseWriter, r *http.Request, id *credentials.Credentials) error {
	idb, err := id.Marshal()
	if err != nil {
		spnegoInternalServerError(logger, w, "SPNEGO could not marshal credentials to add to the session: %v", err)
		return err
	}
	if err := sm.New(w, r, sessionCredentials, idb); err != nil {
		spnegoInternalServerError(logger, w, "SPNEGO could not create new session: %v", err)
		return err
	}
	logHTTP(logger, "%s %s@%s - SPNEGO new session (%s) created", r.RemoteAddr, id.UserName(), id.Domain(), id.SessionID())
	return nil
}

func logHTTP(l *log.Logger, format string, v ...any) {
	if l != nil {
		l.Printf(format, v...)
	}
}

func spnegoNegotiateKRB5MechType(l *log.Logger, w http.ResponseWriter, format string, v ...any) {
	logHTTP(l, format, v...)
	w.Header().Set(HTTPHeaderAuthResponse, spnegoNegTokenRespIncompleteKRB5)
	http.Error(w, UnauthorizedMsg, http.StatusUnauthorized)
}

func spnegoResponseReject(l *log.Logger, w http.ResponseWriter, format string, v ...any) {
	logHTTP(l, format, v...)
	w.Header().Set(HTTPHeaderAuthResponse, spnegoNegTokenRespReject)
	http.Error(w, UnauthorizedMsg, http.StatusUnauthorized)
}

func spnegoInternalServerError(l *log.Logger, w http.ResponseWriter, format string, v ...any) {
	logHTTP(l, format, v...)
	http.Error(w, "Internal Server Error", http.StatusInternalServerError)
}
