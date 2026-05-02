package credentials

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
	"unsafe"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/f0oster/gokrb5/types"
)

const (
	headerFieldTagKDCOffset = 1
)

// CCache is the file credentials cache as define here: https://web.mit.edu/kerberos/krb5-latest/doc/formats/ccache_file_format.html
type CCache struct {
	Version          uint8
	Header           header
	DefaultPrincipal principal
	Credentials      []*Credential
	Path             string
}

type header struct {
	length uint16
	fields []headerField
}

type headerField struct {
	tag    uint16
	length uint16
	value  []byte
}

// Credential cache entry principal struct.
type principal struct {
	Realm         string
	PrincipalName types.PrincipalName
}

// Credential holds a Kerberos client's ccache credential information.
type Credential struct {
	Client       principal
	Server       principal
	Key          types.EncryptionKey
	AuthTime     time.Time
	StartTime    time.Time
	EndTime      time.Time
	RenewTill    time.Time
	IsSKey       bool
	TicketFlags  asn1.BitString
	Addresses    []types.HostAddress
	AuthData     []types.AuthorizationDataEntry
	Ticket       []byte
	SecondTicket []byte
}

// LoadCCache loads a credential cache file into a CCache type.
func LoadCCache(cpath string) (*CCache, error) {
	c := new(CCache)
	b, err := os.ReadFile(cpath)
	if err != nil {
		return c, err
	}
	err = c.Unmarshal(b)
	return c, err
}

// Unmarshal a byte slice of credential cache data into CCache type.
func (c *CCache) Unmarshal(b []byte) error {
	if len(b) < 2 {
		return errors.New("ccache too short")
	}
	p := 0
	//The first byte of the file always has the value 5
	if int8(b[p]) != 5 {
		return errors.New("Invalid credential cache data. First byte does not equal 5")
	}
	p++
	//Get credential cache version
	//The second byte contains the version number (1 to 4)
	c.Version = b[p]
	if c.Version < 1 || c.Version > 4 {
		return errors.New("Invalid credential cache data. Keytab version is not within 1 to 4")
	}
	p++
	//Version 1 or 2 of the file format uses native byte order for integer representations. Versions 3 & 4 always uses big-endian byte order
	var endian binary.ByteOrder
	endian = binary.BigEndian
	if (c.Version == 1 || c.Version == 2) && isNativeEndianLittle() {
		endian = binary.LittleEndian
	}
	if c.Version == 4 {
		err := parseHeader(b, &p, c, &endian)
		if err != nil {
			return err
		}
	}
	pr, err := parsePrincipal(b, &p, c, &endian)
	if err != nil {
		return err
	}
	c.DefaultPrincipal = pr
	for p < len(b) {
		cred, err := parseCredential(b, &p, c, &endian)
		if err != nil {
			return err
		}
		c.Credentials = append(c.Credentials, cred)
	}
	return nil
}

func parseHeader(b []byte, p *int, c *CCache, e *binary.ByteOrder) error {
	if c.Version != 4 {
		return errors.New("Credentials cache version is not 4 so there is no header to parse.")
	}
	h := header{}
	hl, err := readInt16(b, p, e)
	if err != nil {
		return err
	}
	h.length = uint16(hl)
	for *p <= int(h.length) {
		f := headerField{}
		ft, err := readInt16(b, p, e)
		if err != nil {
			return err
		}
		f.tag = uint16(ft)
		fl, err := readInt16(b, p, e)
		if err != nil {
			return err
		}
		f.length = uint16(fl)
		fv, err := readBytes(b, p, int(f.length), e)
		if err != nil {
			return err
		}
		f.value = fv
		if !f.valid() {
			return errors.New("Invalid credential cache header found")
		}
		h.fields = append(h.fields, f)
	}
	c.Header = h
	return nil
}

// Parse the Keytab bytes of a principal into a Keytab entry's principal.
func parsePrincipal(b []byte, p *int, c *CCache, e *binary.ByteOrder) (principal, error) {
	var princ principal
	if c.Version != 1 {
		//Name Type is omitted in version 1
		nt, err := readInt32(b, p, e)
		if err != nil {
			return princ, err
		}
		princ.PrincipalName.NameType = nt
	}
	ncRaw, err := readInt32(b, p, e)
	if err != nil {
		return princ, err
	}
	nc := int(ncRaw)
	if c.Version == 1 {
		//In version 1 the number of components includes the realm. Minus 1 to make consistent with version 2
		nc--
	}
	if nc < 0 || nc > len(b)-*p {
		return princ, fmt.Errorf("ccache: invalid principal component count %d", nc)
	}
	lenRealm, err := readInt32(b, p, e)
	if err != nil {
		return princ, err
	}
	rb, err := readBytes(b, p, int(lenRealm), e)
	if err != nil {
		return princ, err
	}
	princ.Realm = string(rb)
	for i := 0; i < nc; i++ {
		l, err := readInt32(b, p, e)
		if err != nil {
			return princ, err
		}
		cb, err := readBytes(b, p, int(l), e)
		if err != nil {
			return princ, err
		}
		princ.PrincipalName.NameString = append(princ.PrincipalName.NameString, string(cb))
	}
	return princ, nil
}

func parseCredential(b []byte, p *int, c *CCache, e *binary.ByteOrder) (*Credential, error) {
	cred := new(Credential)
	cl, err := parsePrincipal(b, p, c, e)
	if err != nil {
		return nil, err
	}
	cred.Client = cl
	srv, err := parsePrincipal(b, p, c, e)
	if err != nil {
		return nil, err
	}
	cred.Server = srv
	key := types.EncryptionKey{}
	kt, err := readInt16(b, p, e)
	if err != nil {
		return nil, err
	}
	key.KeyType = int32(kt)
	if c.Version == 3 {
		//repeated twice in version 3
		kt, err = readInt16(b, p, e)
		if err != nil {
			return nil, err
		}
		key.KeyType = int32(kt)
	}
	kv, err := readData(b, p, e)
	if err != nil {
		return nil, err
	}
	key.KeyValue = kv
	cred.Key = key
	if cred.AuthTime, err = readTimestamp(b, p, e); err != nil {
		return nil, err
	}
	if cred.StartTime, err = readTimestamp(b, p, e); err != nil {
		return nil, err
	}
	if cred.EndTime, err = readTimestamp(b, p, e); err != nil {
		return nil, err
	}
	if cred.RenewTill, err = readTimestamp(b, p, e); err != nil {
		return nil, err
	}
	ik, err := readInt8(b, p, e)
	if err != nil {
		return nil, err
	}
	cred.IsSKey = ik != 0
	cred.TicketFlags = types.NewKrbFlags()
	tf, err := readBytes(b, p, 4, e)
	if err != nil {
		return nil, err
	}
	cred.TicketFlags.Bytes = tf
	la, err := readInt32(b, p, e)
	if err != nil {
		return nil, err
	}
	l := int(la)
	if l < 0 || l > len(b)-*p {
		return nil, fmt.Errorf("ccache: invalid address count %d", l)
	}
	cred.Addresses = make([]types.HostAddress, l)
	for i := range cred.Addresses {
		if cred.Addresses[i], err = readAddress(b, p, e); err != nil {
			return nil, err
		}
	}
	ld, err := readInt32(b, p, e)
	if err != nil {
		return nil, err
	}
	l = int(ld)
	if l < 0 || l > len(b)-*p {
		return nil, fmt.Errorf("ccache: invalid authdata count %d", l)
	}
	cred.AuthData = make([]types.AuthorizationDataEntry, l)
	for i := range cred.AuthData {
		if cred.AuthData[i], err = readAuthDataEntry(b, p, e); err != nil {
			return nil, err
		}
	}
	if cred.Ticket, err = readData(b, p, e); err != nil {
		return nil, err
	}
	if cred.SecondTicket, err = readData(b, p, e); err != nil {
		return nil, err
	}
	return cred, nil
}

// GetClientPrincipalName returns a PrincipalName type for the client the credentials cache is for.
func (c *CCache) GetClientPrincipalName() types.PrincipalName {
	return c.DefaultPrincipal.PrincipalName
}

// GetClientRealm returns the reals of the client the credentials cache is for.
func (c *CCache) GetClientRealm() string {
	return c.DefaultPrincipal.Realm
}

// GetClientCredentials returns a Credentials object representing the client of the credentials cache.
func (c *CCache) GetClientCredentials() *Credentials {
	return &Credentials{
		username: c.DefaultPrincipal.PrincipalName.PrincipalNameString(),
		realm:    c.GetClientRealm(),
		cname:    c.DefaultPrincipal.PrincipalName,
	}
}

// Contains tests if the cache contains a credential for the provided server PrincipalName
func (c *CCache) Contains(p types.PrincipalName) bool {
	for _, cred := range c.Credentials {
		if cred.Server.PrincipalName.Equal(p) {
			return true
		}
	}
	return false
}

// GetEntry returns a specific credential for the PrincipalName provided.
func (c *CCache) GetEntry(p types.PrincipalName) (*Credential, bool) {
	cred := new(Credential)
	var found bool
	for i := range c.Credentials {
		if c.Credentials[i].Server.PrincipalName.Equal(p) {
			cred = c.Credentials[i]
			found = true
			break
		}
	}
	if !found {
		return cred, false
	}
	return cred, true
}

// GetEntries filters out configuration entries an returns a slice of credentials.
func (c *CCache) GetEntries() []*Credential {
	creds := make([]*Credential, 0)
	for _, cred := range c.Credentials {
		// Filter out configuration entries
		if strings.HasPrefix(cred.Server.Realm, "X-CACHECONF") {
			continue
		}
		creds = append(creds, cred)
	}
	return creds
}

func (h *headerField) valid() bool {
	// See https://web.mit.edu/kerberos/krb5-latest/doc/formats/ccache_file_format.html - Header format
	switch h.tag {
	case headerFieldTagKDCOffset:
		if h.length != 8 || len(h.value) != 8 {
			return false
		}
		return true
	}
	return false
}

func readData(b []byte, p *int, e *binary.ByteOrder) ([]byte, error) {
	l, err := readInt32(b, p, e)
	if err != nil {
		return nil, err
	}
	return readBytes(b, p, int(l), e)
}

func readAddress(b []byte, p *int, e *binary.ByteOrder) (types.HostAddress, error) {
	var a types.HostAddress
	at, err := readInt16(b, p, e)
	if err != nil {
		return a, err
	}
	a.AddrType = int32(at)
	a.Address, err = readData(b, p, e)
	return a, err
}

func readAuthDataEntry(b []byte, p *int, e *binary.ByteOrder) (types.AuthorizationDataEntry, error) {
	var a types.AuthorizationDataEntry
	at, err := readInt16(b, p, e)
	if err != nil {
		return a, err
	}
	a.ADType = int32(at)
	a.ADData, err = readData(b, p, e)
	return a, err
}

// Read bytes representing a timestamp.
func readTimestamp(b []byte, p *int, e *binary.ByteOrder) (time.Time, error) {
	v, err := readInt32(b, p, e)
	if err != nil {
		return time.Time{}, err
	}
	return time.Unix(int64(v), 0), nil
}

// Read bytes representing an eight bit integer.
func readInt8(b []byte, p *int, e *binary.ByteOrder) (int8, error) {
	if *p+1 > len(b) {
		return 0, fmt.Errorf("ccache: short read at offset %d (need 1 byte)", *p)
	}
	var i int8
	binary.Read(bytes.NewBuffer(b[*p:*p+1]), *e, &i)
	*p++
	return i, nil
}

// Read bytes representing a sixteen bit integer.
func readInt16(b []byte, p *int, e *binary.ByteOrder) (int16, error) {
	if *p+2 > len(b) {
		return 0, fmt.Errorf("ccache: short read at offset %d (need 2 bytes)", *p)
	}
	var i int16
	binary.Read(bytes.NewBuffer(b[*p:*p+2]), *e, &i)
	*p += 2
	return i, nil
}

// Read bytes representing a thirty two bit integer.
func readInt32(b []byte, p *int, e *binary.ByteOrder) (int32, error) {
	if *p+4 > len(b) {
		return 0, fmt.Errorf("ccache: short read at offset %d (need 4 bytes)", *p)
	}
	var i int32
	binary.Read(bytes.NewBuffer(b[*p:*p+4]), *e, &i)
	*p += 4
	return i, nil
}

func readBytes(b []byte, p *int, s int, e *binary.ByteOrder) ([]byte, error) {
	if s < 0 {
		return nil, fmt.Errorf("ccache: negative read length %d", s)
	}
	if *p+s > len(b) {
		return nil, fmt.Errorf("ccache: short read at offset %d (need %d bytes, have %d)", *p, s, len(b)-*p)
	}
	r := make([]byte, s)
	copy(r, b[*p:*p+s])
	*p += s
	return r, nil
}

func isNativeEndianLittle() bool {
	var x = 0x012345678
	var p = unsafe.Pointer(&x)
	var bp = (*[4]byte)(p)

	var endian bool
	if 0x01 == bp[0] {
		endian = false
	} else if (0x78 & 0xff) == (bp[0] & 0xff) {
		endian = true
	} else {
		// Default to big endian
		endian = false
	}
	return endian
}
