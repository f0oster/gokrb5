package spnego

import (
	"testing"

	"github.com/jcmturner/goidentity/v6"
	"github.com/stretchr/testify/assert"
)

func TestKRB5BasicAuthenticator_ImplementsAuthenticator(t *testing.T) {
	t.Parallel()
	var s KRB5BasicAuthenticator
	a := new(goidentity.Authenticator)
	assert.Implements(t, a, s, "KRB5BasicAuthenticator does not implement goidentity.Authenticator")
}
