package config

import (
	"github.com/f0oster/gokrb5/test"
	"testing"

	"github.com/f0oster/gokrb5/test/testdata"
	"github.com/stretchr/testify/assert"
)

func TestConfig_GetKDCsUsesConfiguredKDC(t *testing.T) {
	t.Parallel()

	// This test is meant to cover the fix for
	// https://github.com/jcmturner/gokrb5/issues/332
	krb5ConfWithKDCAndDNSLookupKDC := `
[libdefaults]
 dns_lookup_kdc = true

[realms]
 TEST.GOKRB5 = {
  kdc = kdc2b.test.gokrb5:88
 }
`

	c, err := NewFromString(krb5ConfWithKDCAndDNSLookupKDC)
	if err != nil {
		t.Fatalf("Error loading config: %v", err)
	}

	kdcs, err := c.GetKDCs("TEST.GOKRB5", false)
	if err != nil {
		t.Fatal(err)
	}
	if len(kdcs) != 1 {
		t.Fatalf("expected 1 but received %d", len(kdcs))
	}
	if kdcs[0] != "kdc2b.test.gokrb5:88" {
		t.Fatalf("expected kdc2b.test.gokrb5:88 but received %s", kdcs[0])
	}
}

func TestResolveKDC(t *testing.T) {
	test.Privileged(t)

	c, err := NewFromString(testdata.KRB5_CONF)
	if err != nil {
		t.Fatal(err)
	}

	// KDCs when they're not provided and we should be looking them up.
	c.LibDefaults.DNSLookupKDC = true
	c.Realms = make([]Realm, 0)
	res, err := c.GetKDCs(c.LibDefaults.DefaultRealm, true)
	if err != nil {
		t.Errorf("error resolving KDC via DNS TCP: %v", err)
	}
	assert.Equal(t, 5, len(res), "Number of SRV records not as expected: %v", res)
	expected := []string{
		"kdc.test.gokrb5:88",
		"kdc1a.test.gokrb5:88",
		"kdc2a.test.gokrb5:88",
		"kdc1b.test.gokrb5:88",
		"kdc2b.test.gokrb5:88",
	}
	for _, s := range expected {
		var found bool
		for _, v := range res {
			if s == v {
				found = true
				break
			}
		}
		assert.True(t, found, "Record %s not found in results", s)
	}
}

func TestResolveKDCNoDNS(t *testing.T) {
	c, err := NewFromString(testdata.KRB5_CONF)
	if err != nil {
		t.Fatal(err)
	}
	c.LibDefaults.DNSLookupKDC = false
	res, err := c.GetKDCs(c.LibDefaults.DefaultRealm, true)
	if err != nil {
		t.Errorf("error resolving KDCs from config: %v", err)
	}
	expected := []string{
		"127.0.0.1:88",
		"127.0.0.2:88",
	}
	for _, s := range expected {
		var found bool
		for _, v := range res {
			if s == v {
				found = true
				break
			}
		}
		assert.True(t, found, "Record %s not found in results", s)
	}
}
