package oidc

import "testing"

// §5.14.6: an identity's key is its issuer and subject, so a method whose
// issuer changes doesn't find another issuer's subjects.
func TestIdentityKey(t *testing.T) {
	m := &method{issuer: "https://a.example"}
	if got := string(m.identityKey("sub")); got != "https://a.example\x00sub" {
		t.Errorf("key %q", got)
	}
}

// Review 0027: http endpoints only beside an http://localhost issuer.
func TestEndpointOK(t *testing.T) {
	for _, c := range []struct {
		issuer, endpoint string
		ok               bool
	}{
		{"http://localhost:9000", "http://localhost:9000/token", true},
		{"https://localhost:9000", "http://localhost:9000/token", false},
		{"https://idp.example", "http://localhost/token", false},
		{"https://idp.example", "https://idp.example/token", true},
		{"https://idp.example", "https://idp.example/token#x", false},
		{"https://idp.example", "https://u@idp.example/token", false},
	} {
		m := &method{issuer: c.issuer}
		if got := m.endpointOK(c.endpoint); got != c.ok {
			t.Errorf("issuer %s, endpoint %s: %v", c.issuer, c.endpoint, got)
		}
	}
}
