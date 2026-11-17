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
