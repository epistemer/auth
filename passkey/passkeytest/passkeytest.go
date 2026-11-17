// Package passkeytest is a software passkey authenticator for an app's
// tests: it answers auth/passkey's options as a browser and a platform
// authenticator would, with real ES256 signatures (interface §4.11).
//
//	pk := passkeytest.New(t, "https://toyshop.example")
//	ch, _ := a.Challenge(ctx, flow.Token, auth.MethodPasskey) // in an Enroll
//	flow, _ = a.Prove(ctx, flow.Token, passkey.Response(pk.Create(ch.Options.(json.RawMessage))))
//	// later, signing in:
//	flow, _ = a.Prove(ctx, flow.Token, passkey.Response(pk.Get(ch.Options.(json.RawMessage))))
package passkeytest

import (
	"encoding/json"
	"testing"

	"github.com/epistemer/auth/passkey/internal/softauth"
)

// Authenticator is a software authenticator for tests, answering as
// origin. It holds at most one ES256 passkey and keeps its counter; a
// second Create fails the test.
type Authenticator struct {
	tb      testing.TB
	a       *softauth.Authenticator
	created bool
}

// New returns an authenticator with no passkey yet.
func New(tb testing.TB, origin string) *Authenticator {
	tb.Helper()
	return &Authenticator{tb: tb, a: softauth.New(origin)}
}

// Create answers a registration's options with a new passkey. It returns
// what passkey.Response takes.
func (a *Authenticator) Create(options json.RawMessage) []byte {
	a.tb.Helper()
	if a.created {
		a.tb.Fatal("passkeytest: this authenticator already holds a passkey; make another")
	}
	b, err := a.a.Create(options)
	if err != nil {
		a.tb.Fatalf("passkeytest: Create: %v", err)
	}
	a.created = true
	return b
}

// Get answers an assertion's options with the passkey. It returns what
// passkey.Response takes.
func (a *Authenticator) Get(options json.RawMessage) []byte {
	a.tb.Helper()
	if !a.created {
		a.tb.Fatal("passkeytest: Get before Create")
	}
	b, err := a.a.Get(options)
	if err != nil {
		a.tb.Fatalf("passkeytest: Get: %v", err)
	}
	return b
}
