package oidc_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/epistemer/auth"
	"github.com/epistemer/auth/authtest"
	"github.com/epistemer/cfgx"
	jose "github.com/go-jose/go-jose/v4"

	"github.com/epistemer/auth/oidc"
)

// The module through the engine (interface §5.14, §6.7, §7), against the
// tests' own provider.

type config struct {
	provider, issuer, id, secret, redirect string
	scopes                                 []string
	two                                    bool
}

func (c config) AuthOIDCProvider() string { return c.provider }
func (c config) AuthOIDCIssuer() string   { return c.issuer }
func (c config) AuthOIDCClientID() string { return c.id }
func (c config) AuthOIDCClientSecret() cfgx.Secret {
	if c.secret == "" {
		return cfgx.Secret{}
	}
	return cfgx.NewSecret(c.secret)
}
func (c config) AuthOIDCRedirectURL() string { return c.redirect }
func (c config) AuthOIDCScopes() []string    { return c.scopes }
func (c config) AuthOIDCTwoFactors() bool    { return c.two }

const callbackURL = "https://toyshop.example/sign-in/test/callback"

type world struct {
	t   *testing.T
	k   *authtest.Kit
	p   *idp
	ctx context.Context
}

func newWorld(t *testing.T, edit func(*config), opts ...auth.Option) *world {
	t.Helper()
	w := &world{t: t, ctx: context.Background()}
	// The kit's clock is made by authtest.New; the provider reads it
	// through w.k once it exists.
	w.p = newIdP(t, func() time.Time { return w.k.Clock.Now() })
	c := config{provider: "test", issuer: w.p.issuer, id: clientID, secret: clientSecret, redirect: callbackURL}
	if edit != nil {
		edit(&c)
	}
	m, err := oidc.New(c)
	if err != nil {
		t.Fatal(err)
	}
	w.k = authtest.New(t, append([]auth.Option{auth.WithMethods(m), auth.WithFirst(auth.MethodPassword, "oidc_test")}, opts...)...)
	w.k.AddUser("sara", auth.User{ID: "u1", Name: "sara"}, "sara@toyshop.example")
	w.k.AddUser("new9", auth.User{ID: "u9", Name: "nine"})
	return w
}

// start begins a SignInWithout and returns its flow and the URL.
func (w *world) start() (auth.Flow, string) {
	w.t.Helper()
	f, err := w.k.Auth.SignInWithout(w.ctx, auth.Cookie())
	if err != nil {
		w.t.Fatal(err)
	}
	ch, err := w.k.Auth.Challenge(w.ctx, f.Token, "oidc_test")
	if err != nil {
		w.t.Fatal(err)
	}
	u, ok := ch.Options.(string)
	if !ok || ch.Method != "oidc_test" {
		w.t.Fatalf("Challenge: %+v", ch)
	}
	return f, u
}

// signIn runs the provider round trip for sub, and proves the callback.
func (w *world) signIn(sub string) (auth.Flow, error) {
	w.t.Helper()
	f, u := w.start()
	return w.k.Auth.Prove(w.ctx, f.Token, oidc.Callback("test", w.p.authorize(w.t, u, sub)))
}

func (w *world) lastReason(kind string) string {
	var r string
	for _, e := range w.k.Events() {
		if e.Kind == kind {
			r = e.Reason
		}
	}
	return r
}

// §5.14.1, §5.14.7, §6.7: the URL carries what the flow needs; an unknown
// identity comes back unlinked; Link signs in the new user; the identity
// then signs in that user. It is never found by email.
func TestSignInAndLink(t *testing.T) {
	w := newWorld(t, nil, auth.WithPolicy(func(context.Context, auth.User) auth.Policy { return auth.Policy{AllowUnverified: true} }))
	w.p.claims = func(c map[string]any) { c["email"], c["email_verified"] = "sara@toyshop.example", true }
	f, u := w.start()
	q, _ := url.Parse(u)
	v := q.Query()
	if v.Get("response_type") != "code" || v.Get("client_id") != clientID || v.Get("redirect_uri") != callbackURL ||
		v.Get("scope") != "openid email profile" || len(v.Get("state")) != 43 || len(v.Get("nonce")) != 43 ||
		len(v.Get("code_challenge")) != 43 || v.Get("code_challenge_method") != "S256" || v.Has("max_age") {
		t.Errorf("authorization URL: %s", u)
	}
	f, err := w.k.Auth.Prove(w.ctx, f.Token, oidc.Callback("test", w.p.authorize(t, u, "sub-9")))
	if err != nil || f.Unlinked == nil || f.Unlinked.Subject != "sub-9" || f.Unlinked.Issuer != w.p.issuer || !f.Unlinked.EmailVerified {
		t.Fatalf("unlinked: %+v %v", f, err)
	}
	// Sara's address equals the provider's email: she isn't signed in.
	f, err = w.k.Auth.Link(w.ctx, f.Token, "u9")
	if err != nil {
		t.Fatal(err)
	}
	res, err := w.k.Auth.Finish(w.ctx, f.Token)
	if err != nil || res.Session.User != "u9" || res.Session.Verified {
		t.Fatalf("Finish: %+v %v", res.Session, err)
	}
	ids, _ := w.k.Auth.Identities(w.ctx, "u9")
	if len(ids) != 1 || ids[0].Method != "oidc_test" || ids[0].Label != "sara@toyshop.example" {
		t.Errorf("identities: %+v", ids)
	}
	if f, err = w.signIn("sub-9"); err != nil || f.Unlinked != nil || !f.Ready {
		t.Errorf("again: %+v %v", f, err)
	}
}

// §5.14.2–5.14.6: each refusal, with its reason, in order.
func TestRefusals(t *testing.T) {
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	type tc struct {
		setup  func(w *world)
		query  func(w *world, q url.Values) url.Values
		reason string
	}
	keep := func(_ *world, q url.Values) url.Values { return q }
	for name, c := range map[string]tc{
		"over 8 KiB":       {nil, func(_ *world, q url.Values) url.Values { q.Set("pad", strings.Repeat("a", 8<<10)); return q }, "malformed"},
		"a state twice":    {nil, func(_ *world, q url.Values) url.Values { q.Add("state", "x"); return q }, "malformed"},
		"code and error":   {nil, func(_ *world, q url.Values) url.Values { q.Set("error", "access_denied"); return q }, "malformed"},
		"neither":          {nil, func(_ *world, q url.Values) url.Values { q.Del("code"); return q }, "malformed"},
		"an empty code":    {nil, func(_ *world, q url.Values) url.Values { q.Set("code", ""); return q }, "malformed"},
		"another state":    {nil, func(_ *world, q url.Values) url.Values { q.Set("state", "x"); return q }, "state"},
		"another iss":      {nil, func(_ *world, q url.Values) url.Values { q.Set("iss", "https://evil.example"); return q }, "issuer"},
		"no iss, promised": {func(w *world) { w.p.issParam = true }, func(_ *world, q url.Values) url.Values { q.Del("iss"); return q }, "issuer"},
		"a provider error": {nil, func(_ *world, q url.Values) url.Values {
			q.Del("code")
			q.Set("error", "secret-provider-text")
			return q
		}, "provider_error"},
		"a refused grant":  {nil, func(_ *world, q url.Values) url.Values { q.Set("code", "nope"); return q }, "exchange"},
		"another nonce":    {func(w *world) { w.p.claims = func(c map[string]any) { c["nonce"] = "x" } }, keep, "nonce"},
		"another azp":      {func(w *world) { w.p.claims = func(c map[string]any) { c["azp"] = "other" } }, keep, "audience"},
		"two audiences":    {func(w *world) { w.p.claims = func(c map[string]any) { c["aud"] = []string{clientID, "other"} } }, keep, "audience"},
		"another audience": {func(w *world) { w.p.claims = func(c map[string]any) { c["aud"] = "other" } }, keep, "token"},
		"another issuer":   {func(w *world) { w.p.claims = func(c map[string]any) { c["iss"] = "https://evil.example" } }, keep, "token"},
		"expired token": {func(w *world) {
			w.p.claims = func(c map[string]any) { c["exp"] = w.k.Clock.Now().Add(-time.Minute).Unix() }
		}, keep, "token"},
		"a future iat": {func(w *world) {
			w.p.claims = func(c map[string]any) { c["iat"] = w.k.Clock.Now().Add(2 * time.Minute).Unix() }
		}, keep, "token"},
		"no iat":          {func(w *world) { w.p.claims = func(c map[string]any) { delete(c, "iat") } }, keep, "token"},
		"a bad signature": {func(w *world) { w.p.signWith = other }, keep, "token"},
		"a long subject":  {func(w *world) { w.p.claims = func(c map[string]any) { c["sub"] = strings.Repeat("s", 256) } }, keep, "malformed"},
		"a control char":  {func(w *world) { w.p.claims = func(c map[string]any) { c["sub"] = "a\x00b" } }, keep, "malformed"},
	} {
		w := newWorld(t, nil)
		if c.setup != nil {
			c.setup(w)
		}
		f, u := w.start()
		q := c.query(w, w.p.authorize(t, u, "sub-1"))
		_, err := w.k.Auth.Prove(w.ctx, f.Token, oidc.Callback("test", q))
		if !errors.Is(err, auth.ErrBadCredentials) || w.lastReason("proof.refused") != c.reason {
			t.Errorf("%s: %v, reason %q", name, err, w.lastReason("proof.refused"))
		}
		if out := fmt.Sprintf("%v %+v", err, w.k.Events()); strings.Contains(out, "secret-provider-text") || strings.Contains(out, q.Get("code")) && q.Get("code") != "" {
			t.Errorf("%s: a secret is out: %s", name, out)
		}
	}
}

// §5.14.1, §5.14.3: options expire after ten minutes; a callback is
// accepted once; after a second Challenge the first's state is refused.
func TestOnceAndExpiry(t *testing.T) {
	w := newWorld(t, nil)
	f, u := w.start()
	q := w.p.authorize(t, u, "sub-1")
	w.k.Clock.Advance(10 * time.Minute)
	if _, err := w.k.Auth.Prove(w.ctx, f.Token, oidc.Callback("test", q)); !errors.Is(err, auth.ErrBadCredentials) || w.lastReason("proof.refused") != "expired" {
		t.Errorf("expired: %v", err)
	}
	f, u = w.start()
	q = w.p.authorize(t, u, "sub-1")
	if g, err := w.k.Auth.Prove(w.ctx, f.Token, oidc.Callback("test", q)); err != nil || g.Unlinked == nil {
		t.Fatalf("first: %+v %v", g, err)
	}
	if _, err := w.k.Auth.Prove(w.ctx, f.Token, oidc.Callback("test", q)); err == nil {
		t.Error("the same callback twice")
	}
	f, first := w.start()
	w.k.Auth.Challenge(w.ctx, f.Token, "oidc_test")
	if _, err := w.k.Auth.Prove(w.ctx, f.Token, oidc.Callback("test", w.p.authorize(t, first, "sub-1"))); !errors.Is(err, auth.ErrBadCredentials) || w.lastReason("proof.refused") != "state" {
		t.Errorf("after a second Challenge: %v", err)
	}
	// Another provider's callback isn't this method's.
	f, u = w.start()
	if _, err := w.k.Auth.Prove(w.ctx, f.Token, oidc.Callback("other", w.p.authorize(t, u, "sub-1"))); !errors.Is(err, auth.ErrMethodUnavailable) {
		t.Errorf("another provider's callback: %v", err)
	}
}

// §5.14.2: discovery naming another issuer, or an endpoint off https, is
// the method's own failure; a failure isn't cached; a redirect isn't
// followed; a provider that is down, or refuses the client, is the
// method's own failure and takes back the count.
func TestDiscoveryAndOutages(t *testing.T) {
	w := newWorld(t, nil)
	w.p.docIssuer = "https://evil.example"
	f, _ := w.k.Auth.SignInWithout(w.ctx, auth.Cookie())
	if _, err := w.k.Auth.Challenge(w.ctx, f.Token, "oidc_test"); err == nil || errors.Is(err, auth.ErrMethodUnavailable) {
		t.Errorf("another issuer: %v", err)
	}
	w.p.docIssuer, w.p.tokenURL = "", "http://example.com/token"
	if _, err := w.k.Auth.Challenge(w.ctx, f.Token, "oidc_test"); err == nil {
		t.Error("an http endpoint off localhost: accepted")
	}
	w.p.tokenURL = strings.Replace(w.p.issuer, "http://", "http://user:pw@", 1) + "/token"
	if _, err := w.k.Auth.Challenge(w.ctx, f.Token, "oidc_test"); err == nil {
		t.Error("an endpoint with a user: accepted")
	}
	w.p.tokenURL = ""
	if _, err := w.k.Auth.Challenge(w.ctx, f.Token, "oidc_test"); err != nil {
		t.Errorf("a good document after bad ones: %v", err)
	}

	// Discovered once, and cached.
	n := w.p.discoveries
	for range 3 {
		g, _ := w.k.Auth.SignInWithout(w.ctx, auth.Cookie())
		w.k.Auth.Challenge(w.ctx, g.Token, "oidc_test")
	}
	if w.p.discoveries != n {
		t.Errorf("discovered %d times more", w.p.discoveries-n)
	}

	// A failed discovery isn't cached, even with a document attached.
	w = newWorld(t, nil)
	w.p.failDisc = 1
	f, _ = w.k.Auth.SignInWithout(w.ctx, auth.Cookie())
	if _, err := w.k.Auth.Challenge(w.ctx, f.Token, "oidc_test"); err == nil {
		t.Error("a 500 with a document: accepted")
	}
	if _, err := w.k.Auth.Challenge(w.ctx, f.Token, "oidc_test"); err != nil {
		t.Errorf("after a failure: %v", err)
	}

	w = newWorld(t, nil)
	w.p.redirect = true
	f, _ = w.k.Auth.SignInWithout(w.ctx, auth.Cookie())
	if _, err := w.k.Auth.Challenge(w.ctx, f.Token, "oidc_test"); err == nil {
		t.Error("a redirect was followed")
	}

	for name, status := range map[string]struct {
		code int
		err  string
	}{"down": {503, "temporarily_unavailable"}, "too many": {429, ""}, "a refused client": {401, "invalid_client"}, "invalid_client as 400": {400, "invalid_client"}} {
		w = newWorld(t, nil)
		ctx := auth.WithClient(w.ctx, auth.Client{Addr: netip.MustParseAddr("192.0.2.1")})
		f, err := w.k.Auth.SignInWithout(ctx, auth.Cookie())
		if err != nil {
			t.Fatal(err)
		}
		ch, _ := w.k.Auth.Challenge(ctx, f.Token, "oidc_test")
		q := w.p.authorize(t, ch.Options.(string), "sub-1")
		w.p.tokenStatus, w.p.tokenError = status.code, status.err
		if _, err := w.k.Auth.Prove(ctx, f.Token, oidc.Callback("test", q)); err == nil || errors.Is(err, auth.ErrBadCredentials) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// §5.14.9: with two_factors the request asks for a recent sign-in, a
// recent one is verified, a stale one refused; without, the identity is
// one factor and no second.
func TestTwoFactors(t *testing.T) {
	w := newWorld(t, func(c *config) { c.two = true })
	_, u := w.start()
	if !strings.Contains(u, "max_age=300") {
		t.Errorf("no max_age: %s", u)
	}
	f, err := w.signIn("sub-1")
	if err != nil || f.Unlinked == nil {
		t.Fatal(err)
	}
	if f, err = w.k.Auth.Link(w.ctx, f.Token, "u9"); err != nil || !f.Verified {
		t.Errorf("two factors: %+v %v", f, err)
	}
	w.p.claims = func(c map[string]any) { c["auth_time"] = w.k.Clock.Now().Add(-6 * time.Minute).Unix() }
	if _, err := w.signIn("sub-1"); !errors.Is(err, auth.ErrBadCredentials) || w.lastReason("proof.refused") != "token" {
		t.Errorf("a stale sign-in: %v", err)
	}
	w.p.claims = func(c map[string]any) { delete(c, "auth_time") }
	if _, err := w.signIn("sub-1"); !errors.Is(err, auth.ErrBadCredentials) {
		t.Errorf("no auth_time: %v", err)
	}

	// Without: a staff policy can't finish on the identity alone.
	w = newWorld(t, nil, auth.WithPolicy(func(context.Context, auth.User) auth.Policy { return auth.Policy{} }))
	f, _ = w.signIn("sub-1")
	f, err = w.k.Auth.Link(w.ctx, f.Token, "u9")
	if f.Verified || f.Ready || !errors.Is(err, auth.ErrCannotVerify) {
		t.Errorf("one factor: %+v %v", f, err)
	}
}

// §5.14.10: failed callbacks count toward the address alone.
func TestAddressOnly(t *testing.T) {
	w := newWorld(t, nil)
	var err error
	bad := auth.WithClient(w.ctx, auth.Client{Addr: netip.MustParseAddr("198.51.100.1")})
	for i := 0; i < 40 && !errors.Is(err, auth.ErrTooManyAttempts); i++ {
		f, _ := w.k.Auth.SignInWithout(bad, auth.Cookie())
		ch, _ := w.k.Auth.Challenge(bad, f.Token, "oidc_test")
		q := w.p.authorize(t, ch.Options.(string), "sub-1")
		q.Set("state", "x")
		_, err = w.k.Auth.Prove(bad, f.Token, oidc.Callback("test", q))
	}
	if !errors.Is(err, auth.ErrTooManyAttempts) {
		t.Fatalf("the address never waited: %v", err)
	}
	good := auth.WithClient(w.ctx, auth.Client{Addr: netip.MustParseAddr("192.0.2.2")})
	f, _ := w.k.Auth.SignInWithout(good, auth.Cookie())
	ch, _ := w.k.Auth.Challenge(good, f.Token, "oidc_test")
	if _, err := w.k.Auth.Prove(good, f.Token, oidc.Callback("test", w.p.authorize(t, ch.Options.(string), "sub-1"))); err != nil {
		t.Errorf("another address: %v", err)
	}
}

// §4.12: New refuses each bad config.
func TestNew(t *testing.T) {
	good := config{provider: "google", issuer: "https://accounts.google.com", id: "x", redirect: "https://shop.example/cb"}
	if _, err := oidc.New(good); err != nil {
		t.Fatal(err)
	}
	if _, err := oidc.New(nil); err == nil {
		t.Error("nil: accepted")
	}
	var typed *config
	if _, err := oidc.New(typed); err == nil {
		t.Error("a typed nil: accepted")
	}
	for name, edit := range map[string]func(c *config){
		"no provider":      func(c *config) { c.provider = "" },
		"a capital":        func(c *config) { c.provider = "Google" },
		"28 characters":    func(c *config) { c.provider = strings.Repeat("a", 28) },
		"an http issuer":   func(c *config) { c.issuer = "http://accounts.google.com" },
		"an issuer query":  func(c *config) { c.issuer = "https://a.example?x=1" },
		"an issuer user":   func(c *config) { c.issuer = "https://u@a.example" },
		"a fragment":       func(c *config) { c.issuer = "https://a.example#x" },
		"a long issuer":    func(c *config) { c.issuer = "https://a.example/" + strings.Repeat("a", 760) },
		"a relative":       func(c *config) { c.issuer = "/issuer" },
		"no host name":     func(c *config) { c.issuer = "https://:443" },
		"a spaced host":    func(c *config) { c.redirect = "https://shop example/cb" },
		"a redirect frag":  func(c *config) { c.redirect = "https://shop.example/cb#x" },
		"a control scope":  func(c *config) { c.scopes = []string{"a\x01"} },
		"an http redirect": func(c *config) { c.redirect = "http://shop.example/cb" },
		"a redirect user":  func(c *config) { c.redirect = "https://u@shop.example/cb" },
		"no client":        func(c *config) { c.id = "" },
		"a spaced scope":   func(c *config) { c.scopes = []string{"email profile"} },
		"an empty scope":   func(c *config) { c.scopes = []string{""} },
	} {
		c := good
		edit(&c)
		if _, err := oidc.New(c); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	for name, edit := range map[string]func(c *config){
		"27 characters":  func(c *config) { c.provider = strings.Repeat("a", 27) },
		"localhost http": func(c *config) { c.issuer, c.redirect = "http://localhost:9000", "http://localhost:8080/cb" },
		"a query":        func(c *config) { c.redirect = "https://shop.example/cb?x=1" },
		"scopes":         func(c *config) { c.scopes = []string{"openid", "groups"} },
	} {
		c := good
		edit(&c)
		if _, err := oidc.New(c); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	m, _ := oidc.New(good)
	if m.Name() != "oidc_google" {
		t.Errorf("name %q", m.Name())
	}
	if ao, ok := m.(auth.AddressOnly); !ok || !ao.AddressOnly() {
		t.Error("not AddressOnly")
	}
	if s := fmt.Sprint(oidc.Callback("google", url.Values{"code": {"secret-code"}})); strings.Contains(s, "secret") {
		t.Errorf("the proof prints %q", s)
	}
}

// A public client sends no secret, in the body (§5.14.4); scopes are
// passed on.
func TestPublicClientAndScopes(t *testing.T) {
	w := newWorld(t, func(c *config) { c.secret, c.scopes = "", []string{"groups"} })
	_, u := w.start()
	if !strings.Contains(u, "scope=openid+groups") {
		t.Errorf("scopes: %s", u)
	}
	if _, err := w.signIn("sub-1"); err == nil || errors.Is(err, auth.ErrBadCredentials) {
		// The test provider wants the secret: a public client is refused as
		// a client, the method's own failure.
		t.Errorf("a public client: %v", err)
	}
	if !slices.Contains([]string{"openid"}, "openid") {
		t.Fail()
	}
}

// §5.14.5: ES256 tokens are accepted, signed by a P-256 key.
func TestES256(t *testing.T) {
	w := newWorld(t, nil)
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	w.p.ec = ec
	if f, err := w.signIn("sub-1"); err != nil || f.Unlinked == nil {
		t.Errorf("ES256: %+v %v", f, err)
	}
}

// Review 0026: the key set. A key-set outage is the method's own failure;
// a rotated key is fetched once a token no held key verifies, also under
// the same kid; a failed fetch keeps the held keys; unusable keys and
// algorithms are refused.
func TestKeySet(t *testing.T) {
	defer oidc.SetRefetchEvery(0)()
	w := newWorld(t, nil)
	if _, err := w.signIn("sub-1"); err != nil {
		t.Fatal(err)
	}
	// A failed fetch keeps the keys held: a token under an unknown kid
	// brings a fetch that fails, and the held key still verifies after.
	w.p.jwksStatus = 503
	stranger, _ := rsa.GenerateKey(rand.Reader, 2048)
	w.p.rawToken = func(payload []byte) string {
		signer, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: stranger, KeyID: "zz"}}, nil)
		jws, _ := signer.Sign(payload)
		raw, _ := jws.CompactSerialize()
		return raw
	}
	if _, err := w.signIn("sub-1"); err == nil || errors.Is(err, auth.ErrBadCredentials) {
		t.Errorf("an unknown kid with the key set down: %v", err)
	}
	w.p.rawToken = nil
	if _, err := w.signIn("sub-1"); err != nil {
		t.Errorf("with the key set down and the key held: %v", err)
	}
	// Rotated, under the same kid, while the key set is down: an outage.
	w.p.mu.Lock()
	w.p.key, _ = rsa.GenerateKey(rand.Reader, 2048)
	w.p.mu.Unlock()
	if _, err := w.signIn("sub-1"); err == nil || errors.Is(err, auth.ErrBadCredentials) {
		t.Errorf("a key-set outage: %v", err)
	}
	// Back up: the rotated key is fetched.
	w.p.jwksStatus = 0
	if _, err := w.signIn("sub-1"); err != nil {
		t.Errorf("after the rotation: %v", err)
	}

	for name, setup := range map[string]func(w *world){
		"RSA of 1024": func(w *world) { w.p.key, _ = rsa.GenerateKey(rand.Reader, 1024) },
		"a P-384 key": func(w *world) { w.p.ec, _ = ecdsa.GenerateKey(elliptic.P384(), rand.Reader) },
		"use enc":     func(w *world) { w.p.keyUse = "enc" },
		"alg none": func(w *world) {
			w.p.rawToken = func(payload []byte) string {
				return b64(`{"alg":"none","typ":"JWT"}`) + "." + b64(string(payload)) + "."
			}
		},
		"HS256 with the public key": func(w *world) {
			w.p.rawToken = func(payload []byte) string {
				signer, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: w.p.key.PublicKey.N.Bytes()}, nil)
				jws, _ := signer.Sign(payload)
				raw, _ := jws.CompactSerialize()
				return raw
			}
		},
		"JSON serialization": func(w *world) {
			w.p.rawToken = func(payload []byte) string {
				signer, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: w.p.key, KeyID: w.p.kid}}, nil)
				jws, _ := signer.Sign(payload)
				return jws.FullSerialize()
			}
		},
		"no id_token": func(w *world) { w.p.noIDToken = true },
	} {
		w := newWorld(t, nil)
		setup(w)
		if _, err := w.signIn("sub-1"); !errors.Is(err, auth.ErrBadCredentials) || w.lastReason("proof.refused") != "token" {
			t.Errorf("%s: %v %q", name, err, w.lastReason("proof.refused"))
		}
	}
}

func b64(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }

// Review 0026: claims. Fractional dates are dates; two audiences with our
// azp pass; an explicit null azp, a future auth_time, and an empty subject
// are refused; an email is dropped past 254 bytes, and is no verified
// address when absent.
func TestClaims(t *testing.T) {
	for name, c := range map[string]struct {
		two    bool
		claims func(w *world, c map[string]any)
		reason string // "" for accepted
	}{
		"a fractional iat":    {false, func(w *world, c map[string]any) { c["iat"] = float64(w.k.Clock.Now().Unix()) + 0.5 }, ""},
		"two audiences, azp":  {false, func(_ *world, c map[string]any) { c["aud"], c["azp"] = []string{clientID, "other"}, clientID }, ""},
		"a null azp":          {false, func(_ *world, c map[string]any) { c["azp"] = nil }, "audience"},
		"a future auth_time":  {true, func(w *world, c map[string]any) { c["auth_time"] = w.k.Clock.Now().Add(time.Hour).Unix() }, "token"},
		"a fractional recent": {true, func(w *world, c map[string]any) { c["auth_time"] = float64(w.k.Clock.Now().Unix()) - 0.5 }, ""},
		"an empty subject":    {false, func(_ *world, c map[string]any) { c["sub"] = "" }, "malformed"},
	} {
		w := newWorld(t, func(cf *config) { cf.two = c.two })
		w.p.claims = func(m map[string]any) { c.claims(w, m) }
		_, err := w.signIn("sub-1")
		if c.reason == "" {
			if err != nil {
				t.Errorf("%s: %v", name, err)
			}
			continue
		}
		if !errors.Is(err, auth.ErrBadCredentials) || w.lastReason("proof.refused") != c.reason {
			t.Errorf("%s: %v %q", name, err, w.lastReason("proof.refused"))
		}
	}
	w := newWorld(t, nil)
	w.p.claims = func(c map[string]any) { c["email"], c["email_verified"] = strings.Repeat("a", 250)+"@x.io", true }
	if f, err := w.signIn("sub-1"); err != nil || f.Unlinked.Email != "" || f.Unlinked.EmailVerified {
		t.Errorf("a long email: %+v %v", f.Unlinked, err)
	}
	w.p.claims = func(c map[string]any) { c["email_verified"] = true }
	if f, err := w.signIn("sub-2"); err != nil || f.Unlinked.EmailVerified {
		t.Errorf("verified with no email: %+v %v", f.Unlinked, err)
	}
}

// §5.14.3's order, with two defects at once: the earlier wins.
func TestRefusalOrder(t *testing.T) {
	for name, c := range map[string]struct {
		late   bool
		query  func(q url.Values)
		reason string
	}{
		"malformed before expired": {true, func(q url.Values) { q.Add("state", "x") }, "malformed"},
		"expired before state":     {true, func(q url.Values) { q.Set("state", "x") }, "expired"},
		"state before issuer":      {false, func(q url.Values) { q.Set("state", "x"); q.Set("iss", "https://evil.example") }, "state"},
		"issuer before error":      {false, func(q url.Values) { q.Del("code"); q.Set("error", "x"); q.Set("iss", "https://evil.example") }, "issuer"},
		"state before error":       {false, func(q url.Values) { q.Del("code"); q.Set("error", "x"); q.Set("state", "x") }, "state"},
	} {
		w := newWorld(t, nil)
		f, u := w.start()
		q := w.p.authorize(t, u, "sub-1")
		c.query(q)
		if c.late {
			w.k.Clock.Advance(lifetime())
		}
		if _, err := w.k.Auth.Prove(w.ctx, f.Token, oidc.Callback("test", q)); !errors.Is(err, auth.ErrBadCredentials) || w.lastReason("proof.refused") != c.reason {
			t.Errorf("%s: %v %q", name, err, w.lastReason("proof.refused"))
		}
	}
}

func lifetime() time.Duration { return 10 * time.Minute }

// §5.14.4: a public client sends no secret and signs in.
func TestPublicClient(t *testing.T) {
	w := newWorld(t, func(c *config) { c.secret = "" })
	w.p.public = true
	if f, err := w.signIn("sub-1"); err != nil || f.Unlinked == nil {
		t.Fatalf("a public client: %+v %v", f, err)
	}
	if w.p.sawSecret {
		t.Error("a public client sent a secret")
	}
}

// §5.14.2: a provider that is down takes back each attempt's count, so
// its outage makes no address wait.
func TestOutageRefunds(t *testing.T) {
	w := newWorld(t, nil)
	ctx := auth.WithClient(w.ctx, auth.Client{Addr: netip.MustParseAddr("192.0.2.1")})
	for range 30 {
		f, _ := w.k.Auth.SignInWithout(ctx, auth.Cookie())
		ch, _ := w.k.Auth.Challenge(ctx, f.Token, "oidc_test")
		q := w.p.authorize(t, ch.Options.(string), "sub-1")
		w.p.tokenStatus = 503
		w.k.Auth.Prove(ctx, f.Token, oidc.Callback("test", q))
		w.p.tokenStatus = 0
	}
	f, _ := w.k.Auth.SignInWithout(ctx, auth.Cookie())
	ch, _ := w.k.Auth.Challenge(ctx, f.Token, "oidc_test")
	if _, err := w.k.Auth.Prove(ctx, f.Token, oidc.Callback("test", w.p.authorize(t, ch.Options.(string), "sub-1"))); err != nil {
		t.Errorf("after an outage: %v", err)
	}
}
