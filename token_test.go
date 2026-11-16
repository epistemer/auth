package auth

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/epistemer/cfgx"
	bolt "go.etcd.io/bbolt"

	"github.com/epistemer/auth/internal/store"
	"github.com/epistemer/auth/internal/storepb"
)

// bearerSignIn signs sara in on the bearer carrier, password only.
func bearerSignIn(t *testing.T, k *kit) Result {
	t.Helper()
	f, err := k.SignIn(k.ctx, "sara", Bearer())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := k.Prove(k.ctx, f.Token, Password(goodPassword)); err != nil {
		t.Fatal(err)
	}
	res, err := k.Finish(k.ctx, f.Token)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// api answers with the bearer session's user and claims, or 401.
func (k *kit) api(t *testing.T, access string) (int, string) {
	t.Helper()
	h := k.Load(Bearer())(k.Require(Unverified)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s, _ := From(r.Context())
		b, _ := json.Marshal(s.Claims)
		io.WriteString(w, string(s.User)+" "+string(b))
	})))
	r := httptest.NewRequest("GET", "https://shop.example/api/orders", nil)
	if access != "" {
		r.Header.Set("Authorization", "Bearer "+access)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w.Code, w.Body.String()
}

type fixedClaims map[string]any

func (c fixedClaims) Claims(context.Context, User) (map[string]any, error) { return c, nil }

func newBearerKit(t *testing.T, opts ...Option) *kit {
	k := newKit(t, append([]Option{WithPolicy(allowUnverified)}, opts...)...)
	k.addUser(t, "sara", User{ID: "u1", Name: "sara"}, goodPassword, saraMail)
	k.addUser(t, "omar", User{ID: "u2", Name: "omar"}, goodPassword)
	return k
}

// A bearer sign-in returns an access token and a refresh token, and the
// access token signs requests in, with the claims it was issued with.
func TestBearerSignIn(t *testing.T) {
	k := newBearerKit(t, WithClaims(fixedClaims{"plan": "gold"}))
	res := bearerSignIn(t, k)
	if res.Access == "" || res.Refresh == "" || res.cookie != "" {
		t.Fatalf("result %+v", res)
	}
	head, _, _ := strings.Cut(res.Access, ".")
	if h, _ := b64.DecodeString(head); string(h) != `{"alg":"HS256","typ":"at+jwt"}` {
		t.Errorf("header %s", h)
	}
	code, body := k.api(t, res.Access)
	if code != 200 || body != `u1 {"plan":"gold"}` {
		t.Fatalf("api: %d %q", code, body)
	}
	k.clock.advance(10*time.Minute + time.Second)
	if code, _ := k.api(t, res.Access); code != http.StatusUnauthorized {
		t.Errorf("an access token past its lifetime: %d", code)
	}
}

// §7, bearer: an access token is refused as soon as its session is
// revoked; RevokeUser refuses the user's next request on this carrier too.
func TestBearerRevoked(t *testing.T) {
	k := newBearerKit(t)
	a, b := bearerSignIn(t, k), bearerSignIn(t, k)
	if err := k.Revoke(k.ctx, "u1", a.Session.ID); err != nil {
		t.Fatal(err)
	}
	if code, _ := k.api(t, a.Access); code != http.StatusUnauthorized {
		t.Errorf("a revoked session's token: %d", code)
	}
	if code, _ := k.api(t, b.Access); code != 200 {
		t.Fatalf("the other session: %d", code)
	}
	if err := k.RevokeUser(k.ctx, "u1"); err != nil {
		t.Fatal(err)
	}
	if code, _ := k.api(t, b.Access); code != http.StatusUnauthorized {
		t.Errorf("after RevokeUser: %d", code)
	}
}

// forge signs a token with the real key, with any header and claims.
func (k *kit) forge(header string, c accessClaims) string {
	body, _ := json.Marshal(c)
	key, _ := k.keys.SignKey()
	signed := b64.EncodeToString([]byte(header)) + "." + b64.EncodeToString(body)
	return signed + "." + b64.EncodeToString(sign(key, signed))
}

// §7, bearer: a token with the header {"alg":"none"}, with reordered
// header fields, or signed with another key is refused; so is one whose
// sub isn't its session's user, or whose iss or aud isn't the issuer.
func TestBearerForged(t *testing.T) {
	k := newBearerKit(t)
	res := bearerSignIn(t, k)
	now := k.clock.now()
	good := accessClaims{Iss: "toyshop", Aud: "toyshop", Sub: "u1", Sid: string(res.Session.ID), Gen: 1, Iat: now.Unix(), Exp: now.Add(time.Minute).Unix()}
	if code, _ := k.api(t, k.forge(`{"alg":"HS256","typ":"at+jwt"}`, good)); code != 200 {
		t.Fatalf("a well-made token: %d", code)
	}
	with := func(f func(*accessClaims)) accessClaims { c := good; f(&c); return c }
	for name, tok := range map[string]string{
		"alg none":         b64.EncodeToString([]byte(`{"alg":"none"}`)) + "." + strings.Split(res.Access, ".")[1] + ".",
		"reordered header": k.forge(`{"typ":"at+jwt","alg":"HS256"}`, good),
		"spaced header":    k.forge(`{"alg": "HS256","typ":"at+jwt"}`, good),
		"another key":      strings.Join(append(strings.Split(res.Access, ".")[:2], b64.EncodeToString(sign([]byte("another key"), strings.Join(strings.Split(res.Access, ".")[:2], ".")))), "."),
		"another sub":      k.forge(`{"alg":"HS256","typ":"at+jwt"}`, with(func(c *accessClaims) { c.Sub = "u2" })),
		"another iss":      k.forge(`{"alg":"HS256","typ":"at+jwt"}`, with(func(c *accessClaims) { c.Iss = "evil" })),
		"another aud":      k.forge(`{"alg":"HS256","typ":"at+jwt"}`, with(func(c *accessClaims) { c.Aud = "evil" })),
		"another gen":      k.forge(`{"alg":"HS256","typ":"at+jwt"}`, with(func(c *accessClaims) { c.Gen = 2 })),
		"expired":          k.forge(`{"alg":"HS256","typ":"at+jwt"}`, with(func(c *accessClaims) { c.Exp = now.Unix() })),
		"no session":       k.forge(`{"alg":"HS256","typ":"at+jwt"}`, with(func(c *accessClaims) { c.Sid = "nope" })),
		"app null":         k.forge(`{"alg":"HS256","typ":"at+jwt"}`, with(func(c *accessClaims) { c.App = json.RawMessage("null") })),
		"app array":        k.forge(`{"alg":"HS256","typ":"at+jwt"}`, with(func(c *accessClaims) { c.App = json.RawMessage("[1]") })),
		"two parts":        strings.Join(strings.Split(res.Access, ".")[:2], "."),
		"garbage":          "not.a.token",
	} {
		if code, _ := k.api(t, tok); code != http.StatusUnauthorized {
			t.Errorf("%s: %d", name, code)
		}
	}
}

// §7, bearer: an access token issued before a step-up is refused after it.
func TestBearerStepUp(t *testing.T) {
	k := newBearerKit(t)
	res := bearerSignIn(t, k)
	ctx := withSession(k.ctx, res.Session)
	up, err := k.StepUp(ctx, res.Session)
	if err != nil {
		t.Fatal(err)
	}
	k.Challenge(ctx, up.Token, MethodEmailCode)
	if _, err := k.Prove(ctx, up.Token, EmailCode(k.lastCode(t, saraMail))); err != nil {
		t.Fatal(err)
	}
	next, err := k.Finish(ctx, up.Token)
	if err != nil || next.Access == "" || next.Refresh == "" || next.Refresh == res.Refresh || !next.Session.Verified {
		t.Fatalf("step-up: %+v %v", next, err)
	}
	if code, _ := k.api(t, res.Access); code != http.StatusUnauthorized {
		t.Errorf("the token from before the step-up: %d", code)
	}
	if code, _ := k.api(t, next.Access); code != 200 {
		t.Errorf("the token from the step-up: %d", code)
	}
}

// Whether a request is verified comes from the session, never from the
// token; a bearer request is never checked for its origin, and a cookie
// session isn't read beside a bearer header.
func TestBearerVerifiedFromSession(t *testing.T) {
	k := newBearerKit(t)
	res := bearerSignIn(t, k)
	h := k.Load(Cookie(), Bearer())(k.Require()(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})))
	r := httptest.NewRequest("POST", "https://shop.example/api/payouts", nil)
	r.Header.Set("Authorization", "Bearer "+res.Access)
	r.Header.Set("Sec-Fetch-Site", "cross-site")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "verified") {
		t.Errorf("an unverified bearer session on Require(): %d %q", w.Code, w.Body.String())
	}
}

// A bearer access token is no cookie, and a cookie session's token is no
// access token.
func TestCarriersApart(t *testing.T) {
	k := newBearerKit(t)
	res := bearerSignIn(t, k)
	f, _ := k.signIn(t, "sara", goodPassword)
	web, _ := k.Finish(k.ctx, f.Token)
	if code, _ := k.api(t, web.cookie); code != http.StatusUnauthorized {
		t.Errorf("a cookie token as an access token: %d", code)
	}
	h := k.Load(Cookie())(k.Require(Unverified)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})))
	r := httptest.NewRequest("GET", "https://shop.example/", nil)
	r.AddCookie(&http.Cookie{Name: "__Host-session", Value: res.Access})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("an access token as a cookie: %d", w.Code)
	}
}

// After a secret rotation, a token signed with the previous key still
// verifies until it expires.
func TestBearerPreviousKey(t *testing.T) {
	k := newBearerKit(t)
	res := bearerSignIn(t, k)
	cfg := k.cfg.(*config)
	old := cfg.secret
	cfg.secret, cfg.previous = cfgx.NewSecret(strings.Repeat("n", 32)), old
	k2, err := New(k.db, cfg, k.dir, k.out, WithClock(k.clock.now))
	if err != nil {
		t.Fatal(err)
	}
	kk := &kit{Auth: k2, dir: k.dir, out: k.out, events: k.events, clock: k.clock, ctx: k.ctx}
	if code, _ := kk.api(t, res.Access); code != 200 {
		t.Errorf("a token signed with the previous key: %d", code)
	}
}

// An access token can only name a bearer session: one forged, with the real
// key, for a cookie session is refused.
func TestAccessNamesBearerSessions(t *testing.T) {
	k := newBearerKit(t)
	f, _ := k.signIn(t, "sara", goodPassword)
	web, _ := k.Finish(k.ctx, f.Token)
	now := k.clock.now()
	tok := k.forge(`{"alg":"HS256","typ":"at+jwt"}`, accessClaims{Iss: "toyshop", Aud: "toyshop", Sub: "u1", Sid: string(web.Session.ID), Gen: 1, Iat: now.Unix(), Exp: now.Add(time.Minute).Unix()})
	if code, _ := k.api(t, tok); code != http.StatusUnauthorized {
		t.Errorf("an access token for a cookie session: %d", code)
	}
}

// A step-up, a revoke and a sign-out end a bearer session's old refresh
// tokens: one is left after the step-up, none after the revoke.
func TestRefreshTokensEnd(t *testing.T) {
	k := newBearerKit(t)
	res := bearerSignIn(t, k)
	count := func() int {
		n := 0
		k.db.View(func(tx *bolt.Tx) error {
			return store.Scan(tx, store.RefreshBySession, store.Prefix([]byte(res.Session.ID)), func(_, _ []byte) error { n++; return nil })
		})
		m := 0
		k.db.View(func(tx *bolt.Tx) error {
			return store.B(tx, store.Refresh).ForEach(func(_, _ []byte) error { m++; return nil })
		})
		if m != n {
			t.Errorf("%d refresh records, %d in the index", m, n)
		}
		return n
	}
	if count() != 1 {
		t.Fatal("no refresh token")
	}
	ctx := withSession(k.ctx, res.Session)
	up, _ := k.StepUp(ctx, res.Session)
	k.Prove(ctx, up.Token, Password(goodPassword))
	if _, err := k.Finish(ctx, up.Token); err != nil {
		t.Fatal(err)
	}
	// The old token stays, used, to catch reuse; a new one is issued.
	if n := count(); n != 2 {
		t.Errorf("%d refresh tokens after a step-up", n)
	}
	k.Revoke(k.ctx, "u1", res.Session.ID)
	if n := count(); n != 0 {
		t.Errorf("%d refresh tokens after a revoke", n)
	}
}

// §5.6.7: a request carries the claims its token was issued with, not the
// session's now.
func TestBearerClaimsFromToken(t *testing.T) {
	k := newBearerKit(t, WithClaims(fixedClaims{"plan": "gold"}))
	res := bearerSignIn(t, k)
	k.db.Update(func(tx *bolt.Tx) error {
		var s storepb.Session
		store.Get(tx, store.Sessions, []byte(res.Session.ID), &s)
		s.Claims = []byte(`{"plan":"tin"}`)
		return store.Put(tx, store.Sessions, []byte(res.Session.ID), &s)
	})
	if _, body := k.api(t, res.Access); body != `u1 {"plan":"gold"}` {
		t.Errorf("claims %q", body)
	}
}

// §5.6.6: whether a request is verified comes from the session: after a
// step-up its token passes Require(); a token can't claim to be verified.
func TestBearerVerifiedAfterStepUp(t *testing.T) {
	k := newBearerKit(t)
	res := bearerSignIn(t, k)
	strict := func(access string) int {
		h := k.Load(Bearer())(k.Require()(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})))
		r := httptest.NewRequest("GET", "https://shop.example/api/payouts", nil)
		r.Header.Set("Authorization", "Bearer "+access)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	now := k.clock.now()
	forged := k.forge(`{"alg":"HS256","typ":"at+jwt"}`, accessClaims{Iss: "toyshop", Aud: "toyshop", Sub: "u1", Sid: string(res.Session.ID), Gen: 1, Iat: now.Unix(), Exp: now.Add(time.Minute).Unix(), App: json.RawMessage(`{"verified":true}`)})
	if code := strict(forged); code != http.StatusForbidden {
		t.Errorf("a token claiming to be verified: %d", code)
	}
	ctx := withSession(k.ctx, res.Session)
	up, _ := k.StepUp(ctx, res.Session)
	k.Challenge(ctx, up.Token, MethodEmailCode)
	k.Prove(ctx, up.Token, EmailCode(k.lastCode(t, saraMail)))
	next, err := k.Finish(ctx, up.Token)
	if err != nil {
		t.Fatal(err)
	}
	if code := strict(next.Access); code != 200 {
		t.Errorf("a verified session's token on Require(): %d", code)
	}
}

// §5.6.2 on the bearer carrier: a session idle past session.idle is
// refused whatever its token says; one in use lives on.
func TestBearerIdle(t *testing.T) {
	k := newBearerKit(t)
	busy, idle := bearerSignIn(t, k), bearerSignIn(t, k)
	long := func(s *Session) string {
		now := k.clock.now()
		return k.forge(`{"alg":"HS256","typ":"at+jwt"}`, accessClaims{Iss: "toyshop", Aud: "toyshop", Sub: "u1", Sid: string(s.ID), Gen: 1, Iat: now.Unix(), Exp: now.Add(100 * time.Hour).Unix()})
	}
	b, i := long(busy.Session), long(idle.Session)
	for range 4 {
		k.clock.advance(12 * time.Hour)
		if code, _ := k.api(t, b); code != 200 {
			t.Fatalf("a session in use: %d", code)
		}
	}
	if code, _ := k.api(t, i); code != http.StatusUnauthorized {
		t.Errorf("a session idle for two days: %d", code)
	}
}

// The carriers stay apart: Load(Cookie()) ignores a bearer token; with both
// carriers, a bad bearer token doesn't fall back to the cookie; a Load
// inside another uses its own carriers.
func TestBearerLoadCarriers(t *testing.T) {
	k := newBearerKit(t)
	res := bearerSignIn(t, k)
	f, _ := k.signIn(t, "sara", goodPassword)
	web, _ := k.Finish(k.ctx, f.Token)
	run := func(mw func(http.Handler) http.Handler, cookie, bearer string) string {
		var got string
		h := mw(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			if s, ok := From(r.Context()); ok {
				got = string(s.ID)
			}
		}))
		r := httptest.NewRequest("GET", "https://shop.example/", nil)
		if cookie != "" {
			r.AddCookie(&http.Cookie{Name: "__Host-session", Value: cookie})
		}
		if bearer != "" {
			r.Header.Set("Authorization", "Bearer "+bearer)
		}
		h.ServeHTTP(httptest.NewRecorder(), r)
		return got
	}
	if got := run(k.Load(Cookie()), "", res.Access); got != "" {
		t.Errorf("Load(Cookie()) read a bearer token: %s", got)
	}
	if got := run(k.Load(Cookie(), Bearer()), web.cookie, "bad"); got != "" {
		t.Errorf("a bad bearer token fell back to the cookie: %s", got)
	}
	if got := run(k.Load(Cookie(), Bearer()), "", res.Access); got != string(res.Session.ID) {
		t.Errorf("both carriers, a bearer token: %q", got)
	}
	nested := func(h http.Handler) http.Handler { return k.Load(Cookie())(k.Load(Bearer())(h)) }
	if got := run(nested, "", res.Access); got != string(res.Session.ID) {
		t.Errorf("a bearer Load inside a cookie Load: %q", got)
	}
}

// No event and no record holds an access or refresh token.
func TestBearerNoSecrets(t *testing.T) {
	k := newBearerKit(t)
	res := bearerSignIn(t, k)
	k.api(t, res.Access)
	for _, e := range k.events.all {
		for _, s := range []string{res.Access, res.Refresh, strings.Split(res.Access, ".")[2]} {
			if strings.Contains(e.Kind+e.Reason+e.Method+string(e.Session), s) {
				t.Errorf("event %+v holds a token", e)
			}
		}
	}
	k.db.View(func(tx *bolt.Tx) error {
		return tx.ForEach(func(_ []byte, b *bolt.Bucket) error {
			return walk(b, func(key, v []byte) {
				for _, s := range []string{res.Access, res.Refresh} {
					if strings.Contains(string(key), s) || strings.Contains(string(v), s) {
						t.Error("the store holds a token")
					}
				}
			})
		})
	})
}

// Refused too: a token signed with the master secret itself, trailing data
// after the claims, an app claim that isn't an object, an iat in the
// future, missing, or not before exp, and a request with two
// Authorization headers.
func TestBearerMalformed(t *testing.T) {
	k := newBearerKit(t)
	res := bearerSignIn(t, k)
	now := k.clock.now()
	good := accessClaims{Iss: "toyshop", Aud: "toyshop", Sub: "u1", Sid: string(res.Session.ID), Gen: 1, Iat: now.Unix(), Exp: now.Add(time.Minute).Unix()}
	header := `{"alg":"HS256","typ":"at+jwt"}`
	key, _ := k.keys.SignKey()
	raw := func(body string, key []byte) string {
		signed := b64.EncodeToString([]byte(header)) + "." + b64.EncodeToString([]byte(body))
		return signed + "." + b64.EncodeToString(sign(key, signed))
	}
	body, _ := json.Marshal(good)
	with := func(f func(*accessClaims)) accessClaims { c := good; f(&c); return c }
	for name, tok := range map[string]string{
		"master secret":  raw(string(body), []byte(k.cfg.AuthSecret().Reveal())),
		"trailing data":  raw(string(body)+`{"x":1}`, key),
		"app not object": k.forge(header, with(func(c *accessClaims) { c.App = json.RawMessage(`[1,2]`) })),
		"iat ahead":      k.forge(header, with(func(c *accessClaims) { c.Iat = now.Add(time.Hour).Unix() })),
		"no iat":         k.forge(header, with(func(c *accessClaims) { c.Iat = 0 })),
		"iat at exp":     k.forge(header, with(func(c *accessClaims) { c.Iat = c.Exp })),
	} {
		if code, _ := k.api(t, tok); code != http.StatusUnauthorized {
			t.Errorf("%s: %d", name, code)
		}
	}
	if code, _ := k.api(t, raw(string(body), key)); code != 200 {
		t.Fatalf("the well-made token: %d", code)
	}
	h := k.Load(Bearer())(k.Require(Unverified)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})))
	r := httptest.NewRequest("GET", "https://shop.example/", nil)
	r.Header.Add("Authorization", "Bearer "+res.Access)
	r.Header.Add("Authorization", "Bearer "+res.Access)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("two Authorization headers: %d", w.Code)
	}
}
