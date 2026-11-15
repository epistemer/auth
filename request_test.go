package auth

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/epistemer/errors"
	bolt "go.etcd.io/bbolt"

	"github.com/epistemer/auth/internal/secrets"
	"github.com/epistemer/auth/internal/store"
	"github.com/epistemer/auth/internal/storepb"
)

// shop is a toy shop's routes over a kit, for tests through net/http.
type shop struct {
	*kit
	mux *http.ServeMux
}

func newShop(k *kit) *shop {
	s := &shop{kit: k, mux: http.NewServeMux()}
	web := k.Load(Cookie())
	who := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess, ok := From(r.Context())
		if !ok {
			io.WriteString(w, "nobody")
			return
		}
		fmt.Fprintf(w, "%s %s", sess.User, sess.ID)
	})
	s.mux.Handle("POST /sign-in", web(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		f, err := k.SignIn(ctx, r.FormValue("login"), Cookie())
		if err == nil {
			f, err = k.Prove(ctx, f.Token, Password(r.FormValue("password")))
		}
		if err != nil {
			http.Error(w, err.Error(), errors.KindOf(err).Status())
			return
		}
		var opts []FinishOption
		if r.FormValue("remember") != "" {
			opts = append(opts, Remember())
		}
		res, err := k.Finish(ctx, f.Token, opts...)
		if err != nil {
			http.Error(w, err.Error(), errors.KindOf(err).Status())
			return
		}
		res.Write(w)
	})))
	s.mux.Handle("POST /step-up", web(k.Require(Unverified)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		sess, _ := From(ctx)
		f, err := k.StepUp(ctx, sess)
		if err == nil {
			f, err = k.Prove(ctx, f.Token, Password(r.FormValue("password")))
		}
		if err == nil {
			var res Result
			if res, err = k.Finish(ctx, f.Token); err == nil {
				res.Write(w)
				return
			}
		}
		http.Error(w, err.Error(), errors.KindOf(err).Status())
	}))))
	s.mux.Handle("POST /sign-out", web(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := k.SignOut(r.Context(), w); err != nil {
			http.Error(w, err.Error(), 500)
		}
	})))
	s.mux.Handle("/who", web(who))
	s.mux.Handle("/account", web(k.Require(Unverified)(who)))
	s.mux.Handle("/payouts", web(k.Require()(who)))
	s.mux.Handle("/close-account", web(k.Require(Unverified, Within(5*time.Minute))(who)))
	s.mux.Handle("/flow", web(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t, _ := FlowToken(r.Context())
		io.WriteString(w, t)
	})))
	s.mux.Handle("/api/orders", k.Load(Bearer())(k.Require(Unverified)(who)))
	return s
}

// req makes a request to the shop. Each header pair is a name and a value.
func (s *shop) req(method, path string, cookie *http.Cookie, form url.Values, header ...string) *httptest.ResponseRecorder {
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	r := httptest.NewRequest(method, "https://shop.example"+path, body)
	r.RemoteAddr = "192.0.2.1:41000"
	if form != nil {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if cookie != nil {
		r.AddCookie(cookie)
	}
	for i := 0; i+1 < len(header); i += 2 {
		r.Header.Set(header[i], header[i+1])
	}
	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, r)
	return w
}

func cookieOf(t *testing.T, w *httptest.ResponseRecorder, name string) *http.Cookie {
	t.Helper()
	for _, c := range w.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// signIn signs in through the route and returns the session cookie.
func (s *shop) signIn(t *testing.T, login, pw string, extra ...string) *http.Cookie {
	t.Helper()
	form := url.Values{"login": {login}, "password": {pw}}
	for _, e := range extra {
		form.Set(e, "1")
	}
	w := s.req("POST", "/sign-in", nil, form, "Sec-Fetch-Site", "same-origin")
	c := cookieOf(t, w, "__Host-session")
	if w.Code != 200 || c == nil || c.Value == "" {
		t.Fatalf("sign-in: %d %q", w.Code, w.Body.String())
	}
	return c
}

func newShopKit(t *testing.T, edit func(*config), opts ...Option) *shop {
	k := newKitWith(t, edit, append([]Option{WithPolicy(allowUnverified)}, opts...)...)
	k.addUser(t, "sara", User{ID: "u1", Name: "sara"}, goodPassword)
	k.addUser(t, "omar", User{ID: "u2", Name: "omar"}, goodPassword)
	return newShop(k)
}

// §7, sessions: a request with a session cookie that signs in again gets a
// new session token, and the old one is refused.
func TestSignInAgainNewToken(t *testing.T) {
	s := newShopKit(t, nil)
	old := s.signIn(t, "sara", goodPassword)
	form := url.Values{"login": {"sara"}, "password": {goodPassword}}
	w := s.req("POST", "/sign-in", old, form, "Sec-Fetch-Site", "same-origin")
	cur := cookieOf(t, w, "__Host-session")
	if cur == nil || cur.Value == old.Value {
		t.Fatalf("signing in again kept the token")
	}
	if a, b := s.req("GET", "/who", old, nil).Body.String(), s.req("GET", "/who", cur, nil).Body.String(); a == b {
		t.Errorf("signing in again continued the session: %q", b)
	}
	if w := s.req("GET", "/account", old, nil); w.Code != http.StatusUnauthorized {
		t.Errorf("the old token: %d", w.Code)
	}
	if w := s.req("GET", "/account", cur, nil); w.Code != 200 {
		t.Errorf("the new token: %d", w.Code)
	}
}

// §7, sessions: Require() refuses an unverified session; Require(Unverified)
// admits it. Without a session both refuse with ErrNoSession.
func TestRequireLevels(t *testing.T) {
	s := newShopKit(t, nil)
	c := s.signIn(t, "sara", goodPassword)
	if w := s.req("GET", "/payouts", c, nil); w.Code != http.StatusForbidden {
		t.Errorf("Require() with an unverified session: %d", w.Code)
	}
	if w := s.req("GET", "/account", c, nil); w.Code != 200 || !strings.HasPrefix(w.Body.String(), "u1 ") {
		t.Errorf("Require(Unverified): %d %q", w.Code, w.Body.String())
	}
	for _, path := range []string{"/payouts", "/account"} {
		if w := s.req("GET", path, nil, nil); w.Code != http.StatusUnauthorized {
			t.Errorf("%s without a session: %d", path, w.Code)
		}
	}
	// Check, outside a route.
	sess := &Session{ID: "x", User: "u1"}
	ctx := withSession(context.Background(), sess)
	if err := s.Check(ctx); !errors.Is(err, ErrNotVerified) {
		t.Errorf("Check() unverified: %v", err)
	}
	if err := s.Check(ctx, Unverified); err != nil {
		t.Errorf("Check(Unverified): %v", err)
	}
	sess.Verified = true
	if err := s.Check(ctx); err != nil {
		t.Errorf("Check() verified: %v", err)
	}
	if err := s.Check(context.Background(), Unverified); !errors.Is(err, ErrNoSession) {
		t.Errorf("Check without a session: %v", err)
	}
	// A level other than the two is never met, and suppresses no default.
	for _, l := range []Level{-1, 2, 99} {
		if err := s.Check(ctx, l); err == nil {
			t.Errorf("Check(Level(%d)) passed", l)
		}
	}
	if err := s.Check(ctx, nil); err == nil {
		t.Error("Check with a nil requirement passed")
	}
	func() {
		defer func() {
			if recover() == nil {
				t.Error("Require(nil) didn't panic")
			}
		}()
		s.Require(Unverified, nil)
	}()
	// Over HTTP, Require() admits a verified session.
	c2 := s.signIn(t, "omar", goodPassword)
	id := strings.Fields(s.req("GET", "/who", c2, nil).Body.String())[1]
	s.db.Update(func(tx *bolt.Tx) error {
		var rec storepb.Session
		store.Get(tx, store.Sessions, []byte(id), &rec)
		rec.Verified = true
		return store.Put(tx, store.Sessions, []byte(id), &rec)
	})
	if w := s.req("GET", "/payouts", c2, nil); w.Code != 200 {
		t.Errorf("Require() with a verified session: %d", w.Code)
	}
}

// §7, sessions: a cross-origin POST with the cookie is refused; a
// same-origin one isn't. A cross-origin POST to the sign-in route is
// refused though it carries no session; one with a bearer token isn't
// checked. A trusted origin passes.
func TestCrossOrigin(t *testing.T) {
	s := newShopKit(t, func(c *config) { c.origins = []string{"https://pay.example"} })
	c := s.signIn(t, "sara", goodPassword)
	if w := s.req("POST", "/account", c, url.Values{}, "Sec-Fetch-Site", "cross-site"); w.Code != http.StatusForbidden {
		t.Errorf("cross-site POST with the cookie: %d", w.Code)
	}
	if w := s.req("POST", "/account", c, url.Values{}, "Origin", "https://evil.example"); w.Code != http.StatusForbidden {
		t.Errorf("POST from another Origin: %d", w.Code)
	}
	if w := s.req("POST", "/account", c, url.Values{}, "Sec-Fetch-Site", "same-origin"); w.Code != 200 {
		t.Errorf("same-origin POST: %d", w.Code)
	}
	if w := s.req("POST", "/account", c, url.Values{}, "Sec-Fetch-Site", "cross-site", "Origin", "https://pay.example"); w.Code != 200 {
		t.Errorf("POST from a trusted origin: %d", w.Code)
	}
	form := url.Values{"login": {"sara"}, "password": {goodPassword}}
	if w := s.req("POST", "/sign-in", nil, form, "Sec-Fetch-Site", "cross-site"); w.Code != http.StatusForbidden || cookieOf(t, w, "__Host-session") != nil {
		t.Errorf("cross-site sign-in: %d", w.Code)
	}
	if w := s.req("POST", "/sign-in", nil, form, "Sec-Fetch-Site", "cross-site", "Authorization", "Bearer abc"); w.Code != 200 {
		t.Errorf("a request with a bearer token was checked: %d", w.Code)
	}
	// "Bearer" with no token is no bearer token: the request is checked.
	if w := s.req("POST", "/sign-in", nil, form, "Sec-Fetch-Site", "cross-site", "Authorization", "Bearer   "); w.Code != http.StatusForbidden {
		t.Errorf("an empty bearer token skipped the check: %d", w.Code)
	}
	if w := s.req("GET", "/account", c, nil, "Sec-Fetch-Site", "cross-site"); w.Code != 200 {
		t.Errorf("a cross-site GET: %d", w.Code)
	}
	var refused int
	for _, e := range s.events.all {
		if e.Kind == "request.refused" && e.Reason == "cross_origin" {
			refused++
		}
	}
	if refused != 4 {
		t.Errorf("%d refusals recorded", refused)
	}
}

// A request with a bearer token is never read through its cookies: that
// header is why it skips the cross-origin check.
func TestBearerHeaderIgnoresCookie(t *testing.T) {
	s := newShopKit(t, nil)
	c := s.signIn(t, "sara", goodPassword)
	w := s.req("POST", "/account", c, url.Values{}, "Sec-Fetch-Site", "cross-site", "Authorization", "Bearer abc")
	if w.Code != http.StatusUnauthorized {
		t.Errorf("a cookie read beside a bearer header: %d %q", w.Code, w.Body.String())
	}
}

// §7, sessions: RevokeUser refuses that user's next request (the cookie
// carrier; the bearer one comes with M3).
func TestRevokeUser(t *testing.T) {
	s := newShopKit(t, nil)
	a, b := s.signIn(t, "sara", goodPassword), s.signIn(t, "sara", goodPassword)
	o := s.signIn(t, "omar", goodPassword)
	if err := s.RevokeUser(s.ctx, "u1"); err != nil {
		t.Fatal(err)
	}
	for _, c := range []*http.Cookie{a, b} {
		if w := s.req("GET", "/account", c, nil); w.Code != http.StatusUnauthorized {
			t.Errorf("a revoked session: %d", w.Code)
		}
	}
	if w := s.req("GET", "/account", o, nil); w.Code != 200 {
		t.Errorf("another user's session: %d", w.Code)
	}
	if got, _ := s.Sessions(s.ctx, "u1"); len(got) != 0 {
		t.Errorf("sessions left: %v", got)
	}
}

// §7, sessions: Revoke with another user's session ID does nothing.
func TestRevokeOtherUser(t *testing.T) {
	s := newShopKit(t, nil)
	c := s.signIn(t, "sara", goodPassword)
	id := SessionID(strings.Fields(s.req("GET", "/account", c, nil).Body.String())[1])
	if err := s.Revoke(s.ctx, "u2", id); err != nil {
		t.Fatal(err)
	}
	if w := s.req("GET", "/account", c, nil); w.Code != 200 {
		t.Fatalf("Revoke with another user's ID ended the session: %d", w.Code)
	}
	if err := s.Revoke(s.ctx, "u1", id); err != nil {
		t.Fatal(err)
	}
	if w := s.req("GET", "/account", c, nil); w.Code != http.StatusUnauthorized {
		t.Errorf("Revoke by its user: %d", w.Code)
	}
}

// §7, sessions: a session ends at its idle lifetime, at the remembered one
// with Remember, and at session.lifetime whatever its use. Use keeps it
// alive, and Seen is written at most once a minute (§5.6.2).
func TestSessionLifetimesThroughLoad(t *testing.T) {
	s := newShopKit(t, nil)
	plain := s.signIn(t, "sara", goodPassword)
	kept := s.signIn(t, "sara", goodPassword, "remember")
	if kept.Expires.IsZero() || !plain.Expires.IsZero() {
		t.Errorf("cookie expiries: remembered %v, plain %v", kept.Expires, plain.Expires)
	}
	alive := func(c *http.Cookie) bool { return s.req("GET", "/account", c, nil).Code == 200 }
	seen := func(c *http.Cookie) time.Time {
		id := strings.Fields(s.req("GET", "/who", c, nil).Body.String())[1]
		var rec storepb.Session
		s.db.View(func(tx *bolt.Tx) error { return store.Get(tx, store.Sessions, []byte(id), &rec) })
		return time.Unix(0, rec.Seen)
	}
	start := s.clock.now()
	s.clock.advance(30 * time.Second)
	if !alive(plain) || !seen(plain).Equal(start) {
		t.Error("Seen written within a minute")
	}
	s.clock.advance(31 * time.Second)
	if !alive(plain) || !seen(plain).Equal(s.clock.now()) {
		t.Error("Seen not written after a minute")
	}
	// Idle: 24h after the last use for plain, 720h for remembered.
	s.clock.advance(23 * time.Hour)
	if !alive(plain) || !alive(kept) {
		t.Fatal("ended early")
	}
	s.clock.advance(24*time.Hour + time.Minute)
	if alive(plain) {
		t.Error("plain session outlived session.idle")
	}
	if !alive(kept) {
		t.Fatal("remembered session ended at session.idle")
	}
	// Kept in use, the remembered one still ends at session.lifetime.
	for s.clock.now().Before(start.Add(2160*time.Hour - 24*time.Hour)) {
		s.clock.advance(24 * time.Hour)
		if !alive(kept) {
			t.Fatalf("remembered session ended at %v", s.clock.now().Sub(start))
		}
	}
	s.clock.advance(25 * time.Hour)
	if alive(kept) {
		t.Error("remembered session outlived session.lifetime")
	}
}

// SignOut ends the session and clears the cookie.
func TestSignOut(t *testing.T) {
	s := newShopKit(t, nil)
	c := s.signIn(t, "sara", goodPassword)
	w := s.req("POST", "/sign-out", c, url.Values{}, "Sec-Fetch-Site", "same-origin")
	if cl := cookieOf(t, w, "__Host-session"); cl == nil || cl.MaxAge >= 0 || !cl.Secure || !cl.HttpOnly {
		t.Errorf("signing out left the cookie: %+v", cl)
	}
	if w := s.req("GET", "/account", c, nil); w.Code != http.StatusUnauthorized {
		t.Errorf("after signing out: %d", w.Code)
	}
	if w := s.req("POST", "/sign-out", nil, url.Values{}, "Sec-Fetch-Site", "same-origin"); w.Code != 200 {
		t.Errorf("signing out without a session: %d", w.Code)
	}
}

// Within needs a recent proof; a step-up gives one.
func TestWithin(t *testing.T) {
	s := newShopKit(t, nil)
	c := s.signIn(t, "sara", goodPassword)
	s.clock.advance(4 * time.Minute)
	if w := s.req("GET", "/close-account", c, nil); w.Code != 200 {
		t.Fatalf("a proof four minutes old: %d", w.Code)
	}
	s.clock.advance(2 * time.Minute)
	if w := s.req("GET", "/close-account", c, nil); w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "recent proof") {
		t.Fatalf("a proof six minutes old: %d %q", w.Code, w.Body.String())
	}
	w := s.req("POST", "/step-up", c, url.Values{"password": {goodPassword}}, "Sec-Fetch-Site", "same-origin")
	up := cookieOf(t, w, "__Host-session")
	if w.Code != 200 || up == nil {
		t.Fatalf("step-up: %d %q", w.Code, w.Body.String())
	}
	if w := s.req("GET", "/close-account", up, nil); w.Code != 200 {
		t.Errorf("after a step-up: %d", w.Code)
	}
	if w := s.req("GET", "/close-account", c, nil); w.Code != http.StatusUnauthorized {
		t.Errorf("the token before the step-up: %d", w.Code)
	}
}

// Sessions lists a user's live sessions, oldest first, and no one else's.
func TestSessionsList(t *testing.T) {
	s := newShopKit(t, nil)
	a := s.signIn(t, "sara", goodPassword)
	s.clock.advance(time.Second)
	b := s.signIn(t, "sara", goodPassword)
	s.signIn(t, "omar", goodPassword)
	ids := func(c *http.Cookie) SessionID {
		return SessionID(strings.Fields(s.req("GET", "/who", c, nil).Body.String())[1])
	}
	got, err := s.Sessions(s.ctx, "u1")
	if err != nil || len(got) != 2 || got[0].ID != ids(a) || got[1].ID != ids(b) {
		t.Fatalf("Sessions: %v, %v", got, err)
	}
	if got[0].Client.Addr != netip.MustParseAddr("192.0.2.1") {
		t.Errorf("client %v", got[0].Client)
	}
	s.Revoke(s.ctx, "u1", got[0].ID)
	if got, _ := s.Sessions(s.ctx, "u1"); len(got) != 1 || got[0].ID != ids(b) {
		t.Errorf("after a revoke: %v", got)
	}
}

// Load reads the client from the peer address, or from WithClientAddr, and
// throttles by it.
func TestLoadClient(t *testing.T) {
	behind := netip.MustParseAddr("203.0.113.5")
	for _, c := range []struct {
		opts []Option
		want netip.Addr
	}{
		{nil, netip.MustParseAddr("192.0.2.1")},
		{[]Option{WithClientAddr(func(*http.Request) netip.Addr { return behind })}, behind},
	} {
		s := newShopKit(t, nil, c.opts...)
		s.signIn(t, "sara", goodPassword)
		var got netip.Addr
		for _, e := range s.events.all {
			if e.Kind == "session.created" {
				got = e.Client.Addr
			}
		}
		if got != c.want {
			t.Errorf("client %v; want %v", got, c.want)
		}
		sub := userSubject("u2", c.want.String())
		for range 5 {
			s.req("POST", "/sign-in", nil, url.Values{"login": {"omar"}, "password": {wrongPassword}}, "Sec-Fetch-Site", "same-origin")
		}
		if ctr := s.counterOf(t, sub, counterAddr); ctr == nil || ctr.Failures != 5 {
			t.Errorf("address counter for %v: %v", c.want, ctr)
		}
		if w := s.req("POST", "/sign-in", nil, url.Values{"login": {"sara"}, "password": {goodPassword}}, "Sec-Fetch-Site", "same-origin"); w.Code != http.StatusTooManyRequests {
			t.Errorf("after five failures from %v: %d", c.want, w.Code)
		}
	}
	k := newKit(t)
	for in, want := range map[string]string{"[2001:db8::1]:443": "2001:db8::1", "[::ffff:192.0.2.9]:80": "192.0.2.9", "192.0.2.7": "192.0.2.7", "junk": "invalid IP"} {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = in
		if got := k.client(r).Addr.String(); got != want {
			t.Errorf("RemoteAddr %q: %s; want %s", in, got, want)
		}
	}
}

// A flow token written with Flow.Write comes back through FlowToken.
func TestFlowTokenThroughLoad(t *testing.T) {
	s := newShopKit(t, nil)
	f, err := s.SignIn(s.ctx, "sara", Cookie())
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	f.Write(w)
	c := cookieOf(t, w, "__Host-flow")
	if got := s.req("GET", "/flow", c, nil).Body.String(); got != f.Token {
		t.Errorf("FlowToken %q", got)
	}
}

// WithReject answers refusals in the app's way.
func TestWithReject(t *testing.T) {
	var got []error
	s := newShopKit(t, nil, WithReject(func(w http.ResponseWriter, r *http.Request, err error) {
		got = append(got, err)
		w.WriteHeader(http.StatusTeapot)
	}))
	if w := s.req("GET", "/account", nil, nil); w.Code != http.StatusTeapot {
		t.Errorf("status %d", w.Code)
	}
	if w := s.req("POST", "/who", nil, url.Values{}, "Sec-Fetch-Site", "cross-site"); w.Code != http.StatusTeapot {
		t.Errorf("status %d", w.Code)
	}
	if len(got) != 2 || !errors.Is(got[0], ErrNoSession) || !errors.Is(got[1], ErrForbidden) {
		t.Errorf("errors %v", got)
	}
}

// Sweep removes expired flows, dead sessions with their indexes, and old
// counters, and keeps the rest.
func TestSweep(t *testing.T) {
	s := newShopKit(t, nil)
	live := s.signIn(t, "sara", goodPassword)
	gone := s.signIn(t, "omar", goodPassword)
	if err := s.RevokeUser(s.ctx, "u2"); err != nil {
		t.Fatal(err)
	}
	old, err := s.SignIn(s.ctx, "sara", Cookie())
	if err != nil {
		t.Fatal(err)
	}
	s.req("POST", "/sign-in", nil, url.Values{"login": {"ghost"}, "password": {wrongPassword}}, "Sec-Fetch-Site", "same-origin")
	s.clock.advance(16 * time.Minute) // the flow is past its lifetime
	fresh, err := s.SignIn(s.ctx, "sara", Cookie())
	if err != nil {
		t.Fatal(err)
	}
	count := func(b []byte) int {
		n := 0
		s.db.View(func(tx *bolt.Tx) error { return store.B(tx, b).ForEach(func(_, _ []byte) error { n++; return nil }) })
		return n
	}
	before := map[string]int{"sessions": count(store.Sessions), "throttle": count(store.Throttle)}
	if err := s.Sweep(s.ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Flow(s.ctx, old.Token); !errors.Is(err, ErrFlowExpired) {
		t.Errorf("old flow: %v", err)
	}
	if _, err := s.Flow(s.ctx, fresh.Token); err != nil {
		t.Errorf("a live flow was swept: %v", err)
	}
	if count(store.Flows) != 1 {
		t.Errorf("%d flows left", count(store.Flows))
	}
	if n := count(store.Sessions); n != before["sessions"]-1 || count(store.SessionTokens) != n || count(store.SessionsByUser) != n {
		t.Errorf("sessions %d, tokens %d, by user %d", n, count(store.SessionTokens), count(store.SessionsByUser))
	}
	if count(store.Throttle) != before["throttle"] {
		t.Error("counters inside their window were swept")
	}
	if w := s.req("GET", "/account", live, nil); w.Code != 200 {
		t.Errorf("a live session was swept: %d", w.Code)
	}
	_ = gone
	// A session past its idle lifetime goes too, and counters past their
	// window.
	s.clock.advance(25 * time.Hour)
	if err := s.Sweep(s.ctx); err != nil {
		t.Fatal(err)
	}
	if count(store.Sessions) != 0 || count(store.SessionTokens) != 0 || count(store.SessionsByUser) != 0 || count(store.Throttle) != 0 || count(store.Flows) != 0 {
		t.Errorf("left after a day: sessions %d, counters %d, flows %d", count(store.Sessions), count(store.Throttle), count(store.Flows))
	}
}

// A bearer session's token is no cookie: Load ignores it there.
func TestCookieOnlyNamesCookieSessions(t *testing.T) {
	s := newShopKit(t, nil)
	token, hash := secrets.NewToken()
	now := s.clock.now().UnixNano()
	rec := &storepb.Session{
		Id: "bearer1", UserId: "u1", TokenHash: hash, Carrier: storepb.Carrier_CARRIER_BEARER,
		Verified: true, Created: now, Seen: now, Expires: now + int64(time.Hour),
	}
	if err := s.db.Update(func(tx *bolt.Tx) error { return putSession(tx, rec) }); err != nil {
		t.Fatal(err)
	}
	c := &http.Cookie{Name: "__Host-session", Value: token}
	if w := s.req("GET", "/account", c, nil); w.Code != http.StatusUnauthorized {
		t.Errorf("a bearer session's token as a cookie: %d", w.Code)
	}
}

// Sessions leaves out a session past its idle lifetime that Sweep hasn't
// removed yet.
func TestSessionsLeavesOutIdle(t *testing.T) {
	s := newShopKit(t, nil)
	s.signIn(t, "sara", goodPassword)
	s.clock.advance(25 * time.Hour)
	if got, err := s.Sessions(s.ctx, "u1"); err != nil || len(got) != 0 {
		t.Errorf("Sessions after the idle lifetime: %v, %v", got, err)
	}
}

// A session the write of Seen finds ended is no session, though the read
// before it found it live.
func TestTouchFindsItEnded(t *testing.T) {
	s := newShopKit(t, nil)
	c := s.signIn(t, "sara", goodPassword)
	s.clock.advance(2 * time.Minute)
	beforeTouch = func() { s.RevokeUser(s.ctx, "u1") }
	defer func() { beforeTouch = nil }()
	if w := s.req("GET", "/account", c, nil); w.Code != http.StatusUnauthorized {
		t.Errorf("a session revoked between the read and the write: %d", w.Code)
	}
}

// Signing in or out beside a bearer header still ends the cookie session
// the request carried, though it wasn't signed in through it.
func TestBearerHeaderEndsCarried(t *testing.T) {
	s := newShopKit(t, nil)
	old := s.signIn(t, "sara", goodPassword)
	form := url.Values{"login": {"sara"}, "password": {goodPassword}}
	if w := s.req("POST", "/sign-in", old, form, "Authorization", "Bearer abc"); w.Code != 200 {
		t.Fatalf("sign-in: %d", w.Code)
	}
	if w := s.req("GET", "/account", old, nil); w.Code != http.StatusUnauthorized {
		t.Errorf("signing in beside a bearer header kept the old session: %d", w.Code)
	}
	c := s.signIn(t, "sara", goodPassword)
	if w := s.req("POST", "/sign-out", c, url.Values{}, "Authorization", "Bearer abc"); w.Code != 200 {
		t.Fatalf("sign-out: %d", w.Code)
	}
	if w := s.req("GET", "/account", c, nil); w.Code != http.StatusUnauthorized {
		t.Errorf("signing out beside a bearer header kept the session: %d", w.Code)
	}
}

// A Load inside another replaces what the outer one attached: a bearer
// route under the web middleware sees no cookie session.
func TestNestedLoad(t *testing.T) {
	s := newShopKit(t, nil)
	c := s.signIn(t, "sara", goodPassword)
	h := s.Load(Cookie())(s.Load(Bearer())(s.Require(Unverified)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))))
	r := httptest.NewRequest("GET", "https://shop.example/api/orders", nil)
	r.AddCookie(c)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("a cookie session reached a bearer route: %d", w.Code)
	}
}

// Any Authorization header that is a bearer token counts, not only the first.
func TestHasBearer(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Add("Authorization", "Basic eDp5")
	r.Header.Add("Authorization", "bearer abc")
	if !hasBearer(r) {
		t.Error("a second Authorization header was missed")
	}
	for _, v := range []string{"Bearer", "Bearer ", "Bearer \t ", "Basic abc", "Bearerabc"} {
		r := httptest.NewRequest("GET", "/", nil)
		r.Header.Set("Authorization", v)
		if hasBearer(r) {
			t.Errorf("%q counted as a bearer token", v)
		}
	}
}

// §7, sessions: a remembered session ends at session.remembered_idle.
func TestRememberedIdle(t *testing.T) {
	s := newShopKit(t, nil)
	kept := s.signIn(t, "sara", goodPassword, "remember")
	s.clock.advance(719 * time.Hour)
	if w := s.req("GET", "/account", kept, nil); w.Code != 200 {
		t.Fatalf("a remembered session at 719h: %d", w.Code)
	}
	s.clock.advance(720*time.Hour + time.Minute)
	if w := s.req("GET", "/account", kept, nil); w.Code != http.StatusUnauthorized {
		t.Errorf("a remembered session idle past session.remembered_idle: %d", w.Code)
	}
}

// If ending the session fails, SignOut keeps the cookie, so the user can
// try again.
func TestSignOutKeepsCookieOnError(t *testing.T) {
	s := newShopKit(t, nil)
	ctx := withSession(s.ctx, &Session{ID: "x", User: "u1"})
	s.db.Close()
	w := httptest.NewRecorder()
	if err := s.SignOut(ctx, w); err == nil {
		t.Fatal("SignOut on a closed store succeeded")
	}
	if c := cookieOf(t, w, "__Host-session"); c != nil {
		t.Errorf("the cookie was cleared: %+v", c)
	}
}

// A session whose Seen can't be written is no session: the store's state
// is unknown, and Require refuses.
func TestTouchErrorIsNoSession(t *testing.T) {
	s := newShopKit(t, nil)
	c := s.signIn(t, "sara", goodPassword)
	path := s.db.Path()
	s.db.Close()
	ro, err := bolt.Open(path, 0o600, &bolt.Options{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer ro.Close()
	s.Auth.db = ro
	if w := s.req("GET", "/account", c, nil); w.Code != 200 {
		t.Fatalf("within the minute, no write: %d", w.Code)
	}
	s.clock.advance(2 * time.Minute)
	if w := s.req("GET", "/account", c, nil); w.Code != http.StatusUnauthorized {
		t.Errorf("a failed write of Seen: %d", w.Code)
	}
}
