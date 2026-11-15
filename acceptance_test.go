package auth_test

// Interface §7's acceptance tests, through the public API and authtest, as
// an app would write them. Each test names its line. The package's own
// tests check the same rules from inside (hash counts, records) and the
// rest of each rule; these check what an app can see.

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/epistemer/errors"
	"golang.org/x/text/unicode/norm"

	"github.com/epistemer/auth"
	"github.com/epistemer/auth/authtest"
)

const (
	pw    = "orange tiger juggles 47 lamps"
	wrong = "purple walrus sings 12 tunes"
)

func allowUnverified(context.Context, auth.User) auth.Policy {
	return auth.Policy{AllowUnverified: true}
}

// shop is a kit with sara and omar, who have passwords, and a set of
// secrets the suite used, which no event may hold.
type shop struct {
	*authtest.Kit
	t       *testing.T
	ctx     context.Context
	secrets []string
}

func newShop(t *testing.T, opts ...auth.Option) *shop {
	k := authtest.New(t, append([]auth.Option{auth.WithPolicy(allowUnverified)}, opts...)...)
	s := &shop{Kit: k, t: t, ctx: context.Background(), secrets: []string{pw, wrong, authtest.Config().AuthSecret().Reveal()}}
	for _, u := range []struct{ login, id, mail string }{{"sara", "u1", "sara@toyshop.example"}, {"omar", "u2", "omar@toyshop.example"}} {
		k.AddUser(u.login, auth.User{ID: auth.UserID(u.id), Name: u.login}, u.mail)
		if err := k.Auth.SetPassword(s.ctx, auth.UserID(u.id), pw); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(s.noSecrets)
	return s
}

// from is a context whose requests come from addr.
func (s *shop) from(addr string) context.Context {
	return auth.WithClient(s.ctx, auth.Client{Addr: netip.MustParseAddr(addr)})
}

// try signs in as login with a password, up to Prove.
func (s *shop) try(ctx context.Context, login, password string) (auth.Flow, error) {
	s.t.Helper()
	_, f, err := s.try2(ctx, login, password)
	return f, err
}

// try2 is try, also returning the flow SignIn started.
func (s *shop) try2(ctx context.Context, login, password string) (start, proved auth.Flow, err error) {
	s.t.Helper()
	start, err = s.Auth.SignIn(ctx, login, auth.Cookie())
	if err != nil {
		s.t.Fatal(err)
	}
	s.secrets = append(s.secrets, start.Token, password)
	proved, err = s.Auth.Prove(ctx, start.Token, auth.Password(password))
	return start, proved, err
}

// §7, secrets: no event from the suite contains a password, a code, a
// token or a key the suite used.
func (s *shop) noSecrets() {
	for _, e := range s.Events() {
		text := strings.Join([]string{e.Kind, string(e.User), string(e.Session), e.Method, e.Reason, e.Client.UserAgent}, " ")
		for _, sec := range s.secrets {
			if sec != "" && strings.Contains(text, sec) {
				s.t.Errorf("event %+v holds a secret", e)
			}
		}
	}
}

// Enumeration: a wrong password answers alike for a known and an unknown
// login, and for a known user with no password.
func TestAcceptEnumeration(t *testing.T) {
	s := newShop(t)
	s.AddUser("nopass", auth.User{ID: "u3", Name: "nopass"})
	type answer struct {
		startReady, startVerified bool
		startOffers               string
		startLife                 time.Duration
		ready, verified           bool
		offers                    string
		code                      string
	}
	var first *answer
	for _, login := range []string{"sara", "ghost", "nopass"} {
		start, f, err := s.try2(s.from("192.0.2.1"), login, wrong)
		got := answer{start.Ready, start.Verified, strings.Join(start.Offers, ","), start.Expires.Sub(s.Clock.Now()),
			f.Ready, f.Verified, strings.Join(f.Offers, ","), errors.Public(err).K()}
		if got.startOffers != "password" || got.offers != "password" {
			t.Errorf("%s offers %q then %q", login, got.startOffers, got.offers)
		}
		if !errors.Is(err, auth.ErrBadCredentials) {
			t.Fatalf("%s: %v", login, err)
		}
		if first == nil {
			first = &got
		} else if got != *first {
			t.Errorf("%s answers %+v; sara %+v", login, got, *first)
		}
	}
}

// Enumeration: a disabled user with a wrong password gets
// ErrBadCredentials; with the right one, ErrUserDisabled.
func TestAcceptDisabled(t *testing.T) {
	s := newShop(t)
	s.AddUser("sara", auth.User{ID: "u1", Name: "sara", Disabled: true}, "sara@toyshop.example")
	if _, err := s.try(s.ctx, "sara", wrong); !errors.Is(err, auth.ErrBadCredentials) {
		t.Errorf("wrong password: %v", err)
	}
	if _, err := s.try(s.ctx, "sara", pw); !errors.Is(err, auth.ErrUserDisabled) {
		t.Errorf("right password: %v", err)
	}
}

// Flows: a flow is refused after flow.lifetime and after a successful
// Finish. A StepUp flow can't be finished for another session.
func TestAcceptFlows(t *testing.T) {
	s := newShop(t)
	f, err := s.try(s.ctx, "sara", pw)
	if err != nil {
		t.Fatal(err)
	}
	res, err := s.Auth.Finish(s.ctx, f.Token)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Auth.Finish(s.ctx, f.Token); !errors.Is(err, auth.ErrFlowExpired) {
		t.Errorf("a finished flow: %v", err)
	}
	late, _ := s.try(s.ctx, "sara", pw)
	s.Clock.Advance(15*time.Minute + time.Second)
	if _, err := s.Auth.Finish(s.ctx, late.Token); !errors.Is(err, auth.ErrFlowExpired) {
		t.Errorf("a flow past its lifetime: %v", err)
	}

	f2, _ := s.try(s.ctx, "sara", pw)
	other, err := s.Auth.Finish(s.ctx, f2.Token)
	if err != nil {
		t.Fatal(err)
	}
	up, err := s.Auth.StepUp(s.ctx, res.Session)
	if err != nil {
		t.Fatal(err)
	}
	s.secrets = append(s.secrets, up.Token)
	if _, err := s.Auth.Prove(s.ctx, up.Token, auth.Password(pw)); err != nil {
		t.Fatal(err)
	}
	ctx := carrying(t, s, other)
	if _, err := s.Auth.Finish(ctx, up.Token); err == nil {
		t.Error("a step-up finished for another session")
	}
}

// carrying runs a request with res's session cookie through Load and
// returns its context, as a handler would see it.
func carrying(t *testing.T, s *shop, res auth.Result) context.Context {
	t.Helper()
	w := httptest.NewRecorder()
	res.Write(w)
	r := httptest.NewRequest("GET", "https://shop.example/", nil)
	for _, c := range w.Result().Cookies() {
		if c.MaxAge >= 0 {
			r.AddCookie(c)
			s.secrets = append(s.secrets, c.Value)
		}
	}
	var ctx context.Context
	s.Auth.Load(auth.Cookie())(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { ctx = r.Context() })).
		ServeHTTP(httptest.NewRecorder(), r)
	if sess, ok := auth.From(ctx); !ok || sess.ID != res.Session.ID {
		t.Fatal("Load didn't attach the session")
	}
	return ctx
}

// Passwords: long passwords in any script sign in; 1025 bytes is too long;
// spaces count; composed and decomposed forms are one password; weak ones
// are refused, each with its own error.
func TestAcceptPasswords(t *testing.T) {
	s := newShop(t)
	arabic := strings.Repeat("كلمة سر طويلة ", 73)[:1022] + "ab"
	letters := ("the quick brown fox jumps over a lazy dog while seven zebras quietly hum " +
		"jazz tunes near old harbor walls and purple kites drift above green fields " +
		"as twelve monks bake rye bread for the long winter fair in town")[:200]
	composed := "café crème brûlée 1987 ﬁnest"
	for i, p := range []string{arabic, letters, "  " + pw + "  ", composed} {
		id := auth.UserID("p" + string(rune('0'+i)))
		s.AddUser(string(id), auth.User{ID: id, Name: string(id)})
		if err := s.Auth.SetPassword(s.ctx, id, p); err != nil {
			t.Fatalf("set %d bytes: %v", len(p), err)
		}
		s.secrets = append(s.secrets, p)
		try := p
		if p == composed {
			try = norm.NFD.String(p)
		}
		if _, err := s.try(s.ctx, string(id), try); err != nil {
			t.Errorf("%d bytes: %v", len(p), err)
		}
	}
	if _, err := s.try(s.ctx, "p2", pw); !errors.Is(err, auth.ErrBadCredentials) {
		t.Errorf("without its spaces: %v", err)
	}
	if err := s.Auth.SetPassword(s.ctx, "p0", strings.Repeat("x", 1025)); !errors.Is(err, auth.ErrPasswordTooLong) {
		t.Errorf("1025 bytes: %v", err)
	}
	// NFKC also folds the ligature: "ﬁnest" and "finest" are one password.
	if _, err := s.try(s.ctx, "p3", strings.Replace(composed, "ﬁ", "fi", 1)); err != nil {
		t.Errorf("without the ligature: %v", err)
	}
	for p, want := range map[string]error{
		"short":               auth.ErrPasswordTooShort,
		"password1234":        auth.ErrPasswordCommon,
		"sara-is-the-best-99": auth.ErrPasswordPersonal,
		"aaaaaaaaaaaa":        auth.ErrPasswordSimple,
		"P@ssw0rd2024":        auth.ErrPasswordCommon,
		"Summer2024!!":        auth.ErrPasswordCommon,
		"14/02/1990!!!!":      auth.ErrPasswordSimple,
	} {
		if err := s.Auth.CheckPassword(s.ctx, p, "sara"); !errors.Is(err, want) {
			t.Errorf("%q: %v; want %v", p, err, want)
		}
		if err := s.Auth.SetPassword(s.ctx, "u1", p); !errors.Is(err, want) {
			t.Errorf("SetPassword %q: %v; want %v", p, err, want)
		}
		s.secrets = append(s.secrets, p)
	}
}

// Throttling: the sixth wrong password returns ErrTooManyAttempts, and
// RetryAfter doubles with each further failure let through, up to the
// ceiling (A7).
func TestAcceptThrottleSixth(t *testing.T) {
	s := newShop(t)
	ctx := s.from("192.0.2.1")
	for range 5 {
		if _, err := s.try(ctx, "sara", wrong); !errors.Is(err, auth.ErrBadCredentials) {
			t.Fatal(err)
		}
	}
	wait := time.Second
	for n := 6; n <= 18; n++ {
		_, err := s.try(ctx, "sara", pw)
		if d, ok := auth.RetryAfter(err); !errors.Is(err, auth.ErrTooManyAttempts) || !ok || d != wait {
			t.Fatalf("attempt %d: %v, %v; want a wait of %v", n, err, d, wait)
		}
		s.Clock.Advance(wait)
		if _, err := s.try(ctx, "sara", wrong); !errors.Is(err, auth.ErrBadCredentials) {
			t.Fatalf("failure %d: %v", n, err)
		}
		wait = min(2*wait, 15*time.Minute)
	}
}

// Throttling: a wait on one login from one address doesn't block that
// login from another address until the login's own counter is reached.
func TestAcceptThrottleAddresses(t *testing.T) {
	s := newShop(t)
	a, b := s.from("192.0.2.1"), s.from("198.51.100.7")
	for _, login := range []string{"x1", "x2", "x3", "x4", "x5"} {
		s.try(a, login, wrong)
	}
	if _, err := s.try(a, "sara", pw); !errors.Is(err, auth.ErrTooManyAttempts) {
		t.Fatalf("from the waiting address: %v", err)
	}
	for i := range 5 {
		if _, err := s.try(b, "sara", wrong); !errors.Is(err, auth.ErrBadCredentials) {
			t.Fatalf("failure %d from another address: %v", i+1, err)
		}
	}
	if _, err := s.try(s.from("203.0.113.9"), "sara", pw); !errors.Is(err, auth.ErrTooManyAttempts) {
		t.Errorf("after the login's own counter: %v", err)
	}
}

// Throttling: of a thousand concurrent failures, no more than
// throttle.free get through (A7).
func TestAcceptThrottleConcurrent(t *testing.T) {
	s := newShop(t)
	ctx := s.from("192.0.2.1")
	f, err := s.Auth.SignIn(ctx, "sara", auth.Cookie())
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	s.secrets = append(s.secrets, f.Token)
	var mu sync.Mutex
	bad, refused := 0, 0
	for range 1000 {
		wg.Go(func() {
			_, err := s.Auth.Prove(ctx, f.Token, auth.Password(wrong))
			mu.Lock()
			defer mu.Unlock()
			switch {
			case errors.Is(err, auth.ErrBadCredentials):
				bad++
			case errors.Is(err, auth.ErrTooManyAttempts):
				refused++
			}
		})
	}
	wg.Wait()
	if bad != 5 || refused != 995 {
		t.Errorf("%d got through, %d refused", bad, refused)
	}
}

// Throttling: Alice, alice and " alice " share one counter, and a counter
// with no attempt for throttle.window starts again.
func TestAcceptThrottleSpellingsAndWindow(t *testing.T) {
	s := newShop(t)
	for i, login := range []string{"Alice", "alice", " alice ", "ALICE", "alice"} {
		ctx := s.from(netip.AddrFrom4([4]byte{192, 0, 2, byte(10 + i)}).String())
		if _, err := s.try(ctx, login, wrong); !errors.Is(err, auth.ErrBadCredentials) {
			t.Fatal(err)
		}
	}
	if _, err := s.try(s.from("192.0.2.99"), "alice", wrong); !errors.Is(err, auth.ErrTooManyAttempts) {
		t.Errorf("the sixth spelling: %v", err)
	}
	s.Clock.Advance(time.Hour)
	for i := range 5 {
		if _, err := s.try(s.from("192.0.2.99"), "alice", wrong); !errors.Is(err, auth.ErrBadCredentials) {
			t.Fatalf("failure %d after throttle.window: %v", i+1, err)
		}
	}
	if _, err := s.try(s.from("192.0.2.99"), "alice", wrong); !errors.Is(err, auth.ErrTooManyAttempts) {
		t.Errorf("the sixth after throttle.window: %v", err)
	}
}

// web is a toy shop's routes over the kit.
func web(s *shop) http.Handler {
	mux := http.NewServeMux()
	load := s.Auth.Load(auth.Cookie())
	who := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if sess, ok := auth.From(r.Context()); ok {
			io.WriteString(w, string(sess.ID))
		}
	})
	mux.Handle("POST /sign-in", load(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f, err := s.Auth.SignIn(r.Context(), r.FormValue("login"), auth.Cookie())
		if err == nil {
			f, err = s.Auth.Prove(r.Context(), f.Token, auth.Password(r.FormValue("password")))
		}
		var res auth.Result
		if err == nil {
			var opts []auth.FinishOption
			if r.FormValue("remember") != "" {
				opts = append(opts, auth.Remember())
			}
			res, err = s.Auth.Finish(r.Context(), f.Token, opts...)
		}
		if err != nil {
			http.Error(w, errors.T(r.Context(), err), errors.KindOf(err).Status())
			return
		}
		res.Write(w)
	})))
	mux.Handle("/account", load(s.Auth.Require(auth.Unverified)(who)))
	mux.Handle("/payouts", load(s.Auth.Require()(who)))
	return mux
}

type client struct {
	t   *testing.T
	h   http.Handler
	s   *shop
	jar *http.Cookie
}

func (c *client) do(method, path string, form url.Values, header ...string) *httptest.ResponseRecorder {
	c.t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	r := httptest.NewRequest(method, "https://shop.example"+path, body)
	r.RemoteAddr = "192.0.2.1:40000"
	if form != nil {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if c.jar != nil {
		r.AddCookie(c.jar)
	}
	for i := 0; i+1 < len(header); i += 2 {
		r.Header.Set(header[i], header[i+1])
	}
	w := httptest.NewRecorder()
	c.h.ServeHTTP(w, r)
	for _, ck := range w.Result().Cookies() {
		if ck.Name == "__Host-session" {
			if ck.MaxAge < 0 {
				c.jar = nil
			} else {
				c.jar = ck
				c.s.secrets = append(c.s.secrets, ck.Value)
			}
		}
	}
	return w
}

func (c *client) signIn(login string, extra ...string) {
	c.t.Helper()
	form := url.Values{"login": {login}, "password": {pw}}
	for _, e := range extra {
		form.Set(e, "1")
	}
	if w := c.do("POST", "/sign-in", form, "Sec-Fetch-Site", "same-origin"); w.Code != 200 {
		c.t.Fatalf("sign-in: %d %s", w.Code, w.Body)
	}
}

// Sessions: signing in again gives a new token and refuses the old one;
// Require() refuses an unverified session and Require(Unverified) admits
// it; a cross-origin POST is refused, with the cookie or to the sign-in
// route without one, unless it carries a bearer token.
func TestAcceptSessions(t *testing.T) {
	s := newShop(t)
	c := &client{t: t, h: web(s), s: s}
	c.signIn("sara")
	old := c.jar
	c.signIn("sara")
	if c.jar.Value == old.Value {
		t.Fatal("signing in again kept the token")
	}
	stale := &client{t: t, h: c.h, s: s, jar: old}
	if w := stale.do("GET", "/account", nil); w.Code != http.StatusUnauthorized {
		t.Errorf("the old token: %d", w.Code)
	}
	if w := c.do("GET", "/account", nil); w.Code != 200 {
		t.Errorf("Require(Unverified): %d", w.Code)
	}
	if w := c.do("GET", "/payouts", nil); w.Code != http.StatusForbidden {
		t.Errorf("Require() with an unverified session: %d", w.Code)
	}
	if w := c.do("POST", "/account", url.Values{}, "Sec-Fetch-Site", "cross-site"); w.Code != http.StatusForbidden {
		t.Errorf("a cross-origin POST with the cookie: %d", w.Code)
	}
	if w := c.do("POST", "/account", url.Values{}, "Sec-Fetch-Site", "same-origin"); w.Code != 200 {
		t.Errorf("a same-origin POST: %d", w.Code)
	}
	anon := &client{t: t, h: c.h, s: s}
	form := url.Values{"login": {"sara"}, "password": {pw}}
	if w := anon.do("POST", "/sign-in", form, "Sec-Fetch-Site", "cross-site"); w.Code != http.StatusForbidden {
		t.Errorf("a cross-origin sign-in: %d", w.Code)
	}
	if w := anon.do("POST", "/sign-in", form, "Sec-Fetch-Site", "cross-site", "Authorization", "Bearer x"); w.Code != 200 {
		t.Errorf("a sign-in with a bearer token was checked: %d", w.Code)
	}
}

// Sessions: RevokeUser refuses the user's next request; Revoke with another
// user's session ID does nothing; a disabled user is refused at Finish.
func TestAcceptRevoke(t *testing.T) {
	s := newShop(t)
	h := web(s)
	sara, omar := &client{t: t, h: h, s: s}, &client{t: t, h: h, s: s}
	sara.signIn("sara")
	omar.signIn("omar")
	id := auth.SessionID(sara.do("GET", "/account", nil).Body.String())
	if err := s.Auth.Revoke(s.ctx, "u2", id); err != nil {
		t.Fatal(err)
	}
	if w := sara.do("GET", "/account", nil); w.Code != 200 {
		t.Errorf("Revoke with another user's ID: %d", w.Code)
	}
	if err := s.Auth.Revoke(s.ctx, "u1", id); err != nil {
		t.Fatal(err)
	}
	if w := sara.do("GET", "/account", nil); w.Code != http.StatusUnauthorized {
		t.Errorf("after Revoke by its user: %d", w.Code)
	}
	sara.signIn("sara")
	second := &client{t: t, h: h, s: s}
	second.signIn("sara")
	if err := s.Auth.RevokeUser(s.ctx, "u1"); err != nil {
		t.Fatal(err)
	}
	for _, c := range []*client{sara, second} {
		if w := c.do("GET", "/account", nil); w.Code != http.StatusUnauthorized {
			t.Errorf("after RevokeUser: %d", w.Code)
		}
	}
	if w := omar.do("GET", "/account", nil); w.Code != 200 {
		t.Errorf("another user after RevokeUser: %d", w.Code)
	}
	f, err := s.try(s.ctx, "omar", pw)
	if err != nil {
		t.Fatal(err)
	}
	s.AddUser("omar", auth.User{ID: "u2", Name: "omar", Disabled: true})
	if _, err := s.Auth.Finish(s.ctx, f.Token); !errors.Is(err, auth.ErrUserDisabled) {
		t.Errorf("a disabled user at Finish: %v", err)
	}
}

// Sessions: a session ends at its idle lifetime, at the remembered one
// with Remember, and at session.lifetime whatever its use.
func TestAcceptSessionLifetimes(t *testing.T) {
	s := newShop(t)
	h := web(s)
	plain, kept, used := &client{t: t, h: h, s: s}, &client{t: t, h: h, s: s}, &client{t: t, h: h, s: s}
	plain.signIn("sara")
	kept.signIn("sara", "remember")
	used.signIn("sara", "remember")
	busy := &client{t: t, h: h, s: s}
	busy.signIn("sara")
	start := s.Clock.Now()
	alive := func(c *client) bool { return c.do("GET", "/account", nil).Code == 200 }
	// session.idle is idle time: a plain session used twice a day lives on.
	for range 4 {
		s.Clock.Advance(12 * time.Hour)
		if !alive(busy) {
			t.Fatal("a plain session in use ended")
		}
	}
	s.Clock.Advance(time.Minute)
	if alive(plain) {
		t.Error("a plain session outlived session.idle")
	}
	// A remembered one waits session.remembered_idle, used or not.
	for s.Clock.Now().Before(start.Add(719 * time.Hour)) {
		s.Clock.Advance(24 * time.Hour)
		if !alive(used) {
			t.Fatalf("a remembered session in use ended at %v", s.Clock.Now().Sub(start))
		}
	}
	s.Clock.Advance(start.Add(719 * time.Hour).Sub(s.Clock.Now()))
	if !alive(kept) {
		t.Fatal("an unused remembered session ended before session.remembered_idle")
	}
	s.Clock.Advance(720*time.Hour + time.Minute)
	if alive(kept) {
		t.Error("a remembered session outlived session.remembered_idle")
	}
	// In use all along, it still ends at session.lifetime.
	used.jar = nil
	used.signIn("sara", "remember")
	start = s.Clock.Now()
	for s.Clock.Now().Before(start.Add(2160*time.Hour - 24*time.Hour)) {
		s.Clock.Advance(24 * time.Hour)
		if !alive(used) {
			t.Fatalf("a remembered session in use ended at %v", s.Clock.Now().Sub(start))
		}
	}
	s.Clock.Advance(25 * time.Hour)
	if alive(used) {
		t.Error("a session outlived session.lifetime")
	}
}

// A config from authtest satisfies auth.Config and keeps its edits.
func TestAuthtestConfig(t *testing.T) {
	var c auth.Config = authtest.Config(func(v *authtest.Values) { v.ThrottleFree = 2; v.TrustedOrigins = []string{"https://pay.example"} })
	if c.AuthThrottleFree() != 2 || c.AuthIssuer() != "toyshop" || len(c.AuthTrustedOrigins()) != 1 || c.AuthSecret().Reveal() == "" {
		t.Errorf("config %v", c)
	}
	k := authtest.New(t)
	k.AddUser("sara", auth.User{ID: "u1", Name: "sara"}, "sara@toyshop.example")
	if err := k.Auth.SetPassword(context.Background(), "u1", pw); err != nil {
		t.Fatal(err)
	}
	if err := k.Auth.SetPassword(context.Background(), "u1", "another long phrase 93 owls"); err != nil {
		t.Fatal(err)
	}
	if m, ok := k.LastMessage("sara@toyshop.example"); !ok || m.Kind != auth.MsgPasswordChanged {
		t.Errorf("last message %+v, %v", m, ok)
	}
	if ev := k.Events(); len(ev) == 0 || ev[len(ev)-1].Kind != "message.sent" {
		t.Errorf("events %v", ev)
	}
}
