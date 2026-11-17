package shop_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/epistemer/cfgx"
	bolt "go.etcd.io/bbolt"

	"github.com/epistemer/auth"
	"github.com/epistemer/auth/access"
	"github.com/epistemer/auth/examples/shop/internal/settings"
	"github.com/epistemer/auth/examples/shop/internal/shop"
	"github.com/epistemer/auth/passkey/passkeytest"
)

const pw = "orange tiger juggles 47 lamps"

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

type world struct {
	t     *testing.T
	srv   *httptest.Server
	out   *shop.Outbox
	clock *clock
	shop  *shop.Shop
}

// newWorld runs the shop on a TLS test server, over a store of its own,
// with the settings cfgx generated and a clock the test moves. Sara is in
// root; Omar is a customer; Lina, a customer, has no email address and is
// an analyst; Max is in root and has no email address.
func newWorld(t *testing.T) *world {
	cfg := settings.Test(func(v *settings.Values) {
		v.Auth.Issuer = "toyshop"
		v.Auth.Secret = cfgx.NewSecret(strings.Repeat("s", 32))
		v.Auth.Password.Memory, v.Auth.Password.Time = 19, 1
		v.Auth.Passkey.Domain = "toyshop.example"
	})
	db, err := bolt.Open(filepath.Join(t.TempDir(), "shop.db"), 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	dir := shop.NewDirectory()
	dir.Add("u1", "sara@toyshop.example", "Sara", "sara@toyshop.example")
	dir.Add("u2", "omar@toyshop.example", "Omar", "omar@toyshop.example")
	dir.Add("u3", "lina", "Lina", "")
	dir.Add("u4", "max", "Max", "")
	// The clock starts now: the cookie jar expires cookies by the real clock,
	// so a fixed date makes every flow cookie stale once that date has passed.
	c := &clock{t: time.Now().UTC().Truncate(time.Second)}
	out := shop.NewOutbox()
	s, err := shop.New(db, cfg, dir, out, auth.WithClock(c.now))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, id := range []auth.UserID{"u1", "u2", "u3", "u4"} {
		if err := s.Auth.SetPassword(ctx, id, pw); err != nil {
			t.Fatal(err)
		}
	}
	analysts, err := s.Access.CreateGroup(ctx, "Analysts")
	if err != nil {
		t.Fatal(err)
	}
	for _, err := range []error{
		s.Access.Join(ctx, "u1", access.Root),
		s.Access.Join(ctx, "u4", access.Root),
		s.Access.Grant(ctx, analysts.ID, shop.ReportView),
		s.Access.Join(ctx, "u3", analysts.ID),
	} {
		if err != nil {
			t.Fatal(err)
		}
	}
	srv := httptest.NewTLSServer(s.Handler())
	t.Cleanup(srv.Close)
	return &world{t: t, srv: srv, out: out, clock: c, shop: s}
}

// browser is a client with a cookie jar, as a browser would be.
func (w *world) browser() *http.Client {
	jar, _ := cookiejar.New(nil)
	c := w.srv.Client()
	c.Jar = jar
	return c
}

func (w *world) post(c *http.Client, path string, form url.Values, header ...string) (int, map[string]any) {
	w.t.Helper()
	r, _ := http.NewRequest("POST", w.srv.URL+path, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for i := 0; i+1 < len(header); i += 2 {
		r.Header.Set(header[i], header[i+1])
	}
	return w.do(c, r)
}

func (w *world) get(c *http.Client, path string, header ...string) int {
	w.t.Helper()
	r, _ := http.NewRequest("GET", w.srv.URL+path, nil)
	for i := 0; i+1 < len(header); i += 2 {
		r.Header.Set(header[i], header[i+1])
	}
	code, _ := w.do(c, r)
	return code
}

func (w *world) do(c *http.Client, r *http.Request) (int, map[string]any) {
	w.t.Helper()
	res, err := c.Do(r)
	if err != nil {
		w.t.Fatal(err)
	}
	defer res.Body.Close()
	var body map[string]any
	json.NewDecoder(res.Body).Decode(&body)
	return res.StatusCode, body
}

func (w *world) code(to string) string {
	w.t.Helper()
	m, ok := w.out.Last(to)
	if !ok || m.Code == "" {
		w.t.Fatalf("no code to %s", to)
	}
	return m.Code
}

// signIn signs a browser in: the password, then the emailed code if asked.
func (w *world) signIn(c *http.Client, login string) map[string]any {
	w.t.Helper()
	code, body := w.post(c, "/sign-in", url.Values{"login": {login}, "password": {pw}})
	if code != 200 {
		w.t.Fatalf("sign-in: %d %v", code, body)
	}
	if body["next"] == "code" {
		w.clock.advance(time.Second)
		if code, body = w.post(c, "/sign-in/code", url.Values{"code": {w.code(login)}}); code != 200 {
			w.t.Fatalf("code: %d %v", code, body)
		}
	}
	return body
}

// M6.1's done-when: the end-to-end test signs in, steps up and is refused
// where it should be.
func TestWeb(t *testing.T) {
	w := newWorld(t)
	sara := w.browser()
	if body := w.signIn(sara, "sara@toyshop.example"); body["verified"] != true {
		t.Fatalf("sara's sign-in: %v", body)
	}
	if code := w.get(sara, "/me"); code != 200 {
		t.Errorf("/me: %d", code)
	}
	if code := w.get(sara, "/reports"); code != 200 {
		t.Errorf("sara's reports: %d", code)
	}
	if code, _ := w.post(sara, "/payouts/approve", nil); code != 200 {
		t.Errorf("a payout with a fresh proof: %d", code)
	}
	// Six minutes on, the proof is stale: a step-up with the emailed code
	// refreshes it, and the password alone doesn't.
	w.clock.advance(6 * time.Minute)
	if code, body := w.post(sara, "/payouts/approve", nil); code != http.StatusForbidden || body["code"] != "errors.auth.stale" {
		t.Errorf("a payout with a stale proof: %d %v", code, body)
	}
	if code, body := w.post(sara, "/step-up", url.Values{"password": {pw}}); code != 200 || body["next"] != "code" {
		t.Fatalf("step-up: %d %v", code, body)
	}
	if code, body := w.post(sara, "/payouts/approve", nil); code != http.StatusForbidden || body["code"] != "errors.auth.stale" {
		t.Errorf("a payout before the step-up's code: %d %v", code, body)
	}
	w.clock.advance(time.Second)
	if code, body := w.post(sara, "/sign-in/code", url.Values{"code": {w.code("sara@toyshop.example")}}); code != 200 || body["verified"] != true {
		t.Fatalf("step-up's code: %d %v", code, body)
	}
	if code, _ := w.post(sara, "/payouts/approve", nil); code != 200 {
		t.Errorf("a payout after the step-up: %d", code)
	}

	// Omar is verified but holds no permission.
	omar := w.browser()
	if body := w.signIn(omar, "omar@toyshop.example"); body["verified"] != true {
		t.Fatalf("omar's sign-in: %v", body)
	}
	if code, body := w.post(omar, "/payouts/approve", nil); code != http.StatusForbidden || body["code"] != "errors.auth.forbidden" {
		t.Errorf("omar's payout: %d %v", code, body)
	}
	if code := w.get(omar, "/reports"); code != http.StatusForbidden {
		t.Errorf("omar's reports: %d", code)
	}

	// Lina has no address, so no second proof: an unverified session.
	lina := w.browser()
	if body := w.signIn(lina, "lina"); body["verified"] != false {
		t.Fatalf("lina's sign-in: %v", body)
	}
	if code := w.get(lina, "/me"); code != 200 {
		t.Errorf("lina's /me: %d", code)
	}
	if code := w.get(lina, "/reports"); code != 200 {
		t.Errorf("lina's reports, which need no verified session: %d", code)
	}
	if code, body := w.post(lina, "/payouts/approve", nil); code != http.StatusForbidden || body["code"] != "errors.auth.not_verified" {
		t.Errorf("lina's payout: %d %v", code, body)
	}

	// Max is staff with no second factor: staff aren't signed in unverified.
	staff := w.browser()
	if code, body := w.post(staff, "/sign-in", url.Values{"login": {"max"}, "password": {pw}}); code == 200 {
		t.Errorf("max's sign-in: %d %v", code, body)
	}
	if code := w.get(staff, "/me"); code != http.StatusUnauthorized {
		t.Errorf("max's /me: %d", code)
	}

	// Signing out ends the session.
	w.post(sara, "/sign-out", nil)
	if code := w.get(sara, "/me"); code != http.StatusUnauthorized {
		t.Errorf("/me after signing out: %d", code)
	}
}

// A sign-in from another origin is refused, though it carries no session;
// a wrong password is refused alike for a known and an unknown login.
func TestWebRefusals(t *testing.T) {
	w := newWorld(t)
	c := w.browser()
	form := url.Values{"login": {"sara@toyshop.example"}, "password": {pw}}
	if code, _ := w.post(c, "/sign-in", form, "Origin", "https://evil.example"); code != http.StatusForbidden {
		t.Errorf("a cross-origin sign-in: %d", code)
	}
	if _, sent := w.out.Last("sara@toyshop.example"); sent {
		t.Error("a cross-origin sign-in sent a code")
	}
	var bodies []map[string]any
	for _, login := range []string{"sara@toyshop.example", "nobody@toyshop.example"} {
		code, body := w.post(c, "/sign-in", url.Values{"login": {login}, "password": {"wrong password here"}})
		if code != http.StatusUnauthorized {
			t.Errorf("%s with a wrong password: %d", login, code)
		}
		bodies = append(bodies, body)
	}
	if bodies[0]["code"] != bodies[1]["code"] || bodies[0]["message"] != bodies[1]["message"] {
		t.Errorf("a known and an unknown login answer differently: %v %v", bodies[0], bodies[1])
	}
}

func (w *world) api(path string, in any, access string) (int, map[string]any) {
	w.t.Helper()
	var body *bytes.Reader
	method := "GET"
	if in != nil {
		b, _ := json.Marshal(in)
		body, method = bytes.NewReader(b), "POST"
	} else {
		body = bytes.NewReader(nil)
	}
	r, _ := http.NewRequest(method, w.srv.URL+path, body)
	if access != "" {
		r.Header.Set("Authorization", "Bearer "+access)
	}
	return w.do(w.srv.Client(), r)
}

// The API: a password and an emailed code give tokens; the access token
// signs requests in; Refresh rotates; a refresh token used again after the
// grace ends the session.
func TestAPI(t *testing.T) {
	w := newWorld(t)
	// A code sent with the password is no shortcut: the code is still asked for.
	code, body := w.api("/api/sign-in", map[string]string{"login": "omar@toyshop.example", "password": pw, "code": "123456"}, "")
	if code != 200 || body["next"] != "code" {
		t.Fatalf("sign-in: %d %v", code, body)
	}
	w.clock.advance(time.Second)
	code, body = w.api("/api/sign-in", map[string]string{"flow": body["flow"].(string), "code": w.code("omar@toyshop.example")}, "")
	if code != 200 || body["verified"] != true {
		t.Fatalf("the code: %d %v", code, body)
	}
	access, refresh := body["access"].(string), body["refresh"].(string)
	// The sign-in went through Load, which read the client's address.
	if ss, err := w.shop.Auth.Sessions(context.Background(), "u2"); err != nil || len(ss) != 1 || !ss[0].Client.Addr.IsValid() {
		t.Errorf("the API session's client: %v %v", ss, err)
	}
	if code, me := w.api("/api/me", nil, access); code != 200 || me["user"] != "u2" {
		t.Errorf("/api/me: %d %v", code, me)
	}
	if code, _ := w.api("/api/me", nil, ""); code != http.StatusUnauthorized {
		t.Errorf("/api/me without a token: %d", code)
	}
	code, next := w.api("/api/refresh", map[string]string{"refresh": refresh}, "")
	if code != 200 || next["refresh"] == refresh {
		t.Fatalf("refresh: %d %v", code, next)
	}
	w.clock.advance(11 * time.Second)
	if code, _ := w.api("/api/refresh", map[string]string{"refresh": refresh}, ""); code != http.StatusUnauthorized {
		t.Errorf("a refresh token used again: %d", code)
	}
	if code, _ := w.api("/api/me", nil, next["access"].(string)); code != http.StatusUnauthorized {
		t.Errorf("the session after the reuse: %d", code)
	}
}

// postJSON posts raw JSON, as the page posts a credential.
func (w *world) postJSON(c *http.Client, path string, body []byte) (int, map[string]any) {
	w.t.Helper()
	r, _ := http.NewRequest("POST", w.srv.URL+path, bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	return w.do(c, r)
}

// optionsOf takes a passkey's options out of a reply.
func optionsOf(t *testing.T, body map[string]any) json.RawMessage {
	t.Helper()
	o, err := json.Marshal(body["options"])
	if err != nil || body["options"] == nil {
		t.Fatalf("no options in %v", body)
	}
	return o
}

// M7.3's done-when: the example signs in and enrolls with a passkey, and a
// passkey alone makes a verified session. Sara, staff, adds a passkey from
// her two-factor session; a new browser then signs in by passkey alone, is
// verified and approves a payout; signing in by password then asks for the
// passkey, not the code; and a step-up takes the passkey too.
func TestPasskey(t *testing.T) {
	w := newWorld(t)
	sara := w.browser()
	if body := w.signIn(sara, "sara@toyshop.example"); body["verified"] != true {
		t.Fatalf("sara's sign-in: %v", body)
	}
	pk := passkeytest.New(t, "https://toyshop.example")
	code, body := w.post(sara, "/passkey/enroll", nil)
	if code != 200 {
		t.Fatalf("enroll: %d %v", code, body)
	}
	code, body = w.postJSON(sara, "/passkey/enroll/finish?label=Sara%27s+laptop", pk.Create(optionsOf(t, body)))
	if codes, _ := body["recovery_codes"].([]any); code != 200 || len(codes) == 0 {
		t.Fatalf("enroll finish: %d %v", code, body)
	}
	if fs, _ := w.shop.Auth.Factors(context.Background(), "u1"); len(fs) != 1 || fs[0].Label != "Sara's laptop" {
		t.Errorf("factors: %+v", fs)
	}

	// A new browser, by passkey alone.
	laptop := w.browser()
	code, body = w.post(laptop, "/passkey/options", nil)
	if code != 200 || body["next"] != "passkey" {
		t.Fatalf("options: %d %v", code, body)
	}
	code, body = w.postJSON(laptop, "/passkey/prove", pk.Get(optionsOf(t, body)))
	if code != 200 || body["user"] != "u1" || body["verified"] != true {
		t.Fatalf("passkey sign-in: %d %v", code, body)
	}
	if code, _ := w.post(laptop, "/payouts/approve", nil); code != 200 {
		t.Errorf("a payout after a passkey: %d", code)
	}

	// The password now asks for the passkey, not a code.
	phone := w.browser()
	code, body = w.post(phone, "/sign-in", url.Values{"login": {"sara@toyshop.example"}, "password": {pw}})
	if code != 200 || body["next"] != "passkey" {
		t.Fatalf("password: %d %v", code, body)
	}
	if code, body = w.postJSON(phone, "/passkey/prove", pk.Get(optionsOf(t, body))); code != 200 || body["verified"] != true {
		t.Fatalf("password and passkey: %d %v", code, body)
	}

	// A stale proof, stepped up by passkey.
	w.clock.advance(6 * time.Minute)
	if code, _ := w.post(laptop, "/payouts/approve", nil); code != http.StatusForbidden {
		t.Errorf("a stale payout: %d", code)
	}
	code, body = w.post(laptop, "/step-up", nil)
	if code != 200 || body["next"] != "passkey" {
		t.Fatalf("step-up: %d %v", code, body)
	}
	if code, body = w.postJSON(laptop, "/passkey/prove", pk.Get(optionsOf(t, body))); code != 200 {
		t.Fatalf("step-up proof: %d %v", code, body)
	}
	if code, _ := w.post(laptop, "/payouts/approve", nil); code != 200 {
		t.Errorf("a payout after the step-up: %d", code)
	}

	// A passkey nobody enrolled is refused, as a wrong password is.
	stranger := passkeytest.New(t, "https://toyshop.example")
	stranger.Create(json.RawMessage(`{"rp":{"id":"toyshop.example"},"user":{"id":"dTk"},"challenge":"AAAA"}`))
	other := w.browser()
	_, body = w.post(other, "/passkey/options", nil)
	if code, body := w.postJSON(other, "/passkey/prove", stranger.Get(optionsOf(t, body))); code != http.StatusUnauthorized || body["code"] != "errors.auth.bad_credentials" {
		t.Errorf("a stranger's passkey: %d %v", code, body)
	}
}
