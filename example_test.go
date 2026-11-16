package auth_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/epistemer/auth"
	"github.com/epistemer/auth/authtest"
)

// directory is a toy shop's users: a real app reads its database.
type directory struct{}

var sara = auth.User{ID: "u1", Name: "sara@toyshop.example"}

func (directory) Find(_ context.Context, login string) (auth.User, error) {
	if login == sara.Name {
		return sara, nil
	}
	return auth.User{}, auth.ErrNoUser
}

func (directory) Get(_ context.Context, id auth.UserID) (auth.User, error) {
	if id == sara.ID {
		return sara, nil
	}
	return auth.User{}, auth.ErrNoUser
}

func (directory) Address(_ context.Context, id auth.UserID, ch auth.Channel) (string, error) {
	if id == sara.ID && ch == auth.ChannelEmail {
		return "sara@toyshop.example", nil
	}
	return "", nil
}

// mailbox keeps the last message: a real app renders and sends it.
type mailbox struct {
	mu   sync.Mutex
	last auth.Message
}

func (m *mailbox) Send(_ context.Context, msg auth.Message) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.last = msg
	return nil
}

func (m *mailbox) Last() auth.Message {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.last
}

const password = "orange tiger juggles 47 lamps"

// openShop opens a store in a temporary directory and builds an Auth over it,
// with sara's password set. authtest.Config stands in for the app's cfgx
// settings, which satisfy auth.Config.
func openShop(opts ...auth.Option) (*auth.Auth, *mailbox, func()) {
	dir, err := os.MkdirTemp("", "auth-example")
	if err != nil {
		panic(err)
	}
	db, err := bolt.Open(filepath.Join(dir, "shop.db"), 0o600, nil)
	if err != nil {
		panic(err)
	}
	out := &mailbox{}
	a, err := auth.New(db, authtest.Config(), directory{}, out, append([]auth.Option{auth.WithRecorder(quiet{})}, opts...)...)
	if err != nil {
		panic(err)
	}
	if err := a.SetPassword(context.Background(), sara.ID, password); err != nil {
		panic(err)
	}
	return a, out, func() { db.Close(); os.RemoveAll(dir) }
}

// A sign-in collects proofs until the user's policy is met. The default
// policy wants two: here the password, then a code sent by email.
func Example() {
	a, out, done := openShop()
	defer done()
	ctx := context.Background()

	flow, _ := a.SignIn(ctx, "sara@toyshop.example", auth.Cookie())
	flow, _ = a.Prove(ctx, flow.Token, auth.Password(password))
	fmt.Println("after the password:", flow.Ready, flow.Offers)

	ch, _ := a.Challenge(ctx, flow.Token, auth.MethodEmailCode)
	fmt.Println("code sent to:", ch.SentTo)
	flow, _ = a.Prove(ctx, flow.Token, auth.EmailCode(out.Last().Code))
	fmt.Println("after the code:", flow.Ready, flow.Verified)

	res, err := a.Finish(ctx, flow.Token)
	if err != nil {
		panic(err)
	}
	// On the web, res.Write(w) sets the session cookie.
	fmt.Println("session:", res.Session.User, res.Session.Verified, len(res.Session.Factors))
	// Output:
	// after the password: false [email_code]
	// code sent to: s•••@toyshop.example
	// after the code: true true
	// session: u1 true 2
}

// Routes go through Load, which reads the session and refuses forged
// cross-origin requests, then Require, which states what a route needs.
// With no level named, a route needs a verified session.
func ExampleAuth_Require() {
	a, _, done := openShop()
	defer done()

	mux := http.NewServeMux()
	web := a.Load(auth.Cookie())
	mux.Handle("GET /orders", web(a.Require(auth.Unverified)(http.HandlerFunc(orders))))
	mux.Handle("POST /payouts", web(a.Require(auth.Within(5*time.Minute))(http.HandlerFunc(orders))))

	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest("GET", "https://toyshop.example/orders", nil))
	fmt.Println("without a session:", w.Code)

	r := httptest.NewRequest("POST", "https://toyshop.example/payouts", nil)
	r.Header.Set("Origin", "https://evil.example")
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	fmt.Println("from another origin:", w.Code)
	// Output:
	// without a session: 401
	// from another origin: 403
}

func orders(w http.ResponseWriter, r *http.Request) {
	s, _ := auth.From(r.Context())
	fmt.Fprintln(w, "orders of", s.User)
}

// A step-up proves the user again before a dangerous action, so that
// Within is met. It is bound to the session it starts from, so it runs
// inside requests that carry the session.
func ExampleAuth_StepUp() {
	clock := time.Now()
	a, out, done := openShop(auth.WithClock(func() time.Time { return clock }))
	defer done()

	mux := http.NewServeMux()
	web := a.Load(auth.Cookie())
	// The first request starts the step-up and sends a code.
	mux.Handle("POST /step-up", web(a.Require(auth.Unverified)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess, _ := auth.From(r.Context())
		flow, err := a.StepUp(r.Context(), sess)
		if err == nil {
			_, err = a.Challenge(r.Context(), flow.Token, auth.MethodEmailCode)
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		flow.Write(w) // the flow cookie
	}))))
	// The second proves the code and finishes it. Finish refuses a step-up
	// from any session but the one it started from.
	mux.Handle("POST /step-up/code", web(a.Require(auth.Unverified)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, _ := auth.FlowToken(r.Context())
		flow, err := a.Prove(r.Context(), token, auth.EmailCode(r.FormValue("code")))
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		res, err := a.Finish(r.Context(), flow.Token)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		res.Write(w)
	}))))
	mux.Handle("POST /payouts", web(a.Require(auth.Within(5*time.Minute))(http.HandlerFunc(orders))))

	b := browser{h: mux, cookies: signIn(a, out)}
	fmt.Println("payout at once:", b.post("/payouts", ""))
	clock = clock.Add(6 * time.Minute)
	fmt.Println("payout six minutes on:", b.post("/payouts", ""))
	fmt.Println("step-up:", b.post("/step-up", ""))
	fmt.Println("its code:", b.post("/step-up/code", out.Last().Code))
	fmt.Println("payout after it:", b.post("/payouts", ""))
	// Output:
	// payout at once: 200
	// payout six minutes on: 403
	// step-up: 200
	// its code: 200
	// payout after it: 200
}

// browser keeps cookies between requests, as a browser would.
type browser struct {
	h       http.Handler
	cookies map[string]*http.Cookie
}

func (b *browser) post(path, code string) int {
	r := httptest.NewRequest("POST", "https://toyshop.example"+path, strings.NewReader(url.Values{"code": {code}}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range b.cookies {
		r.AddCookie(c)
	}
	w := httptest.NewRecorder()
	b.h.ServeHTTP(w, r)
	for _, c := range w.Result().Cookies() {
		if c.MaxAge < 0 {
			delete(b.cookies, c.Name)
		} else {
			b.cookies[c.Name] = c
		}
	}
	return w.Code
}

// Recovery sends a link; holding it is the proof. Follow is safe on a GET
// a mail scanner fetches first; the POST sets the new password and makes no
// session, so the user signs in next. Sara has no second factor, so the link
// is enough; a user with one is offered it after Follow (flow.Offers), and
// proves it before Finish.
func ExampleAuth_Recover() {
	a, out, done := openShop()
	defer done()
	ctx := context.Background()

	flow, _ := a.Recover(ctx, "sara@toyshop.example")
	if _, err := a.Challenge(ctx, flow.Token, auth.MethodEmailLink); err != nil {
		panic(err)
	}
	link := out.Last().Token // the app puts it in a URL

	flow, _ = a.Follow(ctx, link)
	fmt.Println("ready:", flow.Ready)
	res, err := a.Finish(ctx, flow.Token, auth.NewPassword("violet engine sings 93 rivers"))
	fmt.Println("session:", res.Session != nil, err)
	// Output:
	// ready: true
	// session: false <nil>
}

// signIn signs sara in with two proofs and returns the cookies Result.Write
// set.
func signIn(a *auth.Auth, out *mailbox) map[string]*http.Cookie {
	ctx := context.Background()
	flow, _ := a.SignIn(ctx, "sara@toyshop.example", auth.Cookie())
	flow, _ = a.Prove(ctx, flow.Token, auth.Password(password))
	_, _ = a.Challenge(ctx, flow.Token, auth.MethodEmailCode)
	flow, _ = a.Prove(ctx, flow.Token, auth.EmailCode(out.Last().Code))
	res, err := a.Finish(ctx, flow.Token)
	if err != nil {
		panic(err)
	}
	w := httptest.NewRecorder()
	res.Write(w)
	cookies := map[string]*http.Cookie{}
	for _, c := range w.Result().Cookies() {
		cookies[c.Name] = c
	}
	return cookies
}

// quiet drops events: an app records them for its audit log. Without
// WithRecorder they go to log/slog.
type quiet struct{}

func (quiet) Record(context.Context, auth.Event) {}
