// Package shop is a toy shop that signs people in with auth: on the web
// with a cookie, a password and an emailed code, and through its API with
// bearer tokens. Staff approve payouts, which needs a permission and a
// proof made in the last five minutes.
package shop

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"sync"
	"time"

	autherrors "github.com/epistemer/errors"
	bolt "go.etcd.io/bbolt"

	"github.com/epistemer/auth"
	"github.com/epistemer/auth/access"
	"github.com/epistemer/auth/passkey"
)

// The shop's permissions.
var (
	PayoutApprove = access.Permission("payout.approve", "Approve payouts")
	ReportView    = access.Permission("report.view", "View reports", auth.Unverified)
)

// Directory is the shop's users: in memory, as a real shop's would be its
// database.
type Directory struct {
	mu     sync.Mutex
	users  map[string]auth.User // by login
	emails map[auth.UserID]string
}

// NewDirectory returns an empty directory.
func NewDirectory() *Directory {
	return &Directory{users: map[string]auth.User{}, emails: map[auth.UserID]string{}}
}

// Add adds a user under a login, with an email address or none.
func (d *Directory) Add(id auth.UserID, login, name, email string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.users[login] = auth.User{ID: id, Name: name}
	d.emails[id] = email
}

func (d *Directory) Find(_ context.Context, login string) (auth.User, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if u, ok := d.users[login]; ok {
		return u, nil
	}
	return auth.User{}, auth.ErrNoUser
}

func (d *Directory) Get(_ context.Context, id auth.UserID) (auth.User, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, u := range d.users {
		if u.ID == id {
			return u, nil
		}
	}
	return auth.User{}, auth.ErrNoUser
}

func (d *Directory) Address(_ context.Context, id auth.UserID, ch auth.Channel) (string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if ch == auth.ChannelEmail {
		return d.emails[id], nil
	}
	return "", nil
}

// Outbox stands in for the shop's mailer: it keeps the last message to each
// address. A real shop would render and send it.
type Outbox struct {
	mu   sync.Mutex
	last map[string]auth.Message
}

// NewOutbox returns an empty outbox.
func NewOutbox() *Outbox { return &Outbox{last: map[string]auth.Message{}} }

func (o *Outbox) Send(_ context.Context, m auth.Message) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.last[m.To] = m
	return nil
}

// Last returns the last message to an address.
func (o *Outbox) Last(to string) (auth.Message, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	m, ok := o.last[to]
	return m, ok
}

// policy: customers may shop with an unverified session and skip the code
// on a device they trust. Staff, who can approve payouts, always prove two
// factors, on every device; one who can't make a second proof isn't signed
// in. When the store can't say, the user is treated as staff.
func (s *Shop) policy(ctx context.Context, u auth.User) auth.Policy {
	if errors.Is(s.Access.Check(ctx, u.ID, PayoutApprove), auth.ErrForbidden) {
		return auth.Policy{AllowUnverified: true, TrustDevices: true}
	}
	return auth.Policy{}
}

// Shop is the app.
type Shop struct {
	Auth   *auth.Auth
	Access *access.Access
}

// Config is what the shop reads: auth's keys and the passkeys'. The
// settings cfgx generates from authschema.Group(authschema.Passkey())
// satisfy it.
type Config interface {
	auth.Config
	passkey.Config
}

// New builds the shop over a store, a config, a directory and an outbox.
func New(db *bolt.DB, cfg Config, dir auth.Directory, out auth.Sender, opts ...auth.Option) (*Shop, error) {
	ac, err := access.New(db)
	if err != nil {
		return nil, err
	}
	pk, err := passkey.New(cfg)
	if err != nil {
		return nil, err
	}
	s := &Shop{Access: ac}
	// Refusals by Load and Require answer like every other error: JSON.
	reject := auth.WithReject(fail)
	base := []auth.Option{
		auth.WithPolicy(s.policy), reject,
		// A passkey signs in alone, or stands as the second proof.
		auth.WithMethods(pk), auth.WithFirst(auth.MethodPassword, auth.MethodPasskey),
	}
	s.Auth, err = auth.New(db, cfg, dir, out, append(base, opts...)...)
	if err != nil {
		return nil, err
	}
	return s, nil
}

// Handler is the shop's routes.
func (s *Shop) Handler() http.Handler {
	mux := http.NewServeMux()
	web := s.Auth.Load(auth.Cookie())
	api := s.Auth.Load(auth.Bearer())
	a := s.Auth

	// The web: every route, sign-in included, goes through Load, which is
	// the cross-origin check (§5.9).
	mux.Handle("POST /sign-in", web(http.HandlerFunc(s.signIn)))
	mux.Handle("POST /sign-in/code", web(http.HandlerFunc(s.code)))
	mux.Handle("POST /sign-out", web(http.HandlerFunc(s.signOut)))
	mux.Handle("GET /me", web(a.Require(auth.Unverified)(http.HandlerFunc(me))))
	mux.Handle("GET /reports", web(a.Require(s.Access.Can(ReportView))(http.HandlerFunc(ok("reports")))))
	mux.Handle("POST /step-up", web(a.Require(auth.Unverified)(http.HandlerFunc(s.stepUp))))
	mux.Handle("POST /payouts/approve",
		web(a.Require(s.Access.Can(PayoutApprove), auth.Within(5*time.Minute))(http.HandlerFunc(ok("approved")))))

	// Passkeys: options for a sign-in with no login (the page's autofill),
	// the answer to any passkey challenge the flow cookie names, and adding
	// one from a verified session.
	mux.Handle("POST /passkey/options", web(http.HandlerFunc(s.passkeyOptions)))
	mux.Handle("POST /passkey/prove", web(http.HandlerFunc(s.passkeyProve)))
	mux.Handle("POST /passkey/enroll", web(a.Require()(http.HandlerFunc(s.passkeyEnroll))))
	mux.Handle("POST /passkey/enroll/finish", web(a.Require()(http.HandlerFunc(s.passkeyEnrolled))))

	// The API: bearer tokens, no cookies, no cross-origin check. Its
	// sign-in goes through Load too, which reads the client's address: the
	// throttle counts failures by it (§5.2).
	mux.Handle("POST /api/sign-in", api(http.HandlerFunc(s.apiSignIn)))
	mux.Handle("POST /api/refresh", api(http.HandlerFunc(s.apiRefresh)))
	mux.Handle("GET /api/me", api(a.Require(auth.Unverified)(http.HandlerFunc(me))))
	return mux
}

func ok(what string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) { reply(w, map[string]string{"ok": what}) }
}

func me(w http.ResponseWriter, r *http.Request) {
	s, _ := auth.From(r.Context())
	reply(w, map[string]any{"user": s.User, "verified": s.Verified})
}

// signIn takes a login and a password. With them the session may already
// be ready, unverified; the shop asks for the emailed code whenever one is
// on offer, so most sign-ins end verified.
func (s *Shop) signIn(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	f, err := s.Auth.SignIn(ctx, r.FormValue("login"), auth.Cookie())
	if err == nil {
		f, err = s.Auth.Prove(ctx, f.Token, auth.Password(r.FormValue("password")))
	}
	if err != nil {
		fail(w, r, err)
		return
	}
	s.next(w, r, f)
}

// next asks for a second proof when the flow offers one, else finishes: a
// passkey when the user holds one, else the emailed code.
func (s *Shop) next(w http.ResponseWriter, r *http.Request, f auth.Flow) {
	if !f.Verified && contains(f.Offers, auth.MethodPasskey) {
		s.askPasskey(w, r, f)
		return
	}
	if !f.Verified && contains(f.Offers, auth.MethodEmailCode) {
		ch, err := s.Auth.Challenge(r.Context(), f.Token, auth.MethodEmailCode)
		if err != nil {
			fail(w, r, err)
			return
		}
		f.Write(w)
		reply(w, map[string]any{"next": "code", "sent_to": ch.SentTo})
		return
	}
	s.finish(w, r, f)
}

// code takes the emailed code for the flow in the flow cookie.
func (s *Shop) code(w http.ResponseWriter, r *http.Request) {
	token, ok := auth.FlowToken(r.Context())
	if !ok {
		fail(w, r, auth.ErrFlowExpired)
		return
	}
	f, err := s.Auth.Prove(r.Context(), token, auth.EmailCode(r.FormValue("code")))
	if err != nil {
		fail(w, r, err)
		return
	}
	s.finish(w, r, f)
}

func (s *Shop) finish(w http.ResponseWriter, r *http.Request, f auth.Flow) {
	res, err := s.Auth.Finish(r.Context(), f.Token)
	if err != nil {
		fail(w, r, err)
		return
	}
	res.Write(w)
	reply(w, map[string]any{"user": res.Session.User, "verified": res.Session.Verified})
}

// stepUp starts a step-up, which is bound to the session, and sends the
// emailed code; /sign-in/code finishes it. A user with no address proves
// the password instead.
func (s *Shop) stepUp(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	sess, _ := auth.From(ctx)
	f, err := s.Auth.StepUp(ctx, sess)
	if err != nil {
		fail(w, r, err)
		return
	}
	if contains(f.Offers, auth.MethodPasskey) {
		s.askPasskey(w, r, f)
		return
	}
	if contains(f.Offers, auth.MethodEmailCode) {
		ch, err := s.Auth.Challenge(ctx, f.Token, auth.MethodEmailCode)
		if err != nil {
			fail(w, r, err)
			return
		}
		f.Write(w)
		reply(w, map[string]any{"next": "code", "sent_to": ch.SentTo})
		return
	}
	if f, err = s.Auth.Prove(ctx, f.Token, auth.Password(r.FormValue("password"))); err != nil {
		fail(w, r, err)
		return
	}
	s.finish(w, r, f)
}

// askPasskey answers with a passkey's options for the flow, which the flow
// cookie carries; the page passes them to navigator.credentials.get and
// posts the answer to /passkey/prove.
func (s *Shop) askPasskey(w http.ResponseWriter, r *http.Request, f auth.Flow) {
	ch, err := s.Auth.Challenge(r.Context(), f.Token, auth.MethodPasskey)
	if err != nil {
		fail(w, r, err)
		return
	}
	f.Write(w)
	reply(w, map[string]any{"next": "passkey", "options": ch.Options})
}

// passkeyOptions starts a sign-in that names no login, as the sign-in page
// loads, so the browser can offer the user's passkeys in autofill.
func (s *Shop) passkeyOptions(w http.ResponseWriter, r *http.Request) {
	f, err := s.Auth.SignInWithout(r.Context(), auth.Cookie())
	if err != nil {
		fail(w, r, err)
		return
	}
	s.askPasskey(w, r, f)
}

// passkeyProve takes the browser's answer, the JSON of the credential, for
// the flow in the flow cookie: a sign-in, its second proof, or a step-up.
func (s *Shop) passkeyProve(w http.ResponseWriter, r *http.Request) {
	token, ok := auth.FlowToken(r.Context())
	if !ok {
		fail(w, r, auth.ErrFlowExpired)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 64<<10+1))
	if err != nil {
		fail(w, r, err)
		return
	}
	f, err := s.Auth.Prove(r.Context(), token, passkey.Response(body))
	if err != nil {
		fail(w, r, err)
		return
	}
	s.finish(w, r, f)
}

// passkeyEnroll starts adding a passkey to the session's user, and answers
// with the options for navigator.credentials.create.
func (s *Shop) passkeyEnroll(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	sess, _ := auth.From(ctx)
	f, err := s.Auth.Enroll(ctx, sess, auth.MethodPasskey)
	if err != nil {
		fail(w, r, err)
		return
	}
	ch, err := s.Auth.Challenge(ctx, f.Token, auth.MethodPasskey)
	if err != nil {
		fail(w, r, err)
		return
	}
	f.Write(w)
	reply(w, map[string]any{"options": ch.Options})
}

// passkeyEnrolled takes the browser's new credential and stores it, under
// the label the page names (?label=); the first factor brings recovery
// codes, shown once.
func (s *Shop) passkeyEnrolled(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	token, ok := auth.FlowToken(ctx)
	if !ok {
		fail(w, r, auth.ErrFlowExpired)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 64<<10+1))
	if err != nil {
		fail(w, r, err)
		return
	}
	f, err := s.Auth.Prove(ctx, token, passkey.Response(body))
	if err != nil {
		fail(w, r, err)
		return
	}
	res, err := s.Auth.Finish(ctx, f.Token, auth.FactorLabel(r.URL.Query().Get("label")))
	if err != nil {
		fail(w, r, err)
		return
	}
	res.Write(w)
	reply(w, map[string]any{"recovery_codes": res.RecoveryCodes})
}

func (s *Shop) signOut(w http.ResponseWriter, r *http.Request) {
	if err := s.Auth.SignOut(r.Context(), w); err != nil {
		fail(w, r, err)
		return
	}
	reply(w, map[string]string{"ok": "signed out"})
}

// apiSignIn signs in an API client in two calls: {"login", "password"},
// which answers {"next": "code", "flow"} when a code was sent, then
// {"flow", "code"}.
func (s *Shop) apiSignIn(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var in struct {
		Login    string `json:"login"`
		Password string `json:"password"`
		Flow     string `json:"flow"`
		Code     string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		http.Error(w, "bad JSON", http.StatusBadRequest)
		return
	}
	var f auth.Flow
	var err error
	if in.Flow == "" {
		f, err = s.Auth.SignIn(ctx, in.Login, auth.Bearer())
		if err == nil {
			f, err = s.Auth.Prove(ctx, f.Token, auth.Password(in.Password))
		}
		if err == nil && !f.Verified && contains(f.Offers, auth.MethodEmailCode) {
			_, err = s.Auth.Challenge(ctx, f.Token, auth.MethodEmailCode)
			if err == nil {
				reply(w, map[string]string{"next": "code", "flow": f.Token})
				return
			}
		}
	} else {
		f, err = s.Auth.Prove(ctx, in.Flow, auth.EmailCode(in.Code))
	}
	if err != nil {
		fail(w, r, err)
		return
	}
	res, err := s.Auth.Finish(ctx, f.Token)
	if err != nil {
		fail(w, r, err)
		return
	}
	reply(w, map[string]any{"access": res.Access, "refresh": res.Refresh, "verified": res.Session.Verified})
}

func (s *Shop) apiRefresh(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Refresh string `json:"refresh"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		http.Error(w, "bad JSON", http.StatusBadRequest)
		return
	}
	res, err := s.Auth.Refresh(r.Context(), in.Refresh)
	if err != nil {
		fail(w, r, err)
		return
	}
	reply(w, map[string]any{"access": res.Access, "refresh": res.Refresh})
}

// fail answers an error as an API would: its kind's status and its message
// for people; a wait also says how long.
func fail(w http.ResponseWriter, r *http.Request, err error) {
	if d, ok := auth.RetryAfter(err); ok {
		// Whole seconds, rounded up.
		w.Header().Set("Retry-After", strconv.Itoa(max(1, int((d+time.Second-1)/time.Second))))
	}
	kind := autherrors.KindOf(err)
	if kind.Status() >= 500 {
		slog.ErrorContext(r.Context(), "shop", "err", err)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(kind.Status())
	p := autherrors.Public(err)
	json.NewEncoder(w).Encode(map[string]string{"code": p.K(), "message": p.T(r.Context())})
}

func reply(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}
