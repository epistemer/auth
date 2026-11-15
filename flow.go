package auth

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/epistemer/errors"
	bolt "go.etcd.io/bbolt"
	"golang.org/x/text/unicode/norm"

	"github.com/epistemer/auth/internal/password"
	"github.com/epistemer/auth/internal/secrets"
	"github.com/epistemer/auth/internal/store"
	"github.com/epistemer/auth/internal/storepb"
)

// Purpose is what a flow is for.
type Purpose int

const (
	PurposeSignIn Purpose = iota + 1
	PurposeStepUp
	PurposeRecover
	PurposeAccept
	PurposeEnroll
)

// The built-in methods' names.
const (
	MethodPassword     = "password"
	MethodEmailCode    = "email_code"
	MethodSMSCode      = "sms_code"
	MethodEmailLink    = "email_link"
	MethodTOTP         = "totp"
	MethodRecoveryCode = "recovery_code"
)

// secondMethods are the methods that count as a second proof (§5.7.2).
var secondMethods = map[string]bool{
	MethodTOTP: true, MethodRecoveryCode: true, MethodEmailCode: true, MethodSMSCode: true,
}

// Flow is a flow's state as the client may see it.
type Flow struct {
	Token    string
	Purpose  Purpose
	Ready    bool     // Finish will succeed
	Verified bool     // a SignIn or StepUp would end in a verified session
	Offers   []string // the methods the UI may show next
	Expires  time.Time

	insecure bool
}

// Write keeps the flow's token in the cookie carrier's flow cookie, and
// FlowToken reads it back from a request that went through Load. An app
// may carry the token another way; it is a secret either way (§5.1).
func (f Flow) Write(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: cookieName("flow", f.insecure), Value: f.Token, Path: "/", Expires: f.Expires,
		Secure: !f.insecure, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
}

type flowTokenKey struct{}

// FlowToken returns the flow token a request carried in the flow cookie.
func FlowToken(ctx context.Context) (string, bool) {
	t, _ := ctx.Value(flowTokenKey{}).(string)
	return t, t != ""
}

// cookieName gives a cookie its __Host- prefix, which cookie.insecure drops
// for development over plain HTTP.
func cookieName(base string, insecure bool) string {
	if insecure {
		return base
	}
	return "__Host-" + base
}

// Carrier is how a session travels: a cookie, or a bearer token pair.
type Carrier struct{ c storepb.Carrier }

// Cookie is the browser's carrier.
func Cookie() Carrier { return Carrier{storepb.Carrier_CARRIER_COOKIE} }

// Bearer is an app's carrier: an access token and a refresh token.
func Bearer() Carrier { return Carrier{storepb.Carrier_CARRIER_BEARER} }

// StartOption changes how SignIn starts a flow.
type StartOption func(*startOptions)

type startOptions struct{ device string }

// Device passes the device token an app stored. The cookie carrier reads
// its own.
func Device(token string) StartOption { return func(o *startOptions) { o.device = token } }

// Proof is one proof of who the user is.
type Proof interface{ Method() string }

// secret is a proof whose value is a secret. It prints as its method only.
type secret struct{ method, value string }

func (p secret) Method() string   { return p.method }
func (p secret) String() string   { return p.method + " proof" }
func (p secret) GoString() string { return p.String() }

func Password(pw string) Proof       { return secret{MethodPassword, pw} }
func EmailCode(code string) Proof    { return secret{MethodEmailCode, code} }
func SMSCode(code string) Proof      { return secret{MethodSMSCode, code} }
func TOTP(code string) Proof         { return secret{MethodTOTP, code} }
func RecoveryCode(code string) Proof { return secret{MethodRecoveryCode, code} }

// FinishOption changes what Finish does.
type FinishOption func(*finishOptions)

type finishOptions struct {
	newPassword *string
	remember    bool
	device      *string
}

// NewPassword sets the password a Recover, an Accept or an Enroll of the
// password stores.
func NewPassword(pw string) FinishOption { return func(o *finishOptions) { o.newPassword = &pw } }

// Remember gives a SignIn's session the longer idle lifetime.
func Remember() FinishOption { return func(o *finishOptions) { o.remember = true } }

// RememberDevice registers the device in a SignIn or StepUp that proved a
// second method. Devices arrive with milestone M2.3; until then no flow can
// prove a second method, and the option registers nothing, as §5.7.5 says.
func RememberDevice(label string) FinishOption {
	return func(o *finishOptions) { o.device = &label }
}

// loginKey is the throttle key of a login that didn't resolve: the SHA-256
// of its NFKC, lower-case, trimmed form, so spelling it differently buys
// nothing and the store holds no login (§5.8.1).
func loginKey(login string) []byte {
	k := sha256.Sum256([]byte(strings.TrimSpace(strings.ToLower(norm.NFKC.String(login)))))
	return k[:]
}

// SignIn starts a sign-in. It returns a flow for an unknown login exactly
// as for a known one (§5.1.3).
func (a *Auth) SignIn(ctx context.Context, login string, c Carrier, opts ...StartOption) (Flow, error) {
	switch c.c {
	case storepb.Carrier_CARRIER_COOKIE:
	case storepb.Carrier_CARRIER_BEARER:
		return Flow{}, fmt.Errorf("auth: the bearer carrier arrives with milestone M3: %w", errors.ErrUnsupported)
	default:
		return Flow{}, errors.New("auth: SignIn needs auth.Cookie() or auth.Bearer()")
	}
	var o startOptions
	for _, f := range opts {
		f(&o)
	}
	rec := &storepb.Flow{Purpose: int32(PurposeSignIn), LoginKey: loginKey(login), Carrier: c.c}
	u, err := a.dir.Find(ctx, login)
	switch {
	case err == nil:
		if err := validID(u.ID); err != nil {
			return Flow{}, err
		}
		rec.UserId = string(u.ID)
	case errors.Is(err, ErrNoUser):
		rec.NoUser = true
	default:
		return Flow{}, fmt.Errorf("auth: finding a login: %w", err)
	}
	return a.start(ctx, rec)
}

func validID(id UserID) error {
	if id == "" || len(id) > 64 || strings.IndexByte(string(id), 0) >= 0 {
		return fmt.Errorf("auth: the directory returned a user ID that is empty, over 64 bytes or holds a zero byte")
	}
	return nil
}

// StepUp starts a flow that upgrades s: to verified, or with a fresh proof.
// It is bound to s and can only be finished for it (§5.1.12).
func (a *Auth) StepUp(ctx context.Context, s *Session) (Flow, error) {
	if s == nil {
		return Flow{}, ErrNoSession
	}
	var sess storepb.Session
	err := a.db.View(func(tx *bolt.Tx) error {
		return store.Get(tx, store.Sessions, []byte(s.ID), &sess)
	})
	if errors.Is(err, store.ErrNotFound) || err == nil && !a.live(&sess) {
		return Flow{}, ErrNoSession
	}
	if err != nil {
		return Flow{}, err
	}
	return a.start(ctx, &storepb.Flow{
		Purpose: int32(PurposeStepUp), UserId: sess.UserId, SessionId: sess.Id, Carrier: sess.Carrier,
	})
}

func (a *Auth) start(ctx context.Context, rec *storepb.Flow) (Flow, error) {
	now := a.now()
	rec.Created = now.UnixNano()
	rec.Expires = now.Add(a.cfg.AuthFlowLifetime()).UnixNano()
	token, hash := secrets.NewToken()
	if err := a.db.Update(func(tx *bolt.Tx) error {
		return store.Put(tx, store.Flows, hash, rec)
	}); err != nil {
		return Flow{}, err
	}
	v, err := a.view(ctx, rec, nil)
	if err != nil {
		return Flow{}, err
	}
	a.record(ctx, Event{Kind: "flow.started", User: UserID(rec.UserId), Session: SessionID(rec.SessionId), Reason: purposeWord(Purpose(rec.Purpose))})
	return a.flowOut(token, rec, v), nil
}

func purposeWord(p Purpose) string {
	return map[Purpose]string{
		PurposeSignIn: "signin", PurposeStepUp: "stepup", PurposeRecover: "recover",
		PurposeAccept: "accept", PurposeEnroll: "enroll",
	}[p]
}

// view is what a flow's proofs add up to.
type view struct {
	ready, verified bool
	offers          []string
	cannot          bool // the policy needs verification and nothing left can give it
}

// view works out a flow's state. Before a SignIn's first proof it doesn't
// look at the user at all, so a known and an unknown login answer alike
// (§5.1.3). sess is the bound session of a StepUp; nil loads it.
func (a *Auth) view(ctx context.Context, rec *storepb.Flow, sess *storepb.Session) (view, error) {
	proven := func(f func(string) bool) bool {
		return slices.ContainsFunc(rec.Proofs, func(p *storepb.Factor) bool { return f(p.Method) })
	}
	isFirst := func(m string) bool { return slices.Contains(a.first, m) }
	switch Purpose(rec.Purpose) {
	case PurposeSignIn:
		if !proven(isFirst) {
			return view{offers: slices.Clone(a.first)}, nil
		}
		u, err := a.user(ctx, UserID(rec.UserId))
		if err != nil {
			return view{}, err
		}
		pol := a.policy(ctx, u)
		seconds, err := a.seconds(ctx, u)
		if err != nil {
			return view{}, err
		}
		verified := proven(isSecond)
		v := view{verified: verified, ready: verified || pol.AllowUnverified}
		if !verified {
			v.offers = seconds
			v.cannot = !pol.AllowUnverified && len(seconds) == 0
		}
		return v, nil
	case PurposeStepUp:
		if sess == nil {
			sess = new(storepb.Session)
			err := a.db.View(func(tx *bolt.Tx) error {
				return store.Get(tx, store.Sessions, []byte(rec.SessionId), sess)
			})
			if errors.Is(err, store.ErrNotFound) {
				return view{}, ErrNoSession
			}
			if err != nil {
				return view{}, err
			}
		}
		// A step-up outlives nothing: once its session ends, so does it.
		if !a.live(sess) {
			return view{}, ErrNoSession
		}
		u, err := a.user(ctx, UserID(rec.UserId))
		if err != nil {
			return view{}, err
		}
		pol := a.policy(ctx, u)
		seconds, err := a.seconds(ctx, u)
		if err != nil {
			return view{}, err
		}
		verified := sess.Verified || proven(isSecond)
		v := view{verified: verified, ready: len(rec.Proofs) > 0 && (verified || pol.AllowUnverified)}
		has, err := a.hasPassword(UserID(rec.UserId))
		if err != nil {
			return view{}, err
		}
		if has {
			v.offers = append(v.offers, MethodPassword)
		}
		v.offers = append(v.offers, seconds...)
		v.offers = slices.DeleteFunc(v.offers, func(m string) bool { return proven(func(p string) bool { return p == m }) })
		v.cannot = !verified && !pol.AllowUnverified && len(seconds) == 0
		return v, nil
	}
	return view{}, fmt.Errorf("auth: a flow with purpose %d", rec.Purpose)
}

func isSecond(m string) bool { return secondMethods[m] }

// seconds are the second methods the user can prove now. The built-in ones
// arrive with codes (M2) and authenticator apps (M4); until then a user has
// none, and only a policy that allows unverified sessions lets one sign in.
func (a *Auth) seconds(ctx context.Context, u User) ([]string, error) {
	return nil, nil
}

// user gets a user the flow already resolved.
func (a *Auth) user(ctx context.Context, id UserID) (User, error) {
	u, err := a.dir.Get(ctx, id)
	if err != nil {
		return User{}, fmt.Errorf("auth: getting user: %w", err)
	}
	return u, nil
}

func (a *Auth) flowOut(token string, rec *storepb.Flow, v view) Flow {
	return Flow{
		Token: token, Purpose: Purpose(rec.Purpose), Ready: v.ready, Verified: v.verified,
		Offers: v.offers, Expires: time.Unix(0, rec.Expires), insecure: a.cfg.AuthCookieInsecure(),
	}
}

// loadFlow reads a live flow by its token's hash.
func (a *Auth) loadFlow(hash []byte) (*storepb.Flow, error) {
	rec := new(storepb.Flow)
	err := a.db.View(func(tx *bolt.Tx) error { return store.Get(tx, store.Flows, hash, rec) })
	if errors.Is(err, store.ErrNotFound) {
		return nil, ErrFlowExpired
	}
	if err != nil {
		return nil, err
	}
	if a.now().UnixNano() >= rec.Expires {
		return nil, ErrFlowExpired
	}
	return rec, nil
}

// Flow returns a flow's current state.
func (a *Auth) Flow(ctx context.Context, token string) (Flow, error) {
	rec, err := a.loadFlow(secrets.Hash(token))
	if err != nil {
		return Flow{}, err
	}
	v, err := a.view(ctx, rec, nil)
	if err != nil {
		return Flow{}, err
	}
	return a.flowOut(token, rec, v), nil
}

// Prove adds a proof to a flow. A wrong proof returns the flow as it was,
// with the error.
func (a *Auth) Prove(ctx context.Context, token string, p Proof) (Flow, error) {
	hash := secrets.Hash(token)
	rec, err := a.loadFlow(hash)
	if err != nil {
		return Flow{}, err
	}
	v, err := a.view(ctx, rec, nil)
	if err != nil {
		return Flow{}, err
	}
	if p == nil || !slices.Contains(v.offers, p.Method()) {
		return a.flowOut(token, rec, v), ErrMethodUnavailable
	}
	switch p.Method() {
	case MethodPassword:
		s, ok := p.(secret)
		if !ok {
			return a.flowOut(token, rec, v), ErrMethodUnavailable
		}
		return a.provePassword(ctx, token, hash, rec, v, s.value)
	}
	return a.flowOut(token, rec, v), ErrMethodUnavailable
}

// provePassword does one password hash whatever the login: against the
// user's hash, or the dummy for an unknown login or a user with no
// password (§5.1.4).
func (a *Auth) provePassword(ctx context.Context, token string, hash []byte, rec *storepb.Flow, v view, pw string) (Flow, error) {
	before := a.flowOut(token, rec, v)
	var stored string
	if !rec.NoUser {
		var err error
		if stored, err = a.passwordHash(UserID(rec.UserId)); err != nil {
			return before, err
		}
	}
	ok, rehash := false, false
	reason := "bad_credentials"
	if stored == "" {
		if err := a.hasher.Dummy(ctx, pw); err != nil {
			return before, err
		}
	} else {
		var err error
		ok, rehash, err = a.hasher.Verify(ctx, pw, stored)
		switch {
		case errors.Is(err, password.ErrMalformed):
			reason = "malformed_hash"
		case err != nil:
			return before, err
		}
	}
	if !ok {
		a.record(ctx, Event{Kind: "proof.refused", User: UserID(rec.UserId), Session: SessionID(rec.SessionId), Method: MethodPassword, Reason: reason})
		return before, ErrBadCredentials
	}
	u, err := a.user(ctx, UserID(rec.UserId))
	if err != nil {
		return before, err
	}
	if u.Disabled {
		a.record(ctx, Event{Kind: "proof.refused", User: u.ID, Session: SessionID(rec.SessionId), Method: MethodPassword, Reason: "disabled"})
		return before, ErrUserDisabled
	}
	if rehash {
		// A failure here costs only the upgrade; the next sign-in retries.
		if phc, err := a.hasher.Hash(ctx, pw); err == nil {
			_ = a.storePassword(u.ID, phc, false)
		}
	}
	rec, err = a.addProof(hash, &storepb.Factor{Method: MethodPassword, At: a.now().UnixNano()})
	if err != nil {
		return before, err
	}
	a.record(ctx, Event{Kind: "proof.accepted", User: u.ID, Session: SessionID(rec.SessionId), Method: MethodPassword})
	v, err = a.view(ctx, rec, nil)
	if err != nil {
		return before, err
	}
	out := a.flowOut(token, rec, v)
	if v.cannot {
		return out, ErrCannotVerify
	}
	return out, nil
}

// addProof records a proof in the flow, which must still be live.
func (a *Auth) addProof(hash []byte, f *storepb.Factor) (*storepb.Flow, error) {
	rec := new(storepb.Flow)
	err := a.db.Update(func(tx *bolt.Tx) error {
		if err := store.Get(tx, store.Flows, hash, rec); err != nil {
			return err
		}
		if a.now().UnixNano() >= rec.Expires {
			return store.ErrNotFound
		}
		rec.Proofs = append(rec.Proofs, f)
		return store.Put(tx, store.Flows, hash, rec)
	})
	if errors.Is(err, store.ErrNotFound) {
		return nil, ErrFlowExpired
	}
	return rec, err
}

// Finish ends the flow. For a SignIn it makes the session; for a StepUp it
// upgrades the flow's session.
func (a *Auth) Finish(ctx context.Context, token string, opts ...FinishOption) (Result, error) {
	hash := secrets.Hash(token)
	rec, err := a.loadFlow(hash)
	if err != nil {
		return Result{}, err
	}
	var o finishOptions
	for _, f := range opts {
		f(&o)
	}
	switch Purpose(rec.Purpose) {
	case PurposeSignIn:
		return a.finishSignIn(ctx, hash, rec, o)
	case PurposeStepUp:
		return a.finishStepUp(ctx, hash, rec)
	}
	return Result{}, fmt.Errorf("auth: a flow with purpose %d", rec.Purpose)
}

func (a *Auth) finishSignIn(ctx context.Context, hash []byte, rec *storepb.Flow, o finishOptions) (Result, error) {
	v, err := a.view(ctx, rec, nil)
	if err != nil {
		return Result{}, err
	}
	if !v.ready {
		return Result{}, ErrNotReady
	}
	u, err := a.user(ctx, UserID(rec.UserId))
	if err != nil {
		return Result{}, err
	}
	if u.Disabled {
		a.record(ctx, Event{Kind: "session.refused", User: u.ID, Reason: "disabled"})
		return Result{}, ErrUserDisabled
	}
	claims, err := a.claims(ctx, u)
	if err != nil {
		return Result{}, err
	}
	now := a.now()
	token, tokenHash := secrets.NewToken()
	sess := &storepb.Session{
		Id: secrets.NewID(), UserId: string(u.ID), TokenHash: tokenHash, Carrier: rec.Carrier,
		Verified: v.verified, Generation: 1, Factors: rec.Proofs, Remembered: o.remember,
		Created: now.UnixNano(), Seen: now.UnixNano(), Expires: now.Add(a.cfg.AuthSessionLifetime()).UnixNano(),
		Client: clientRecord(clientFrom(ctx)), Claims: claims,
	}
	err = a.db.Update(func(tx *bolt.Tx) error {
		// The flow is spent here, in the transaction that makes the
		// session: of two concurrent Finishes only one finds it.
		if err := store.Get(tx, store.Flows, hash, new(storepb.Flow)); err != nil {
			return err
		}
		if err := store.Delete(tx, store.Flows, hash); err != nil {
			return err
		}
		// A sign-in never continues the session the request carries: that
		// one ends, whoever it belonged to (§5.6.3).
		if cur, ok := From(ctx); ok {
			if err := a.endSession(tx, string(cur.ID)); err != nil {
				return err
			}
		}
		return putSession(tx, sess)
	})
	if errors.Is(err, store.ErrNotFound) {
		return Result{}, ErrFlowExpired
	}
	if err != nil {
		return Result{}, err
	}
	a.record(ctx, Event{Kind: "session.created", User: u.ID, Session: SessionID(sess.Id), Reason: verifiedWord(sess.Verified)})
	return a.result(sess, token), nil
}

func verifiedWord(v bool) string {
	if v {
		return "verified"
	}
	return "unverified"
}

// finishStepUp upgrades the bound session in place: its new proofs, its
// status, a new token and a higher generation (§5.6.3, §5.7.7).
func (a *Auth) finishStepUp(ctx context.Context, hash []byte, rec *storepb.Flow) (Result, error) {
	cur, ok := From(ctx)
	if !ok {
		return Result{}, ErrNoSession
	}
	if string(cur.ID) != rec.SessionId {
		a.record(ctx, Event{Kind: "session.refused", User: cur.User, Session: cur.ID, Reason: "other_session"})
		return Result{}, ErrFlowExpired
	}
	v, err := a.view(ctx, rec, nil)
	if err != nil {
		return Result{}, err
	}
	if !v.ready {
		return Result{}, ErrNotReady
	}
	u, err := a.user(ctx, UserID(rec.UserId))
	if err != nil {
		return Result{}, err
	}
	if u.Disabled {
		a.record(ctx, Event{Kind: "session.refused", User: u.ID, Session: cur.ID, Reason: "disabled"})
		return Result{}, ErrUserDisabled
	}
	claims, err := a.claims(ctx, u)
	if err != nil {
		return Result{}, err
	}
	token, tokenHash := secrets.NewToken()
	sess := new(storepb.Session)
	err = a.db.Update(func(tx *bolt.Tx) error {
		if err := store.Get(tx, store.Flows, hash, new(storepb.Flow)); err != nil {
			return err
		}
		if err := store.Get(tx, store.Sessions, []byte(rec.SessionId), sess); err != nil {
			return err
		}
		if !a.live(sess) {
			return errNoSession
		}
		if err := store.Delete(tx, store.SessionTokens, sess.TokenHash); err != nil {
			return err
		}
		if err := store.Delete(tx, store.Flows, hash); err != nil {
			return err
		}
		sess.TokenHash = tokenHash
		sess.Verified = sess.Verified || v.verified
		sess.Generation++
		sess.Factors = append(sess.Factors, rec.Proofs...)
		sess.Claims = claims
		return putSession(tx, sess)
	})
	switch {
	case errors.Is(err, store.ErrNotFound):
		return Result{}, ErrFlowExpired
	case errors.Is(err, errNoSession):
		return Result{}, ErrNoSession
	case err != nil:
		return Result{}, err
	}
	a.record(ctx, Event{Kind: "session.upgraded", User: u.ID, Session: SessionID(sess.Id), Reason: verifiedWord(sess.Verified)})
	return a.result(sess, token), nil
}

var errNoSession = errors.New("auth: the session ended")
