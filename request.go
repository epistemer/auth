package auth

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/epistemer/errors"
	bolt "go.etcd.io/bbolt"

	"github.com/epistemer/auth/internal/secrets"
	"github.com/epistemer/auth/internal/store"
	"github.com/epistemer/auth/internal/storepb"
)

// seenEvery is how often a session's Seen is written (§5.6.2).
const seenEvery = time.Minute

// beforeTouch lets a test act between reading a session and writing its
// Seen. It is nil outside tests.
var beforeTouch func()

// Load attaches the request's session, when it has a live one, and its
// client. It rejects nothing but a forged request: with the cookie carrier
// it checks every request that carries no bearer token with
// http.CrossOriginProtection, a request without a session too (§5.9).
//
// A request with an Authorization: Bearer header is never signed in through
// its cookies: that header is why it skips the cross-origin check. Signing
// in or out still ends the cookie session it carried.
//
// Load replaces what an outer Load attached, so a route under
// Load(Bearer()) never sees a cookie session from a Load(Cookie()) around
// it.
func (a *Auth) Load(carriers ...Carrier) func(http.Handler) http.Handler {
	var cookie, bearerCarrier bool
	for _, c := range carriers {
		cookie = cookie || c.c == storepb.Carrier_CARRIER_COOKIE
		bearerCarrier = bearerCarrier || c.c == storepb.Carrier_CARRIER_BEARER
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := WithClient(r.Context(), a.client(r))
			ctx = context.WithValue(ctx, clockKey{}, a.now)
			ctx = withSession(ctx, nil)
			ctx = context.WithValue(ctx, carriedKey{}, (*Session)(nil))
			ctx = context.WithValue(ctx, flowTokenKey{}, "")
			ctx = context.WithValue(ctx, deviceTokenKey{}, "")
			if cookie {
				bearer := hasBearer(r)
				if !bearer {
					if err := a.cop.Check(r); err != nil {
						a.record(ctx, Event{Kind: "request.refused", Reason: "cross_origin"})
						a.rejectWith(w, r.WithContext(ctx), ErrForbidden.Wrap(err))
						return
					}
				}
				if s := a.cookieSession(ctx, r); s != nil {
					ctx = context.WithValue(ctx, carriedKey{}, s)
					if !bearer {
						ctx = withSession(ctx, s)
					}
				}
				if c, err := r.Cookie(cookieName("flow", a.cfg.AuthCookieInsecure())); !bearer && err == nil && c.Value != "" {
					ctx = context.WithValue(ctx, flowTokenKey{}, c.Value)
				}
				if c, err := r.Cookie(cookieName("device", a.cfg.AuthCookieInsecure())); !bearer && err == nil && c.Value != "" {
					ctx = context.WithValue(ctx, deviceTokenKey{}, c.Value)
				}
			}
			// The bearer carrier: an access token, checked as §5.6.6 says.
			// No cross-origin check: a browser doesn't attach one itself.
			if bearerCarrier && hasBearer(r) {
				if s := a.bearerSession(ctx, bearerToken(r.Header.Values("Authorization"))); s != nil {
					ctx = withSession(ctx, s)
				}
			}
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// hasBearer reports whether any of r's Authorization headers is a bearer
// token. "Bearer" with nothing after it is none.
func hasBearer(r *http.Request) bool {
	for _, h := range r.Header.Values("Authorization") {
		if len(h) > 7 && strings.EqualFold(h[:7], "bearer ") && strings.TrimSpace(h[7:]) != "" {
			return true
		}
	}
	return false
}

// client reads who made r: WithClientAddr's answer, else the peer address.
func (a *Auth) client(r *http.Request) Client {
	var addr netip.Addr
	if a.clientAddr != nil {
		addr = a.clientAddr(r)
	} else if ap, err := netip.ParseAddrPort(r.RemoteAddr); err == nil {
		addr = ap.Addr()
	} else if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		addr, _ = netip.ParseAddr(host)
	} else {
		addr, _ = netip.ParseAddr(r.RemoteAddr)
	}
	return Client{Addr: addr.Unmap(), UserAgent: r.UserAgent()}
}

// cookieSession returns the live session the request's session cookie
// names, or nil. A store error is logged and counts as no session, the
// side Require refuses. It decides with one reading of the clock, and a
// session the write of Seen finds ended or replaced is no session.
func (a *Auth) cookieSession(ctx context.Context, r *http.Request) *Session {
	c, err := r.Cookie(cookieName("session", a.cfg.AuthCookieInsecure()))
	if err != nil || c.Value == "" {
		return nil
	}
	hash := secrets.Hash(c.Value)
	var rec storepb.Session
	err = a.db.View(func(tx *bolt.Tx) error {
		id := store.B(tx, store.SessionTokens).Get(hash)
		if id == nil {
			return store.ErrNotFound
		}
		return store.Get(tx, store.Sessions, id, &rec)
	})
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil {
		slog.ErrorContext(ctx, "auth: reading a session", "err", err)
		return nil
	}
	now := a.now().UnixNano()
	if rec.Carrier != storepb.Carrier_CARRIER_COOKIE || !a.liveAt(&rec, now) {
		return nil
	}
	if now-rec.Seen >= int64(seenEvery) {
		if beforeTouch != nil {
			beforeTouch()
		}
		alive, err := a.touch(rec.Id, hash, now)
		if err != nil {
			slog.ErrorContext(ctx, "auth: writing a session's last use", "err", err)
			return nil
		}
		if !alive {
			return nil
		}
		rec.Seen = now
	}
	return toSession(&rec)
}

// touch writes a session's Seen, with Batch (ADR 0002), and reports whether
// the token still names it and it is still live at now.
func (a *Auth) touch(id string, hash []byte, now int64) (bool, error) {
	var alive bool
	err := a.db.Batch(func(tx *bolt.Tx) error {
		alive = false
		if string(store.B(tx, store.SessionTokens).Get(hash)) != id {
			return nil
		}
		var rec storepb.Session
		if err := store.Get(tx, store.Sessions, []byte(id), &rec); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return nil
			}
			return err
		}
		if !a.liveAt(&rec, now) {
			return nil
		}
		alive = true
		if rec.Seen >= now {
			return nil
		}
		rec.Seen = now
		return store.Put(tx, store.Sessions, []byte(id), &rec)
	})
	return alive, err
}

// rejectWith answers a refused request: WithReject's handler, or the
// error's status and its message in the request's locale.
func (a *Auth) rejectWith(w http.ResponseWriter, r *http.Request, err error) {
	if a.reject != nil {
		a.reject(w, r, err)
		return
	}
	http.Error(w, errors.T(r.Context(), err), errors.KindOf(err).Status())
}

// Requirement is something a request's session must meet.
type Requirement interface {
	Check(ctx context.Context, s *Session) error
}

// Level is how verified a session must be. A Level is a Requirement.
type Level int

const (
	Verified   Level = iota // the default: a verified session
	Unverified              // any session
)

// Check meets the level or returns ErrNotVerified. A Level other than the
// two is never met.
func (l Level) Check(_ context.Context, s *Session) error {
	switch {
	case l == Unverified:
		return nil
	case l == Verified && s.Verified:
		return nil
	case l == Verified:
		return ErrNotVerified
	}
	return ErrForbidden.Wrap(fmt.Errorf("auth: unknown level %d", int(l)))
}

type within time.Duration

// Within needs a proof, of any method, made no longer ago than d. A device
// never meets it (§5.7.9).
func Within(d time.Duration) Requirement { return within(d) }

func (w within) Check(ctx context.Context, s *Session) error {
	since := nowFrom(ctx).Add(-time.Duration(w))
	for _, f := range s.Factors {
		// An identity's proof of one factor shows the provider's session,
		// which may be weeks old: like a device, it meets no Within
		// (review 0027).
		if isIdentity(f.Method) && !f.verified {
			continue
		}
		if !f.At.Before(since) {
			return nil
		}
	}
	return ErrStale
}

type clockKey struct{}

// nowFrom is Auth's clock, which Load and Check put in the context, or the
// wall clock.
func nowFrom(ctx context.Context) time.Time {
	if f, ok := ctx.Value(clockKey{}).(func() time.Time); ok {
		return f()
	}
	return time.Now()
}

// Require rejects a request whose session doesn't meet every requirement,
// through WithReject's handler. With no requirement that names a level, it
// needs a verified session.
//
// It panics on a nil requirement, so a mistake shows when routes are built.
func (a *Auth) Require(reqs ...Requirement) func(http.Handler) http.Handler {
	if slices.Contains(reqs, nil) {
		panic("auth: Require with a nil requirement")
	}
	reqs = append([]Requirement(nil), reqs...)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if err := a.Check(r.Context(), reqs...); err != nil {
				a.rejectWith(w, r, err)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// Check is Require for code that isn't a route. It returns ErrNoSession
// without a session, else the first requirement's error.
func (a *Auth) Check(ctx context.Context, reqs ...Requirement) error {
	// A Level given outright decides the route's level. Otherwise the
	// default, Verified, holds unless every requirement names its own
	// level, as auth/access's Can does; each named level is enforced here
	// too, so a requirement can't claim one it doesn't check (A18).
	explicit, unnamed := false, len(reqs) == 0
	for _, r := range reqs {
		if r == nil {
			return errors.New("auth: a nil requirement")
		}
		if _, ok := r.(Level); ok {
			explicit = true
			continue
		}
		if _, ok := r.(interface{ RequiredLevel() Level }); !ok {
			unnamed = true
		}
	}
	s, ok := From(ctx)
	if !ok {
		return ErrNoSession
	}
	ctx = context.WithValue(ctx, clockKey{}, a.now)
	if !explicit && unnamed {
		reqs = append([]Requirement{Verified}, reqs...)
	}
	for _, r := range reqs {
		if named, ok := r.(interface{ RequiredLevel() Level }); ok {
			if err := named.RequiredLevel().Check(ctx, s); err != nil {
				return err
			}
		}
		if err := r.Check(ctx, s); err != nil {
			return err
		}
	}
	return nil
}

// SignOut ends the session the request carried and clears the session
// cookie: its cookie session, also one beside a bearer header, else its
// bearer session. Without a session it only clears the cookie. If ending
// fails the cookie stays, so the user can try again.
func (a *Auth) SignOut(ctx context.Context, w http.ResponseWriter) error {
	if s, ok := carried(ctx); ok {
		if err := a.end(ctx, s.User, s.ID, "signout"); err != nil {
			return err
		}
	}
	insecure := a.cfg.AuthCookieInsecure()
	http.SetCookie(w, &http.Cookie{
		Name: cookieName("session", insecure), Value: "", Path: "/", MaxAge: -1,
		Secure: !insecure, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
	return nil
}

// Revoke ends one of a user's sessions. An ID that isn't that user's does
// nothing, so an ID from a request can't reach someone else's session.
func (a *Auth) Revoke(ctx context.Context, user UserID, id SessionID) error {
	return a.end(ctx, user, id, "revoked")
}

func (a *Auth) end(ctx context.Context, user UserID, id SessionID, reason string) error {
	var ended bool
	err := a.db.Update(func(tx *bolt.Tx) error {
		var rec storepb.Session
		if err := store.Get(tx, store.Sessions, []byte(id), &rec); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return nil
			}
			return err
		}
		if rec.UserId != string(user) {
			return nil
		}
		var err error
		ended, err = a.endSession(tx, string(id))
		return err
	})
	if err != nil {
		return err
	}
	if ended {
		a.record(ctx, Event{Kind: "session.ended", User: user, Session: id, Reason: reason})
	}
	return nil
}

// RevokeUser ends every session of a user.
func (a *Auth) RevokeUser(ctx context.Context, id UserID) error {
	if err := validID(id); err != nil {
		return err
	}
	var ended []string
	err := a.db.Update(func(tx *bolt.Tx) error {
		var err error
		ended, err = a.endSessions(tx, id, "")
		return err
	})
	if err != nil {
		return err
	}
	for _, s := range ended {
		a.record(ctx, Event{Kind: "session.ended", User: id, Session: SessionID(s), Reason: "revoked_user"})
	}
	return nil
}

// Sessions returns a user's live sessions, oldest first.
func (a *Auth) Sessions(ctx context.Context, id UserID) ([]Session, error) {
	if validID(id) != nil {
		return nil, nil
	}
	var out []Session
	err := a.db.View(func(tx *bolt.Tx) error {
		return store.Scan(tx, store.SessionsByUser, store.Prefix([]byte(id)), func(k, _ []byte) error {
			var rec storepb.Session
			if err := store.Get(tx, store.Sessions, k[len(id)+1:], &rec); err != nil {
				if errors.Is(err, store.ErrNotFound) {
					return nil
				}
				return err
			}
			if rec.UserId == string(id) && a.live(&rec) {
				out = append(out, *toSession(&rec))
			}
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	slices.SortFunc(out, func(x, y Session) int { return x.Created.Compare(y.Created) })
	return out, nil
}
