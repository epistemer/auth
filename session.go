package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"time"

	"github.com/epistemer/errors"
	bolt "go.etcd.io/bbolt"

	"github.com/epistemer/auth/internal/store"
	"github.com/epistemer/auth/internal/storepb"
)

// SessionID identifies a session. It is not a secret: the token is.
type SessionID string

// DeviceID identifies a registered device.
type DeviceID string

// Session is a signed-in session.
type Session struct {
	ID       SessionID
	User     UserID
	Verified bool
	Factors  []Factor
	Device   DeviceID
	Created  time.Time
	Seen     time.Time
	Expires  time.Time // the absolute end, session.lifetime after Created
	Client   Client    // as seen when it was made
	Claims   map[string]any
}

// Factor is one proof a session's flows accepted.
type Factor struct {
	Method string
	At     time.Time
}

type sessionKey struct{}

// From returns the session Load attached to the request.
func From(ctx context.Context) (*Session, bool) {
	s, ok := ctx.Value(sessionKey{}).(*Session)
	return s, ok && s != nil
}

func withSession(ctx context.Context, s *Session) context.Context {
	return context.WithValue(ctx, sessionKey{}, s)
}

type carriedKey struct{}

// carried returns the live cookie session a request carried, whether or
// not Load attached it: one beside a bearer header isn't attached, but
// signing in or out still ends it (§5.6.3).
func carried(ctx context.Context) (*Session, bool) {
	if s, ok := ctx.Value(carriedKey{}).(*Session); ok && s != nil {
		return s, true
	}
	return From(ctx)
}

// live reports whether a session can still be used: not ended, within
// session.lifetime, and seen within its idle lifetime (§5.6.2).
func (a *Auth) live(s *storepb.Session) bool { return a.liveAt(s, a.now().UnixNano()) }

// liveAt is live at a given time, so one decision reads the clock once.
func (a *Auth) liveAt(s *storepb.Session, now int64) bool {
	idle := a.cfg.AuthSessionIdle()
	if s.Remembered {
		idle = a.cfg.AuthSessionRememberedIdle()
	}
	return s.Ended == 0 && now < s.Expires && now < s.Seen+int64(idle)
}

// putSession writes a session and its indexes.
func putSession(tx *bolt.Tx, s *storepb.Session) error {
	if err := store.Put(tx, store.Sessions, []byte(s.Id), s); err != nil {
		return err
	}
	if err := store.B(tx, store.SessionTokens).Put(s.TokenHash, []byte(s.Id)); err != nil {
		return err
	}
	return store.B(tx, store.SessionsByUser).Put(store.Key([]byte(s.UserId), []byte(s.Id)), nil)
}

// endSessions ends every live session of a user but keep, in tx.
func (a *Auth) endSessions(tx *bolt.Tx, user UserID, keep string) ([]string, error) {
	var ids []string
	err := store.Scan(tx, store.SessionsByUser, store.Prefix([]byte(user)), func(k, _ []byte) error {
		ids = append(ids, string(k[len(user)+1:]))
		return nil
	})
	if err != nil {
		return nil, err
	}
	var ended []string
	for _, id := range ids {
		if id == keep {
			continue
		}
		ok, err := a.endSession(tx, id)
		if err != nil {
			return nil, err
		}
		if ok {
			ended = append(ended, id)
		}
	}
	return ended, nil
}

// endSession ends one session, in tx: its token stops resolving at once,
// and it leaves the user's index. The record stays, marked ended, until
// Sweep. A missing or ended session is left as it is.
func (a *Auth) endSession(tx *bolt.Tx, id string) (bool, error) {
	var s storepb.Session
	if err := store.Get(tx, store.Sessions, []byte(id), &s); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return false, nil
		}
		return false, err
	}
	if s.Ended != 0 {
		return false, nil
	}
	s.Ended = a.now().UnixNano()
	if err := store.Delete(tx, store.SessionTokens, s.TokenHash); err != nil {
		return false, err
	}
	if err := store.Delete(tx, store.SessionsByUser, store.Key([]byte(s.UserId), []byte(id))); err != nil {
		return false, err
	}
	return true, store.Put(tx, store.Sessions, []byte(id), &s)
}

func toSession(s *storepb.Session) *Session {
	out := &Session{
		ID: SessionID(s.Id), User: UserID(s.UserId), Verified: s.Verified, Device: DeviceID(s.DeviceId),
		Created: time.Unix(0, s.Created), Seen: time.Unix(0, s.Seen), Expires: time.Unix(0, s.Expires),
	}
	for _, f := range s.Factors {
		out.Factors = append(out.Factors, Factor{Method: f.Method, At: time.Unix(0, f.At)})
	}
	if c := s.Client; c != nil {
		var addr netip.Addr
		_ = addr.UnmarshalBinary(c.Addr)
		out.Client = Client{Addr: addr, UserAgent: c.UserAgent}
	}
	if len(s.Claims) > 0 {
		_ = json.Unmarshal(s.Claims, &out.Claims)
	}
	return out
}

func clientRecord(c Client) *storepb.Client {
	addr, _ := c.Addr.MarshalBinary()
	return &storepb.Client{Addr: addr, UserAgent: c.UserAgent}
}

// claims asks the Claimer for the user's claims, as JSON.
func (a *Auth) claims(ctx context.Context, u User) ([]byte, error) {
	if a.claimer == nil {
		return nil, nil
	}
	c, err := a.claimer.Claims(ctx, u)
	if err != nil {
		return nil, fmt.Errorf("auth: claims: %w", err)
	}
	if c == nil {
		return nil, nil
	}
	b, err := json.Marshal(c)
	if err != nil {
		return nil, fmt.Errorf("auth: claims aren't JSON: %w", err)
	}
	return b, nil
}

// Result is what Finish made.
type Result struct {
	Session       *Session // SignIn and StepUp
	Access        string   // bearer
	Refresh       string   // bearer
	Device        string   // bearer: the device's token, new or replaced
	RecoveryCodes []string // shown once, when the first second factor was enrolled

	cookie   string // the cookie carrier's session token
	remember bool
	expires  time.Time
	insecure bool
}

func (a *Auth) result(s *storepb.Session, token string) Result {
	r := Result{Session: toSession(s), remember: s.Remembered, expires: time.Unix(0, s.Expires), insecure: a.cfg.AuthCookieInsecure()}
	if s.Carrier == storepb.Carrier_CARRIER_COOKIE {
		r.cookie = token
	}
	return r
}

// Write sets the cookie carrier's cookies (session, device) and clears the
// flow cookie. A session that isn't remembered gets a cookie that ends with
// the browser's session; the server ends it at its idle lifetime either way.
func (r Result) Write(w http.ResponseWriter) {
	if r.cookie != "" {
		c := &http.Cookie{
			Name: cookieName("session", r.insecure), Value: r.cookie, Path: "/",
			Secure: !r.insecure, HttpOnly: true, SameSite: http.SameSiteLaxMode,
		}
		if r.remember {
			c.Expires = r.expires
		}
		http.SetCookie(w, c)
	}
	http.SetCookie(w, &http.Cookie{
		Name: cookieName("flow", r.insecure), Value: "", Path: "/", MaxAge: -1,
		Secure: !r.insecure, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
}
