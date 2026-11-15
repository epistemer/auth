package auth

import (
	"context"

	"github.com/epistemer/errors"
	bolt "go.etcd.io/bbolt"

	"github.com/epistemer/auth/internal/secrets"
	"github.com/epistemer/auth/internal/store"
	"github.com/epistemer/auth/internal/storepb"
)

// Refresh tokens (interface §5.6.8) and reissued claims (§5.6.10–11).

// betweenRefreshLooks lets a test act between Refresh's two transactions.
// It is nil outside tests.
var betweenRefreshLooks func()

// Refresh replaces a refresh token with a new one and a new access token,
// with the claims the Claimer returns now (§5.6.8).
//
// A token used again ends its session and records refresh.reused. The one
// exception is a client that never got the answer: for refresh.grace after
// a token was replaced, it returns the same successor, but only while that
// successor is unused. Reuse is judged first, before the directory or the
// Claimer is asked anything, so neither failing can spare a session. A
// disabled user is refused. An unknown token, or one whose session ended,
// is ErrNoSession.
func (a *Auth) Refresh(ctx context.Context, refresh string) (Result, error) {
	hash := secrets.Hash(refresh)
	key := secrets.KeyFromToken([]byte(refresh), "refresh")

	// First, reuse: one transaction, nothing asked of anyone else.
	var user string
	var sid string
	var grace string // the successor a lost answer gets again
	var reused bool
	err := a.db.Update(func(tx *bolt.Tx) error {
		user, sid, grace, reused = "", "", "", false
		now := a.now().UnixNano()
		r, s, err := a.refreshRecord(tx, hash, now)
		if err != nil {
			return err
		}
		user, sid = s.UserId, s.Id
		if r.Replaced == 0 {
			return nil
		}
		if next, ok := a.graceSuccessor(tx, r, key, hash, now); ok {
			grace = next
			return nil
		}
		// Used again after its successor: someone else holds one of the
		// two. The session ends (§5.6.8).
		reused = true
		_, err = a.endSession(tx, s.Id)
		return err
	})
	if errors.Is(err, store.ErrNotFound) {
		return Result{}, ErrNoSession
	}
	if err != nil {
		return Result{}, err
	}
	if reused {
		a.record(ctx, Event{Kind: "refresh.reused", User: UserID(user), Session: SessionID(sid)})
		a.record(ctx, Event{Kind: "session.ended", User: UserID(user), Session: SessionID(sid), Reason: "refresh_reused"})
		return Result{}, ErrNoSession
	}

	if betweenRefreshLooks != nil {
		betweenRefreshLooks()
	}
	u, err := a.user(ctx, UserID(user))
	if err != nil {
		return Result{}, err
	}
	if u.Disabled {
		a.record(ctx, Event{Kind: "session.refused", User: u.ID, Session: SessionID(sid), Reason: "disabled"})
		return Result{}, ErrUserDisabled
	}
	claims, err := a.claims(ctx, u)
	if err != nil {
		return Result{}, err
	}

	var next, access string
	var out *storepb.Session
	err = a.db.Update(func(tx *bolt.Tx) error {
		next, access, out, reused = "", "", nil, false
		now := a.now().UnixNano()
		r, s, err := a.refreshRecord(tx, hash, now)
		if err != nil {
			return err
		}
		switch {
		case r.Replaced != 0:
			// Replaced since the first look, or a grace answer: the same
			// successor while the grace holds, else reuse. Two refreshes
			// racing with one token are a client asking twice.
			n, ok := a.graceSuccessor(tx, r, key, hash, now)
			if !ok {
				reused = true
				_, err := a.endSession(tx, s.Id)
				return err
			}
			next, grace = n, n
		default:
			t, err := a.issueRefreshAfter(tx, s, hash)
			if err != nil {
				return err
			}
			sealed, err := secrets.SealWith(key, []byte(t), hash)
			if err != nil {
				return err
			}
			r.Replaced, r.Successor, next = now, sealed, t
			if err := store.Put(tx, store.Refresh, hash, r); err != nil {
				return err
			}
			// Rotating this token wipes its predecessor's sealed copy of
			// it: the grace for that one is over.
			if len(r.Predecessor) > 0 {
				p := new(storepb.Refresh)
				if err := store.Get(tx, store.Refresh, r.Predecessor, p); err == nil {
					p.Successor = nil
					if err := store.Put(tx, store.Refresh, r.Predecessor, p); err != nil {
						return err
					}
				} else if !errors.Is(err, store.ErrNotFound) {
					return err
				}
			}
		}
		// A new access token with the claims as they are now. A refresh is
		// a use of the session; Seen is written at most once a minute.
		s.Claims = claims
		if now-s.Seen >= int64(seenEvery) {
			s.Seen = now
		}
		if err := store.Put(tx, store.Sessions, []byte(s.Id), s); err != nil {
			return err
		}
		if access, err = a.issueAccess(s); err != nil {
			return err
		}
		out = s
		return nil
	})
	if errors.Is(err, store.ErrNotFound) {
		return Result{}, ErrNoSession
	}
	if err != nil {
		return Result{}, err
	}
	if reused {
		a.record(ctx, Event{Kind: "refresh.reused", User: u.ID, Session: SessionID(sid)})
		a.record(ctx, Event{Kind: "session.ended", User: u.ID, Session: SessionID(sid), Reason: "refresh_reused"})
		return Result{}, ErrNoSession
	}
	reason := ""
	if grace != "" {
		reason = "grace"
	}
	a.record(ctx, Event{Kind: "session.refreshed", User: u.ID, Session: SessionID(out.Id), Reason: reason})
	return Result{Session: toSession(out), Access: access, Refresh: next}, nil
}

// refreshRecord reads a refresh token's record and its session, which must
// be a live bearer session; anything else is store.ErrNotFound.
func (a *Auth) refreshRecord(tx *bolt.Tx, hash []byte, now int64) (*storepb.Refresh, *storepb.Session, error) {
	r := new(storepb.Refresh)
	if err := store.Get(tx, store.Refresh, hash, r); err != nil {
		return nil, nil, err
	}
	s := new(storepb.Session)
	if err := store.Get(tx, store.Sessions, []byte(r.SessionId), s); err != nil {
		return nil, nil, err
	}
	if s.Carrier != storepb.Carrier_CARRIER_BEARER || !a.liveAt(s, now) {
		return nil, nil, store.ErrNotFound
	}
	return r, s, nil
}

// graceSuccessor returns a replaced token's successor if the grace holds:
// within refresh.grace of the replacement, with the successor still sealed
// here and not used yet.
func (a *Auth) graceSuccessor(tx *bolt.Tx, r *storepb.Refresh, key, hash []byte, now int64) (string, bool) {
	if now-r.Replaced >= int64(a.cfg.AuthRefreshGrace()) || len(r.Successor) == 0 {
		return "", false
	}
	pt, err := secrets.OpenWith(key, r.Successor, hash)
	if err != nil {
		return "", false
	}
	succ := new(storepb.Refresh)
	if err := store.Get(tx, store.Refresh, secrets.Hash(string(pt)), succ); err != nil || succ.Replaced != 0 {
		return "", false
	}
	return string(pt), true
}

// Reissue gives a session the claims the Claimer returns now: a new access
// token for a bearer session, which it returns, and new Session.Claims for
// a cookie one, set on s too, with no token (§5.6.10–11). The session is
// read from the store first: it must be live and s.User's. A disabled user
// is refused.
func (a *Auth) Reissue(ctx context.Context, s *Session) (string, error) {
	if s == nil {
		return "", ErrNoSession
	}
	var first storepb.Session
	err := a.db.View(func(tx *bolt.Tx) error { return store.Get(tx, store.Sessions, []byte(s.ID), &first) })
	if errors.Is(err, store.ErrNotFound) || err == nil && (first.UserId != string(s.User) || !a.live(&first)) {
		return "", ErrNoSession
	}
	if err != nil {
		return "", err
	}
	u, err := a.user(ctx, UserID(first.UserId))
	if err != nil {
		return "", err
	}
	if u.Disabled {
		a.record(ctx, Event{Kind: "session.refused", User: u.ID, Session: s.ID, Reason: "disabled"})
		return "", ErrUserDisabled
	}
	claims, err := a.claims(ctx, u)
	if err != nil {
		return "", err
	}
	var access string
	err = a.db.Update(func(tx *bolt.Tx) error {
		access = ""
		rec := new(storepb.Session)
		if err := store.Get(tx, store.Sessions, []byte(s.ID), rec); err != nil {
			return err
		}
		if rec.UserId != string(u.ID) || !a.live(rec) {
			return store.ErrNotFound
		}
		rec.Claims = claims
		if err := store.Put(tx, store.Sessions, []byte(rec.Id), rec); err != nil {
			return err
		}
		s.Claims = toSession(rec).Claims
		if rec.Carrier == storepb.Carrier_CARRIER_BEARER {
			var err error
			access, err = a.issueAccess(rec)
			return err
		}
		return nil
	})
	if errors.Is(err, store.ErrNotFound) {
		return "", ErrNoSession
	}
	if err != nil {
		return "", err
	}
	a.record(ctx, Event{Kind: "session.reissued", User: u.ID, Session: s.ID})
	return access, nil
}
