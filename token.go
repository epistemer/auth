package auth

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"strings"
	"time"

	"github.com/epistemer/errors"
	bolt "go.etcd.io/bbolt"

	"github.com/epistemer/auth/internal/secrets"
	"github.com/epistemer/auth/internal/store"
	"github.com/epistemer/auth/internal/storepb"
)

// Access tokens (interface §5.6.5–7): a JWT whose header is exactly
// {"alg":"HS256","typ":"at+jwt"}, signed with the key derived for signing.

var b64 = base64.RawURLEncoding

// accessHeader is the only header an access token may have, as it travels.
var accessHeader = b64.EncodeToString([]byte(`{"alg":"HS256","typ":"at+jwt"}`))

// accessClaims are an access token's claims.
type accessClaims struct {
	Iss string          `json:"iss"`
	Aud string          `json:"aud"`
	Sub string          `json:"sub"`
	Sid string          `json:"sid"`
	Gen uint32          `json:"gen"`
	Iat int64           `json:"iat"`
	Exp int64           `json:"exp"`
	App json.RawMessage `json:"app,omitempty"`
}

// issueAccess makes an access token for a session, with its claims as they
// are now.
func (a *Auth) issueAccess(s *storepb.Session) (string, error) {
	now := a.now()
	c := accessClaims{
		Iss: a.cfg.AuthIssuer(), Aud: a.cfg.AuthIssuer(), Sub: s.UserId, Sid: s.Id, Gen: s.Generation,
		Iat: now.Unix(), Exp: now.Add(a.cfg.AuthAccessLifetime()).Unix(), App: s.Claims,
	}
	body, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	key, _ := a.keys.SignKey()
	signed := accessHeader + "." + b64.EncodeToString(body)
	return signed + "." + b64.EncodeToString(sign(key, signed)), nil
}

func sign(key []byte, s string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(s))
	return m.Sum(nil)
}

// errBadAccess is an access token Load won't take; it never leaves Load.
var errBadAccess = errors.New("auth: a bad access token")

// verifyAccess checks an access token at now (§5.6.6): the header's bytes,
// the signature in constant time under the current key and, during a
// rotation, the previous one, then the claims: one JSON object and nothing
// after it, iat no later than now and before exp, exp, iss and aud, an app
// claim that is an object. Then the session sid names, which must be a live
// bearer session of sub at generation gen. It returns that session and the
// claims the token was issued with.
func (a *Auth) verifyAccess(token string, now time.Time) (*storepb.Session, accessClaims, map[string]any, error) {
	var c accessClaims
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] != accessHeader {
		return nil, c, nil, errBadAccess
	}
	sig, err := b64.DecodeString(parts[2])
	if err != nil {
		return nil, c, nil, errBadAccess
	}
	signed := parts[0] + "." + parts[1]
	cur, prev := a.keys.SignKey()
	ok := hmac.Equal(sig, sign(cur, signed))
	if prev != nil {
		// Both, whichever matches, so the time taken says nothing.
		okPrev := hmac.Equal(sig, sign(prev, signed))
		ok = ok || okPrev
	}
	if !ok {
		return nil, c, nil, errBadAccess
	}
	body, err := b64.DecodeString(parts[1])
	if err != nil {
		return nil, c, nil, errBadAccess
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, c, nil, errBadAccess
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, c, nil, errBadAccess // something after the object
	}
	// The app's claims, when present, are an object: never null (A13).
	var app map[string]any
	if c.App != nil {
		if err := json.Unmarshal(c.App, &app); err != nil || app == nil {
			return nil, c, nil, errBadAccess
		}
	}
	issuer := a.cfg.AuthIssuer()
	if now.Unix() >= c.Exp || c.Iat <= 0 || c.Iat > now.Unix() || c.Iat >= c.Exp ||
		c.Iss != issuer || c.Aud != issuer || c.Sid == "" || c.Sub == "" {
		return nil, c, nil, errBadAccess
	}
	s := new(storepb.Session)
	err = a.db.View(func(tx *bolt.Tx) error { return store.Get(tx, store.Sessions, []byte(c.Sid), s) })
	if errors.Is(err, store.ErrNotFound) {
		return nil, c, nil, errBadAccess
	}
	if err != nil {
		return nil, c, nil, err
	}
	if s.Carrier != storepb.Carrier_CARRIER_BEARER || s.UserId != c.Sub || s.Generation != c.Gen || !a.liveAt(s, now.UnixNano()) {
		return nil, c, nil, errBadAccess
	}
	return s, c, app, nil
}

// bearerSession returns the session a request's access token names, with
// the claims it carries, or nil (§5.6.6). Its Seen is written at most once
// a minute, as for a cookie, and the write checks the session is still live
// at the token's generation.
func (a *Auth) bearerSession(ctx context.Context, token string) *Session {
	now := a.now()
	rec, c, app, err := a.verifyAccess(token, now)
	if err != nil {
		if !errors.Is(err, errBadAccess) {
			logStore(ctx, "auth: reading a session", err)
		}
		return nil
	}
	if ns := now.UnixNano(); ns-rec.Seen >= int64(seenEvery) {
		alive, err := a.touchBearer(rec.Id, c.Gen, ns)
		if err != nil || !alive {
			if err != nil {
				logStore(ctx, "auth: writing a session's last use", err)
			}
			return nil
		}
		rec.Seen = ns
	}
	rec.Claims = nil
	s := toSession(rec)
	// The claims the token was issued with, not the session's now (§5.6.7).
	s.Claims = app
	return s
}

// touchBearer writes a bearer session's Seen, with Batch, and reports
// whether it is still live at generation gen.
func (a *Auth) touchBearer(id string, gen uint32, now int64) (bool, error) {
	var alive bool
	err := a.db.Batch(func(tx *bolt.Tx) error {
		alive = false
		var rec storepb.Session
		if err := store.Get(tx, store.Sessions, []byte(id), &rec); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return nil
			}
			return err
		}
		if rec.Generation != gen || !a.liveAt(&rec, now) {
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

// bearerToken returns the token of the request's Authorization header, if
// it has exactly one and that one is a bearer token: two make the request
// ambiguous, and it signs nobody in.
func bearerToken(h []string) string {
	if len(h) != 1 {
		return ""
	}
	v := h[0]
	if len(v) > 7 && strings.EqualFold(v[:7], "bearer ") {
		return strings.TrimSpace(v[7:])
	}
	return ""
}

// issueRefresh makes a refresh token for a session, in tx (§5.6.8). The
// rotation and its grace come with Refresh.
func (a *Auth) issueRefresh(tx *bolt.Tx, s *storepb.Session) (string, error) {
	token, hash := secrets.NewToken()
	r := &storepb.Refresh{SessionId: s.Id, Issued: a.now().UnixNano()}
	if err := store.Put(tx, store.Refresh, hash, r); err != nil {
		return "", err
	}
	// The index's key names the token by its hash in hex (a key part holds
	// no zero byte); its value is the hash itself.
	return token, store.B(tx, store.RefreshBySession).Put(store.Key([]byte(s.Id), []byte(hex.EncodeToString(hash))), hash)
}

// issueRefreshAfter is issueRefresh for a token that replaces prev.
func (a *Auth) issueRefreshAfter(tx *bolt.Tx, s *storepb.Session, prev []byte) (string, error) {
	token, err := a.issueRefresh(tx, s)
	if err != nil {
		return "", err
	}
	r := new(storepb.Refresh)
	h := secrets.Hash(token)
	if err := store.Get(tx, store.Refresh, h, r); err != nil {
		return "", err
	}
	r.Predecessor = prev
	return token, store.Put(tx, store.Refresh, h, r)
}

// retireRefresh marks every refresh token of a session used, with no
// successor, in tx, as a step-up does: the client gets new ones, and one of
// the old used again is reuse, which ends the session.
func (a *Auth) retireRefresh(tx *bolt.Tx, sid string) error {
	now := a.now().UnixNano()
	return store.Scan(tx, store.RefreshBySession, store.Prefix([]byte(sid)), func(_, v []byte) error {
		r := new(storepb.Refresh)
		if err := store.Get(tx, store.Refresh, v, r); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return nil
			}
			return err
		}
		if r.Replaced == 0 {
			r.Replaced = now
		}
		r.Successor = nil
		return store.Put(tx, store.Refresh, v, r)
	})
}

// endRefresh removes every refresh token of a session, in tx: an ended
// session's are refused at once.
func endRefresh(tx *bolt.Tx, sid string) error {
	var keys, hashes [][]byte
	err := store.Scan(tx, store.RefreshBySession, store.Prefix([]byte(sid)), func(k, v []byte) error {
		keys, hashes = append(keys, k), append(hashes, v)
		return nil
	})
	if err != nil {
		return err
	}
	for i, k := range keys {
		if err := store.Delete(tx, store.Refresh, hashes[i]); err != nil {
			return err
		}
		if err := store.Delete(tx, store.RefreshBySession, k); err != nil {
			return err
		}
	}
	return nil
}

// logStore logs a store error that a request turns into no session.
func logStore(ctx context.Context, msg string, err error) { slog.ErrorContext(ctx, msg, "err", err) }
