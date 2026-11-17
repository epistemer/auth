package auth

import (
	"context"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/epistemer/errors"
	bolt "go.etcd.io/bbolt"
	"google.golang.org/protobuf/proto"

	"github.com/epistemer/auth/internal/store"
	"github.com/epistemer/auth/internal/storepb"
)

// Changing factors (interface §5.1.9, §4.5).

// FactorInfo is an enrolled factor, as a user's factor list shows it.
type FactorInfo struct {
	ID     string
	Method string
	Label  string
	Added  time.Time
	Used   time.Time
}

// credentialKey is a credential's store key: the user, the method, and the
// SHA-256 of the method's key, appended whole (it may hold a zero byte,
// and its length is fixed, so nothing can pose as another).
func credentialKey(user UserID, method string, key []byte) []byte {
	return append(store.Prefix([]byte(user), []byte(method)), store.CredKey(key)...)
}

// factorID names a credential to the app: its method and its key's hash.
func factorID(method string, storeKey []byte) string {
	if len(storeKey) < 32 {
		return method + ":"
	}
	return method + ":" + hex.EncodeToString(storeKey[len(storeKey)-32:])
}

// whileHashing lets a test act between changePassword's first check and
// its transaction. It is nil outside tests.
var whileHashing func()

// enrollable are the methods Enroll can add, by the milestone that adds
// them. Modules' methods join when their storage does (after v0.1.0).
var enrollable = map[string]bool{MethodPassword: true, MethodTOTP: true, MethodRecoveryCode: true}

// Enroll starts a flow that adds a factor, or changes the password, for the
// session's user. It needs a verified session and a proof made within
// fresh.window; for a user with an enrolled second factor that proof must
// be of a second method (§5.1.9). It is bound to the session.
func (a *Auth) Enroll(ctx context.Context, s *Session, method string) (Flow, error) {
	if s == nil {
		return Flow{}, ErrNoSession
	}
	if !enrollable[method] && a.methods[method] == nil {
		return Flow{}, ErrMethodUnavailable
	}
	sess, u, err := a.liveSession(ctx, s)
	if err != nil {
		return Flow{}, err
	}
	if err := a.mayChange(sess, u); err != nil {
		a.record(ctx, Event{Kind: "factor.refused", User: u.ID, Session: s.ID, Method: method, Reason: reasonOf(err)})
		return Flow{}, err
	}
	// A new set of recovery codes needs a factor they go with.
	if method == MethodRecoveryCode {
		if f, err := a.enrolled(u.ID); err != nil || len(f) == 0 {
			if err != nil {
				return Flow{}, err
			}
			a.record(ctx, Event{Kind: "factor.refused", User: u.ID, Session: s.ID, Method: method, Reason: "no_factor"})
			return Flow{}, ErrMethodUnavailable
		}
	}
	// A method whose section limits how many a user holds (§5.13.2).
	if limit := methodLimit[method]; limit > 0 {
		var n int
		if err := a.db.View(func(tx *bolt.Tx) (err error) {
			n, err = countMethodTx(tx, u.ID, method)
			return err
		}); err != nil {
			return Flow{}, err
		}
		if n >= limit {
			a.record(ctx, Event{Kind: "factor.refused", User: u.ID, Session: s.ID, Method: method, Reason: "limit"})
			return Flow{}, ErrMethodUnavailable
		}
	}
	return a.start(ctx, &storepb.Flow{
		Purpose: int32(PurposeEnroll), UserId: sess.UserId, SessionId: sess.Id,
		Carrier: sess.Carrier, EnrollMethod: method,
	})
}

// liveSession reads the live session s names, at the generation s was read
// at, and its user, who mustn't be disabled.
func (a *Auth) liveSession(ctx context.Context, s *Session) (*storepb.Session, User, error) {
	sess := new(storepb.Session)
	err := a.db.View(func(tx *bolt.Tx) error { return store.Get(tx, store.Sessions, []byte(s.ID), sess) })
	if errors.Is(err, store.ErrNotFound) || err == nil && (!a.live(sess) || s.superseded(sess)) {
		return nil, User{}, ErrNoSession
	}
	if err != nil {
		return nil, User{}, err
	}
	u, err := a.user(ctx, UserID(sess.UserId))
	if err != nil {
		return nil, User{}, err
	}
	if u.Disabled {
		return nil, User{}, ErrUserDisabled
	}
	return sess, u, nil
}

// mayChange applies §5.1.9 to a session: verified, with a proof made within
// fresh.window, which for a user with an enrolled second factor must be of
// a second method that still counts for them (an enrolled factor or a
// recovery code: never a device, a password, or a code to an address).
func (a *Auth) mayChange(sess *storepb.Session, u User) error {
	return a.db.View(func(tx *bolt.Tx) error { return a.mayChangeTx(tx, sess, u.ID) })
}

// mayChangeTx is mayChange in a transaction of the caller's, so the check
// and the change it allows see one state.
func (a *Auth) mayChangeTx(tx *bolt.Tx, sess *storepb.Session, user UserID) error {
	if !sess.Verified {
		return ErrNotVerified
	}
	enrolled, err := enrolledTx(tx, user)
	if err != nil {
		return err
	}
	cutoff := a.now().Add(-a.cfg.AuthFreshWindow()).UnixNano()
	for _, f := range sess.Factors {
		if f.At < cutoff || isIdentity(f.Method) && !f.Verified {
			continue
		}
		if len(enrolled) == 0 || slices.Contains(enrolled, f.Method) || f.Method == MethodRecoveryCode {
			return nil
		}
	}
	return ErrStale
}

func reasonOf(err error) string {
	switch {
	case errors.Is(err, ErrNotVerified):
		return "not_verified"
	case errors.Is(err, ErrStale):
		return "stale"
	}
	return "error"
}

// finishEnroll ends an Enroll flow for its own session: it checks §5.1.9
// again, then stores what the flow proved. Changing the password takes
// NewPassword, and ends the user's other sessions, forgets their devices
// and sends MsgPasswordChanged (§5.1.10).
func (a *Auth) finishEnroll(ctx context.Context, hash []byte, rec *storepb.Flow, o finishOptions) (Result, error) {
	cur, ok := From(ctx)
	if !ok {
		return Result{}, ErrNoSession
	}
	if string(cur.ID) != rec.SessionId {
		return Result{}, ErrFlowExpired
	}
	v, err := a.view(ctx, rec, nil)
	if err != nil {
		return Result{}, err
	}
	if !v.ready {
		return Result{}, ErrNotReady
	}
	sess, u, err := a.liveSession(ctx, cur)
	if err != nil {
		return Result{}, err
	}
	if err := a.mayChange(sess, u); err != nil {
		a.record(ctx, Event{Kind: "factor.refused", User: u.ID, Session: cur.ID, Method: rec.EnrollMethod, Reason: reasonOf(err)})
		return Result{}, err
	}
	switch rec.EnrollMethod {
	case MethodPassword:
		return a.changePassword(ctx, hash, sess, u, o)
	case MethodTOTP, MethodRecoveryCode:
		return a.addFactor(ctx, hash, sess, u, o)
	}
	if a.methods[rec.EnrollMethod] != nil {
		return a.addFactor(ctx, hash, sess, u, o)
	}
	return Result{}, fmt.Errorf("auth: enrolling %q: %w", rec.EnrollMethod, ErrMethodUnavailable)
}

// changePassword sets a new password from an Enroll flow, keeping the
// session that made the change.
func (a *Auth) changePassword(ctx context.Context, hash []byte, sess *storepb.Session, u User, o finishOptions) (Result, error) {
	if o.newPassword == nil {
		return Result{}, ErrPasswordRequired
	}
	hints, err := a.userHints(ctx, u)
	if err != nil {
		return Result{}, err
	}
	if err := a.CheckPassword(ctx, *o.newPassword, hints...); err != nil {
		return Result{}, err
	}
	phc, err := a.hasher.Hash(ctx, *o.newPassword)
	if err != nil {
		return Result{}, err
	}
	if whileHashing != nil {
		whileHashing()
	}
	var replaced bool
	var ended []string
	out := new(storepb.Session)
	err = a.db.Update(func(tx *bolt.Tx) error {
		// §5.1.9 again, on the state the change is made on: a factor may
		// have been enrolled while the password was hashed.
		if err := store.Get(tx, store.Sessions, []byte(sess.Id), out); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return errNoSession
			}
			return err
		}
		if !a.live(out) || out.Generation != sess.Generation {
			return errNoSession
		}
		if err := a.mayChangeTx(tx, out, u.ID); err != nil {
			return err
		}
		if _, err := a.spend(tx, hash); err != nil {
			return err
		}
		var err error
		replaced, ended, err = a.storePasswordTx(tx, u.ID, phc, "", sess.Id)
		return err
	})
	switch {
	case errors.Is(err, errNoSession):
		return Result{}, ErrNoSession
	case errors.Is(err, ErrNotVerified), errors.Is(err, ErrStale):
		return Result{}, err
	case errors.Is(err, store.ErrNotFound):
		return Result{}, ErrFlowExpired
	case errors.Is(err, errChanged):
		return Result{}, ErrNotReady
	case err != nil:
		return Result{}, err
	}
	a.record(ctx, Event{Kind: "password.set", User: u.ID, Session: SessionID(sess.Id), Reason: "enroll"})
	for _, id := range ended {
		a.record(ctx, Event{Kind: "session.ended", User: u.ID, Session: SessionID(id), Reason: "password_changed"})
	}
	// Any password set from a session is a change: the first one too.
	_ = replaced
	a.notify(ctx, u, MsgPasswordChanged)
	return Result{Session: toSession(out)}, nil
}

// addFactor stores the factor an Enroll flow proved, checking §5.1.9 again
// in the same transaction, and sends MsgFactorAdded.
func (a *Auth) addFactor(ctx context.Context, hash []byte, sess *storepb.Session, u User, o finishOptions) (Result, error) {
	out := new(storepb.Session)
	var method, refused string
	var codes []string
	err := a.db.Update(func(tx *bolt.Tx) error {
		codes, refused = nil, ""
		if err := store.Get(tx, store.Sessions, []byte(sess.Id), out); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return errNoSession
			}
			return err
		}
		if !a.live(out) || out.Generation != sess.Generation {
			return errNoSession
		}
		if err := a.mayChangeTx(tx, out, u.ID); err != nil {
			return err
		}
		cur := new(storepb.Flow)
		if err := store.Get(tx, store.Flows, hash, cur); err != nil {
			return err
		}
		method = cur.EnrollMethod
		if a.methods[method] != nil {
			var err error
			codes, refused, err = a.enrollModuleTx(tx, hash, cur, o)
			return err
		}
		if _, err := a.spend(tx, hash); err != nil {
			return err
		}
		switch method {
		case MethodTOTP:
			// The first factor brings a set of recovery codes (§5.4.6).
			before, err := enrolledTx(tx, u.ID)
			if err != nil {
				return err
			}
			if err := a.enrollTOTP(tx, cur, factorLabel(o, "Authenticator app")); err != nil {
				return err
			}
			if len(before) == 0 {
				codes, err = a.newRecoverySet(tx, u.ID)
			}
			return err
		case MethodRecoveryCode:
			// A new set cancels the old.
			if f, err := enrolledTx(tx, u.ID); err != nil || len(f) == 0 {
				if err != nil {
					return err
				}
				return errChanged
			}
			var err error
			codes, err = a.newRecoverySet(tx, u.ID)
			return err
		}
		return errChanged
	})
	switch {
	case errors.Is(err, errNoSession):
		return Result{}, ErrNoSession
	case errors.Is(err, ErrNotVerified), errors.Is(err, ErrStale):
		return Result{}, err
	case errors.Is(err, store.ErrNotFound):
		return Result{}, ErrFlowExpired
	case errors.Is(err, errChanged):
		return Result{}, ErrNotReady
	case err != nil:
		return Result{}, err
	case refused != "":
		// Rule 10 of §5.5: the flow stays, offering the method again.
		a.record(ctx, Event{Kind: "factor.refused", User: u.ID, Session: SessionID(sess.Id), Method: method, Reason: refused})
		return Result{}, ErrBadCredentials
	}
	a.record(ctx, Event{Kind: "factor.added", User: u.ID, Session: SessionID(sess.Id), Method: method})
	a.notify(ctx, u, MsgFactorAdded)
	return Result{Session: toSession(out), RecoveryCodes: codes}, nil
}

// Factors returns a user's enrolled second factors.
func (a *Auth) Factors(ctx context.Context, id UserID) ([]FactorInfo, error) {
	if err := validID(id); err != nil {
		return nil, err
	}
	var out []FactorInfo
	err := a.db.View(func(tx *bolt.Tx) error {
		return store.Scan(tx, store.Credentials, store.Prefix([]byte(id)), func(k, v []byte) error {
			method, _, _ := strings.Cut(string(k[len(id)+1:]), "\x00")
			if !isSecond(method) || method == MethodRecoveryCode {
				return nil
			}
			var c storepb.Credential
			if err := proto.Unmarshal(v, &c); err != nil {
				return err
			}
			out = append(out, FactorInfo{
				ID: factorID(method, k), Method: method, Label: c.Label,
				Added: unixOrZero(c.Added), Used: unixOrZero(c.Used),
			})
			return nil
		})
	})
	return out, err
}

// unixOrZero is a stored time, or the zero time for none.
func unixOrZero(ns int64) time.Time {
	if ns == 0 {
		return time.Time{}
	}
	return time.Unix(0, ns)
}

// RemoveFactor removes one of the session's user's factors, under the same
// rule as Enroll (§5.1.9), and sends MsgFactorRemoved. An ID that isn't one
// of the user's factors is ErrMethodUnavailable.
func (a *Auth) RemoveFactor(ctx context.Context, s *Session, factorID string) error {
	if s == nil {
		return ErrNoSession
	}
	method, sum, ok := strings.Cut(factorID, ":")
	raw, herr := hex.DecodeString(sum)
	if !ok || herr != nil || len(raw) != 32 || !isSecond(method) || method == MethodRecoveryCode {
		return ErrMethodUnavailable
	}
	sess, u, err := a.liveSession(ctx, s)
	if err != nil {
		return err
	}
	if err := a.mayChange(sess, u); err != nil {
		a.record(ctx, Event{Kind: "factor.refused", User: u.ID, Session: s.ID, Method: method, Reason: reasonOf(err)})
		return err
	}
	key := append(store.Prefix([]byte(u.ID), []byte(method)), raw...)
	var found bool
	err = a.db.Update(func(tx *bolt.Tx) error {
		found = false
		// §5.1.9 again, on the state the removal is made on.
		cur := new(storepb.Session)
		if err := store.Get(tx, store.Sessions, []byte(sess.Id), cur); err != nil || !a.live(cur) || cur.Generation != sess.Generation {
			if err == nil || errors.Is(err, store.ErrNotFound) {
				return errNoSession
			}
			return err
		}
		if err := a.mayChangeTx(tx, cur, u.ID); err != nil {
			return err
		}
		if store.B(tx, store.Credentials).Get(key) == nil {
			return nil
		}
		found = true
		if err := a.deleteCredential(tx, u.ID, method, key); err != nil {
			return err
		}
		// The last factor takes its recovery codes with it.
		left, err := enrolledTx(tx, u.ID)
		if err != nil || len(left) > 0 {
			return err
		}
		return a.deleteMethod(tx, u.ID, MethodRecoveryCode)
	})
	if errors.Is(err, errNoSession) {
		return ErrNoSession
	}
	if err != nil {
		return err
	}
	if !found {
		return ErrMethodUnavailable
	}
	a.record(ctx, Event{Kind: "factor.removed", User: u.ID, Session: s.ID, Method: method})
	a.notify(ctx, u, MsgFactorRemoved)
	return nil
}

// deleteCredential removes a credential and its key index, in tx.
func (a *Auth) deleteCredential(tx *bolt.Tx, user UserID, method string, key []byte) error {
	var c storepb.Credential
	if err := store.Get(tx, store.Credentials, key, &c); err == nil && len(c.Key) > 0 {
		idx := append(store.Prefix([]byte(method)), store.CredKey(c.Key)...)
		if string(store.B(tx, store.CredentialKeys).Get(idx)) == string(user) {
			if err := store.Delete(tx, store.CredentialKeys, idx); err != nil {
				return err
			}
		}
	}
	return store.Delete(tx, store.Credentials, key)
}

// deleteMethod removes every credential of one method of a user, in tx.
func (a *Auth) deleteMethod(tx *bolt.Tx, user UserID, method string) error {
	var keys [][]byte
	err := store.Scan(tx, store.Credentials, store.Prefix([]byte(user), []byte(method)), func(k, _ []byte) error {
		keys = append(keys, k)
		return nil
	})
	if err != nil {
		return err
	}
	for _, k := range keys {
		if err := a.deleteCredential(tx, user, method, k); err != nil {
			return err
		}
	}
	return nil
}

// ResetFactors removes all of a user's second factors and recovery codes:
// an admin's answer to a lost phone. It sends MsgFactorRemoved.
func (a *Auth) ResetFactors(ctx context.Context, id UserID) error {
	if err := validID(id); err != nil {
		return err
	}
	u, err := a.user(ctx, id)
	if err != nil {
		return err
	}
	var n int
	err = a.db.Update(func(tx *bolt.Tx) error {
		n = 0
		var keys [][]byte
		var methods []string
		err := store.Scan(tx, store.Credentials, store.Prefix([]byte(id)), func(k, _ []byte) error {
			method, _, _ := strings.Cut(string(k[len(id)+1:]), "\x00")
			if isSecond(method) {
				keys, methods = append(keys, k), append(methods, method)
			}
			return nil
		})
		if err != nil {
			return err
		}
		for i, k := range keys {
			if err := a.deleteCredential(tx, id, methods[i], k); err != nil {
				return err
			}
		}
		n = len(keys)
		return nil
	})
	if err != nil {
		return err
	}
	if n > 0 {
		a.record(ctx, Event{Kind: "factor.removed", User: id, Reason: "reset"})
		a.notify(ctx, u, MsgFactorRemoved)
	}
	return nil
}
