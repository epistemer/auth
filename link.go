package auth

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/epistemer/errors"
	bolt "go.etcd.io/bbolt"
	"google.golang.org/protobuf/proto"

	"github.com/epistemer/auth/internal/secrets"
	"github.com/epistemer/auth/internal/store"
	"github.com/epistemer/auth/internal/storepb"
)

// Identities from modules such as OpenID Connect (interface §4.3, §4.5,
// §5.14, amendment A25).

// isIdentity reports whether a credential's method is a module's that is
// no second factor: an identity a user signs in with.
func isIdentity(method string) bool { return !coreMethods[method] && !isSecond(method) }

// Link links the identity the flow proved, and holds, to id, a user the
// app has just created for it, and records the proof (§5.14.7). The user
// must be one the Directory knows who is new to auth: no password, no
// credential, no recovery codes, no device, no session (ended ones
// included), no invitation or recovery under way; else ErrBadCredentials
// and nothing is stored. An identity someone linked meanwhile is refused
// alike, and the flow starts again.
func (a *Auth) Link(ctx context.Context, token string, id UserID) (Flow, error) {
	hash := secrets.Hash(token)
	rec, err := a.loadFlow(hash)
	if err != nil {
		return Flow{}, err
	}
	if rec.UnlinkedMethod == "" {
		return Flow{}, ErrMethodUnavailable
	}
	method := rec.UnlinkedMethod
	refused := func(reason string) {
		a.record(ctx, Event{Kind: "proof.refused", User: id, Method: method, Reason: reason})
	}
	if err := validID(id); err != nil {
		return Flow{}, err
	}
	u, err := a.dir.Get(ctx, id)
	switch {
	case errors.Is(err, ErrNoUser):
		refused("not_new")
		return Flow{}, ErrBadCredentials
	case err != nil:
		return Flow{}, fmt.Errorf("auth: getting user: %w", err)
	case u.ID != id:
		return Flow{}, fmt.Errorf("auth: the directory returned another user for an ID")
	case u.Disabled:
		refused("disabled")
		return Flow{}, ErrUserDisabled
	}
	// A user who couldn't finish (a policy needing two factors, a proof of
	// one, and no address that would count) gets nothing stored
	// (review 0027).
	if pol := a.policy(ctx, u); !pol.AllowUnverified && rec.PendingProof != nil && !rec.PendingProof.Verified {
		seconds, err := a.addresses(ctx, u)
		if err != nil {
			return Flow{}, err
		}
		seconds, err = a.notSameMailbox(ctx, u, []*storepb.Factor{rec.PendingProof}, seconds)
		if err != nil {
			return Flow{}, err
		}
		if len(seconds) == 0 {
			refused("cannot_verify")
			return Flow{}, ErrCannotVerify
		}
	}
	var reason string
	got := new(storepb.Flow)
	err = a.db.Update(func(tx *bolt.Tx) error {
		reason = ""
		cur := got
		proto.Reset(cur)
		if err := store.Get(tx, store.Flows, hash, cur); err != nil {
			return err
		}
		now := a.now().UnixNano()
		if now >= cur.Expires {
			return store.ErrNotFound
		}
		// Linked or started again by another request since it was read.
		if cur.UnlinkedMethod != method || !bytes.Equal(cur.Pending, rec.Pending) || cur.PendingProof == nil ||
			cur.UserId != "" || len(cur.Proofs) > 0 || !cur.Without {
			return errOffered
		}
		var c storepb.Credential
		if err := proto.Unmarshal(cur.Pending, &c); err != nil || len(c.Key) == 0 {
			return errOffered
		}
		if store.B(tx, store.CredentialKeys).Get(credentialIndex(method, c.Key)) != nil {
			// Linked to someone meanwhile: the flow starts again.
			reason = "duplicate"
			cur.Pending, cur.UnlinkedMethod, cur.Unlinked, cur.PendingProof = nil, "", nil, nil
			cur.MethodState = nil
			return store.Put(tx, store.Flows, hash, cur)
		}
		fresh, err := a.newToAuthTx(tx, id)
		if err != nil {
			return err
		}
		if !fresh {
			reason = "not_new"
			return nil
		}
		stored := &storepb.Credential{
			Method: method, Key: c.Key, Data: c.Data,
			Label: factorLabel(finishOptions{}, methodOwnLabel(method, &c)), Added: now, Used: now,
		}
		if err := store.Put(tx, store.Credentials, credentialKey(id, method, c.Key), stored); err != nil {
			return err
		}
		if err := store.B(tx, store.CredentialKeys).Put(credentialIndex(method, c.Key), []byte(id)); err != nil {
			return err
		}
		// Dated when it was proved, not when it was linked (review 0027).
		f := cur.PendingProof
		cur.UserId = string(id)
		cur.Proofs = append(cur.Proofs, f)
		cur.Pending, cur.UnlinkedMethod, cur.Unlinked, cur.PendingProof = nil, "", nil, nil
		return store.Put(tx, store.Flows, hash, cur)
	})
	switch {
	case errors.Is(err, store.ErrNotFound):
		return Flow{}, ErrFlowExpired
	case errors.Is(err, errOffered):
		return Flow{}, ErrMethodUnavailable
	case err != nil:
		return Flow{}, err
	case reason != "":
		refused(reason)
		return Flow{}, ErrBadCredentials
	}
	a.record(ctx, Event{Kind: "identity.linked", User: id, Method: method})
	a.record(ctx, Event{Kind: "proof.accepted", User: id, Method: method})
	v, err := a.view(ctx, got, nil)
	if err != nil {
		return Flow{}, err
	}
	out := a.flowOut(token, got, v)
	if v.cannot {
		return out, ErrCannotVerify
	}
	return out, nil
}

// newToAuthTx reports whether auth holds nothing for a user: no password
// or other credential (recovery codes included), no device, no session of
// any age, and no link or flow of a recovery or an invitation under way.
func (a *Auth) newToAuthTx(tx *bolt.Tx, id UserID) (bool, error) {
	holds := func(bucket []byte) (bool, error) {
		found := false
		err := store.Scan(tx, bucket, store.Prefix([]byte(id)), func(_, _ []byte) error {
			found = true
			return nil
		})
		return found, err
	}
	for _, b := range [][]byte{store.Credentials, store.DevicesByUser, store.SessionsByUser} {
		if found, err := holds(b); err != nil || found {
			return false, err
		}
	}
	// Links and flows have no index by user: they are scanned, stopping at
	// the first one under way. Both expire within the hour and Sweep
	// removes them (review 0025).
	now := a.now().UnixNano()
	err := store.B(tx, store.Links).ForEach(func(_, v []byte) error {
		var l storepb.Link
		if err := proto.Unmarshal(v, &l); err != nil {
			return err
		}
		if l.UserId == string(id) && l.Spent == 0 && now < l.Expires {
			return errFound
		}
		return nil
	})
	if err == nil {
		err = store.B(tx, store.Flows).ForEach(func(_, v []byte) error {
			var f storepb.Flow
			if err := proto.Unmarshal(v, &f); err != nil {
				return err
			}
			p := Purpose(f.Purpose)
			if f.UserId == string(id) && (p == PurposeRecover || p == PurposeAccept) && now < f.Expires {
				return errFound
			}
			return nil
		})
	}
	if errors.Is(err, errFound) {
		return false, nil
	}
	return err == nil, err
}

var errFound = errors.New("auth: found")

// IdentityInfo is a linked identity, as a user's list shows it.
type IdentityInfo struct {
	ID     string // to pass to Unlink
	Method string // oidc_google
	Label  string // the provider's email when it gave one, else the provider
	Added  time.Time
	Used   time.Time
}

// Identities lists a user's linked identities. They are no factors:
// Factors doesn't list them, and ResetFactors leaves them.
func (a *Auth) Identities(ctx context.Context, id UserID) ([]IdentityInfo, error) {
	if err := validID(id); err != nil {
		return nil, err
	}
	var out []IdentityInfo
	err := a.db.View(func(tx *bolt.Tx) error {
		return store.Scan(tx, store.Credentials, store.Prefix([]byte(id)), func(k, v []byte) error {
			method, _, _ := strings.Cut(string(k[len(id)+1:]), "\x00")
			if !isIdentity(method) {
				return nil
			}
			var c storepb.Credential
			if err := proto.Unmarshal(v, &c); err != nil {
				return err
			}
			out = append(out, IdentityInfo{
				ID: factorID(method, k), Method: method, Label: c.Label,
				Added: unixOrZero(c.Added), Used: unixOrZero(c.Used),
			})
			return nil
		})
	})
	return out, err
}

// Unlink removes one of the session's user's identities, under the rule
// for changing factors (§5.1.9), and sends MsgFactorRemoved. It refuses
// the user's last way in: with no password, no passkey and no other
// identity left it is ErrMethodUnavailable, as is an ID that isn't one of
// the user's identities.
func (a *Auth) Unlink(ctx context.Context, s *Session, identityID string) error {
	if s == nil {
		return ErrNoSession
	}
	method, sum, ok := strings.Cut(identityID, ":")
	raw, herr := hex.DecodeString(sum)
	if !ok || herr != nil || len(raw) != 32 || !methodNameRE.MatchString(method) || !isIdentity(method) {
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
	var found, last bool
	err = a.db.Update(func(tx *bolt.Tx) error {
		found, last = false, false
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
		// Another way in: a password, a passkey, or another identity.
		other := false
		err := store.Scan(tx, store.Credentials, store.Prefix([]byte(u.ID)), func(k, _ []byte) error {
			m, _, _ := strings.Cut(string(k[len(u.ID)+1:]), "\x00")
			if !bytes.Equal(k, key) && (m == MethodPassword || m == MethodPasskey || isIdentity(m)) {
				other = true
			}
			return nil
		})
		if err != nil {
			return err
		}
		if !other {
			last = true
			return nil
		}
		return a.deleteCredential(tx, u.ID, method, key)
	})
	switch {
	case errors.Is(err, errNoSession):
		return ErrNoSession
	case err != nil:
		return err
	case !found:
		return ErrMethodUnavailable
	case last:
		a.record(ctx, Event{Kind: "factor.refused", User: u.ID, Session: s.ID, Method: method, Reason: "last"})
		return ErrMethodUnavailable
	}
	a.record(ctx, Event{Kind: "identity.unlinked", User: u.ID, Session: s.ID, Method: method})
	a.notify(ctx, u, MsgFactorRemoved)
	return nil
}
