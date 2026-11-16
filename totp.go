package auth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base32"
	"fmt"
	"log/slog"
	"net/url"
	"slices"
	"strconv"

	"github.com/epistemer/errors"
	bolt "go.etcd.io/bbolt"
	"google.golang.org/protobuf/proto"

	"github.com/epistemer/auth/internal/store"
	"github.com/epistemer/auth/internal/storepb"
	"github.com/epistemer/auth/internal/totp"
)

// Authenticator apps (interface §5.4.1–5): TOTP, six digits, thirty-second
// steps, a code from the step before or after accepted, never a step at or
// before the last one accepted.

const totpDigits = 6

// stateTOTPStep is the flow state key of the step an Enroll flow's code
// was accepted at.
const stateTOTPStep = "totp_step"

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// challengeTOTP prepares an Enroll of an authenticator app: a 160-bit
// secret, sealed in the flow under the user's ID until a code proves it
// (§5.4.3–4). Asked again, it returns the same secret.
func (a *Auth) challengeTOTP(ctx context.Context, hash []byte, rec *storepb.Flow) (Challenge, error) {
	u, err := a.user(ctx, UserID(rec.UserId))
	if err != nil {
		return Challenge{}, err
	}
	fresh := make([]byte, 20)
	rand.Read(fresh)
	var secret []byte
	err = a.db.Update(func(tx *bolt.Tx) error {
		cur := new(storepb.Flow)
		if err := store.Get(tx, store.Flows, hash, cur); err != nil {
			return err
		}
		if a.now().UnixNano() >= cur.Expires {
			return store.ErrNotFound
		}
		if len(cur.Pending) > 0 {
			pt, stale, err := a.keys.Open(cur.Pending, []byte(cur.UserId))
			if err != nil {
				return err
			}
			secret = pt
			if !stale {
				return nil
			}
			if cur.Pending, err = a.keys.Seal(pt, []byte(cur.UserId)); err != nil {
				return err
			}
			return store.Put(tx, store.Flows, hash, cur)
		}
		sealed, err := a.keys.Seal(fresh, []byte(cur.UserId))
		if err != nil {
			return err
		}
		cur.Pending, secret = sealed, fresh
		return store.Put(tx, store.Flows, hash, cur)
	})
	if errors.Is(err, store.ErrNotFound) {
		return Challenge{}, ErrFlowExpired
	}
	if err != nil {
		return Challenge{}, err
	}
	key := b32.EncodeToString(secret)
	issuer := a.cfg.AuthIssuer()
	q := url.Values{
		"secret": {key}, "issuer": {issuer}, "algorithm": {"SHA1"},
		"digits": {strconv.Itoa(totpDigits)}, "period": {"30"},
	}
	label := url.PathEscape(issuer) + ":" + url.PathEscape(u.Name)
	uri := "otpauth://totp/" + label + "?" + q.Encode()
	return Challenge{Method: MethodTOTP, TOTP: &TOTPSetup{Secret: key, URI: uri}}, nil
}

// totpMatch returns the step, among the one before, now and the one after,
// whose code is code and that is later than after; or false. It compares
// every candidate, so the time it takes says nothing.
func (a *Auth) totpMatch(secret []byte, code string, after int64) (int64, bool) {
	now := totp.StepAt(a.now())
	var step int64
	found := 0
	for _, s := range []int64{now - 1, now, now + 1} {
		ok := subtle.ConstantTimeCompare([]byte(totp.Code(secret, s, totpDigits)), []byte(code))
		later := 0
		if s > after {
			later = 1
		}
		take := ok & later & (1 - found)
		step = int64(subtle.ConstantTimeSelect(take, int(s), int(step)))
		found |= take
	}
	return step, found == 1
}

// proveTOTP checks an authenticator code: against the pending secret in an
// Enroll flow, else against each of the user's TOTP credentials. For a
// credential the comparison and the update of its last step are one write
// transaction, so one code is accepted once, also by concurrent requests
// (§5.4.2). A secret opened only under the previous key is sealed again.
func (a *Auth) proveTOTP(ctx context.Context, token string, hash []byte, rec *storepb.Flow, v view, code string) (Flow, error) {
	before := a.flowOut(token, rec, v)
	sub, err := a.subjectFor(ctx, rec)
	if err != nil {
		return before, err
	}
	at, err := a.count(sub)
	if err != nil {
		if errors.Is(err, ErrTooManyAttempts) {
			a.record(ctx, Event{Kind: "proof.refused", User: UserID(rec.UserId), Session: SessionID(rec.SessionId), Method: MethodTOTP, Reason: "throttled"})
		}
		return before, err
	}
	// A disabled user's code isn't spent (§5.1.6: the first proof already
	// told them so).
	u, err := a.user(ctx, UserID(rec.UserId))
	if err != nil {
		return before, err
	}
	if u.Disabled {
		a.record(ctx, Event{Kind: "proof.refused", User: u.ID, Session: SessionID(rec.SessionId), Method: MethodTOTP, Reason: "disabled"})
		return before, ErrUserDisabled
	}
	// The code is checked, its step moved, and the proof recorded in the
	// flow, in one transaction: one code proves once, and one flow takes
	// one code (§5.4.2).
	ok := false
	err = a.db.Update(func(tx *bolt.Tx) error {
		ok = false
		cur := new(storepb.Flow)
		if err := store.Get(tx, store.Flows, hash, cur); err != nil {
			return err
		}
		now := a.now().UnixNano()
		if now >= cur.Expires {
			return store.ErrNotFound
		}
		if slices.ContainsFunc(cur.Proofs, func(p *storepb.Factor) bool { return p.Method == MethodTOTP }) {
			return nil // proved already: a second code proves nothing more
		}
		if Purpose(cur.Purpose) == PurposeEnroll && cur.EnrollMethod == MethodTOTP {
			if len(cur.Pending) == 0 || cur.MethodState[stateTOTPStep] != nil {
				return nil
			}
			secret, stale, err := a.keys.Open(cur.Pending, []byte(cur.UserId))
			if err != nil {
				return err
			}
			step, match := a.totpMatch(secret, code, -1)
			if !match {
				return nil
			}
			if stale {
				if cur.Pending, err = a.keys.Seal(secret, []byte(cur.UserId)); err != nil {
					return err
				}
			}
			if cur.MethodState == nil {
				cur.MethodState = map[string][]byte{}
			}
			cur.MethodState[stateTOTPStep] = []byte(strconv.FormatInt(step, 10))
			ok = true
		} else if err := a.useTOTP(tx, UserID(cur.UserId), code, &ok); err != nil || !ok {
			return err
		}
		cur.Proofs = append(cur.Proofs, &storepb.Factor{Method: MethodTOTP, At: now})
		rec = cur
		return store.Put(tx, store.Flows, hash, cur)
	})
	if errors.Is(err, store.ErrNotFound) {
		return before, ErrFlowExpired
	}
	if err != nil {
		return before, err
	}
	if !ok {
		a.record(ctx, Event{Kind: "proof.refused", User: UserID(rec.UserId), Session: SessionID(rec.SessionId), Method: MethodTOTP, Reason: "bad_code"})
		return before, ErrBadCode
	}
	if err := a.succeed(at); err != nil {
		return before, err
	}
	a.record(ctx, Event{Kind: "proof.accepted", User: u.ID, Session: SessionID(rec.SessionId), Method: MethodTOTP})
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

// useTOTP looks for a credential of the user whose code is code at a step
// after its last, in tx, and moves its last step there.
func (a *Auth) useTOTP(tx *bolt.Tx, user UserID, code string, ok *bool) error {
	var keys [][]byte
	err := store.Scan(tx, store.Credentials, store.Prefix([]byte(user), []byte(MethodTOTP)), func(k, _ []byte) error {
		keys = append(keys, k)
		return nil
	})
	if err != nil {
		return err
	}
	for _, k := range keys {
		c := new(storepb.Credential)
		if err := store.Get(tx, store.Credentials, k, c); err != nil {
			return err
		}
		d := new(storepb.TOTPData)
		if err := proto.Unmarshal(c.Data, d); err != nil {
			return err
		}
		secret, stale, err := a.keys.Open(d.SealedSecret, []byte(user))
		if err != nil {
			// Sealed under a key no longer configured: this credential is
			// lost (§5.12.3); the others may still match.
			continue
		}
		step, match := a.totpMatch(secret, code, d.LastStep)
		if !match {
			continue
		}
		d.LastStep = step
		if stale {
			if d.SealedSecret, err = a.keys.Seal(secret, []byte(user)); err != nil {
				return err
			}
		}
		if c.Data, err = proto.Marshal(d); err != nil {
			return err
		}
		c.Used = a.now().UnixNano()
		*ok = true
		return store.Put(tx, store.Credentials, k, c)
	}
	return nil
}

// enrollTOTP stores the authenticator app an Enroll flow proved, in tx
// (§5.4.4), keyed by a random ID, never its label.
func (a *Auth) enrollTOTP(tx *bolt.Tx, cur *storepb.Flow) error {
	if len(cur.Pending) == 0 {
		return errChanged
	}
	step, err := strconv.ParseInt(string(cur.MethodState[stateTOTPStep]), 10, 64)
	if err != nil {
		return errChanged
	}
	// Stored under the current key, whatever the flow's was sealed under.
	secret, _, err := a.keys.Open(cur.Pending, []byte(cur.UserId))
	if err != nil {
		return err
	}
	sealed, err := a.keys.Seal(secret, []byte(cur.UserId))
	if err != nil {
		return err
	}
	data, err := proto.Marshal(&storepb.TOTPData{SealedSecret: sealed, LastStep: step})
	if err != nil {
		return err
	}
	id := make([]byte, 16)
	rand.Read(id)
	now := a.now().UnixNano()
	c := &storepb.Credential{Method: MethodTOTP, Key: id, Data: data, Label: "Authenticator app", Added: now, Used: now}
	return store.Put(tx, store.Credentials, credentialKey(UserID(cur.UserId), MethodTOTP, id), c)
}

// errUnreadable reports authenticator secrets that open under no
// configured key: lost, as §5.12.3 warns.
type errUnreadable struct{ n int }

func (e errUnreadable) Error() string {
	return fmt.Sprintf("auth: %d authenticator secrets open under no configured key", e.n)
}

// Rekey seals every authenticator secret under the current secret, those
// of enrollments in progress too (§5.12.3). Once it has run, and returned
// no error, secret_previous can be dropped. Secrets no configured key opens
// are counted in its error, never passed over in silence.
func (a *Auth) Rekey(ctx context.Context) error {
	n, lost := 0, 0
	err := a.db.Update(func(tx *bolt.Tx) error {
		n, lost = 0, 0
		return a.eachSecret(tx, func(user UserID, sealed []byte, set func([]byte) error) error {
			secret, stale, err := a.keys.Open(sealed, []byte(user))
			switch {
			case err != nil:
				lost++
				return nil
			case !stale:
				return nil
			}
			fresh, err := a.keys.Seal(secret, []byte(user))
			if err != nil {
				return err
			}
			n++
			return set(fresh)
		})
	})
	if err != nil {
		return err
	}
	a.record(ctx, Event{Kind: "keys.rekeyed", Reason: strconv.Itoa(n)})
	if lost > 0 {
		return errUnreadable{lost}
	}
	return nil
}

// eachSecret calls f with every sealed authenticator secret, in a
// credential or a pending enrollment, and a setter that stores a new one.
func (a *Auth) eachSecret(tx *bolt.Tx, f func(user UserID, sealed []byte, set func([]byte) error) error) error {
	type item struct {
		k []byte
		c *storepb.Credential
	}
	var creds []item
	err := store.Scan(tx, store.Credentials, nil, func(k, v []byte) error {
		c := new(storepb.Credential)
		if err := proto.Unmarshal(v, c); err != nil {
			return err
		}
		if c.Method == MethodTOTP {
			creds = append(creds, item{k, c})
		}
		return nil
	})
	if err != nil {
		return err
	}
	for _, it := range creds {
		d := new(storepb.TOTPData)
		if err := proto.Unmarshal(it.c.Data, d); err != nil {
			return err
		}
		err := f(userOfKey(it.k), d.SealedSecret, func(fresh []byte) error {
			d.SealedSecret = fresh
			var err error
			if it.c.Data, err = proto.Marshal(d); err != nil {
				return err
			}
			return store.Put(tx, store.Credentials, it.k, it.c)
		})
		if err != nil {
			return err
		}
	}
	type pending struct {
		k   []byte
		rec *storepb.Flow
	}
	var flows []pending
	err = store.Scan(tx, store.Flows, nil, func(k, v []byte) error {
		rec := new(storepb.Flow)
		if err := proto.Unmarshal(v, rec); err != nil {
			return err
		}
		if len(rec.Pending) > 0 {
			flows = append(flows, pending{k, rec})
		}
		return nil
	})
	if err != nil {
		return err
	}
	for _, p := range flows {
		err := f(UserID(p.rec.UserId), p.rec.Pending, func(fresh []byte) error {
			p.rec.Pending = fresh
			return store.Put(tx, store.Flows, p.k, p.rec)
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// staleSecrets counts the authenticator secrets that open only under the
// previous key, and those that open under none, for New to report.
func (a *Auth) staleSecrets() (stale, lost int, err error) {
	err = a.db.View(func(tx *bolt.Tx) error {
		return a.eachSecret(tx, func(user UserID, sealed []byte, _ func([]byte) error) error {
			_, s, err := a.keys.Open(sealed, []byte(user))
			switch {
			case err != nil:
				lost++
			case s:
				stale++
			}
			return nil
		})
	})
	return stale, lost, err
}

// userOfKey is the user a credential's store key names.
func userOfKey(k []byte) UserID {
	i := slices.Index(k, 0)
	if i < 0 {
		return ""
	}
	return UserID(k[:i])
}

func logStale(stale, lost int) {
	if stale > 0 {
		slog.Warn(fmt.Sprintf("auth: %d authenticator secrets still need secret_previous; run Rekey", stale))
	}
	if lost > 0 {
		slog.Error(fmt.Sprintf("auth: %d authenticator secrets open under no configured key", lost))
	}
}
