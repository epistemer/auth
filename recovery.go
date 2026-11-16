package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"slices"
	"strings"

	"github.com/epistemer/errors"
	bolt "go.etcd.io/bbolt"
	"google.golang.org/protobuf/proto"

	"github.com/epistemer/auth/internal/store"
	"github.com/epistemer/auth/internal/storepb"
)

// Recovery codes (interface §5.4.6): ten per set, each sixteen base32
// characters (80 bits), stored as SHA-256, used once. They don't use the
// master secret, so no rotation loses them. A new set cancels the old.

const recoveryCodes = 10

// recoveryKey is where a user's set lives: one credential per user.
func recoveryKey(user UserID) []byte {
	return credentialKey(user, MethodRecoveryCode, []byte("set"))
}

// normalizeRecovery folds what a person may type: case, spaces, dashes.
func normalizeRecovery(code string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r == ' ' || r == '-':
			return -1
		case r >= 'a' && r <= 'z':
			return r - 'a' + 'A'
		}
		return r
	}, code)
}

// newRecoverySet makes a set, in tx, replacing any the user had, and
// returns its codes.
func (a *Auth) newRecoverySet(tx *bolt.Tx, user UserID) ([]string, error) {
	codes := make([]string, recoveryCodes)
	d := &storepb.RecoveryData{Hashes: make([][]byte, recoveryCodes), Used: make([]bool, recoveryCodes)}
	for i := range codes {
		raw := make([]byte, 10)
		rand.Read(raw)
		codes[i] = b32.EncodeToString(raw)
		sum := sha256.Sum256([]byte(codes[i]))
		d.Hashes[i] = sum[:]
	}
	data, err := proto.Marshal(d)
	if err != nil {
		return nil, err
	}
	now := a.now().UnixNano()
	c := &storepb.Credential{Method: MethodRecoveryCode, Key: []byte("set"), Data: data, Label: "Recovery codes", Added: now}
	return codes, store.Put(tx, store.Credentials, recoveryKey(user), c)
}

// hasRecovery reports whether a user has a recovery code left.
func (a *Auth) hasRecovery(tx *bolt.Tx, user UserID) (bool, error) {
	c := new(storepb.Credential)
	if err := store.Get(tx, store.Credentials, recoveryKey(user), c); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return false, nil
		}
		return false, err
	}
	d := new(storepb.RecoveryData)
	if err := proto.Unmarshal(c.Data, d); err != nil {
		return false, err
	}
	for _, used := range d.Used {
		if !used {
			return true, nil
		}
	}
	return false, nil
}

// recoveryHash is what a typed code is compared by.
func recoveryHash(code string) []byte {
	sum := sha256.Sum256([]byte(normalizeRecovery(code)))
	return sum[:]
}

// useRecovery spends a recovery code of the user, in tx, and reports
// whether one matched. Every code of the set is compared, and the first
// unused match chosen, in constant time.
func useRecovery(tx *bolt.Tx, user UserID, sum []byte, now int64) (bool, error) {
	c := new(storepb.Credential)
	if err := store.Get(tx, store.Credentials, recoveryKey(user), c); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return false, nil
		}
		return false, err
	}
	d := new(storepb.RecoveryData)
	if err := proto.Unmarshal(c.Data, d); err != nil {
		return false, err
	}
	hit := -1
	for i, h := range d.Hashes {
		match := subtle.ConstantTimeCompare(h, sum)
		unused := 0
		if i < len(d.Used) && !d.Used[i] {
			unused = 1
		}
		first := subtle.ConstantTimeEq(int32(hit), -1)
		hit = subtle.ConstantTimeSelect(match&unused&first, i, hit)
	}
	if hit < 0 {
		return false, nil
	}
	d.Used[hit] = true
	data, err := proto.Marshal(d)
	if err != nil {
		return false, err
	}
	c.Data, c.Used = data, now
	return true, store.Put(tx, store.Credentials, recoveryKey(user), c)
}

// proveRecovery checks a recovery code, counted against throttling first,
// and spends it with the flow's proof in one transaction: one code, once.
func (a *Auth) proveRecovery(ctx context.Context, token string, hash []byte, rec *storepb.Flow, v view, code string) (Flow, error) {
	before := a.flowOut(token, rec, v)
	sub, err := a.subjectFor(ctx, rec)
	if err != nil {
		return before, err
	}
	at, err := a.count(sub)
	if err != nil {
		if errors.Is(err, ErrTooManyAttempts) {
			a.record(ctx, Event{Kind: "proof.refused", User: UserID(rec.UserId), Session: SessionID(rec.SessionId), Method: MethodRecoveryCode, Reason: "throttled"})
		}
		return before, err
	}
	u, err := a.user(ctx, UserID(rec.UserId))
	if err != nil {
		return before, err
	}
	if u.Disabled {
		a.record(ctx, Event{Kind: "proof.refused", User: u.ID, Session: SessionID(rec.SessionId), Method: MethodRecoveryCode, Reason: "disabled"})
		return before, ErrUserDisabled
	}
	sum := recoveryHash(code)
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
		// Spent only where it proves something: a user with a factor, a
		// flow holding no second proof yet. A code isn't burnt on a flow a
		// racing proof already verified.
		enrolled, err := enrolledTx(tx, UserID(cur.UserId))
		if err != nil {
			return err
		}
		if len(enrolled) == 0 {
			return errOffered
		}
		for _, p := range cur.Proofs {
			if p.Method == MethodRecoveryCode || slices.Contains(enrolled, p.Method) {
				return errOffered
			}
		}
		matched, err := useRecovery(tx, UserID(cur.UserId), sum, now)
		if err != nil || !matched {
			return err
		}
		ok = true
		cur.Proofs = append(cur.Proofs, &storepb.Factor{Method: MethodRecoveryCode, At: now})
		rec = cur
		return store.Put(tx, store.Flows, hash, cur)
	})
	if errors.Is(err, store.ErrNotFound) {
		return before, ErrFlowExpired
	}
	if errors.Is(err, errOffered) {
		// Nothing was tried: the attempt isn't held against anyone.
		if err := a.succeed(at); err != nil {
			return before, err
		}
		return before, ErrMethodUnavailable
	}
	if err != nil {
		return before, err
	}
	if !ok {
		a.record(ctx, Event{Kind: "proof.refused", User: u.ID, Session: SessionID(rec.SessionId), Method: MethodRecoveryCode, Reason: "bad_code"})
		return before, ErrBadCode
	}
	if err := a.succeed(at); err != nil {
		return before, err
	}
	a.record(ctx, Event{Kind: "proof.accepted", User: u.ID, Session: SessionID(rec.SessionId), Method: MethodRecoveryCode})
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
