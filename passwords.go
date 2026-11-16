package auth

import (
	"context"
	"fmt"

	"github.com/epistemer/errors"
	bolt "go.etcd.io/bbolt"

	"github.com/epistemer/auth/internal/password"
	"github.com/epistemer/auth/internal/store"
	"github.com/epistemer/auth/internal/storepb"
)

// CheckPassword judges a new password (§5.2.4): its length, the hints
// (with the issuer), whole-password patterns and zxcvbn's estimate. Every
// path that sets a password calls it.
func (a *Auth) CheckPassword(ctx context.Context, pw string, hints ...string) error {
	hints = append(hints, a.cfg.AuthIssuer())
	switch password.Check(pw, password.Rules{
		MinLength: a.cfg.AuthPasswordMinLength(),
		MinScore:  a.cfg.AuthPasswordMinScore(),
		Year:      a.now().Year(),
	}, hints...) {
	case password.OK:
		return nil
	case password.TooShort:
		return ErrPasswordTooShort.With(a.cfg.AuthPasswordMinLength())
	case password.TooLong:
		return ErrPasswordTooLong
	case password.Common:
		return ErrPasswordCommon
	case password.Personal:
		return ErrPasswordPersonal
	default:
		return ErrPasswordSimple
	}
}

// userHints are the user's own words a password may not contain: the name
// and the addresses.
func (a *Auth) userHints(ctx context.Context, u User) ([]string, error) {
	hints := []string{u.Name}
	for _, ch := range []Channel{ChannelEmail, ChannelSMS} {
		addr, err := a.dir.Address(ctx, u.ID, ch)
		if err != nil {
			return nil, fmt.Errorf("auth: an address: %w", err)
		}
		if addr != "" {
			hints = append(hints, addr)
		}
	}
	return hints, nil
}

// SetPassword sets a user's password, for seeding and admin tools. It is
// judged like any new password. Replacing a password ends the user's
// sessions and sends MsgPasswordChanged (§5.1.10); setting the first one
// doesn't.
func (a *Auth) SetPassword(ctx context.Context, id UserID, pw string) error {
	if err := validID(id); err != nil {
		return err
	}
	u, err := a.user(ctx, id)
	if err != nil {
		return err
	}
	hints, err := a.userHints(ctx, u)
	if err != nil {
		return err
	}
	if err := a.CheckPassword(ctx, pw, hints...); err != nil {
		return err
	}
	phc, err := a.hasher.Hash(ctx, pw)
	if err != nil {
		return err
	}
	replaced, ended, err := a.storePassword(id, phc, "")
	if err != nil {
		return err
	}
	a.record(ctx, Event{Kind: "password.set", User: id})
	for _, s := range ended {
		a.record(ctx, Event{Kind: "session.ended", User: id, Session: SessionID(s), Reason: "password_changed"})
	}
	if replaced {
		a.notify(ctx, u, MsgPasswordChanged)
	}
	return nil
}

func passwordKey(id UserID) []byte {
	return store.Key([]byte(id), []byte(MethodPassword), store.CredKey(nil))
}

// passwordHash returns a user's PHC string, or "" for a user with none.
func (a *Auth) passwordHash(id UserID) (string, error) {
	var c storepb.Credential
	err := a.db.View(func(tx *bolt.Tx) error { return store.Get(tx, store.Credentials, passwordKey(id), &c) })
	if errors.Is(err, store.ErrNotFound) {
		return "", nil
	}
	return string(c.Data), err
}

func (a *Auth) hasPassword(id UserID) (bool, error) {
	h, err := a.passwordHash(id)
	return h != "", err
}

// passwordAdded is when the user's password was last set, in Unix
// nanoseconds; 0 for a user with none.
func passwordAdded(tx *bolt.Tx, id UserID) (int64, error) {
	if id == "" {
		return 0, nil
	}
	var c storepb.Credential
	err := store.Get(tx, store.Credentials, passwordKey(id), &c)
	if errors.Is(err, store.ErrNotFound) {
		return 0, nil
	}
	return c.Added, err
}

// storePassword writes a user's hash, in one transaction with what it
// decides. With rehashOf set, it replaces only that hash, as a rehash at
// sign-in does: a password changed meanwhile stays. Without, it sets the
// password; replacing one is a change, which also ends the user's sessions
// and makes older password proofs in flows stale.
func (a *Auth) storePassword(id UserID, phc, rehashOf string) (replaced bool, ended []string, err error) {
	err = a.db.Update(func(tx *bolt.Tx) error {
		var err error
		replaced, ended, err = a.storePasswordTx(tx, id, phc, rehashOf)
		return err
	})
	return replaced, ended, err
}

// storePasswordTx is storePassword in a transaction of the caller's.
func (a *Auth) storePasswordTx(tx *bolt.Tx, id UserID, phc, rehashOf string) (replaced bool, ended []string, err error) {
	now := a.now().UnixNano()
	c := &storepb.Credential{Method: MethodPassword, Added: now}
	err = store.Get(tx, store.Credentials, passwordKey(id), c)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return false, nil, err
	}
	exists := err == nil
	if rehashOf != "" {
		if !exists || string(c.Data) != rehashOf {
			return false, nil, nil
		}
		c.Data = []byte(phc)
		return false, nil, store.Put(tx, store.Credentials, passwordKey(id), c)
	}
	c.Data, c.Added = []byte(phc), now
	if exists {
		replaced = true
		if ended, err = a.endSessions(tx, id, ""); err != nil {
			return false, nil, err
		}
	}
	// Any new password forgets the user's devices (§5.1.10), the first one
	// too: a device registered without a password goes with it.
	if _, err := forgetDevices(tx, id); err != nil {
		return false, nil, err
	}
	return replaced, ended, store.Put(tx, store.Credentials, passwordKey(id), c)
}

// notify sends a notice to the user's email, or their phone when they have
// no email. A failure is an event: the change it reports already happened.
func (a *Auth) notify(ctx context.Context, u User, kind MessageKind) {
	for _, ch := range []Channel{ChannelEmail, ChannelSMS} {
		addr, err := a.dir.Address(ctx, u.ID, ch)
		if err != nil || addr == "" {
			continue
		}
		reason := ""
		if err := a.sender.Send(ctx, Message{Kind: kind, Channel: ch, To: addr, User: u.ID}); err != nil {
			reason = "send_failed"
		}
		a.record(ctx, Event{Kind: "message.sent", User: u.ID, Reason: reason})
		return
	}
	a.record(ctx, Event{Kind: "message.sent", User: u.ID, Reason: "no_address"})
}
