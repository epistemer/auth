package auth

import (
	"context"
	"fmt"
	"slices"

	"github.com/epistemer/errors"
	bolt "go.etcd.io/bbolt"

	"github.com/epistemer/auth/internal/secrets"
	"github.com/epistemer/auth/internal/store"
	"github.com/epistemer/auth/internal/storepb"
)

// Recovering an account and accepting an invitation (interface §5.1.7–8,
// §5.3.6). Both set a password and make no session (D25).

// recoverFirst are a Recover's first proofs, the same for every login: a
// link or a code sent to an address (§5.1.7).
var recoverFirst = []string{MethodEmailLink, MethodEmailCode, MethodSMSCode}

// methodInvitation is the proof an Accept flow holds: the invitation.
const methodInvitation = "invitation"

// Recover starts a recovery. It returns a flow for an unknown login exactly
// as for a known one (§5.1.3).
func (a *Auth) Recover(ctx context.Context, login string) (Flow, error) {
	rec, err := a.resolve(ctx, login, PurposeRecover)
	if err != nil {
		return Flow{}, err
	}
	return a.start(ctx, rec)
}

// resolve makes a flow record for a login: its user, or none.
func (a *Auth) resolve(ctx context.Context, login string, p Purpose) (*storepb.Flow, error) {
	rec := &storepb.Flow{Purpose: int32(p), LoginKey: loginKey(login)}
	u, err := a.dir.Find(ctx, login)
	switch {
	case err == nil:
		if err := validID(u.ID); err != nil {
			return nil, err
		}
		rec.UserId = string(u.ID)
	case errors.Is(err, ErrNoUser):
		rec.NoUser = true
	default:
		return nil, fmt.Errorf("auth: finding a login: %w", err)
	}
	return rec, nil
}

// Follow returns the flow an emailed link belongs to. Holding the link is
// the proof. It spends nothing, so it is safe on a GET a mail scanner may
// fetch first, and a second call returns the same flow. A wrong, spent,
// cancelled or expired link is ErrBadCode (§5.3.6).
func (a *Auth) Follow(ctx context.Context, link string) (Flow, error) {
	return a.useLink(ctx, link, PurposeRecover, MethodEmailLink)
}

// Accept starts, or returns again, the flow of an invitation. Holding the
// invitation is the only proof; Finish sets the password (§5.1.8).
func (a *Auth) Accept(ctx context.Context, invitation string) (Flow, error) {
	return a.useLink(ctx, invitation, PurposeAccept, methodInvitation)
}

// useLink finds a link's flow and adds the link as its proof.
//
// Only the link's holder can finish: the first use moves the flow to a new
// token, sealed in the link, so whoever started a Recover, and holds its
// first token, can't finish it when someone else (or their mail scanner)
// follows the link. Later uses return that same token and refresh the
// flow's lifetime, never past the link's own. A link whose flow has ended
// unspent starts a new one. A link older than the user's password is stale:
// one recovery or invitation ends the others.
func (a *Auth) useLink(ctx context.Context, link string, p Purpose, method string) (Flow, error) {
	lh := secrets.Hash(link)
	key := secrets.KeyFromToken([]byte(link), "flow")
	var token string
	var rec *storepb.Flow
	bad := ""
	err := a.db.Update(func(tx *bolt.Tx) error {
		bad, token, rec = "", "", nil
		now := a.now().UnixNano()
		l := new(storepb.Link)
		if err := store.Get(tx, store.Links, lh, l); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				bad = "unknown"
				return nil
			}
			return err
		}
		added, err := passwordAdded(tx, UserID(l.UserId))
		if err != nil {
			return err
		}
		switch {
		case Purpose(l.Purpose) != p:
			bad = "unknown"
			return nil
		case l.Spent != 0:
			bad = "spent"
			return nil
		case now >= l.Expires:
			bad = "expired"
			return nil
		case added > l.Created:
			bad = "stale"
			return nil
		}
		cur := new(storepb.Flow)
		err = store.Get(tx, store.Flows, l.FlowHash, cur)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
		live := err == nil && now < cur.Expires
		used := live && slices.ContainsFunc(cur.Proofs, func(f *storepb.Factor) bool { return f.Method == method })
		switch {
		case live && string(cur.LinkHash) != string(lh):
			bad = "cancelled" // a newer link replaced it
			return nil
		case used:
			pt, err := secrets.OpenWith(key, l.FlowToken, lh)
			if err != nil {
				return err
			}
			token = string(pt)
		default:
			// The first use, or the flow ended unspent: a new token only
			// the link's holder learns.
			if !live {
				cur = &storepb.Flow{Purpose: int32(p), UserId: l.UserId, LinkHash: lh, Created: now}
			}
			if len(l.FlowHash) > 0 {
				if err := store.Delete(tx, store.Flows, l.FlowHash); err != nil {
					return err
				}
			}
			t, h := secrets.NewToken()
			sealed, err := secrets.SealWith(key, []byte(t), lh)
			if err != nil {
				return err
			}
			token, l.FlowHash, l.FlowToken = t, h, sealed
			if err := store.Put(tx, store.Links, lh, l); err != nil {
				return err
			}
			cur.Proofs = append(cur.Proofs, &storepb.Factor{Method: method, At: now, Channel: l.Channel})
		}
		cur.Expires = min(now+int64(a.cfg.AuthFlowLifetime()), l.Expires)
		rec = cur
		return store.Put(tx, store.Flows, l.FlowHash, cur)
	})
	if err != nil {
		return Flow{}, err
	}
	if bad != "" {
		a.record(ctx, Event{Kind: "proof.refused", Method: method, Reason: bad})
		return Flow{}, ErrBadCode
	}
	u, err := a.user(ctx, UserID(rec.UserId))
	if err != nil {
		return Flow{}, err
	}
	if u.Disabled {
		a.record(ctx, Event{Kind: "proof.refused", User: u.ID, Method: method, Reason: "disabled"})
		return Flow{}, ErrUserDisabled
	}
	v, err := a.view(ctx, rec, nil)
	if err != nil {
		return Flow{}, err
	}
	a.record(ctx, Event{Kind: "proof.accepted", User: u.ID, Method: method})
	return a.flowOut(token, rec, v), nil
}

// Invite makes an invitation for a user the app created, and sends it as
// MsgInvitation to their email, or their phone without one. It returns the
// token too, for an app that delivers it another way. The user sets a
// password through Accept.
func (a *Auth) Invite(ctx context.Context, id UserID) (string, error) {
	if err := validID(id); err != nil {
		return "", err
	}
	u, err := a.user(ctx, id)
	if err != nil {
		return "", err
	}
	token, hash := secrets.NewToken()
	now := a.now()
	expires := now.Add(a.cfg.AuthInvitationLifetime())
	var to string
	var ch Channel
	for _, c := range []Channel{ChannelEmail, ChannelSMS} {
		addr, err := a.dir.Address(ctx, id, c)
		if err != nil {
			return "", fmt.Errorf("auth: an address: %w", err)
		}
		if addr != "" {
			to, ch = addr, c
			break
		}
	}
	l := &storepb.Link{
		Purpose: int32(PurposeAccept), UserId: string(id),
		Created: now.UnixNano(), Expires: expires.UnixNano(), Channel: channelKey(to),
	}
	if err := a.db.Update(func(tx *bolt.Tx) error { return store.Put(tx, store.Links, hash, l) }); err != nil {
		return "", err
	}
	a.record(ctx, Event{Kind: "invitation.created", User: u.ID})
	if to == "" {
		a.record(ctx, Event{Kind: "message.not_sent", User: u.ID, Reason: "no_address"})
		return token, nil
	}
	if err := a.sender.Send(ctx, Message{Kind: MsgInvitation, Channel: ch, To: to, User: u.ID, Token: token, Expires: expires}); err != nil {
		a.record(ctx, Event{Kind: "message.not_sent", User: u.ID, Reason: "send_failed"})
		return token, nil
	}
	a.record(ctx, Event{Kind: "message.sent", User: u.ID})
	return token, nil
}

// finishPassword ends a Recover or an Accept: it sets the new password and
// makes no session. A weak password is refused and leaves the flow as it
// was (§5.1.1). Setting it spends the flow and its link, ends the user's
// sessions, and sends MsgPasswordChanged after a recovery or a replaced
// password (§5.1.10).
func (a *Auth) finishPassword(ctx context.Context, hash []byte, rec *storepb.Flow, o finishOptions) (Result, error) {
	v, err := a.view(ctx, rec, nil)
	if err != nil {
		return Result{}, err
	}
	if !v.ready {
		return Result{}, ErrNotReady
	}
	if o.newPassword == nil {
		return Result{}, ErrPasswordRequired
	}
	u, err := a.user(ctx, UserID(rec.UserId))
	if err != nil {
		return Result{}, err
	}
	if u.Disabled {
		a.record(ctx, Event{Kind: "password.refused", User: u.ID, Reason: "disabled"})
		return Result{}, ErrUserDisabled
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
	var replaced bool
	var ended []string
	err = a.db.Update(func(tx *bolt.Tx) error {
		// Judge the flow as it is now, under the write lock, not as it was
		// read before hashing.
		cur := new(storepb.Flow)
		if err := store.Get(tx, store.Flows, hash, cur); err != nil {
			return err
		}
		now := a.now().UnixNano()
		added, err := passwordAdded(tx, u.ID)
		if err != nil {
			return err
		}
		if added > cur.Created {
			return errChanged // the password changed since this flow began
		}
		if _, err := a.spend(tx, hash); err != nil {
			return err
		}
		// A flow proved by a link spends it, and needs it whole.
		if slices.ContainsFunc(cur.Proofs, func(f *storepb.Factor) bool { return f.Method == MethodEmailLink || f.Method == methodInvitation }) {
			l := new(storepb.Link)
			if err := store.Get(tx, store.Links, cur.LinkHash, l); err != nil {
				if errors.Is(err, store.ErrNotFound) {
					return errChanged
				}
				return err
			}
			if l.Spent != 0 || now >= l.Expires {
				return errChanged
			}
			l.Spent = now
			if err := store.Put(tx, store.Links, cur.LinkHash, l); err != nil {
				return err
			}
		}
		replaced, ended, err = a.storePasswordTx(tx, u.ID, phc, "")
		if err != nil {
			return err
		}
		// A recovery ends every session, also where there was no password
		// to replace (§5.1.10).
		if Purpose(cur.Purpose) == PurposeRecover && !replaced {
			more, err := a.endSessions(tx, u.ID, "")
			if err != nil {
				return err
			}
			ended = append(ended, more...)
		}
		return nil
	})
	switch {
	case errors.Is(err, store.ErrNotFound):
		return Result{}, ErrFlowExpired
	case errors.Is(err, errChanged):
		return Result{}, ErrNotReady
	case err != nil:
		return Result{}, err
	}
	a.record(ctx, Event{Kind: "password.set", User: u.ID, Reason: purposeWord(Purpose(rec.Purpose))})
	for _, s := range ended {
		a.record(ctx, Event{Kind: "session.ended", User: u.ID, Session: SessionID(s), Reason: "password_changed"})
	}
	if replaced || Purpose(rec.Purpose) == PurposeRecover {
		a.notify(ctx, u, MsgPasswordChanged)
	}
	return Result{}, nil
}

// linkExpiry is how long a link sent now lives.
func (a *Auth) linkExpiry(now int64) int64 { return now + int64(a.cfg.AuthLinkLifetime()) }
