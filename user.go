package auth

import (
	"context"
	"strings"

	bolt "go.etcd.io/bbolt"
	"google.golang.org/protobuf/proto"

	"github.com/epistemer/auth/internal/store"
	"github.com/epistemer/auth/internal/storepb"
)

// DeleteUser removes everything auth holds for a user, in one transaction:
// every session, ended ones included, with its refresh tokens, so the
// user's cookies and access tokens stop at once; every credential and its
// index; every device; and the flows, links and invitations that name the
// user. It sends nothing. Throttle counters hold only a digest and are
// left to Sweep.
//
// Remove or disable the user in the Directory first: a flow already under
// way then fails at its next lookup, and can't make a session or set a
// password; the flow records such a race leaves expire with Sweep. Deleted
// the other way round, a recovery started before the Directory lets go
// could set a password again. auth/access keeps memberships of its own:
// call its RemoveUser too.
//
// It reads every session, flow and link, so it costs a scan of the store.
func (a *Auth) DeleteUser(ctx context.Context, id UserID) error {
	if err := validID(id); err != nil {
		return err
	}
	var ended []string
	err := a.db.Update(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		ended = nil
		var keys [][]byte
		var sessions []*storepb.Session
		err := store.Scan(tx, store.Sessions, nil, func(k, v []byte) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			s := new(storepb.Session)
			if err := proto.Unmarshal(v, s); err != nil {
				return err
			}
			if s.UserId == string(id) {
				keys, sessions = append(keys, k), append(sessions, s)
			}
			return nil
		})
		if err != nil {
			return err
		}
		for i, s := range sessions {
			// An event for each session that was live; one that ended or
			// expired already had its end.
			if s.Ended == 0 && a.live(s) {
				ended = append(ended, s.Id)
			}
			if err := deleteSession(tx, keys[i], s); err != nil {
				return err
			}
		}
		// An index entry whose record is gone goes too.
		var orphans [][]byte
		err = store.Scan(tx, store.SessionsByUser, store.Prefix([]byte(id)), func(k, _ []byte) error {
			orphans = append(orphans, k)
			return nil
		})
		if err != nil {
			return err
		}
		for _, k := range orphans {
			if err := store.Delete(tx, store.SessionsByUser, k); err != nil {
				return err
			}
		}
		var creds [][]byte
		var methods []string
		err = store.Scan(tx, store.Credentials, store.Prefix([]byte(id)), func(k, _ []byte) error {
			method, _, _ := strings.Cut(string(k[len(id)+1:]), "\x00")
			creds, methods = append(creds, k), append(methods, method)
			return nil
		})
		if err != nil {
			return err
		}
		for i, k := range creds {
			if err := a.deleteCredential(tx, id, methods[i], k); err != nil {
				return err
			}
		}
		if _, err := forgetDevices(tx, id); err != nil {
			return err
		}
		flows, err := keysOfUser(ctx, tx, store.Flows, id, func(v []byte) (string, error) {
			var f storepb.Flow
			err := proto.Unmarshal(v, &f)
			return f.UserId, err
		})
		if err != nil {
			return err
		}
		links, err := keysOfUser(ctx, tx, store.Links, id, func(v []byte) (string, error) {
			var l storepb.Link
			err := proto.Unmarshal(v, &l)
			return l.UserId, err
		})
		if err != nil {
			return err
		}
		for _, k := range flows {
			if err := store.Delete(tx, store.Flows, k); err != nil {
				return err
			}
		}
		for _, k := range links {
			if err := store.Delete(tx, store.Links, k); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	for _, s := range ended {
		a.record(ctx, Event{Kind: "session.ended", User: id, Session: SessionID(s), Reason: "user_deleted"})
	}
	a.record(ctx, Event{Kind: "user.deleted", User: id})
	return nil
}

// keysOfUser returns the keys of a bucket's records that belong to a user,
// in tx.
func keysOfUser(ctx context.Context, tx *bolt.Tx, bucket []byte, id UserID, owner func(v []byte) (string, error)) ([][]byte, error) {
	var out [][]byte
	err := store.Scan(tx, bucket, nil, func(k, v []byte) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		u, err := owner(v)
		if err != nil {
			return err
		}
		if u == string(id) {
			out = append(out, k)
		}
		return nil
	})
	return out, err
}

// deleteSession removes the session record under key, its indexes and its
// refresh tokens, in tx.
func deleteSession(tx *bolt.Tx, key []byte, s *storepb.Session) error {
	// The token index points here only if no newer session took the hash,
	// which 256 random bits rule out; check anyway.
	if string(store.B(tx, store.SessionTokens).Get(s.TokenHash)) == s.Id {
		if err := store.Delete(tx, store.SessionTokens, s.TokenHash); err != nil {
			return err
		}
	}
	if err := store.Delete(tx, store.SessionsByUser, store.Key([]byte(s.UserId), []byte(s.Id))); err != nil {
		return err
	}
	if err := endRefresh(tx, s.Id); err != nil {
		return err
	}
	return store.Delete(tx, store.Sessions, key)
}
