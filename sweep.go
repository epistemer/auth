package auth

import (
	"bytes"
	"context"
	"time"

	bolt "go.etcd.io/bbolt"
	"google.golang.org/protobuf/proto"

	"github.com/epistemer/auth/internal/store"
	"github.com/epistemer/auth/internal/storepb"
)

// Sweep removes what has expired: flows past their lifetime, sessions that
// ended or are no longer live, with their indexes, and throttle counters
// that would start again from zero (§8). Codes, links, devices and refresh
// tokens join with their milestones. The app schedules it; hourly is enough.
// It runs in one write transaction, which other writes wait for; Scan
// hands it copies of keys and values, so deleting after is safe.
func (a *Auth) Sweep(ctx context.Context) error {
	return a.db.Update(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		now := a.now().UnixNano()
		var flows, sessions, counters [][]byte
		err := store.Scan(tx, store.Flows, nil, func(k, v []byte) error {
			var rec storepb.Flow
			if err := proto.Unmarshal(v, &rec); err != nil {
				return err
			}
			if now >= rec.Expires {
				flows = append(flows, k)
			}
			return nil
		})
		if err != nil {
			return err
		}
		var dead []*storepb.Session
		err = store.Scan(tx, store.Sessions, nil, func(k, v []byte) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			rec := new(storepb.Session)
			if err := proto.Unmarshal(v, rec); err != nil {
				return err
			}
			if !a.live(rec) {
				sessions = append(sessions, k)
				dead = append(dead, rec)
			}
			return nil
		})
		if err != nil {
			return err
		}
		window := int64(a.cfg.AuthThrottleWindow())
		err = store.Scan(tx, store.Throttle, nil, func(k, v []byte) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			var rec storepb.Counter
			if err := proto.Unmarshal(v, &rec); err != nil {
				return err
			}
			// A send counter keeps its hour (§5.3.5); a throttle counter
			// goes once it would start again.
			kind, _, _ := bytes.Cut(k, []byte{0})
			keep := window
			if string(kind) == sentUser || string(kind) == sentAddr {
				keep = int64(time.Hour)
			}
			if now-rec.Last >= keep && now >= rec.Until {
				counters = append(counters, k)
			}
			return nil
		})
		if err != nil {
			return err
		}
		for _, k := range flows {
			if err := store.Delete(tx, store.Flows, k); err != nil {
				return err
			}
		}
		for i, k := range sessions {
			s := dead[i]
			// The token index points here only if no newer session took
			// the hash, which 256 random bits rule out; check anyway.
			if string(store.B(tx, store.SessionTokens).Get(s.TokenHash)) == s.Id {
				if err := store.Delete(tx, store.SessionTokens, s.TokenHash); err != nil {
					return err
				}
			}
			if err := store.Delete(tx, store.SessionsByUser, store.Key([]byte(s.UserId), []byte(s.Id))); err != nil {
				return err
			}
			if err := store.Delete(tx, store.Sessions, k); err != nil {
				return err
			}
		}
		for _, k := range counters {
			if err := store.Delete(tx, store.Throttle, k); err != nil {
				return err
			}
		}
		return nil
	})
}
