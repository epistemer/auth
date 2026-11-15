package auth

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/netip"
	"time"

	"github.com/epistemer/errors"
	bolt "go.etcd.io/bbolt"

	"github.com/epistemer/auth/internal/store"
	"github.com/epistemer/auth/internal/storepb"
)

// Throttling (interface §5.8, ADR 0007). Each attempt at a proof is counted
// against three counters, before the proof is checked: the user's, the
// client address's and the pair's.

// The kinds of counter, the first part of a throttle key.
const (
	counterUser = "u"
	counterAddr = "a"
	counterPair = "p"
)

// subject is who an attempt is counted against.
type subject struct {
	// user is the user's ID for a login that resolved, else the login's
	// normalized hash (§5.8.1), each under its own label.
	user []byte
	// addr is the client's address, normalized by throttleAddr; invalid
	// when the request has none (§5.8.9).
	addr netip.Addr
	// device is set when the request presents a registered device of this
	// user (§5.8.6). Devices arrive with M2.3.
	device bool
}

// subjectOf returns whom an attempt at rec's flow is counted against.
func subjectOf(ctx context.Context, rec *storepb.Flow) subject {
	s := subject{addr: throttleAddr(clientFrom(ctx).Addr)}
	if rec.UserId != "" {
		s.user = digest("user", []byte(rec.UserId))
	} else {
		s.user = digest("login", rec.LoginKey)
	}
	return s
}

// throttleAddr is the address a counter is kept for: an IPv4 address as
// itself, also when mapped into IPv6, and an IPv6 address by its /64, which
// is what one subscriber is usually given (amendment A6).
func throttleAddr(a netip.Addr) netip.Addr {
	if !a.IsValid() {
		return netip.Addr{}
	}
	a = a.Unmap().WithZone("")
	if a.Is6() {
		p, _ := a.Prefix(64)
		return p.Addr()
	}
	return a
}

// digest hashes a label and parts, each with its length, so no two
// different lists of parts give the same input.
func digest(label string, parts ...[]byte) []byte {
	h := sha256.New()
	var n [4]byte
	for _, p := range append([][]byte{[]byte(label)}, parts...) {
		binary.BigEndian.PutUint32(n[:], uint32(len(p)))
		h.Write(n[:])
		h.Write(p)
	}
	return h.Sum(nil)
}

// counter is one counter an attempt touches.
type counter struct {
	kind string
	key  []byte // in the throttle bucket
}

func counterKey(kind string, d []byte) counter {
	return counter{kind, store.Key([]byte(kind), []byte(hex.EncodeToString(d)))}
}

// counters returns the counters an attempt by s touches: all three; the
// pair's alone for a registered device (§5.8.6); the user's alone without
// an address, or for a device without one (§5.8.9).
func (s subject) counters() []counter {
	user := counterKey(counterUser, s.user)
	if !s.addr.IsValid() {
		return []counter{user}
	}
	addr := s.addr.As16()
	pair := counterKey(counterPair, digest("pair", s.user, addr[:]))
	if s.device {
		return []counter{pair}
	}
	return []counter{user, counterKey(counterAddr, digest("addr", addr[:])), pair}
}

// cleared returns the counters a success clears: the user's and the
// pair's, whether or not the attempt was counted against them (§5.8.5).
func (s subject) cleared() []counter {
	out := []counter{counterKey(counterUser, s.user)}
	if s.addr.IsValid() {
		addr := s.addr.As16()
		out = append(out, counterKey(counterPair, digest("pair", s.user, addr[:])))
	}
	return out
}

// attempt is an attempt counted and let through, for succeed.
type attempt struct {
	subject  subject
	counters []counter
	before   []*storepb.Counter // each counter as the attempt found it
	after    []*storepb.Counter // and as it left it
}

// waitError carries the wait for RetryAfter. Its text reaches logs only.
type waitError struct{ d time.Duration }

func (e waitError) Error() string { return fmt.Sprintf("auth: a wait of %v is in force", e.d) }

// RetryAfter reports how long the wait behind an ErrTooManyAttempts lasts.
func RetryAfter(err error) (time.Duration, bool) {
	var w waitError
	if errors.As(err, &w) {
		return w.d, true
	}
	return 0, false
}

// count decides, in one transaction, whether an attempt by s may go on
// (§5.8.3, amendment A7). If any counter is in a wait it is refused and
// changes nothing: a refusal costs no hash and gives no guess, so it isn't
// a failure, and counting it would let an address already in a wait push
// other counters further. Otherwise it is added to every counter before
// its proof is checked, so concurrent attempts are ordered and can't all
// find the counters empty. It returns ErrTooManyAttempts, wrapping the
// longest wait, or the attempt to pass to succeed.
func (a *Auth) count(s subject) (*attempt, error) {
	cs := s.counters()
	var at *attempt
	var wait int64
	// Batch may run this more than once: it depends only on what it reads.
	err := a.db.Batch(func(tx *bolt.Tx) error {
		now := a.now().UnixNano()
		at, wait = &attempt{subject: s, counters: cs}, 0
		recs := make([]*storepb.Counter, len(cs))
		for i, c := range cs {
			rec := new(storepb.Counter)
			if err := store.Get(tx, store.Throttle, c.key, rec); err != nil && !errors.Is(err, store.ErrNotFound) {
				return err
			}
			a.expire(rec, now)
			if rec.Until > now {
				wait = max(wait, rec.Until-now)
			}
			recs[i] = rec
		}
		if wait > 0 {
			return nil
		}
		for i, c := range cs {
			rec := recs[i]
			before := &storepb.Counter{Failures: rec.Failures, Last: rec.Last, Until: rec.Until, Seq: rec.Seq}
			if rec.Failures < 1<<31 {
				rec.Failures++
			}
			rec.Last = now
			if d := a.backoff(rec.Failures); d > 0 {
				rec.Until = max(rec.Until, now+int64(d))
			}
			rec.Seq++
			if err := store.Put(tx, store.Throttle, c.key, rec); err != nil {
				return err
			}
			at.before = append(at.before, before)
			at.after = append(at.after, rec)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("auth: throttle: %w", err)
	}
	if wait > 0 {
		return nil, ErrTooManyAttempts.Wrap(waitError{time.Duration(wait)})
	}
	return at, nil
}

// expire starts a counter again from zero when it has seen no attempt for
// throttle.window and no wait is in force (§5.8.5).
func (a *Auth) expire(c *storepb.Counter, now int64) {
	if now-c.Last >= int64(a.cfg.AuthThrottleWindow()) && now >= c.Until {
		c.Failures, c.Until = 0, 0
	}
}

// backoff is the wait after n failures: none up to throttle.free, then one
// second, doubling with each failure, up to throttle.ceiling (§5.8.2).
func (a *Auth) backoff(n uint32) time.Duration {
	free, ceiling := uint32(a.cfg.AuthThrottleFree()), a.cfg.AuthThrottleCeiling()
	if n < free {
		return 0
	}
	// time.Second<<34 overflows: past 2^30 seconds every ceiling is reached.
	if n-free >= 30 {
		return ceiling
	}
	return min(time.Second<<(n-free), ceiling)
}

// succeed records that the attempt's proof was right (§5.8.5). The user's
// and the pair's counters are cleared. The address's isn't: it counts
// failures, so it loses this attempt's count alone. When no other attempt
// touched it since, it goes back to how this attempt found it, wait
// included. Otherwise the count drops by one, unless the counter may have
// started again since (the window has passed), and the wait shrinks to
// what the remaining count would have set: a wait this attempt's count
// set ends, one a failure set stays.
func (a *Auth) succeed(at *attempt) error {
	return a.db.Batch(func(tx *bolt.Tx) error {
		now := a.now().UnixNano()
		for _, c := range at.subject.cleared() {
			if err := store.Delete(tx, store.Throttle, c.key); err != nil {
				return err
			}
		}
		for i, c := range at.counters {
			if c.kind != counterAddr {
				continue
			}
			rec := new(storepb.Counter)
			if err := store.Get(tx, store.Throttle, c.key, rec); err != nil {
				if errors.Is(err, store.ErrNotFound) {
					continue
				}
				return err
			}
			mine := at.after[i]
			switch {
			case now-mine.Last >= int64(a.cfg.AuthThrottleWindow()):
				// The counter may have started again since, without this
				// attempt's count: taking one off could erase a failure.
				// (Checked first: a counter that started again may also
				// have been deleted and remade, and its seq reused.)
			case rec.Seq == mine.Seq:
				b := at.before[i]
				rec.Failures, rec.Last, rec.Until = b.Failures, b.Last, b.Until
			case rec.Failures > 0:
				rec.Failures--
				rec.Until = min(rec.Until, now+int64(a.backoff(rec.Failures)))
			}
			if rec.Failures == 0 && rec.Until <= now {
				if err := store.Delete(tx, store.Throttle, c.key); err != nil {
					return err
				}
				continue
			}
			rec.Seq++
			if err := store.Put(tx, store.Throttle, c.key, rec); err != nil {
				return err
			}
		}
		return nil
	})
}
