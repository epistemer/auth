package auth

import (
	"context"
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/epistemer/errors"
	bolt "go.etcd.io/bbolt"

	"github.com/epistemer/auth/internal/store"
	"github.com/epistemer/auth/internal/storepb"
)

const wrongPassword = "purple walrus sings 12 tunes"

// from returns a context whose requests come from addr.
func (k *kit) from(addr string) context.Context {
	return WithClient(k.ctx, Client{Addr: netip.MustParseAddr(addr)})
}

// try signs in as login with pw from ctx's client, and reports the error
// and the hashes it cost.
func (k *kit) try(t *testing.T, ctx context.Context, login, pw string) (int64, error) {
	t.Helper()
	f, err := k.SignIn(ctx, login, Cookie())
	if err != nil {
		t.Fatal(err)
	}
	n := k.hasher.Count()
	_, err = k.Prove(ctx, f.Token, Password(pw))
	return k.hasher.Count() - n, err
}

// counterOf reads one counter of the subject.
func (k *kit) counterOf(t *testing.T, s subject, kind string) *storepb.Counter {
	t.Helper()
	for _, c := range s.counters() {
		if c.kind != kind {
			continue
		}
		rec := new(storepb.Counter)
		err := k.db.View(func(tx *bolt.Tx) error { return store.Get(tx, store.Throttle, c.key, rec) })
		if errors.Is(err, store.ErrNotFound) {
			return nil
		}
		if err != nil {
			t.Fatal(err)
		}
		return rec
	}
	t.Fatalf("no %s counter", kind)
	return nil
}

func userSubject(id UserID, addr string) subject {
	return subjectOf(WithClient(context.Background(), Client{Addr: netip.MustParseAddr(addr)}), &storepb.Flow{UserId: string(id)})
}

// §7, throttling: the sixth wrong password returns ErrTooManyAttempts
// without hashing, and RetryAfter doubles with each further failure up to
// the ceiling. A known and an unknown login answer alike.
func TestThrottleSixth(t *testing.T) {
	k := newKit(t, WithPolicy(allowUnverified))
	k.addUser(t, "sara", User{ID: "u1", Name: "sara"}, goodPassword)
	for _, login := range []string{"sara", "ghost"} {
		ctx := k.from("192.0.2.1")
		if login == "ghost" {
			ctx = k.from("192.0.2.2")
		}
		for i := 1; i <= 5; i++ {
			if hashes, err := k.try(t, ctx, login, wrongPassword); !errors.Is(err, ErrBadCredentials) || hashes != 1 {
				t.Fatalf("%s, failure %d: %v, %d hashes", login, i, err, hashes)
			}
		}
		for n := 6; n <= 20; n++ {
			hashes, err := k.try(t, ctx, login, goodPassword)
			if !errors.Is(err, ErrTooManyAttempts) || hashes != 0 {
				t.Fatalf("%s, attempt %d: %v, %d hashes", login, n, err, hashes)
			}
			want := min(time.Second<<(n-5), 15*time.Minute)
			if d, ok := RetryAfter(err); !ok || d != want {
				t.Errorf("%s, attempt %d: RetryAfter = %v, %v; want %v", login, n, d, ok, want)
			}
			if errors.KindOf(err) != errors.RateLimited {
				t.Errorf("kind %v", errors.KindOf(err))
			}
		}
	}
	if _, ok := RetryAfter(ErrBadCredentials); ok {
		t.Error("RetryAfter found a wait in ErrBadCredentials")
	}
	// Once the wait is over the right password signs in.
	k.clock.advance(15 * time.Minute)
	if _, err := k.try(t, k.from("192.0.2.1"), "sara", goodPassword); err != nil {
		t.Fatal(err)
	}
}

// §7, throttling: a wait on one address doesn't block a login from
// another address until the login's own counter is reached.
func TestThrottleOtherAddress(t *testing.T) {
	k := newKit(t, WithPolicy(allowUnverified))
	k.addUser(t, "sara", User{ID: "u1", Name: "sara"}, goodPassword)
	a, b, c := k.from("192.0.2.1"), k.from("198.51.100.7"), k.from("203.0.113.9")
	for _, login := range []string{"one", "two", "three", "four", "five"} {
		if _, err := k.try(t, a, login, wrongPassword); !errors.Is(err, ErrBadCredentials) {
			t.Fatal(err)
		}
	}
	// a is in a wait; sara isn't, from b. The refused try counts against
	// sara too.
	if _, err := k.try(t, a, "sara", goodPassword); !errors.Is(err, ErrTooManyAttempts) {
		t.Fatalf("from the waiting address: %v", err)
	}
	if hashes, err := k.try(t, b, "sara", wrongPassword); !errors.Is(err, ErrBadCredentials) || hashes != 1 {
		t.Fatalf("from another address: %v, %d hashes", err, hashes)
	}
	// Three more failures from b make five against sara: then no address
	// gets through.
	for range 3 {
		if _, err := k.try(t, b, "sara", wrongPassword); !errors.Is(err, ErrBadCredentials) {
			t.Fatal(err)
		}
	}
	if hashes, err := k.try(t, c, "sara", goodPassword); !errors.Is(err, ErrTooManyAttempts) || hashes != 0 {
		t.Fatalf("after the login's own counter: %v, %d hashes", err, hashes)
	}
}

// §7, throttling: a thousand concurrent failures lose no count, and no more
// than throttle.free of them reach the hash.
func TestThrottleConcurrent(t *testing.T) {
	k := newKit(t, WithPolicy(allowUnverified))
	k.addUser(t, "sara", User{ID: "u1", Name: "sara"}, goodPassword)
	ctx := k.from("192.0.2.1")
	f, err := k.SignIn(ctx, "sara", Cookie())
	if err != nil {
		t.Fatal(err)
	}
	n := k.hasher.Count()
	var wg sync.WaitGroup
	var mu sync.Mutex
	got := map[error]int{}
	for range 1000 {
		wg.Go(func() {
			_, err := k.Prove(ctx, f.Token, Password(wrongPassword))
			switch {
			case errors.Is(err, ErrBadCredentials):
				err = ErrBadCredentials
			case errors.Is(err, ErrTooManyAttempts):
				err = ErrTooManyAttempts
			}
			mu.Lock()
			got[err]++
			mu.Unlock()
		})
	}
	wg.Wait()
	if got[ErrBadCredentials] != 5 || got[ErrTooManyAttempts] != 995 || len(got) != 2 {
		t.Errorf("answers %v", got)
	}
	if d := k.hasher.Count() - n; d != 5 {
		t.Errorf("%d hashes", d)
	}
	s := userSubject("u1", "192.0.2.1")
	for _, kind := range []string{counterUser, counterAddr, counterPair} {
		if c := k.counterOf(t, s, kind); c == nil || c.Failures != 1000 {
			t.Errorf("%s counter %v", kind, c)
		}
	}
}

// §7, throttling: Alice, alice and " alice " share one counter, whether or
// not the login resolves.
func TestThrottleSpellings(t *testing.T) {
	k := newKit(t, WithPolicy(allowUnverified))
	u := User{ID: "u1", Name: "alice"}
	k.addUser(t, "alice", u, goodPassword)
	k.dir.mu.Lock()
	k.dir.users["Alice"], k.dir.users[" alice "] = u, u
	k.dir.mu.Unlock()
	spellings := []string{"Alice", "alice", " alice "}
	for _, base := range []string{"alice", "bob"} {
		for i := range 5 {
			login := spellings[i%3]
			if base == "bob" {
				login = []string{"Bob", "bob", " bob ", "BOB", "ｂob"}[i] // NFKC folds the fullwidth b
			}
			// A new address each time, so only the login's counter adds up.
			ctx := k.from(netip.AddrFrom4([4]byte{192, 0, 2, byte(10 + i)}).String())
			if _, err := k.try(t, ctx, login, wrongPassword); !errors.Is(err, ErrBadCredentials) {
				t.Fatalf("%s, %q: %v", base, login, err)
			}
		}
		if _, err := k.try(t, k.from("192.0.2.99"), base, goodPassword); !errors.Is(err, ErrTooManyAttempts) {
			t.Errorf("%s: the sixth try from any spelling: %v", base, err)
		}
	}
}

// §7, throttling: a counter with no attempt for throttle.window starts
// again; a counter in a wait doesn't, until the wait is over.
func TestThrottleWindow(t *testing.T) {
	k := newKit(t, WithPolicy(allowUnverified))
	k.addUser(t, "sara", User{ID: "u1", Name: "sara"}, goodPassword)
	ctx := k.from("192.0.2.1")
	fail := func(n int) {
		t.Helper()
		for i := range n {
			if hashes, err := k.try(t, ctx, "sara", wrongPassword); !errors.Is(err, ErrBadCredentials) || hashes != 1 {
				t.Fatalf("failure %d: %v, %d hashes", i+1, err, hashes)
			}
		}
	}
	fail(5)
	// Once the wait is over, the counter still counts: the next failure
	// waits two seconds.
	k.clock.advance(time.Second)
	fail(1)
	_, err := k.try(t, ctx, "sara", wrongPassword)
	if d, _ := RetryAfter(err); d != 4*time.Second {
		t.Fatalf("after a sixth failure: %v, %v", err, d)
	}
	k.clock.advance(time.Hour)
	fail(5)
	if _, err := k.try(t, ctx, "sara", wrongPassword); !errors.Is(err, ErrTooManyAttempts) {
		t.Fatal(err)
	}

	// A window shorter than the wait: the counter keeps its wait.
	c := &storepb.Counter{Failures: 20, Last: 0, Until: int64(2 * time.Hour)}
	k.expire(c, int64(90*time.Minute))
	if c.Failures != 20 {
		t.Error("a counter in a wait started again")
	}
	k.expire(c, int64(2*time.Hour))
	if c.Failures != 0 || c.Until != 0 {
		t.Error("a counter past its window and its wait didn't start again")
	}
}

// §5.8.5: a success clears the user's and the pair's counters, and the
// address's loses only that attempt's count. So people signing in from one
// address put it in no wait, and a stranger can't clear it by signing in
// to an account of their own.
func TestThrottleSuccess(t *testing.T) {
	k := newKit(t, WithPolicy(allowUnverified))
	k.addUser(t, "sara", User{ID: "u1", Name: "sara"}, goodPassword)
	k.addUser(t, "omar", User{ID: "u2", Name: "omar"}, goodPassword)
	office := k.from("192.0.2.1")
	for range 4 {
		if _, err := k.try(t, office, "sara", wrongPassword); !errors.Is(err, ErrBadCredentials) {
			t.Fatal(err)
		}
	}
	if _, err := k.try(t, office, "sara", goodPassword); err != nil {
		t.Fatal(err)
	}
	s := userSubject("u1", "192.0.2.1")
	if c := k.counterOf(t, s, counterUser); c != nil {
		t.Errorf("user counter %v after a success", c)
	}
	if c := k.counterOf(t, s, counterPair); c != nil {
		t.Errorf("pair counter %v after a success", c)
	}
	if c := k.counterOf(t, s, counterAddr); c == nil || c.Failures != 4 || c.Until != 0 {
		t.Errorf("address counter %v after a success; want 4 failures", c)
	}
	for i := range 20 {
		if _, err := k.try(t, office, "omar", goodPassword); err != nil {
			t.Fatalf("sign-in %d from the office: %v", i+1, err)
		}
	}
	// A fifth failure from the office puts it in a wait, successes or not.
	if _, err := k.try(t, office, "nobody", wrongPassword); !errors.Is(err, ErrBadCredentials) {
		t.Fatal(err)
	}
	if _, err := k.try(t, office, "omar", goodPassword); !errors.Is(err, ErrTooManyAttempts) {
		t.Fatalf("a stranger's own sign-in cleared the address: %v", err)
	}
}

// succeed takes back only its own count from an address another attempt
// touched meanwhile, and leaves that attempt's wait.
func TestSucceedAfterAnotherAttempt(t *testing.T) {
	k := newKit(t)
	s := userSubject("u1", "192.0.2.1")
	for range 4 {
		if _, err := k.count(s); err != nil {
			t.Fatal(err)
		}
	}
	mine, err := k.count(s) // the fifth: a wait starts
	if err != nil {
		t.Fatal(err)
	}
	k.clock.advance(time.Second)
	other := userSubject("u2", "192.0.2.1")
	if _, err := k.count(other); err != nil { // the sixth on the address
		t.Fatal(err)
	}
	if err := k.succeed(mine); err != nil {
		t.Fatal(err)
	}
	// Five failures remain, the last one now: the wait is five failures'.
	if c := k.counterOf(t, s, counterAddr); c.Failures != 5 || c.Until != k.clock.now().Add(time.Second).UnixNano() {
		t.Errorf("address counter %v; want 5 failures and a wait of 1s", c)
	}

	// Untouched since, the address goes back as the attempt found it.
	k2 := newKit(t)
	at, err := k2.count(s)
	if err != nil {
		t.Fatal(err)
	}
	if err := k2.succeed(at); err != nil {
		t.Fatal(err)
	}
	if c := k2.counterOf(t, s, counterAddr); c != nil {
		t.Errorf("address counter %v; want none", c)
	}
}

// §5.8.6 and §5.8.9: which counters an attempt touches.
func TestThrottleCounters(t *testing.T) {
	s := userSubject("u1", "192.0.2.1")
	kinds := func(s subject) (out []string) {
		for _, c := range s.counters() {
			out = append(out, c.kind)
		}
		return out
	}
	if got := kinds(s); len(got) != 3 {
		t.Errorf("with an address: %v", got)
	}
	s.device = true
	if got := kinds(s); len(got) != 1 || got[0] != counterPair {
		t.Errorf("with a registered device: %v", got)
	}
	none := subjectOf(context.Background(), &storepb.Flow{UserId: "u1"})
	if got := kinds(none); len(got) != 1 || got[0] != counterUser {
		t.Errorf("without an address: %v", got)
	}
	none.device = true
	if got := kinds(none); len(got) != 1 || got[0] != counterUser {
		t.Errorf("a device without an address: %v", got)
	}
	// A user's ID and a login's hash never share a counter.
	byID := subjectOf(context.Background(), &storepb.Flow{UserId: "u1"})
	byLogin := subjectOf(context.Background(), &storepb.Flow{LoginKey: []byte("u1")})
	if string(byID.counters()[0].key) == string(byLogin.counters()[0].key) {
		t.Error("an ID and a login share a counter")
	}
}

// Amendment A6: an IPv6 address is counted by its /64; an IPv4 address
// mapped into IPv6 is the IPv4 address.
func TestThrottleAddr(t *testing.T) {
	for _, c := range []struct{ a, b string }{
		{"2001:db8:1:2::1", "2001:db8:1:2:ffff:ffff:ffff:ffff"},
		{"2001:db8:1:2::1%eth0", "2001:db8:1:2::9"},
		{"::ffff:192.0.2.1", "192.0.2.1"},
	} {
		if x, y := throttleAddr(netip.MustParseAddr(c.a)), throttleAddr(netip.MustParseAddr(c.b)); x != y {
			t.Errorf("%s and %s: %v and %v", c.a, c.b, x, y)
		}
	}
	for _, c := range []struct{ a, b string }{
		{"2001:db8:1:2::1", "2001:db8:1:3::1"},
		{"192.0.2.1", "192.0.2.2"},
	} {
		if throttleAddr(netip.MustParseAddr(c.a)) == throttleAddr(netip.MustParseAddr(c.b)) {
			t.Errorf("%s and %s share a counter", c.a, c.b)
		}
	}
	if throttleAddr(netip.Addr{}).IsValid() {
		t.Error("no address became one")
	}
}

// Concurrent successes from one address leave it with no count and no
// wait, whatever order they finish in.
func TestConcurrentSuccesses(t *testing.T) {
	for _, order := range [][]int{{0, 1, 2, 3, 4}, {4, 3, 2, 1, 0}, {2, 4, 0, 3, 1}} {
		k := newKit(t)
		var ats []*attempt
		for i := range 5 {
			at, err := k.count(userSubject(UserID(fmt.Sprint("u", i)), "192.0.2.1"))
			if err != nil {
				t.Fatal(err)
			}
			ats = append(ats, at)
		}
		for _, i := range order {
			if err := k.succeed(ats[i]); err != nil {
				t.Fatal(err)
			}
		}
		if c := k.counterOf(t, userSubject("u0", "192.0.2.1"), counterAddr); c != nil {
			t.Errorf("order %v: address counter %v", order, c)
		}
	}
}

// A success that outlived throttle.window takes nothing off a counter that
// may have started again meanwhile.
func TestSucceedAfterTheWindow(t *testing.T) {
	k := newKit(t)
	at, err := k.count(userSubject("u1", "192.0.2.1"))
	if err != nil {
		t.Fatal(err)
	}
	k.clock.advance(time.Hour)
	s := userSubject("u2", "192.0.2.1")
	if _, err := k.count(s); err != nil { // starts the counter again
		t.Fatal(err)
	}
	if err := k.succeed(at); err != nil {
		t.Fatal(err)
	}
	if c := k.counterOf(t, s, counterAddr); c == nil || c.Failures != 1 {
		t.Errorf("address counter %v; want the new failure", c)
	}
}

// The wait never wraps: after any number of failures it is positive, never
// shorter than the one before, and at most the ceiling.
func TestBackoffBounds(t *testing.T) {
	k := newKit(t)
	prev := time.Duration(0)
	for n := uint32(5); n < 300; n++ {
		d := k.backoff(n)
		if d <= 0 || d < prev || d > 15*time.Minute {
			t.Fatalf("backoff(%d) = %v after %v", n, d, prev)
		}
		prev = d
	}
	for _, n := range []uint32{1 << 20, 1 << 31, 1<<32 - 1} {
		if d := k.backoff(n); d != 15*time.Minute {
			t.Errorf("backoff(%d) = %v", n, d)
		}
	}
}

// §5.8.5 with §5.8.6: a success from a registered device, counted against
// the pair alone, clears the user's counter too.
func TestDeviceSuccessClearsUser(t *testing.T) {
	k := newKit(t)
	far := userSubject("u1", "198.51.100.1")
	for range 5 {
		if _, err := k.count(far); err != nil {
			t.Fatal(err)
		}
	}
	dev := userSubject("u1", "192.0.2.1")
	dev.device = true
	at, err := k.count(dev)
	if err != nil {
		t.Fatalf("a registered device during a wait on its user: %v", err)
	}
	if err := k.succeed(at); err != nil {
		t.Fatal(err)
	}
	if c := k.counterOf(t, far, counterUser); c != nil {
		t.Errorf("user counter %v after the device's success", c)
	}
	if c := k.counterOf(t, far, counterPair); c == nil || c.Failures != 5 {
		t.Errorf("another address's pair counter %v; want it kept", c)
	}
}

// A disabled user's right password is no success: the counters keep it.
func TestDisabledStaysCounted(t *testing.T) {
	k := newKit(t, WithPolicy(allowUnverified))
	k.addUser(t, "sara", User{ID: "u1", Name: "sara", Disabled: true}, goodPassword)
	ctx := k.from("192.0.2.1")
	for range 4 {
		if _, err := k.try(t, ctx, "sara", wrongPassword); !errors.Is(err, ErrBadCredentials) {
			t.Fatal(err)
		}
	}
	if _, err := k.try(t, ctx, "sara", goodPassword); !errors.Is(err, ErrUserDisabled) {
		t.Fatal(err)
	}
	if _, err := k.try(t, ctx, "sara", wrongPassword); !errors.Is(err, ErrTooManyAttempts) {
		t.Errorf("after a disabled user's right password: %v", err)
	}
}

// §7, throttling: a wait on one login from one address doesn't block that
// login from another address until the login's own counter is reached.
// The login's counter is cleared by a success elsewhere; the pair's isn't.
func TestThrottleOneLoginOneAddress(t *testing.T) {
	k := newKit(t, WithPolicy(allowUnverified))
	k.addUser(t, "sara", User{ID: "u1", Name: "sara"}, goodPassword)
	k.addUser(t, "omar", User{ID: "u2", Name: "omar"}, goodPassword)
	a, b := k.from("192.0.2.1"), k.from("198.51.100.7")
	for range 5 {
		if _, err := k.try(t, a, "sara", wrongPassword); !errors.Is(err, ErrBadCredentials) {
			t.Fatal(err)
		}
	}
	if _, err := k.try(t, b, "sara", goodPassword); !errors.Is(err, ErrTooManyAttempts) {
		t.Fatalf("the login's own counter: %v", err)
	}
	k.clock.advance(5 * time.Second)
	if _, err := k.try(t, b, "sara", goodPassword); err != nil {
		t.Fatal(err)
	}
	// The user's counter is clear: b gets its tries. The pair (a, sara)
	// is still counted: its next failure starts a wait there.
	for range 4 {
		if _, err := k.try(t, b, "sara", wrongPassword); !errors.Is(err, ErrBadCredentials) {
			t.Fatal(err)
		}
	}
	if c := k.counterOf(t, userSubject("u1", "192.0.2.1"), counterPair); c == nil || c.Failures < 5 {
		t.Fatalf("pair counter %v", c)
	}
	// Omar from a is held by a's own counter, which a success elsewhere
	// doesn't clear.
	if _, err := k.try(t, a, "omar", goodPassword); err != nil {
		t.Fatalf("a's wait is over: %v", err)
	}
}

// §5.8.9: a request with no address is throttled per user.
func TestThrottleNoAddress(t *testing.T) {
	k := newKit(t, WithPolicy(allowUnverified))
	k.addUser(t, "sara", User{ID: "u1", Name: "sara"}, goodPassword)
	for range 5 {
		if _, err := k.try(t, k.ctx, "sara", wrongPassword); !errors.Is(err, ErrBadCredentials) {
			t.Fatal(err)
		}
	}
	if hashes, err := k.try(t, k.ctx, "sara", goodPassword); !errors.Is(err, ErrTooManyAttempts) || hashes != 0 {
		t.Errorf("sixth without an address: %v, %d hashes", err, hashes)
	}
	if _, err := k.try(t, k.from("192.0.2.1"), "sara", goodPassword); !errors.Is(err, ErrTooManyAttempts) {
		t.Errorf("the user's counter didn't hold for an address: %v", err)
	}
}

// ADR 0007 §8: a step-up's password proof is throttled like a sign-in's.
func TestThrottleStepUp(t *testing.T) {
	k := newKit(t, WithPolicy(allowUnverified))
	k.addUser(t, "sara", User{ID: "u1", Name: "sara"}, goodPassword)
	ctx := k.from("192.0.2.1")
	f, err := k.SignIn(ctx, "sara", Cookie())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := k.Prove(ctx, f.Token, Password(goodPassword)); err != nil {
		t.Fatal(err)
	}
	r, err := k.Finish(ctx, f.Token)
	if err != nil {
		t.Fatal(err)
	}
	up, err := k.StepUp(ctx, r.Session)
	if err != nil {
		t.Fatal(err)
	}
	for range 5 {
		if _, err := k.Prove(ctx, up.Token, Password(wrongPassword)); !errors.Is(err, ErrBadCredentials) {
			t.Fatal(err)
		}
	}
	n := k.hasher.Count()
	if _, err := k.Prove(ctx, up.Token, Password(goodPassword)); !errors.Is(err, ErrTooManyAttempts) || k.hasher.Count() != n {
		t.Errorf("sixth step-up proof: %v", err)
	}
}
