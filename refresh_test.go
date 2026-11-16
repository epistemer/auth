package auth

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/epistemer/errors"
	bolt "go.etcd.io/bbolt"

	"github.com/epistemer/auth/internal/secrets"
	"github.com/epistemer/auth/internal/store"
	"github.com/epistemer/auth/internal/storepb"
)

// countingClaims is a Claimer whose claims change with each call.
type countingClaims struct {
	mu sync.Mutex
	n  int
}

func (c *countingClaims) Claims(context.Context, User) (map[string]any, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.n++
	return map[string]any{"n": c.n}, nil
}

// §5.6.8: Refresh replaces the refresh token, and returns a new access
// token with the claims the Claimer returns now; the access token from
// before keeps working, with its own claims, until it expires.
func TestRefresh(t *testing.T) {
	c := &countingClaims{}
	k := newBearerKit(t, WithClaims(c))
	res := bearerSignIn(t, k)
	next, err := k.Refresh(k.ctx, res.Refresh)
	if err != nil || next.Refresh == "" || next.Refresh == res.Refresh || next.Access == "" || next.Access == res.Access {
		t.Fatalf("Refresh: %+v %v", next, err)
	}
	if _, body := k.api(t, next.Access); body != `u1 {"n":2}` {
		t.Errorf("the new token's claims: %q", body)
	}
	if code, body := k.api(t, res.Access); code != 200 || body != `u1 {"n":1}` {
		t.Errorf("the token from before: %d %q", code, body)
	}
	again, err := k.Refresh(k.ctx, next.Refresh)
	if err != nil || again.Refresh == next.Refresh {
		t.Fatalf("Refresh again: %+v %v", again, err)
	}
}

// §7, bearer: a replayed refresh token ends the session; within the grace
// period it returns the same successor.
func TestRefreshReplay(t *testing.T) {
	k := newBearerKit(t)
	res := bearerSignIn(t, k)
	first, err := k.Refresh(k.ctx, res.Refresh)
	if err != nil {
		t.Fatal(err)
	}
	k.clock.advance(5 * time.Second)
	lost, err := k.Refresh(k.ctx, res.Refresh)
	if err != nil || lost.Refresh != first.Refresh {
		t.Fatalf("within refresh.grace: %+v %v", lost, err)
	}
	if code, _ := k.api(t, lost.Access); code != 200 {
		t.Errorf("the access token from the grace answer: %d", code)
	}
	k.clock.advance(6 * time.Second)
	if _, err := k.Refresh(k.ctx, res.Refresh); !errors.Is(err, ErrNoSession) {
		t.Fatalf("a replay after refresh.grace: %v", err)
	}
	if code, _ := k.api(t, first.Access); code != http.StatusUnauthorized {
		t.Errorf("the session after a replay: %d", code)
	}
	if _, err := k.Refresh(k.ctx, first.Refresh); !errors.Is(err, ErrNoSession) {
		t.Errorf("the successor after a replay: %v", err)
	}
	reused := false
	for _, e := range k.events.all {
		reused = reused || e.Kind == "refresh.reused"
	}
	if !reused {
		t.Error("no refresh.reused event")
	}
	if _, err := k.Refresh(k.ctx, "made-up"); !errors.Is(err, ErrNoSession) {
		t.Errorf("a made-up refresh token: %v", err)
	}
}

// Of concurrent refreshes with one token, one rotates and the others get
// its successor (all within the grace), never two successors.
func TestRefreshConcurrent(t *testing.T) {
	k := newBearerKit(t)
	res := bearerSignIn(t, k)
	var wg sync.WaitGroup
	var mu sync.Mutex
	got := map[string]int{}
	for range 10 {
		wg.Go(func() {
			r, err := k.Refresh(k.ctx, res.Refresh)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				got["err "+err.Error()]++
				return
			}
			got[r.Refresh]++
		})
	}
	wg.Wait()
	if len(got) != 1 {
		t.Errorf("answers %v", got)
	}
	for k := range got {
		if strings.HasPrefix(k, "err ") {
			t.Errorf("a refresh failed: %s", k)
		}
	}
}

// §7, bearer: the store holds no refresh token in the clear, the
// successor included.
func TestRefreshStoreHoldsNoToken(t *testing.T) {
	k := newBearerKit(t)
	res := bearerSignIn(t, k)
	next, _ := k.Refresh(k.ctx, res.Refresh)
	k.db.View(func(tx *bolt.Tx) error {
		return tx.ForEach(func(_ []byte, b *bolt.Bucket) error {
			return walk(b, func(key, v []byte) {
				for _, s := range []string{res.Refresh, next.Refresh, res.Access, next.Access} {
					if strings.Contains(string(key), s) || strings.Contains(string(v), s) {
						t.Error("the store holds a token")
					}
				}
			})
		})
	})
}

// §5.6.10, §7: a disabled user is refused at Refresh and Reissue.
func TestRefreshDisabled(t *testing.T) {
	k := newBearerKit(t)
	res := bearerSignIn(t, k)
	k.dir.mu.Lock()
	k.dir.users["sara"] = User{ID: "u1", Name: "sara", Disabled: true}
	k.dir.mu.Unlock()
	if _, err := k.Refresh(k.ctx, res.Refresh); !errors.Is(err, ErrUserDisabled) {
		t.Errorf("Refresh: %v", err)
	}
	if _, err := k.Reissue(k.ctx, res.Session); !errors.Is(err, ErrUserDisabled) {
		t.Errorf("Reissue: %v", err)
	}
}

// §7, bearer: Refresh and Reissue carry the claims the Claimer returns at
// that moment; a cookie session's Reissue changes its Session.Claims.
func TestReissue(t *testing.T) {
	c := &countingClaims{}
	k := newBearerKit(t, WithClaims(c))
	res := bearerSignIn(t, k)
	access, err := k.Reissue(k.ctx, res.Session)
	if err != nil || access == "" {
		t.Fatalf("Reissue: %q %v", access, err)
	}
	if _, body := k.api(t, access); body != `u1 {"n":2}` {
		t.Errorf("claims after Reissue: %q", body)
	}
	if next, _ := k.Refresh(k.ctx, res.Refresh); next.Session.Claims["n"] != float64(3) {
		t.Errorf("claims after Refresh: %v", next.Session.Claims)
	}

	f, _ := k.signIn(t, "sara", goodPassword)
	web, _ := k.Finish(k.ctx, f.Token)
	if tok, err := k.Reissue(k.ctx, web.Session); err != nil || tok != "" {
		t.Fatalf("Reissue of a cookie session: %q %v", tok, err)
	}
	if web.Session.Claims["n"] != float64(5) {
		t.Errorf("Reissue didn't update the caller's claims: %v", web.Session.Claims)
	}
	called := false
	h := k.Load(Cookie())(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		s, _ := From(r.Context())
		if s.Claims["n"] != float64(5) {
			t.Errorf("cookie session claims %v", s.Claims)
		}
	}))
	r := httptestRequest(web.cookie)
	h.ServeHTTP(nopWriter{}, r)
	if !called {
		t.Error("the handler didn't run")
	}
	// Another user's session, by its ID with the wrong user, is none.
	if _, err := k.Reissue(k.ctx, &Session{ID: web.Session.ID, User: "u2"}); !errors.Is(err, ErrNoSession) {
		t.Errorf("Reissue with another user: %v", err)
	}

	k.Revoke(k.ctx, "u1", res.Session.ID)
	if _, err := k.Reissue(k.ctx, res.Session); !errors.Is(err, ErrNoSession) {
		t.Errorf("Reissue of a revoked session: %v", err)
	}
	if _, err := k.Refresh(k.ctx, res.Refresh); !errors.Is(err, ErrNoSession) {
		t.Errorf("Refresh of a revoked session: %v", err)
	}
}

// Sweep removes a dead session's refresh tokens with it.
func TestSweepRefresh(t *testing.T) {
	k := newBearerKit(t)
	bearerSignIn(t, k)
	k.clock.advance(25 * time.Hour)
	k.Sweep(k.ctx)
	n := 0
	k.db.View(func(tx *bolt.Tx) error {
		for _, b := range [][]byte{store.Refresh, store.RefreshBySession} {
			store.B(tx, b).ForEach(func(_, _ []byte) error { n++; return nil })
		}
		return nil
	})
	if n != 0 {
		t.Errorf("%d refresh records after the session's end", n)
	}
}

func httptestRequest(cookie string) *http.Request {
	r, _ := http.NewRequest("GET", "https://shop.example/", nil)
	r.AddCookie(&http.Cookie{Name: "__Host-session", Value: cookie})
	return r
}

type nopWriter struct{}

func (nopWriter) Header() http.Header         { return http.Header{} }
func (nopWriter) Write(b []byte) (int, error) { return len(b), nil }
func (nopWriter) WriteHeader(int)             {}

// A session idle past session.idle can't be revived by its refresh token,
// nor one kept in use past session.lifetime; Reissue refuses an idle one.
func TestRefreshIdleSession(t *testing.T) {
	k := newBearerKit(t)
	res := bearerSignIn(t, k)
	k.clock.advance(25 * time.Hour) // past idle (24h), within lifetime (2160h)
	if _, err := k.Refresh(k.ctx, res.Refresh); !errors.Is(err, ErrNoSession) {
		t.Errorf("Refresh of an idle session: %v", err)
	}
	if _, err := k.Reissue(k.ctx, res.Session); !errors.Is(err, ErrNoSession) {
		t.Errorf("Reissue of an idle session: %v", err)
	}
	// Refreshed twice a day, it lives until session.lifetime and no longer.
	busy := bearerSignIn(t, k)
	start, tok := k.clock.now(), busy.Refresh
	for k.clock.now().Before(start.Add(2160*time.Hour - 12*time.Hour)) {
		k.clock.advance(12 * time.Hour)
		r, err := k.Refresh(k.ctx, tok)
		if err != nil {
			t.Fatalf("a session in use at %v: %v", k.clock.now().Sub(start), err)
		}
		tok = r.Refresh
	}
	k.clock.advance(13 * time.Hour)
	if _, err := k.Refresh(k.ctx, tok); !errors.Is(err, ErrNoSession) {
		t.Errorf("Refresh past session.lifetime: %v", err)
	}
}

// Review 0012, finding 1: the grace returns a successor only while it is
// unused. Once it has been refreshed, the old token is reuse, even within
// the grace, and the session ends; the chain can't be walked.
func TestRefreshGraceUsedSuccessor(t *testing.T) {
	k := newBearerKit(t)
	res := bearerSignIn(t, k)
	t1, _ := k.Refresh(k.ctx, res.Refresh)
	if _, err := k.Refresh(k.ctx, t1.Refresh); err != nil {
		t.Fatal(err)
	}
	k.clock.advance(time.Second)
	if _, err := k.Refresh(k.ctx, res.Refresh); !errors.Is(err, ErrNoSession) {
		t.Errorf("the first token, its successor used: %v", err)
	}
	if code, _ := k.api(t, t1.Access); code != http.StatusUnauthorized {
		t.Errorf("the session after the reuse: %d", code)
	}
}

// Rotating a token wipes its predecessor's sealed copy of it.
func TestRefreshPredecessorWiped(t *testing.T) {
	k := newBearerKit(t)
	res := bearerSignIn(t, k)
	t1, _ := k.Refresh(k.ctx, res.Refresh)
	succ := func() int {
		var r storepb.Refresh
		k.db.View(func(tx *bolt.Tx) error { return store.Get(tx, store.Refresh, secrets.Hash(res.Refresh), &r) })
		return len(r.Successor)
	}
	if succ() == 0 {
		t.Fatal("no sealed successor within the grace")
	}
	k.Refresh(k.ctx, t1.Refresh)
	if succ() != 0 {
		t.Error("the predecessor kept its successor after the successor rotated")
	}
}

// Sweep wipes a sealed successor once its grace is over.
func TestSweepWipesSuccessor(t *testing.T) {
	k := newBearerKit(t)
	res := bearerSignIn(t, k)
	k.Refresh(k.ctx, res.Refresh)
	k.clock.advance(11 * time.Second)
	k.Sweep(k.ctx)
	var r storepb.Refresh
	k.db.View(func(tx *bolt.Tx) error { return store.Get(tx, store.Refresh, secrets.Hash(res.Refresh), &r) })
	if len(r.Successor) != 0 || r.Replaced == 0 {
		t.Errorf("record %+v", &r)
	}
}

// Review 0012, finding 2: a refresh token from before a step-up, used
// after it, is reuse: the session ends.
func TestRefreshAfterStepUp(t *testing.T) {
	k := newBearerKit(t)
	res := bearerSignIn(t, k)
	ctx := withSession(k.ctx, res.Session)
	up, _ := k.StepUp(ctx, res.Session)
	k.Prove(ctx, up.Token, Password(goodPassword))
	next, err := k.Finish(ctx, up.Token)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := k.Refresh(k.ctx, res.Refresh); !errors.Is(err, ErrNoSession) {
		t.Errorf("a pre-step-up refresh token: %v", err)
	}
	if code, _ := k.api(t, next.Access); code != http.StatusUnauthorized {
		t.Errorf("the session after the reuse: %d", code)
	}
}

// failingClaims fails after its first answer.
type failingClaims struct{ n int }

func (f *failingClaims) Claims(context.Context, User) (map[string]any, error) {
	f.n++
	if f.n > 2 {
		return nil, errors.New("claims are down")
	}
	return map[string]any{}, nil
}

// Review 0012, finding 3: reuse ends the session though the Claimer fails.
func TestRefreshReuseClaimerDown(t *testing.T) {
	k := newBearerKit(t, WithClaims(&failingClaims{}))
	res := bearerSignIn(t, k)
	t1, err := k.Refresh(k.ctx, res.Refresh)
	if err != nil {
		t.Fatal(err)
	}
	k.clock.advance(time.Minute)
	if _, err := k.Refresh(k.ctx, res.Refresh); !errors.Is(err, ErrNoSession) {
		t.Errorf("a replay with the Claimer down: %v", err)
	}
	if code, _ := k.api(t, t1.Access); code != http.StatusUnauthorized {
		t.Errorf("the session survived a replay: %d", code)
	}
}

// A token replaced between Refresh's first look and its rotation, by a
// racing use, gets that use's successor: never a second one.
func TestRefreshReplacedBetweenLooks(t *testing.T) {
	k := newBearerKit(t)
	res := bearerSignIn(t, k)
	var other Result
	betweenRefreshLooks = func() {
		betweenRefreshLooks = nil
		other, _ = k.Refresh(k.ctx, res.Refresh)
	}
	defer func() { betweenRefreshLooks = nil }()
	got, err := k.Refresh(k.ctx, res.Refresh)
	if err != nil || got.Refresh != other.Refresh {
		t.Errorf("a refresh that lost the race: %+v %v; the winner's %q", got, err, other.Refresh)
	}
	// Outside the grace, the same race is reuse.
	k2 := newBearerKitGrace(t, 0)
	r2 := bearerSignIn(t, k2)
	var won Result
	betweenRefreshLooks = func() {
		betweenRefreshLooks = nil
		won, _ = k2.Refresh(k2.ctx, r2.Refresh)
	}
	if _, err := k2.Refresh(k2.ctx, r2.Refresh); !errors.Is(err, ErrNoSession) {
		t.Errorf("a race with no grace: %v", err)
	}
	if code, _ := k2.api(t, won.Access); code != http.StatusUnauthorized {
		t.Errorf("the session after a race with no grace: %d", code)
	}
}

func newBearerKitGrace(t *testing.T, grace time.Duration) *kit {
	k := newBearerKit(t)
	k.cfg.(*config).grace = grace
	return k
}
