package password

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/text/unicode/norm"
)

var cheap = Params{MemoryKiB: 64, Time: 1}

func mustNew(t testing.TB, p Params, n int) *Hasher {
	t.Helper()
	h, err := New(p, n)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestHashAndVerify(t *testing.T) {
	ctx := context.Background()
	h := mustNew(t, cheap, 2)
	for _, pw := range []string{
		"correct horse battery staple",
		"  leading and trailing  ",
		strings.Repeat("كلمة سر طويلة ", 73)[:1022] + "ab", // 1024 bytes of Arabic
		strings.Repeat("a b", 341) + "c",                   // 1024 bytes, spaces and letters
	} {
		phc, err := h.Hash(ctx, pw)
		if err != nil {
			t.Fatalf("%d bytes: %v", len(pw), err)
		}
		if strings.Contains(phc, pw) || !strings.HasPrefix(phc, "$argon2id$v=19$m=64,t=1,p=1$") {
			t.Fatalf("hash %q", phc)
		}
		if ok, rehash, err := h.Verify(ctx, pw, phc); !ok || rehash || err != nil {
			t.Fatalf("%d bytes: ok=%v rehash=%v err=%v", len(pw), ok, rehash, err)
		}
		if ok, _, _ := h.Verify(ctx, pw+"x", phc); ok {
			t.Fatal("a longer password verifies")
		}
	}
}

func TestNeverTrimmed(t *testing.T) {
	ctx := context.Background()
	h := mustNew(t, cheap, 1)
	phc, _ := h.Hash(ctx, " secret ")
	if ok, _, _ := h.Verify(ctx, "secret", phc); ok {
		t.Fatal("spaces were trimmed")
	}
}

func TestTooLong(t *testing.T) {
	ctx := context.Background()
	h := mustNew(t, cheap, 1)
	long := strings.Repeat("x", MaxInput+1)
	if _, err := h.Hash(ctx, long); !errors.Is(err, ErrTooLong) {
		t.Fatalf("Hash: %v", err)
	}
	phc, _ := h.Hash(ctx, long[:MaxInput])
	// Nothing is truncated: the 1025-byte password doesn't match the hash of
	// its first 1024 bytes.
	if ok, _, err := h.Verify(ctx, long, phc); ok || err != nil {
		t.Fatalf("Verify: ok=%v err=%v", ok, err)
	}
	if Check(long, rules) != TooLong {
		t.Fatal("Check doesn't refuse it")
	}
}

func TestNFKC(t *testing.T) {
	ctx := context.Background()
	h := mustNew(t, cheap, 1)
	composed := "café-passwörd-ﬁne"
	decomposed := norm.NFD.String(composed)
	if composed == decomposed {
		t.Fatal("test input has no decomposable characters")
	}
	phc, _ := h.Hash(ctx, composed)
	if ok, _, _ := h.Verify(ctx, decomposed, phc); !ok {
		t.Fatal("the decomposed form doesn't verify")
	}
}

func TestRehash(t *testing.T) {
	ctx := context.Background()
	old := mustNew(t, cheap, 1)
	phc, _ := old.Hash(ctx, "pw")
	cur := mustNew(t, Params{MemoryKiB: 128, Time: 1}, 1)
	if ok, rehash, _ := cur.Verify(ctx, "pw", phc); !ok || !rehash {
		t.Fatalf("ok=%v rehash=%v", ok, rehash)
	}
	if ok, rehash, _ := cur.Verify(ctx, "wrong", phc); ok || rehash {
		t.Fatal("a wrong password asks for a rehash")
	}
}

func TestMalformed(t *testing.T) {
	ctx := context.Background()
	h := mustNew(t, cheap, 1)
	good, _ := h.Hash(ctx, "pw")
	for _, bad := range []string{
		"", "$2a$10$abc", strings.Replace(good, "argon2id", "argon2i", 1),
		strings.Replace(good, "v=19", "v=16", 1), strings.Replace(good, "p=1", "p=4", 1),
		strings.Replace(good, "m=64", "m=99999999", 1), good[:len(good)-20],
	} {
		if ok, _, err := h.Verify(ctx, "pw", bad); ok || !errors.Is(err, ErrMalformed) {
			t.Errorf("%q: ok=%v err=%v", bad, ok, err)
		}
	}
}

func TestBound(t *testing.T) {
	h := mustNew(t, cheap, 2)
	var running, peak atomic.Int32
	h.sem = make(chan struct{}, 2)
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			h.acquire(context.Background())
			n := running.Add(1)
			for {
				p := peak.Load()
				if n <= p || peak.CompareAndSwap(p, n) {
					break
				}
			}
			time.Sleep(time.Millisecond)
			running.Add(-1)
			h.release()
		}()
	}
	wg.Wait()
	if peak.Load() > 2 {
		t.Fatalf("%d ran at once", peak.Load())
	}
}

// Every path that hashes waits for a slot, and gives up when its context
// ends: Hash, Verify, Verify of a password too long or a malformed hash,
// and Dummy.
func TestWaitingRequestGivesUp(t *testing.T) {
	h := mustNew(t, cheap, 1)
	good, _ := h.Hash(context.Background(), "pw")
	h.sem <- struct{}{} // the one slot is taken
	for name, f := range map[string]func(context.Context) error{
		"Hash":   func(ctx context.Context) error { _, err := h.Hash(ctx, "pw"); return err },
		"Verify": func(ctx context.Context) error { _, _, err := h.Verify(ctx, "pw", good); return err },
		"Verify too long": func(ctx context.Context) error {
			_, _, err := h.Verify(ctx, strings.Repeat("a", MaxInput+1), good)
			return err
		},
		"Verify malformed": func(ctx context.Context) error { _, _, err := h.Verify(ctx, "pw", "$bad"); return err },
		"Dummy":            func(ctx context.Context) error { return h.Dummy(ctx, "pw") },
	} {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		if err := f(ctx); !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("%s: got %v", name, err)
		}
		cancel()
	}
}

// New refuses what decode would refuse, so no Hasher makes hashes it can't
// read, and a stored hash may ask for no more than the bounds.
func TestParamBounds(t *testing.T) {
	for _, p := range []Params{{7, 1}, {64, 0}, {64, 65}, {4<<20 + 1, 1}} {
		if _, err := New(p, 1); err == nil {
			t.Errorf("%+v accepted", p)
		}
	}
	h := mustNew(t, cheap, 1)
	good, _ := h.Hash(context.Background(), "pw")
	parts := strings.Split(good, "$")
	for _, bad := range []string{
		strings.Replace(good, "p=1$", "p=1,x=1$", 1),
		strings.Replace(good, "m=64,", "m=064,", 1),
		strings.Replace(good, "t=1,", "t=65,", 1),
		strings.Join(append(parts[:4:4], b64.EncodeToString(make([]byte, 65)), parts[5]), "$"),
	} {
		if ok, _, err := h.Verify(context.Background(), "pw", bad); ok || !errors.Is(err, ErrMalformed) {
			t.Errorf("%q: ok=%v err=%v", bad, ok, err)
		}
	}
	// A malformed hash is reported also for a password that is too long.
	if _, _, err := h.Verify(context.Background(), strings.Repeat("a", MaxInput+1), "$bad"); !errors.Is(err, ErrMalformed) {
		t.Errorf("too long and malformed: %v", err)
	}
}

// The trivial patterns are refused as a whole even where the estimate
// would be enough on its own.
func TestSimple(t *testing.T) {
	for _, c := range []struct {
		s    string
		want bool
	}{
		{"aaaaaaaaaaaa", true}, {"abcabcabcabc", true}, {"k#9qk#9qk#9q", true}, {"abcdefghijkl", true},
		{"987654321098", true}, {"qwertyuiop[]", true}, {"asdfasdfasdf", true}, {"1qaz2wsx3edc", true},
		{"k#9qk#9qk#9x", false}, {"abcdefghijkx", false}, {"qwerty is fun", false},
	} {
		if got := simple(c.s); got != c.want {
			t.Errorf("%q: %v", c.s, got)
		}
	}
}

// The dummy costs what a real verification costs (§5.1.4), measured as the
// ratio of the two medians.
func TestDummyCostsTheSame(t *testing.T) {
	ctx := context.Background()
	h := mustNew(t, Params{MemoryKiB: 8 << 10, Time: 1}, 1)
	phc, _ := h.Hash(ctx, "pw")
	median := func(f func()) time.Duration {
		var d []time.Duration
		for range 9 {
			s := time.Now()
			f()
			d = append(d, time.Since(s))
		}
		for i := range d {
			for j := i + 1; j < len(d); j++ {
				if d[j] < d[i] {
					d[i], d[j] = d[j], d[i]
				}
			}
		}
		return d[len(d)/2]
	}
	real := median(func() { h.Verify(ctx, "wrong", phc) })
	dummy := median(func() { _ = h.Dummy(ctx, "wrong") })
	if r := float64(dummy) / float64(real); r < 0.5 || r > 2 {
		t.Fatalf("dummy %v, real %v", dummy, real)
	}
}

var rules = Rules{MinLength: 12, MinScore: 4, Year: 2026}

func TestCheck(t *testing.T) {
	hints := []string{"sara.ali@example.com", "Sara Ali", "Toy Shop", "Jo Ann Li", "alice1999"}
	for _, c := range []struct {
		pw   string
		want Reason
	}{
		{"short", TooShort},
		{"ççççççççççç", TooShort}, // 11 characters, 22 bytes: characters count
		{"Password1234", Common},
		{"letmein12345 ", Common},
		{"P@ssw0rd2024", Common},
		{"baseball!football", Common},
		{"jennifer1987", Common},
		{"my-sara-is-great", Personal},
		{"EXAMPLE-of-a-pass", Personal},
		{"toyshop-rocks-99", Personal}, // the issuer, written as one word
		{"aaaaaaaaaaaa", Simple},
		{"abcabcabcabc", Simple},
		{"abcdefghijklm", Simple},
		{"987654321098", Simple},
		{"qwertyuiop[]", Simple},
		{"asdfasdfasdf", Simple},
		{"lkjhgfdsalkjh", Simple},
		{"1qaz2wsx3edc", Simple},
		{"qwerty123456789", Common}, // on the list whole
		{"Summer2024!!", Common},
		{"14/02/1990!!!!", Simple}, // patterns inside, which the whole-password check misses
		{"14/02/1990-12345", Simple},
		{"purple-monkey-dishwasher", OK},
		{"orange tiger 47", OK},
		{"correct horse battery staple", OK},
		{"ali-is-short-for-something", OK}, // "ali" is under four characters
		{"qwerty is part of this one", OK}, // a pattern inside a longer password
		{"كلمة سر طويلة جدا", OK},
		{"vR7#kq2!Lm9@", OK},
		// Over 100 characters, a unit repeated whole: cutting at 100
		// would chop the second copy and price it as random.
		{strings.Repeat(strings.Repeat("a", 47)+"!9#k", 2), Simple},
		// Hints the word check misses, which the estimate finds: words
		// under four letters, joined, and a hint's word in l33t with its
		// digits kept.
		{"joannli12345", Personal},
		{"4lice1999!xQz", Personal},
	} {
		if got := Check(c.pw, rules, hints...); got != c.want {
			t.Errorf("%q: got %d, want %d", c.pw, got, c.want)
		}
	}
}

// The minimum score is a dial: a password of score 3 passes 3 and fails 4.
// Three cheap pieces reach score 3 on zxcvbn's length term alone, which is
// why the default is 4 (ADR 0006).
func TestMinScore(t *testing.T) {
	pw := "Summer2024!!"
	e := newJudge(2026, nil).analyze([]rune(pw))
	s := e.score()
	if s != 3 {
		t.Fatalf("score %d, want 3 for this test", s)
	}
	for _, min := range []int{s, s + 1} {
		got := Check(pw, Rules{MinLength: 12, MinScore: min, Year: 2026})
		if want := min <= s; (got == OK) != want {
			t.Errorf("min %d: got %d", min, got)
		}
	}
}

// BenchmarkParams prints ADR 0003's table for the machine it runs on:
//
//	go test ./internal/password -run '^$' -bench Params -benchtime 3x
func BenchmarkParams(b *testing.B) {
	for _, p := range []Params{
		{19 << 10, 2}, {46 << 10, 1}, {64 << 10, 2}, {64 << 10, 3}, {128 << 10, 2},
	} {
		for _, n := range []int{1, runtime.NumCPU(), 4 * runtime.NumCPU()} {
			b.Run(fmt.Sprintf("m=%dMiB,t=%d/%d-at-once", p.MemoryKiB>>10, p.Time, n), func(b *testing.B) {
				h := mustNew(b, p, n)
				ctx := context.Background()
				for b.Loop() {
					var wg sync.WaitGroup
					for range n {
						wg.Add(1)
						go func() { defer wg.Done(); h.Hash(ctx, "correct horse battery staple") }()
					}
					wg.Wait()
				}
			})
		}
	}
}
