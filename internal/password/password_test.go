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

func TestWaitingRequestGivesUp(t *testing.T) {
	h := mustNew(t, cheap, 1)
	h.sem <- struct{}{} // the one slot is taken
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := h.Hash(ctx, "pw"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v", err)
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
	dummy := median(func() { h.Dummy(ctx, "wrong") })
	if r := float64(dummy) / float64(real); r < 0.5 || r > 2 {
		t.Fatalf("dummy %v, real %v", dummy, real)
	}
}

var rules = Rules{MinLength: 12, MinScore: 4, Year: 2026}

func TestCheck(t *testing.T) {
	hints := []string{"sara.ali@example.com", "Sara Ali", "Toy Shop"}
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
