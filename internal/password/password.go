// Package password hashes passwords with argon2id, bounds how many hash at
// once, and judges new passwords (interface §5.2, ADR 0003).
package password

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync/atomic"

	"golang.org/x/crypto/argon2"
	"golang.org/x/text/unicode/norm"
)

// MaxInput is the longest password accepted, in bytes as typed (§5.2.3).
const MaxInput = 1024

const (
	saltLen = 16
	keyLen  = 32
	threads = 1
)

// ErrTooLong is returned for a password over MaxInput bytes.
var ErrTooLong = errors.New("password: longer than 1024 bytes")

// ErrMalformed is returned for a stored hash this package can't read.
var ErrMalformed = errors.New("password: malformed hash")

// Params are argon2id's cost parameters.
type Params struct {
	MemoryKiB uint32
	Time      uint32
}

// Hasher hashes and verifies, never more than its bound at once.
type Hasher struct {
	params Params
	sem    chan struct{}
	dummy  string
	count  atomic.Int64 // argon2 runs, for tests of equal work
}

// Count reports how many argon2 computations this Hasher has run.
func (h *Hasher) Count() int64 { return h.count.Load() }

// The bounds on parameters, for new hashes and stored ones alike: a stored
// hash outside them is malformed, so a damaged record can't ask for more
// than 4 GiB or 64 passes.
const (
	minMemoryKiB = 8
	maxMemoryKiB = 4 << 20
	maxTime      = 64
	minSalt      = 8
	maxSalt      = 64
)

func (p Params) valid() bool {
	return p.MemoryKiB >= minMemoryKiB && p.MemoryKiB <= maxMemoryKiB && p.Time >= 1 && p.Time <= maxTime
}

// New returns a Hasher. concurrency is the most hashes that run at once.
func New(p Params, concurrency int) (*Hasher, error) {
	if !p.valid() || concurrency < 1 {
		return nil, fmt.Errorf("password: invalid parameters %+v, concurrency %d", p, concurrency)
	}
	h := &Hasher{params: p, sem: make(chan struct{}, concurrency)}
	salt := make([]byte, saltLen)
	rand.Read(salt)
	// A hash of a random password nobody knows, made like real ones, so an
	// unknown login costs what a wrong password costs (§5.1.4).
	h.dummy = encode(p, salt, argon2.IDKey(salt, salt, p.Time, p.MemoryKiB, threads, keyLen))
	return h, nil
}

// Normalize returns the password as it is hashed: NFKC, never trimmed.
func Normalize(pw string) (string, error) {
	if len(pw) > MaxInput {
		return "", ErrTooLong
	}
	return norm.NFKC.String(pw), nil
}

func (h *Hasher) acquire(ctx context.Context) error {
	select {
	case h.sem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (h *Hasher) release() { <-h.sem }

// Hash returns the PHC string of a new password.
func (h *Hasher) Hash(ctx context.Context, pw string) (string, error) {
	n, err := Normalize(pw)
	if err != nil {
		return "", err
	}
	salt := make([]byte, saltLen)
	rand.Read(salt)
	if err := h.acquire(ctx); err != nil {
		return "", err
	}
	defer h.release()
	h.count.Add(1)
	return encode(h.params, salt, argon2.IDKey([]byte(n), salt, h.params.Time, h.params.MemoryKiB, threads, keyLen)), nil
}

// Verify reports whether pw matches the stored hash, and whether the hash
// was made with other parameters and should be replaced (§5.2.1). A
// password over MaxInput bytes is checked against the dummy hash, so it
// costs the same and never matches. A malformed stored hash is
// ErrMalformed, also after the dummy's work.
func (h *Hasher) Verify(ctx context.Context, pw, stored string) (ok, rehash bool, err error) {
	n, nerr := Normalize(pw)
	p, salt, want, perr := decode(stored)
	if nerr != nil || perr != nil {
		if err := h.Dummy(ctx, pw); err != nil {
			return false, false, err
		}
		return false, false, perr
	}
	if err := h.acquire(ctx); err != nil {
		return false, false, err
	}
	defer h.release()
	h.count.Add(1)
	got := argon2.IDKey([]byte(n), salt, p.Time, p.MemoryKiB, threads, keyLen)
	ok = subtle.ConstantTimeCompare(got, want) == 1
	return ok, ok && p != h.params, nil
}

// Dummy does the work of Verify against a hash that never matches. Its
// error is the context's, when the context ends while it waits.
func (h *Hasher) Dummy(ctx context.Context, pw string) error {
	if len(pw) > MaxInput {
		pw = pw[:MaxInput]
	}
	p, salt, want, err := decode(h.dummy)
	if err != nil {
		panic("password: the dummy hash is malformed") // New made it
	}
	if err := h.acquire(ctx); err != nil {
		return err
	}
	defer h.release()
	h.count.Add(1)
	got := argon2.IDKey([]byte(norm.NFKC.String(pw)), salt, p.Time, p.MemoryKiB, threads, keyLen)
	subtle.ConstantTimeCompare(got, want)
	return nil
}

var b64 = base64.RawStdEncoding

func encode(p Params, salt, key []byte) string {
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, p.MemoryKiB, p.Time, threads, b64.EncodeToString(salt), b64.EncodeToString(key))
}

func decode(s string) (p Params, salt, key []byte, err error) {
	parts := strings.Split(s, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" || parts[2] != "v="+strconv.Itoa(argon2.Version) {
		return p, nil, nil, ErrMalformed
	}
	var par uint32
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.MemoryKiB, &p.Time, &par); err != nil ||
		par != threads || !p.valid() || parts[3] != fmt.Sprintf("m=%d,t=%d,p=%d", p.MemoryKiB, p.Time, par) {
		return p, nil, nil, ErrMalformed
	}
	if salt, err = b64.DecodeString(parts[4]); err != nil || len(salt) < minSalt || len(salt) > maxSalt {
		return p, nil, nil, ErrMalformed
	}
	if key, err = b64.DecodeString(parts[5]); err != nil || len(key) != keyLen {
		return p, nil, nil, ErrMalformed
	}
	return p, salt, key, nil
}
