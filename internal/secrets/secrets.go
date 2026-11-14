// Package secrets derives auth's keys from the master secret and holds the
// primitives every record uses: random tokens and their hashes, code HMACs,
// token signatures and sealing at rest (interface §5.12).
package secrets

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
)

// MinSecret is the shortest master secret New accepts, in bytes.
const MinSecret = 32

// Purpose names one derived key. Each is a separate HKDF output, so a key
// for one use is never a key for another. The strings are permanent:
// changing one makes every record that used it unreadable.
type Purpose string

const (
	Codes Purpose = "codes" // HMACs of one-time codes
	Sign  Purpose = "sign"  // access token signatures
	Seal  Purpose = "seal"  // encryption at rest
)

const (
	salt       = "github.com/epistemer/auth"
	info       = "auth/v1/"
	sealFormat = 1
	nonceSize  = 12
	tagSize    = 16
)

// ErrShortSecret is returned for a master secret under MinSecret bytes.
var ErrShortSecret = fmt.Errorf("secrets: a master secret needs at least %d bytes", MinSecret)

// ErrOpen is returned when sealed data opens under no key: it was changed,
// or sealed under a secret that is no longer configured.
var ErrOpen = errors.New("secrets: sealed data doesn't open under any configured key")

// Keys holds the keys derived from the current master secret and, during a
// rotation, from the previous one.
type Keys struct {
	current  keyset
	previous *keyset
}

type keyset map[Purpose][]byte

func derive(secret []byte) (keyset, error) {
	if len(secret) < MinSecret {
		return nil, ErrShortSecret
	}
	ks := keyset{}
	for _, p := range []Purpose{Codes, Sign, Seal} {
		k, err := hkdf.Key(sha256.New, secret, []byte(salt), info+string(p), 32)
		if err != nil {
			return nil, err
		}
		ks[p] = k
	}
	return ks, nil
}

// New derives the keys. previous may be nil.
func New(current, previous []byte) (*Keys, error) {
	cur, err := derive(current)
	if err != nil {
		return nil, err
	}
	k := &Keys{current: cur}
	if previous != nil {
		prev, err := derive(previous)
		if err != nil {
			return nil, fmt.Errorf("previous secret: %w", err)
		}
		k.previous = &prev
	}
	return k, nil
}

// HasPrevious reports whether a previous secret is configured.
func (k *Keys) HasPrevious() bool { return k.previous != nil }

// MAC returns HMAC-SHA256 of the parts under the current key for p. The
// parts are length-prefixed, so ("ab","c") and ("a","bc") differ.
func (k *Keys) MAC(p Purpose, parts ...[]byte) []byte {
	return mac(k.current[p], parts)
}

// Verify reports whether sum is the MAC of parts under the current key for
// p or, during a rotation, the previous one. Both are always computed, so
// the time taken doesn't say which matched.
func (k *Keys) Verify(p Purpose, sum []byte, parts ...[]byte) bool {
	ok := hmac.Equal(sum, mac(k.current[p], parts))
	if k.previous != nil {
		ok = hmac.Equal(sum, mac((*k.previous)[p], parts)) || ok
	}
	return ok
}

// SignKey returns copies of the current signing key, and of the previous
// one if any, for the access token, which signs with the key directly. No
// other purpose's key ever leaves this package.
func (k *Keys) SignKey() (current, previous []byte) {
	if k.previous != nil {
		previous = bytes.Clone((*k.previous)[Sign])
	}
	return bytes.Clone(k.current[Sign]), previous
}

func mac(key []byte, parts [][]byte) []byte {
	h := hmac.New(sha256.New, key)
	var n [8]byte
	for _, part := range parts {
		l := uint64(len(part))
		for i := range n {
			n[i] = byte(l >> (56 - 8*i))
		}
		h.Write(n[:])
		h.Write(part)
	}
	return h.Sum(nil)
}

// Seal encrypts plaintext with AES-256-GCM under the current seal key, bound
// to ad. The result is a format byte, a random nonce, and the ciphertext with
// its tag.
func (k *Keys) Seal(plaintext, ad []byte) ([]byte, error) {
	return seal(k.current[Seal], plaintext, ad)
}

// Open decrypts what Seal made, under the current seal key or, during a
// rotation, the previous one. stale reports that it opened only under the
// previous key, so the caller should seal it again.
func (k *Keys) Open(sealed, ad []byte) (plaintext []byte, stale bool, err error) {
	if pt, err := open(k.current[Seal], sealed, ad); err == nil {
		return pt, false, nil
	}
	if k.previous != nil {
		if pt, err := open((*k.previous)[Seal], sealed, ad); err == nil {
			return pt, true, nil
		}
	}
	return nil, false, ErrOpen
}

// SealWith and OpenWith seal under a key the caller derived, such as one
// derived from a refresh token (interface §5.6.8). key must be 32 bytes.
func SealWith(key, plaintext, ad []byte) ([]byte, error) { return seal(key, plaintext, ad) }

func OpenWith(key, sealed, ad []byte) ([]byte, error) {
	pt, err := open(key, sealed, ad)
	if err != nil {
		return nil, ErrOpen
	}
	return pt, nil
}

// KeyFromToken derives a 32-byte key from a high-entropy token, for SealWith.
// It is unrelated to the token's stored hash.
func KeyFromToken(token []byte, purpose string) []byte {
	k, err := hkdf.Key(sha256.New, token, []byte(salt), info+"token/"+purpose, 32)
	if err != nil {
		panic(err) // only fails for a length over 255*32
	}
	return k
}

func seal(key, plaintext, ad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 1+nonceSize, 1+nonceSize+len(plaintext)+tagSize)
	out[0] = sealFormat
	if _, err := rand.Read(out[1:]); err != nil {
		return nil, err
	}
	return gcm.Seal(out, out[1:1+nonceSize], plaintext, ad), nil
}

func open(key, sealed, ad []byte) ([]byte, error) {
	if len(sealed) < 1+nonceSize+tagSize || sealed[0] != sealFormat {
		return nil, ErrOpen
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, sealed[1:1+nonceSize], sealed[1+nonceSize:], ad)
}

// TokenSize is the size of every random token, in bytes (256 bits).
const TokenSize = 32

// NewToken returns a random token, as it travels (base64url without
// padding), and the SHA-256 the store keeps.
func NewToken() (token string, hash []byte) {
	b := make([]byte, TokenSize)
	rand.Read(b) // never fails; see crypto/rand
	token = base64.RawURLEncoding.EncodeToString(b)
	return token, Hash(token)
}

// NewID returns a random identifier for a record people may see, such as a
// session's or a device's ID. It is 128 bits, base64url. It is not a secret.
func NewID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// Hash returns the SHA-256 a token is stored under.
func Hash(token string) []byte {
	s := sha256.Sum256([]byte(token))
	return s[:]
}

// Equal compares two byte strings in constant time for equal lengths.
func Equal(a, b []byte) bool { return subtle.ConstantTimeCompare(a, b) == 1 }
