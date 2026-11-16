// Package totp computes time-based one-time passwords as RFC 6238 and the
// authenticator apps define them: HMAC-SHA1 over the step counter, dynamic
// truncation, decimal digits.
package totp

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"time"
)

// Step is the length of one step.
const Step = 30 * time.Second

// StepAt is the step a time falls in.
func StepAt(t time.Time) int64 { return t.Unix() / int64(Step/time.Second) }

// Code is the code of n digits for a secret at a step (RFC 4226 §5.3).
func Code(secret []byte, step int64, n int) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(step))
	m := hmac.New(sha1.New, secret)
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	mod := uint32(1)
	for range n {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", n, v%mod)
}
