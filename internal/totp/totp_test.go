package totp

import (
	"testing"
	"time"
)

// RFC 6238 Appendix B, the SHA-1 rows: eight digits, the 20-byte ASCII
// secret "12345678901234567890".
func TestRFC6238Vectors(t *testing.T) {
	secret := []byte("12345678901234567890")
	for _, c := range []struct {
		unix int64
		want string
	}{
		{59, "94287082"},
		{1111111109, "07081804"},
		{1111111111, "14050471"},
		{1234567890, "89005924"},
		{2000000000, "69279037"},
		{20000000000, "65353130"},
	} {
		if got := Code(secret, StepAt(time.Unix(c.unix, 0)), 8); got != c.want {
			t.Errorf("T=%d: %s; want %s", c.unix, got, c.want)
		}
	}
}

// RFC 4226 Appendix D: six digits, counters 0 to 9.
func TestRFC4226Vectors(t *testing.T) {
	secret := []byte("12345678901234567890")
	for i, want := range []string{"755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"} {
		if got := Code(secret, int64(i), 6); got != want {
			t.Errorf("counter %d: %s; want %s", i, got, want)
		}
	}
}
