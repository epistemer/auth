package secrets

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

var (
	secretA = []byte(strings.Repeat("a", 32))
	secretB = []byte(strings.Repeat("b", 32))
	secretC = []byte(strings.Repeat("c", 32))
)

func mustNew(t *testing.T, cur, prev []byte) *Keys {
	t.Helper()
	k, err := New(cur, prev)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestShortSecret(t *testing.T) {
	if _, err := New(secretA[:31], nil); !errors.Is(err, ErrShortSecret) {
		t.Fatalf("31 bytes: got %v", err)
	}
	if _, err := New(secretA, secretB[:10]); !errors.Is(err, ErrShortSecret) {
		t.Fatalf("short previous: got %v", err)
	}
}

func TestPurposesDiffer(t *testing.T) {
	k := mustNew(t, secretA, nil)
	seen := map[string]Purpose{}
	for _, p := range []Purpose{Codes, Sign, Seal} {
		key, _ := k.SignKey(p)
		if len(key) != 32 {
			t.Fatalf("%s: %d bytes", p, len(key))
		}
		if q, ok := seen[string(key)]; ok {
			t.Fatalf("%s and %s share a key", p, q)
		}
		seen[string(key)] = p
		if bytes.Contains(key, secretA[:8]) {
			t.Fatalf("%s: key contains the secret", p)
		}
	}
}

func TestDerivationIsStable(t *testing.T) {
	// A record written today must verify tomorrow: derivation depends on
	// the secret and the permanent purpose strings only.
	k1, k2 := mustNew(t, secretA, nil), mustNew(t, secretA, nil)
	if !bytes.Equal(k1.MAC(Codes, []byte("x")), k2.MAC(Codes, []byte("x"))) {
		t.Fatal("same secret, different MAC")
	}
}

func TestMACFraming(t *testing.T) {
	k := mustNew(t, secretA, nil)
	if bytes.Equal(k.MAC(Codes, []byte("ab"), []byte("c")), k.MAC(Codes, []byte("a"), []byte("bc"))) {
		t.Fatal("parts are not framed")
	}
	if bytes.Equal(k.MAC(Codes, []byte("x")), k.MAC(Sign, []byte("x"))) {
		t.Fatal("purposes share a MAC")
	}
}

func TestVerifyDuringRotation(t *testing.T) {
	old := mustNew(t, secretA, nil)
	sum := old.MAC(Codes, []byte("flow"), []byte("123456"))

	rotated := mustNew(t, secretB, secretA)
	if !rotated.Verify(Codes, sum, []byte("flow"), []byte("123456")) {
		t.Fatal("a MAC under the previous secret doesn't verify")
	}
	if rotated.Verify(Codes, sum, []byte("flow"), []byte("654321")) {
		t.Fatal("a wrong code verifies")
	}
	if mustNew(t, secretB, nil).Verify(Codes, sum, []byte("flow"), []byte("123456")) {
		t.Fatal("a MAC verifies after the previous secret was dropped")
	}
	if !rotated.Verify(Codes, rotated.MAC(Codes, []byte("x")), []byte("x")) {
		t.Fatal("a MAC under the current secret doesn't verify")
	}
}

func TestSealRoundTrip(t *testing.T) {
	k := mustNew(t, secretA, nil)
	ad := []byte("user-1")
	sealed, err := k.Seal([]byte("totp secret"), ad)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, []byte("totp secret")) {
		t.Fatal("sealed data holds the plaintext")
	}
	pt, stale, err := k.Open(sealed, ad)
	if err != nil || stale || string(pt) != "totp secret" {
		t.Fatalf("open: %q %v %v", pt, stale, err)
	}
	again, _ := k.Seal([]byte("totp secret"), ad)
	if bytes.Equal(again, sealed) {
		t.Fatal("two seals of one plaintext are equal: the nonce isn't random")
	}
}

func TestSealBindsAD(t *testing.T) {
	k := mustNew(t, secretA, nil)
	sealed, _ := k.Seal([]byte("s"), []byte("user-1"))
	if _, _, err := k.Open(sealed, []byte("user-2")); !errors.Is(err, ErrOpen) {
		t.Fatalf("opened for another user: %v", err)
	}
	sealed[len(sealed)-1] ^= 1
	if _, _, err := k.Open(sealed, []byte("user-1")); !errors.Is(err, ErrOpen) {
		t.Fatalf("opened after tampering: %v", err)
	}
	for _, bad := range [][]byte{nil, {1}, bytes.Repeat([]byte{2}, 40)} {
		if _, _, err := k.Open(bad, nil); !errors.Is(err, ErrOpen) {
			t.Fatalf("opened %v: %v", bad, err)
		}
	}
}

func TestOpenDuringRotation(t *testing.T) {
	sealed, _ := mustNew(t, secretA, nil).Seal([]byte("s"), nil)

	// A, then B with A as previous: opens, and says it is stale.
	pt, stale, err := mustNew(t, secretB, secretA).Open(sealed, nil)
	if err != nil || !stale || string(pt) != "s" {
		t.Fatalf("rotation: %q %v %v", pt, stale, err)
	}
	// The caller seals it again under B; then C with B as previous opens it.
	resealed, _ := mustNew(t, secretB, secretA).Seal(pt, nil)
	if pt, _, err := mustNew(t, secretC, secretB).Open(resealed, nil); err != nil || string(pt) != "s" {
		t.Fatalf("second rotation after reseal: %q %v", pt, err)
	}
	// Without the reseal, a second rotation loses it, which is why Rekey exists.
	if _, _, err := mustNew(t, secretC, secretB).Open(sealed, nil); !errors.Is(err, ErrOpen) {
		t.Fatalf("opened two rotations later: %v", err)
	}
}

func TestSealWithToken(t *testing.T) {
	tok, _ := NewToken()
	key := KeyFromToken([]byte(tok), "refresh")
	sealed, err := SealWith(key, []byte("successor"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if pt, err := OpenWith(key, sealed, nil); err != nil || string(pt) != "successor" {
		t.Fatalf("%q %v", pt, err)
	}
	other, _ := NewToken()
	if _, err := OpenWith(KeyFromToken([]byte(other), "refresh"), sealed, nil); !errors.Is(err, ErrOpen) {
		t.Fatalf("opened with another token: %v", err)
	}
	if _, err := OpenWith(KeyFromToken([]byte(tok), "other"), sealed, nil); !errors.Is(err, ErrOpen) {
		t.Fatalf("opened under another purpose: %v", err)
	}
}

func TestTokens(t *testing.T) {
	seen := map[string]bool{}
	for range 1000 {
		tok, h := NewToken()
		if len(tok) != 43 {
			t.Fatalf("token %q has %d characters", tok, len(tok))
		}
		if !bytes.Equal(h, Hash(tok)) || len(h) != 32 {
			t.Fatal("hash mismatch")
		}
		if seen[tok] {
			t.Fatal("repeated token")
		}
		seen[tok] = true
	}
	if id := NewID(); len(id) != 22 {
		t.Fatalf("id %q", id)
	}
}
