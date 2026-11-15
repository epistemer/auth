package auth

import (
	"strings"
	"testing"

	"github.com/epistemer/auth/internal/password"
	"github.com/epistemer/auth/internal/testhook"
)

// authtest's hook swaps in hashing with cheapParams: a hash it makes
// carries them.
func TestCheapHashingHook(t *testing.T) {
	k := newKit(t)
	var err error
	if k.hasher, err = password.New(password.Params{MemoryKiB: 19 << 10, Time: 1}, 1); err != nil {
		t.Fatal(err)
	}
	testhook.CheapHashing.(Option)(k.Auth)
	phc, err := k.hasher.Hash(k.ctx, goodPassword)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(phc, "$m=64,t=1,") {
		t.Errorf("hash %s doesn't carry cheapParams", phc)
	}
}
