package auth

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/epistemer/cfgx"
	"github.com/epistemer/errors"
	bolt "go.etcd.io/bbolt"

	"github.com/epistemer/auth/internal/totp"
)

// enrollAppCodes enrolls an app and returns its secret and the recovery
// codes its Finish gave.
func enrollAppCodes(t *testing.T, k *kit) ([]byte, []string) {
	t.Helper()
	k.clock.advance(time.Minute)
	res := twoFactorSignIn(t, k, nil)
	ctx := withSession(k.ctx, res.Session)
	f, _ := k.Enroll(ctx, res.Session, MethodTOTP)
	ch, _ := k.Challenge(ctx, f.Token, MethodTOTP)
	secret, _ := b32.DecodeString(ch.TOTP.Secret)
	f, _ = k.Prove(ctx, f.Token, TOTP(totp.Code(secret, totp.StepAt(k.clock.now()), 6)))
	r, err := k.Finish(ctx, f.Token)
	if err != nil {
		t.Fatal(err)
	}
	return secret, r.RecoveryCodes
}

// §5.4.6: the first factor brings ten codes of sixteen base32 characters;
// a second factor brings none.
func TestRecoveryCodesMade(t *testing.T) {
	k := newDeviceKit(t)
	_, codes := enrollAppCodes(t, k)
	if len(codes) != 10 {
		t.Fatalf("%d codes", len(codes))
	}
	seen := map[string]bool{}
	for _, c := range codes {
		if len(c) != 16 || strings.Trim(c, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567") != "" || seen[c] {
			t.Errorf("code %q", c)
		}
		seen[c] = true
	}
	// A second app, from a session the first verified: no new set.
	k.clock.advance(time.Minute)
	f := passwordOnly(t, k, "sara")
	f, _ = k.Prove(k.ctx, f.Token, RecoveryCode(codes[9]))
	res, err := k.Finish(k.ctx, f.Token)
	if err != nil {
		t.Fatal(err)
	}
	ctx := withSession(k.ctx, res.Session)
	ef, _ := k.Enroll(ctx, res.Session, MethodTOTP)
	ch, _ := k.Challenge(ctx, ef.Token, MethodTOTP)
	b, _ := b32.DecodeString(ch.TOTP.Secret)
	ef, _ = k.Prove(ctx, ef.Token, TOTP(totp.Code(b, totp.StepAt(k.clock.now()), 6)))
	r2, err := k.Finish(ctx, ef.Token)
	if err != nil || len(r2.RecoveryCodes) != 0 {
		t.Errorf("a second app: %d codes, %v", len(r2.RecoveryCodes), err)
	}
	k.clock.advance(time.Minute)
	g := passwordOnly(t, k, "sara")
	if g, _ = k.Prove(k.ctx, g.Token, RecoveryCode(codes[0])); !g.Verified {
		t.Error("the first set stopped working after a second app")
	}
}

// §7: a recovery code works once, as a second proof, whatever its case and
// dashes; a new set cancels the old.
func TestRecoveryCodeOnce(t *testing.T) {
	k := newDeviceKit(t)
	_, codes := enrollAppCodes(t, k)
	k.clock.advance(time.Minute)
	prove := func(code string) (Flow, error) {
		f := passwordOnly(t, k, "sara")
		return k.Prove(k.ctx, f.Token, RecoveryCode(code))
	}
	typed := strings.ToLower(codes[0][:4] + "-" + codes[0][4:8] + " " + codes[0][8:])
	if f, err := prove(typed); err != nil || !f.Verified {
		t.Fatalf("a code as typed: %+v %v", f, err)
	}
	if _, err := prove(codes[0]); !errors.Is(err, ErrBadCode) {
		t.Errorf("the same code again: %v", err)
	}
	// A new set cancels the old.
	f := passwordOnly(t, k, "sara")
	f, _ = k.Prove(k.ctx, f.Token, RecoveryCode(codes[1]))
	res, _ := k.Finish(k.ctx, f.Token)
	ctx := withSession(k.ctx, res.Session)
	ef, err := k.Enroll(ctx, res.Session, MethodRecoveryCode)
	if err != nil || !ef.Ready {
		t.Fatalf("Enroll of a new set: %+v %v", ef, err)
	}
	r, err := k.Finish(ctx, ef.Token)
	if err != nil || len(r.RecoveryCodes) != 10 {
		t.Fatalf("a new set: %+v %v", r, err)
	}
	k.clock.advance(time.Minute)
	if _, err := prove(codes[2]); !errors.Is(err, ErrBadCode) {
		t.Errorf("an old code after a new set: %v", err)
	}
	if f, err := prove(r.RecoveryCodes[0]); err != nil || !f.Verified {
		t.Errorf("a new code: %v", err)
	}
}

// Of two racing proofs with one code, one wins.
func TestRecoveryCodeRace(t *testing.T) {
	k := newDeviceKit(t)
	_, codes := enrollAppCodes(t, k)
	k.clock.advance(time.Minute)
	flows := make([]Flow, 4)
	for i := range flows {
		flows[i] = passwordOnly(t, k, "sara")
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	start := make(chan struct{})
	ok, bad := 0, 0
	for _, f := range flows {
		wg.Go(func() {
			<-start
			out, err := k.Prove(k.ctx, f.Token, RecoveryCode(codes[3]))
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil && out.Verified:
				ok++
			case errors.Is(err, ErrBadCode):
				bad++
			}
		})
	}
	close(start)
	wg.Wait()
	if ok != 1 || bad != 3 {
		t.Errorf("one code: %d accepted, %d refused", ok, bad)
	}
}

// A recovery code finishes a recovery for a user with TOTP, and is
// offered beside the app; with every code used it isn't offered.
func TestRecoveryCodeInRecover(t *testing.T) {
	k := newDeviceKit(t)
	_, codes := enrollAppCodes(t, k)
	k.clock.advance(time.Minute)
	recoverLink(t, k, "sara")
	f, _ := k.Follow(k.ctx, k.lastMessage(t, saraMail).Token)
	if strings.Join(f.Offers, ",") != "totp,recovery_code" {
		t.Fatalf("offers %v", f.Offers)
	}
	if f, err := k.Prove(k.ctx, f.Token, RecoveryCode(codes[0])); err != nil || !f.Ready {
		t.Fatalf("a recovery code: %+v %v", f, err)
	}
	if _, err := k.Finish(k.ctx, f.Token, NewPassword(newPassword)); err != nil {
		t.Fatalf("Finish of the recovery: %v", err)
	}
	// Every other code verifies a sign-in, the last one too.
	for i, c := range codes[1:] {
		g, err := k.SignIn(k.ctx, "sara", Cookie())
		if err != nil {
			t.Fatal(err)
		}
		g, _ = k.Prove(k.ctx, g.Token, Password(newPassword))
		if g, err = k.Prove(k.ctx, g.Token, RecoveryCode(c)); err != nil || !g.Verified || !g.Ready {
			t.Fatalf("code %d: %+v %v", i+2, g, err)
		}
	}
	k.clock.advance(time.Minute)
	recoverLink(t, k, "sara")
	rf, _ := k.Follow(k.ctx, k.lastMessage(t, saraMail).Token)
	if rf.Ready || strings.Join(rf.Offers, ",") != MethodTOTP {
		t.Errorf("a recovery with every code used: %+v", rf)
	}
}

// §7: after the secret is rotated twice with Rekey in between, recovery
// codes still work: they never used it.
func TestRecoveryCodesAcrossRotations(t *testing.T) {
	k := newDeviceKit(t)
	_, codes := enrollAppCodes(t, k)
	for _, next := range []string{"b", "c"} {
		cfg := k.cfg.(*config)
		cfg.previous, cfg.secret = cfg.secret, cfgx.NewSecret(strings.Repeat(next, 32))
		a, err := New(k.db, cfg, k.dir, k.out, WithRecorder(k.events), WithClock(k.clock.now))
		if err != nil {
			t.Fatal(err)
		}
		a.hasher = k.hasher
		k.Auth = a
		if err := k.Rekey(k.ctx); err != nil {
			t.Fatal(err)
		}
	}
	k.clock.advance(time.Minute)
	f := passwordOnly(t, k, "sara")
	if f, err := k.Prove(k.ctx, f.Token, RecoveryCode(codes[0])); err != nil || !f.Verified {
		t.Errorf("a recovery code after two rotations: %v", err)
	}
}

// No new set without a factor; the store holds no code as it was given.
func TestRecoveryCodesGuarded(t *testing.T) {
	k := newDeviceKit(t)
	res := twoFactorSignIn(t, k, nil)
	if _, err := k.Enroll(withSession(k.ctx, res.Session), res.Session, MethodRecoveryCode); !errors.Is(err, ErrMethodUnavailable) {
		t.Errorf("a set without a factor: %v", err)
	}
	_, codes := enrollAppCodes(t, k)
	k.db.View(func(tx *bolt.Tx) error {
		return tx.ForEach(func(_ []byte, b *bolt.Bucket) error {
			return walk(b, func(key, v []byte) {
				for _, c := range codes {
					if strings.Contains(string(key), c) || strings.Contains(string(v), c) {
						t.Error("the store holds a recovery code")
					}
				}
			})
		})
	})
}

// A code isn't spent on a flow a racing proof already verified, and a
// second recovery code on one flow is ErrMethodUnavailable, not held
// against the user.
func TestRecoveryCodeNotBurnt(t *testing.T) {
	k := newDeviceKit(t)
	secret, codes := enrollAppCodes(t, k)
	k.clock.advance(time.Minute)
	f := passwordOnly(t, k, "sara")
	hash := hashOf(f.Token)
	rec, _ := k.loadFlow(hash)
	v, _ := k.view(k.ctx, rec, nil)
	if _, err := k.Prove(k.ctx, f.Token, TOTP(totp.Code(secret, totp.StepAt(k.clock.now()), 6))); err != nil {
		t.Fatal(err)
	}
	// As a request that read the flow before the TOTP proof would.
	if _, err := k.proveRecovery(k.ctx, f.Token, hash, rec, v, codes[0]); !errors.Is(err, ErrMethodUnavailable) {
		t.Errorf("a recovery code on a verified flow: %v", err)
	}
	g := passwordOnly(t, k, "sara")
	if g, err := k.Prove(k.ctx, g.Token, RecoveryCode(codes[0])); err != nil || !g.Verified {
		t.Errorf("the code was burnt: %v", err)
	}
}
