package auth

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/epistemer/cfgx"
	"github.com/epistemer/errors"

	"github.com/epistemer/auth/internal/totp"
)

// enrollApp enrolls an authenticator app for sara from a fresh verified
// session and returns its secret.
func enrollApp(t *testing.T, k *kit) []byte {
	t.Helper()
	k.clock.advance(time.Minute)
	res := twoFactorSignIn(t, k, nil)
	ctx := withSession(k.ctx, res.Session)
	f, err := k.Enroll(ctx, res.Session, MethodTOTP)
	if err != nil {
		t.Fatal(err)
	}
	ch, err := k.Challenge(ctx, f.Token, MethodTOTP)
	if err != nil || ch.TOTP == nil {
		t.Fatalf("Challenge: %+v %v", ch, err)
	}
	secret, err := b32.DecodeString(ch.TOTP.Secret)
	if err != nil || len(secret) != 20 {
		t.Fatalf("secret %q %v", ch.TOTP.Secret, err)
	}
	if f, err = k.Prove(ctx, f.Token, TOTP(totp.Code(secret, totp.StepAt(k.clock.now()), 6))); err != nil || !f.Ready {
		t.Fatalf("Prove: %+v %v", f, err)
	}
	if _, err := k.Finish(ctx, f.Token); err != nil {
		t.Fatal(err)
	}
	return secret
}

func (k *kit) code(secret []byte, steps int64) string {
	return totp.Code(secret, totp.StepAt(k.clock.now())+steps, 6)
}

// §5.4, §6.5: enrolling an authenticator app. Challenge returns the secret
// and its otpauth URI, the same each time; one code stores it; then it is
// the second proof, and a code sent to an address no longer is (§5.7.2).
func TestEnrollTOTP(t *testing.T) {
	k := newDeviceKit(t)
	res := twoFactorSignIn(t, k, nil)
	ctx := withSession(k.ctx, res.Session)
	f, err := k.Enroll(ctx, res.Session, MethodTOTP)
	if err != nil || f.Ready || strings.Join(f.Offers, ",") != MethodTOTP {
		t.Fatalf("Enroll: %+v %v", f, err)
	}
	ch, _ := k.Challenge(ctx, f.Token, MethodTOTP)
	again, _ := k.Challenge(ctx, f.Token, MethodTOTP)
	if ch.TOTP.Secret != again.TOTP.Secret {
		t.Error("a second Challenge made a new secret")
	}
	for _, want := range []string{"otpauth://totp/toyshop:sara?", "issuer=toyshop", "digits=6", "period=30", "algorithm=SHA1", "secret=" + ch.TOTP.Secret} {
		if !strings.Contains(ch.TOTP.URI, want) {
			t.Errorf("URI %q lacks %q", ch.TOTP.URI, want)
		}
	}
	secret, _ := b32.DecodeString(ch.TOTP.Secret)
	bad := "000000"
	for _, d := range []int64{-1, 0, 1} {
		if k.code(secret, d) == bad {
			bad = "999999"
		}
	}
	if _, err := k.Prove(ctx, f.Token, TOTP(bad)); !errors.Is(err, ErrBadCode) {
		t.Errorf("a wrong code: %v", err)
	}
	if fs, _ := k.Factors(k.ctx, "u1"); len(fs) != 0 {
		t.Fatal("stored before a code proved it")
	}
	f, err = k.Prove(ctx, f.Token, TOTP(k.code(secret, 0)))
	if err != nil || !f.Ready {
		t.Fatalf("the right code: %+v %v", f, err)
	}
	n := k.sentCount()
	if _, err := k.Finish(ctx, f.Token); err != nil {
		t.Fatal(err)
	}
	if k.sentCount() != n+1 || k.lastMessage(t, saraMail).Kind != MsgFactorAdded {
		t.Error("no MsgFactorAdded")
	}
	if fs, _ := k.Factors(k.ctx, "u1"); len(fs) != 1 || fs[0].Method != MethodTOTP {
		t.Fatalf("Factors: %+v", fs)
	}
	// Signing in now offers the app, never the emailed code.
	k.clock.advance(time.Minute)
	sf := passwordOnly(t, k, "sara")
	if strings.Join(sf.Offers, ",") != "totp,recovery_code" {
		t.Errorf("offers with TOTP: %v", sf.Offers)
	}
	if _, err := k.Challenge(k.ctx, sf.Token, MethodEmailCode); !errors.Is(err, ErrMethodUnavailable) {
		t.Errorf("an emailed code offered beside TOTP: %v", err)
	}
	if sf, err = k.Prove(k.ctx, sf.Token, TOTP(k.code(secret, 0))); err != nil || !sf.Verified {
		t.Errorf("signing in with the app: %+v %v", sf, err)
	}
}

// §7: a TOTP code is refused the second time, also when both tries arrive
// at once; one from the next step is accepted and then the current one
// isn't.
func TestTOTPReplay(t *testing.T) {
	k := newDeviceKit(t)
	secret := enrollApp(t, k)
	k.clock.advance(time.Minute)
	prove := func(code string) error {
		f := passwordOnly(t, k, "sara")
		_, err := k.Prove(k.ctx, f.Token, TOTP(code))
		return err
	}
	now := k.code(secret, 0)
	if err := prove(now); err != nil {
		t.Fatal(err)
	}
	if err := prove(now); !errors.Is(err, ErrBadCode) {
		t.Errorf("the same code again: %v", err)
	}

	k.clock.advance(time.Minute)
	code := k.code(secret, 0)
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok := 0
	for range 2 {
		f := passwordOnly(t, k, "sara")
		wg.Go(func() {
			if _, err := k.Prove(k.ctx, f.Token, TOTP(code)); err == nil {
				mu.Lock()
				ok++
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	if ok != 1 {
		t.Errorf("%d concurrent tries of one code accepted", ok)
	}

	k.clock.advance(time.Minute)
	if err := prove(k.code(secret, 1)); err != nil {
		t.Fatalf("the next step's code: %v", err)
	}
	if err := prove(k.code(secret, 0)); !errors.Is(err, ErrBadCode) {
		t.Errorf("the current step's code after the next one's: %v", err)
	}
	if err := prove(k.code(secret, 2)); !errors.Is(err, ErrBadCode) {
		t.Errorf("a code two steps ahead: %v", err)
	}
}

// §5.4.5: wrong authenticator codes count toward throttling.
func TestTOTPThrottled(t *testing.T) {
	k := newDeviceKit(t)
	secret := enrollApp(t, k)
	k.clock.advance(time.Minute)
	f := passwordOnly(t, k, "sara")
	bad := "000000"
	if k.code(secret, 0) == bad || k.code(secret, -1) == bad || k.code(secret, 1) == bad {
		bad = "000001"
	}
	for range 5 {
		k.Prove(k.ctx, f.Token, TOTP(bad))
	}
	if _, err := k.Prove(k.ctx, f.Token, TOTP(k.code(secret, 0))); !errors.Is(err, ErrTooManyAttempts) {
		t.Errorf("the sixth try: %v", err)
	}
}

// §7: Recover for a user with TOTP is ready after the link and the app.
func TestRecoverWithTOTP(t *testing.T) {
	k := newDeviceKit(t)
	secret := enrollApp(t, k)
	k.clock.advance(time.Minute)
	recoverLink(t, k, "sara")
	f, _ := k.Follow(k.ctx, k.lastMessage(t, saraMail).Token)
	if f.Ready {
		t.Fatal("ready after the link alone")
	}
	if _, err := k.Challenge(k.ctx, f.Token, MethodEmailCode); !errors.Is(err, ErrMethodUnavailable) {
		t.Errorf("an emailed code offered in a recovery with TOTP: %v", err)
	}
	if f, err := k.Prove(k.ctx, f.Token, TOTP(k.code(secret, 0))); err != nil || !f.Ready {
		t.Fatalf("after the app: %+v %v", f, err)
	}
}

// Two apps enrolled under the same label are two factors: a credential is
// keyed by a random ID.
func TestTwoApps(t *testing.T) {
	k := newDeviceKit(t)
	a := enrollApp(t, k)
	k.clock.advance(time.Minute)
	sf := passwordOnly(t, k, "sara")
	sf, _ = k.Prove(k.ctx, sf.Token, TOTP(k.code(a, 0)))
	res, err := k.Finish(k.ctx, sf.Token)
	if err != nil {
		t.Fatal(err)
	}
	ctx := withSession(k.ctx, res.Session)
	f, _ := k.Enroll(ctx, res.Session, MethodTOTP)
	ch, _ := k.Challenge(ctx, f.Token, MethodTOTP)
	b, _ := b32.DecodeString(ch.TOTP.Secret)
	f, _ = k.Prove(ctx, f.Token, TOTP(k.code(b, 0)))
	if _, err := k.Finish(ctx, f.Token); err != nil {
		t.Fatal(err)
	}
	if fs, _ := k.Factors(k.ctx, "u1"); len(fs) != 2 {
		t.Errorf("Factors: %+v", fs)
	}
	for name, sec := range map[string][]byte{"first": a, "second": b} {
		k.clock.advance(time.Minute)
		f := passwordOnly(t, k, "sara")
		if f, err := k.Prove(k.ctx, f.Token, TOTP(k.code(sec, 0))); err != nil || !f.Verified {
			t.Errorf("the %s app: %v", name, err)
		}
	}
}

// §7, §5.12: after the secret is rotated twice with Rekey in between, an
// authenticator app still works; without Rekey it would be lost.
func TestRekey(t *testing.T) {
	k := newDeviceKit(t)
	secret := enrollApp(t, k)
	rotate := func(next string) {
		cfg := k.cfg.(*config)
		cfg.previous, cfg.secret = cfg.secret, cfgx.NewSecret(strings.Repeat(next, 32))
		a, err := New(k.db, cfg, k.dir, k.out, WithRecorder(k.events), WithClock(k.clock.now))
		if err != nil {
			t.Fatal(err)
		}
		a.hasher = k.hasher
		k.Auth = a
	}
	rotate("b")
	if n, _, _ := k.staleSecrets(); n != 1 {
		t.Errorf("%d stale secrets after the first rotation", n)
	}
	if err := k.Rekey(k.ctx); err != nil {
		t.Fatal(err)
	}
	if n, _, _ := k.staleSecrets(); n != 0 {
		t.Errorf("%d stale secrets after Rekey", n)
	}
	rotate("c")
	k.clock.advance(time.Minute)
	f := passwordOnly(t, k, "sara")
	if f, err := k.Prove(k.ctx, f.Token, TOTP(k.code(secret, 0))); err != nil || !f.Verified {
		t.Errorf("the app after two rotations: %+v %v", f, err)
	}
}

// A secret used under the previous key is sealed again under the current
// one (§5.12.3).
func TestTOTPResealedOnUse(t *testing.T) {
	k := newDeviceKit(t)
	secret := enrollApp(t, k)
	cfg := k.cfg.(*config)
	cfg.previous, cfg.secret = cfg.secret, cfgx.NewSecret(strings.Repeat("b", 32))
	a, err := New(k.db, cfg, k.dir, k.out, WithRecorder(k.events), WithClock(k.clock.now))
	if err != nil {
		t.Fatal(err)
	}
	a.hasher = k.hasher
	k.Auth = a
	k.clock.advance(time.Minute)
	f := passwordOnly(t, k, "sara")
	if _, err := k.Prove(k.ctx, f.Token, TOTP(k.code(secret, 0))); err != nil {
		t.Fatal(err)
	}
	if n, lost, _ := k.staleSecrets(); n != 0 || lost != 0 {
		t.Errorf("%d stale, %d lost secrets after a use", n, lost)
	}
	// Sealed again under "b": a second rotation, to "c", keeps it.
	cfg.previous, cfg.secret = cfg.secret, cfgx.NewSecret(strings.Repeat("c", 32))
	a2, err := New(k.db, cfg, k.dir, k.out, WithRecorder(k.events), WithClock(k.clock.now))
	if err != nil {
		t.Fatal(err)
	}
	a2.hasher = k.hasher
	k.Auth = a2
	k.clock.advance(time.Minute)
	f = passwordOnly(t, k, "sara")
	if _, err := k.Prove(k.ctx, f.Token, TOTP(k.code(secret, 0))); err != nil {
		t.Errorf("after a second rotation: %v", err)
	}
}

// The code that enrolled an app can't sign in: the enrolled step is the
// credential's last. The step before now is accepted, two before isn't, and
// a used code stays used when it falls into the step before.
func TestTOTPWindow(t *testing.T) {
	k := newDeviceKit(t)
	secret := enrollApp(t, k)
	enrolled := k.code(secret, 0)
	f := passwordOnly(t, k, "sara")
	if _, err := k.Prove(k.ctx, f.Token, TOTP(enrolled)); !errors.Is(err, ErrBadCode) {
		t.Errorf("the enrolling code at sign-in: %v", err)
	}
	k.clock.advance(2 * time.Minute)
	prove := func(code string) error {
		f := passwordOnly(t, k, "sara")
		_, err := k.Prove(k.ctx, f.Token, TOTP(code))
		return err
	}
	if err := prove(k.code(secret, -2)); !errors.Is(err, ErrBadCode) {
		t.Errorf("two steps back: %v", err)
	}
	used := k.code(secret, -1)
	if err := prove(used); err != nil {
		t.Fatalf("one step back: %v", err)
	}
	k.clock.advance(totp.Step)
	if err := prove(used); !errors.Is(err, ErrBadCode) {
		t.Errorf("a used code a step later: %v", err)
	}
}

// Review 0014, finding 1: an enrollment takes one code, also when two
// arrive at once; a second can't move its step back.
func TestEnrollTOTPOneCode(t *testing.T) {
	k := newDeviceKit(t)
	res := twoFactorSignIn(t, k, nil)
	ctx := withSession(k.ctx, res.Session)
	f, _ := k.Enroll(ctx, res.Session, MethodTOTP)
	ch, _ := k.Challenge(ctx, f.Token, MethodTOTP)
	secret, _ := b32.DecodeString(ch.TOTP.Secret)
	hash := hashOf(f.Token)
	rec, _ := k.loadFlow(hash)
	v, _ := k.view(ctx, rec, nil)
	// Both read the flow before either proved, as racing requests would.
	if _, err := k.proveTOTP(ctx, f.Token, hash, rec, v, k.code(secret, 1)); err != nil {
		t.Fatal(err)
	}
	if _, err := k.proveTOTP(ctx, f.Token, hash, rec, v, k.code(secret, -1)); err == nil {
		t.Error("an enrollment took a second code")
	}
	after, _ := k.loadFlow(hash)
	if string(after.MethodState[stateTOTPStep]) != fmt.Sprint(totp.StepAt(k.clock.now())+1) {
		t.Errorf("the enrolled step moved: %s", after.MethodState[stateTOTPStep])
	}
}

// Review 0014, finding 2: an enrollment begun before a rotation is sealed
// again, and its app survives the next rotation.
func TestEnrollAcrossRotation(t *testing.T) {
	k := newDeviceKit(t)
	res := twoFactorSignIn(t, k, nil)
	ctx := withSession(k.ctx, res.Session)
	f, _ := k.Enroll(ctx, res.Session, MethodTOTP)
	ch, _ := k.Challenge(ctx, f.Token, MethodTOTP)
	secret, _ := b32.DecodeString(ch.TOTP.Secret)
	rotate := func(next string) {
		cfg := k.cfg.(*config)
		cfg.previous, cfg.secret = cfg.secret, cfgx.NewSecret(strings.Repeat(next, 32))
		a, err := New(k.db, cfg, k.dir, k.out, WithRecorder(k.events), WithClock(k.clock.now))
		if err != nil {
			t.Fatal(err)
		}
		a.hasher = k.hasher
		k.Auth = a
	}
	rotate("b")
	if n, _, _ := k.staleSecrets(); n != 1 {
		t.Errorf("the pending secret isn't counted: %d", n)
	}
	if err := k.Rekey(k.ctx); err != nil {
		t.Fatal(err)
	}
	f, _ = k.Prove(ctx, f.Token, TOTP(k.code(secret, 0)))
	if _, err := k.Finish(ctx, f.Token); err != nil {
		t.Fatal(err)
	}
	rotate("c")
	k.clock.advance(time.Minute)
	sf := passwordOnly(t, k, "sara")
	if _, err := k.Prove(k.ctx, sf.Token, TOTP(k.code(secret, 0))); err != nil {
		t.Errorf("an app enrolled across a rotation: %v", err)
	}
}

// Review 0014, finding 4: Rekey reports secrets no configured key opens.
func TestRekeyReportsLost(t *testing.T) {
	k := newDeviceKit(t)
	enrollApp(t, k)
	cfg := k.cfg.(*config)
	cfg.secret, cfg.previous = cfgx.NewSecret(strings.Repeat("z", 32)), cfgx.Secret{}
	a, err := New(k.db, cfg, k.dir, k.out, WithRecorder(k.events), WithClock(k.clock.now))
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Rekey(k.ctx); err == nil || !strings.Contains(err.Error(), "1 authenticator") {
		t.Errorf("Rekey with a lost secret: %v", err)
	}
}

// Review 0014, finding 3: a disabled user's code isn't spent.
func TestTOTPDisabledNotSpent(t *testing.T) {
	k := newDeviceKit(t)
	secret := enrollApp(t, k)
	k.clock.advance(time.Minute)
	f := passwordOnly(t, k, "sara")
	k.dir.mu.Lock()
	k.dir.users["sara"] = User{ID: "u1", Name: "sara", Disabled: true}
	k.dir.mu.Unlock()
	code := k.code(secret, 0)
	if _, err := k.Prove(k.ctx, f.Token, TOTP(code)); !errors.Is(err, ErrUserDisabled) {
		t.Fatalf("disabled: %v", err)
	}
	k.dir.mu.Lock()
	k.dir.users["sara"] = User{ID: "u1", Name: "sara"}
	k.dir.mu.Unlock()
	if _, err := k.Prove(k.ctx, f.Token, TOTP(code)); err != nil {
		t.Errorf("the code after the user is enabled again: %v", err)
	}
}

// The otpauth label escapes the issuer and the name.
func TestTOTPURIEscaped(t *testing.T) {
	k := newKit(t)
	k.addUser(t, "odd", User{ID: "u1", Name: "a/b:c d"}, goodPassword, saraMail)
	k.cfg.(*config).issuer = "Toy/Shop"
	k.clock.advance(time.Minute)
	f, _ := k.SignIn(k.ctx, "odd", Cookie())
	f, _ = k.Prove(k.ctx, f.Token, Password(goodPassword))
	k.Challenge(k.ctx, f.Token, MethodEmailCode)
	f, _ = k.Prove(k.ctx, f.Token, EmailCode(k.lastCode(t, saraMail)))
	res, err := k.Finish(k.ctx, f.Token)
	if err != nil {
		t.Fatal(err)
	}
	ctx := withSession(k.ctx, res.Session)
	ef, _ := k.Enroll(ctx, res.Session, MethodTOTP)
	ch, _ := k.Challenge(ctx, ef.Token, MethodTOTP)
	if !strings.HasPrefix(ch.TOTP.URI, "otpauth://totp/Toy%2FShop:a%2Fb:c%20d?") {
		t.Errorf("URI %s", ch.TOTP.URI)
	}
}

// One flow takes one code: two racing proofs in a sign-in, with the codes
// of two steps, accept one and leave the other unspent.
func TestTOTPOneCodePerFlow(t *testing.T) {
	k := newDeviceKit(t)
	secret := enrollApp(t, k)
	k.clock.advance(time.Minute)
	f := passwordOnly(t, k, "sara")
	hash := hashOf(f.Token)
	rec, _ := k.loadFlow(hash)
	v, _ := k.view(k.ctx, rec, nil)
	if _, err := k.proveTOTP(k.ctx, f.Token, hash, rec, v, k.code(secret, 0)); err != nil {
		t.Fatal(err)
	}
	if _, err := k.proveTOTP(k.ctx, f.Token, hash, rec, v, k.code(secret, 1)); err == nil {
		t.Error("a flow took a second code")
	}
	// The next step's code wasn't spent: another sign-in may use it.
	g := passwordOnly(t, k, "sara")
	if _, err := k.Prove(k.ctx, g.Token, TOTP(k.code(secret, 1))); err != nil {
		t.Errorf("the next step's code was spent by a refused proof: %v", err)
	}
}
