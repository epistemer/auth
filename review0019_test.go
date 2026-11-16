package auth

import (
	"context"
	"fmt"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/epistemer/errors"
	bolt "go.etcd.io/bbolt"
	"google.golang.org/protobuf/proto"

	"github.com/epistemer/auth/internal/store"
	"github.com/epistemer/auth/internal/storepb"
)

// Review 0019, finding 7: an address that folds to nothing is no address.
// It isn't offered, nothing is sent to it, and it is no second factor.
func TestAddressFoldingToNothing(t *testing.T) {
	k := newKit(t)
	k.addUser(t, "lina", User{ID: "u3", Name: "lina"}, goodPassword, "   ", "N/A")
	f := passwordOnly(t, k, "lina")
	if f.Ready || slices.Contains(f.Offers, MethodEmailCode) || slices.Contains(f.Offers, MethodSMSCode) {
		t.Fatalf("offers for addresses that fold to nothing: %+v", f)
	}
	if _, err := k.Challenge(k.ctx, f.Token, MethodEmailCode); err == nil {
		t.Error("a code was challenged to an address that folds to nothing")
	}
	if n := k.sentCount(); n != 0 {
		t.Errorf("%d messages sent", n)
	}
}

// Review 0019, finding 12: RevokeUser refuses an ID with a zero byte
// rather than panicking.
func TestRevokeUserBadID(t *testing.T) {
	k := newKit(t)
	if err := k.RevokeUser(k.ctx, "u\x001"); err == nil {
		t.Error("RevokeUser took an ID with a zero byte")
	}
}

// Review 0019, finding 14: with cookie.insecure, finishing any flow clears
// the flow cookie under the name it was set with.
func TestFinishClearsInsecureFlowCookie(t *testing.T) {
	k := newKitWith(t, func(c *config) { c.insecure = true }, WithPolicy(allowUnverified))
	k.addUser(t, "sara", User{ID: "u1", Name: "sara"}, goodPassword, saraMail)
	f, err := k.Recover(k.ctx, "sara")
	if err == nil {
		_, err = k.Challenge(k.ctx, f.Token, MethodEmailCode)
	}
	if err == nil {
		f, err = k.Prove(k.ctx, f.Token, EmailCode(k.lastCode(t, saraMail)))
	}
	if err != nil {
		t.Fatal(err)
	}
	k.clock.advance(time.Second)
	res, err := k.Finish(k.ctx, f.Token, NewPassword("violet engine sings 93 rivers"))
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	res.Write(w)
	for _, c := range w.Result().Cookies() {
		if c.Name == "flow" && c.MaxAge < 0 {
			return
		}
	}
	t.Errorf("cookies %v", w.Result().Cookies())
}

// Review 0019, finding 4: a password changed while an old one is being
// verified wins; the old one's proof doesn't count.
func TestPasswordChangedWhileVerifying(t *testing.T) {
	k := newKit(t, WithPolicy(allowUnverified))
	k.addUser(t, "sara", User{ID: "u1", Name: "sara"}, goodPassword, saraMail)
	f, err := k.SignIn(k.ctx, "sara", Cookie())
	if err != nil {
		t.Fatal(err)
	}
	whileVerifying = func() {
		whileVerifying = nil
		k.clock.advance(time.Second)
		if err := k.SetPassword(k.ctx, "u1", "violet engine sings 93 rivers"); err != nil {
			t.Error(err)
		}
	}
	t.Cleanup(func() { whileVerifying = nil })
	f, _ = k.Prove(k.ctx, f.Token, Password(goodPassword))
	if f.Ready {
		t.Error("the old password's proof made the flow ready")
	}
	if _, err := k.Finish(k.ctx, f.Token); err == nil {
		t.Error("a sign-in finished on a password changed while it was verified")
	}
}

// Review 0019, finding 3: a factor enrolled while a recovery's new password
// is hashed stops the recovery, which didn't prove it.
func TestRecoverFactorEnrolledWhileHashing(t *testing.T) {
	k := newKit(t)
	k.addUser(t, "sara", User{ID: "u1", Name: "sara"}, goodPassword, saraMail)
	f, err := k.Recover(k.ctx, "sara")
	if err == nil {
		_, err = k.Challenge(k.ctx, f.Token, MethodEmailCode)
	}
	if err == nil {
		f, err = k.Prove(k.ctx, f.Token, EmailCode(k.lastCode(t, saraMail)))
	}
	if err != nil || !f.Ready {
		t.Fatalf("recovery: %+v %v", f, err)
	}
	whileHashing = func() {
		whileHashing = nil
		k.addTOTP(t, "u1", "phone")
	}
	t.Cleanup(func() { whileHashing = nil })
	if _, err := k.Finish(k.ctx, f.Token, NewPassword("violet engine sings 93 rivers")); err == nil {
		t.Error("a recovery set a password past a factor enrolled meanwhile")
	}
	if g, err := k.signIn(t, "sara", goodPassword); err != nil && !errors.Is(err, ErrCannotVerify) {
		t.Errorf("the old password: %+v %v", g, err)
	}
}

// Review 0019, finding 10: a recovery older than the password takes no more
// proofs, so it can't spend a recovery code it could never use.
func TestStaleRecoveryTakesNoProof(t *testing.T) {
	k := newDeviceKit(t)
	_, codes := enrollAppCodes(t, k)
	k.clock.advance(time.Minute)
	f := recoverLink(t, k, "sara")
	f, err := k.Follow(k.ctx, k.lastMessage(t, saraMail).Token)
	if err != nil || f.Ready {
		t.Fatalf("follow: %+v %v", f, err)
	}
	k.clock.advance(time.Second)
	if err := k.SetPassword(k.ctx, "u1", "violet engine sings 93 rivers"); err != nil {
		t.Fatal(err)
	}
	if _, err := k.Prove(k.ctx, f.Token, RecoveryCode(codes[0])); !errors.Is(err, ErrFlowExpired) {
		t.Errorf("a recovery code on a stale recovery: %v", err)
	}
	// The code is still there for a recovery that can finish.
	k.clock.advance(time.Minute)
	g := recoverLink(t, k, "sara")
	g, err = k.Follow(k.ctx, k.lastMessage(t, saraMail).Token)
	if err == nil {
		g, err = k.Prove(k.ctx, g.Token, RecoveryCode(codes[0]))
	}
	if err != nil || !g.Ready {
		t.Errorf("the code afterwards: %+v %v", g, err)
	}
}

// Review 0019, finding 11: once a recovery is proved by a code, the link
// still on its way is cancelled: following it can't take the flow over.
func TestRecoverCodeCancelsLink(t *testing.T) {
	k := newKit(t)
	k.addUser(t, "sara", User{ID: "u1", Name: "sara"}, goodPassword, saraMail)
	f := recoverLink(t, k, "sara")
	link := k.lastMessage(t, saraMail).Token
	k.clock.advance(time.Minute)
	if _, err := k.Challenge(k.ctx, f.Token, MethodEmailCode); err != nil {
		t.Fatal(err)
	}
	f, err := k.Prove(k.ctx, f.Token, EmailCode(k.lastCode(t, saraMail)))
	if err != nil || !f.Ready {
		t.Fatalf("the code: %+v %v", f, err)
	}
	if _, err := k.Follow(k.ctx, link); err == nil {
		t.Error("the link took over a recovery proved by a code")
	}
	err = k.db.View(func(tx *bolt.Tx) error {
		links, err := keysOfUser(k.ctx, tx, store.Links, "u1", func(v []byte) (string, error) {
			var l storepb.Link
			err := proto.Unmarshal(v, &l)
			return l.UserId, err
		})
		if err == nil && len(links) != 0 {
			t.Errorf("%d links left after the code", len(links))
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := k.Finish(k.ctx, f.Token, NewPassword("violet engine sings 93 rivers")); err != nil {
		t.Errorf("the recovery itself: %v", err)
	}
}

// Review 0019, finding 1: once a user has an authenticator app, a code
// sent to an address is no second factor, whichever way the proofs
// arrived: a step-up adding the password to a session that signed in by
// code, or a sign-in proved before the app was enrolled and finished after.
func TestAddressCodeNoSecondOnceEnrolled(t *testing.T) {
	t.Run("step-up", func(t *testing.T) {
		k := newKit(t, WithFirst(MethodPassword, MethodEmailCode), WithPolicy(allowUnverified))
		k.addUser(t, "sara", User{ID: "u1", Name: "sara"}, goodPassword, saraMail)
		k.addTOTP(t, "u1", "phone")
		f, err := k.SignIn(k.ctx, "sara", Cookie())
		if err == nil {
			_, err = k.Challenge(k.ctx, f.Token, MethodEmailCode)
		}
		if err == nil {
			f, err = k.Prove(k.ctx, f.Token, EmailCode(k.lastCode(t, saraMail)))
		}
		var res Result
		if err == nil {
			res, err = k.Finish(k.ctx, f.Token)
		}
		if err != nil || res.Session.Verified {
			t.Fatalf("sign-in by code: %+v %v", res, err)
		}
		k.clock.advance(time.Second)
		g, err := k.StepUp(k.ctx, res.Session)
		if err == nil {
			g, err = k.Prove(k.ctx, g.Token, Password(goodPassword))
		}
		if err != nil {
			t.Fatal(err)
		}
		if g.Verified {
			t.Error("the password and an emailed code made two factors past an app")
		}
		up, err := k.Finish(withSession(k.ctx, res.Session), g.Token)
		if err == nil && up.Session.Verified {
			t.Error("the step-up verified the session without the app")
		}
	})
	t.Run("enrolled before finish", func(t *testing.T) {
		k := newKit(t)
		k.addUser(t, "sara", User{ID: "u1", Name: "sara"}, goodPassword, saraMail)
		f := passwordOnly(t, k, "sara")
		k.clock.advance(time.Minute)
		_, err := k.Challenge(k.ctx, f.Token, MethodEmailCode)
		if err == nil {
			f, err = k.Prove(k.ctx, f.Token, EmailCode(k.lastCode(t, saraMail)))
		}
		if err != nil || !f.Ready {
			t.Fatalf("two proofs: %+v %v", f, err)
		}
		k.addTOTP(t, "u1", "phone")
		if res, err := k.Finish(k.ctx, f.Token); err == nil {
			t.Errorf("a sign-in finished with a code past an app enrolled since: %+v", res.Session)
		}
	})
}

// enrollingClaimer enrolls an app for u1 when armed: the Claimer runs
// between Finish's view and its transaction.
type enrollingClaimer struct {
	k     *kit
	t     *testing.T
	armed bool
}

func (c *enrollingClaimer) Claims(context.Context, User) (map[string]any, error) {
	if c.armed {
		c.armed = false
		c.k.addTOTP(c.t, "u1", "phone")
	}
	return nil, nil
}

// Review 0019, finding 1: a step-up's Finish judges the factors again under
// the write lock, so an app enrolled after its view still counts.
func TestStepUpRejudgedInTransaction(t *testing.T) {
	c := &enrollingClaimer{t: t}
	k := newKit(t, WithFirst(MethodPassword, MethodEmailCode), WithPolicy(allowUnverified), WithClaims(c))
	c.k = k
	k.addUser(t, "sara", User{ID: "u1", Name: "sara"}, goodPassword, saraMail)
	f, err := k.SignIn(k.ctx, "sara", Cookie())
	if err == nil {
		_, err = k.Challenge(k.ctx, f.Token, MethodEmailCode)
	}
	if err == nil {
		f, err = k.Prove(k.ctx, f.Token, EmailCode(k.lastCode(t, saraMail)))
	}
	var res Result
	if err == nil {
		res, err = k.Finish(k.ctx, f.Token)
	}
	if err != nil {
		t.Fatal(err)
	}
	k.clock.advance(time.Second)
	g, err := k.StepUp(k.ctx, res.Session)
	if err == nil {
		g, err = k.Prove(k.ctx, g.Token, Password(goodPassword))
	}
	if err != nil || !g.Verified {
		t.Fatalf("before the app: %+v %v", g, err)
	}
	c.armed = true
	up, err := k.Finish(withSession(k.ctx, res.Session), g.Token)
	if err == nil && up.Session.Verified {
		t.Error("a step-up verified the session by a code past an app enrolled meanwhile")
	}
}

// Review 0019, finding 2: a right password doesn't reset the guesses at an
// authenticator app. Someone who knows the password and proves it again
// between guesses, from a new address each time, still meets a wait after
// throttle.free wrong codes.
func TestPasswordDoesNotResetAppGuesses(t *testing.T) {
	k := newDeviceKit(t)
	secret, _ := enrollAppCodes(t, k)
	right := k.code(secret, 0)
	wrong := right[:5] + string('0'+(right[5]-'0'+1)%10)
	for i := range 8 {
		ctx := k.from(fmt.Sprintf("198.51.100.%d", i+1))
		f, err := k.SignIn(ctx, "sara", Cookie())
		if err == nil {
			f, err = k.Prove(ctx, f.Token, Password(goodPassword))
		}
		if err != nil {
			t.Fatalf("round %d, the password: %v", i, err)
		}
		_, err = k.Prove(ctx, f.Token, TOTP(wrong))
		switch {
		case i < 5 && !errors.Is(err, ErrBadCode):
			t.Fatalf("guess %d: %v", i+1, err)
		case i >= 5 && !errors.Is(err, ErrTooManyAttempts):
			t.Fatalf("guess %d went through: %v", i+1, err)
		}
	}
}

// Review 0019, finding 5: a copy of a session read before a step-up, from
// the token the step-up replaced, can't act on the upgraded session:
// StepUp, Enroll, RemoveFactor and Reissue refuse it.
func TestSupersededSessionCopy(t *testing.T) {
	k := newDeviceKit(t)
	secret, _ := enrollAppCodes(t, k)
	k.clock.advance(time.Minute)
	f, err := k.SignIn(k.ctx, "sara", Cookie())
	if err == nil {
		f, err = k.Prove(k.ctx, f.Token, Password(goodPassword))
	}
	if err == nil {
		f, err = k.Prove(k.ctx, f.Token, TOTP(k.code(secret, 0)))
	}
	var res Result
	if err == nil {
		res, err = k.Finish(k.ctx, f.Token)
	}
	if err != nil {
		t.Fatal(err)
	}
	old := res.Session
	// Past fresh.window, a step-up with the app makes the session fresh.
	k.clock.advance(11 * time.Minute)
	g, err := k.StepUp(k.ctx, old)
	if err == nil {
		g, err = k.Prove(k.ctx, g.Token, TOTP(k.code(secret, 0)))
	}
	var up Result
	if err == nil {
		up, err = k.Finish(withSession(k.ctx, old), g.Token)
	}
	if err != nil {
		t.Fatal(err)
	}
	fs, err := k.Factors(k.ctx, "u1")
	if err != nil || len(fs) != 1 {
		t.Fatalf("factors: %v %v", fs, err)
	}
	ctx := withSession(k.ctx, old)
	if err := k.RemoveFactor(ctx, old, fs[0].ID); !errors.Is(err, ErrNoSession) {
		t.Errorf("RemoveFactor from the old copy: %v", err)
	}
	if _, err := k.Enroll(ctx, old, MethodPassword); !errors.Is(err, ErrNoSession) {
		t.Errorf("Enroll from the old copy: %v", err)
	}
	if _, err := k.Reissue(ctx, old); !errors.Is(err, ErrNoSession) {
		t.Errorf("Reissue from the old copy: %v", err)
	}
	if _, err := k.StepUp(ctx, old); !errors.Is(err, ErrNoSession) {
		t.Errorf("StepUp from the old copy: %v", err)
	}
	// The session the step-up returned acts.
	if err := k.RemoveFactor(withSession(k.ctx, up.Session), up.Session, fs[0].ID); err != nil {
		t.Errorf("RemoveFactor from the new session: %v", err)
	}
}

// Review 0019, finding 4 (re-check): the password is checked again when the
// proof is recorded, so a change at the very instant the old one was read
// refuses it too, whatever the clock's grain.
func TestPasswordChangedSameInstant(t *testing.T) {
	k := newKit(t, WithPolicy(allowUnverified))
	k.addUser(t, "sara", User{ID: "u1", Name: "sara"}, goodPassword, saraMail)
	k.clock.advance(time.Minute)
	f, err := k.SignIn(k.ctx, "sara", Cookie())
	if err != nil {
		t.Fatal(err)
	}
	whileVerifying = func() {
		whileVerifying = nil
		if err := k.SetPassword(k.ctx, "u1", "violet engine sings 93 rivers"); err != nil {
			t.Error(err)
		}
	}
	t.Cleanup(func() { whileVerifying = nil })
	if _, err := k.Prove(k.ctx, f.Token, Password(goodPassword)); !errors.Is(err, ErrBadCredentials) {
		t.Errorf("the old password, changed the same instant: %v", err)
	}
}

// Review 0019, finding 10 (re-check): a recovery holding no proof yet looks
// the same after a password change, as an unknown login's does.
func TestFreshRecoveryNotStale(t *testing.T) {
	k := newKit(t)
	k.addUser(t, "sara", User{ID: "u1", Name: "sara"}, goodPassword, saraMail)
	f, err := k.Recover(k.ctx, "sara")
	if err != nil {
		t.Fatal(err)
	}
	k.clock.advance(time.Second)
	if err := k.SetPassword(k.ctx, "u1", "violet engine sings 93 rivers"); err != nil {
		t.Fatal(err)
	}
	if _, err := k.Flow(k.ctx, f.Token); err != nil {
		t.Errorf("a recovery with no proof after a password change: %v", err)
	}
}

// Review 0019, finding 1 (re-check): a sign-in's Finish counts its factors
// again under the write lock: an app enrolled between its view and its
// transaction takes away what the emailed code proved.
func TestSignInRejudgedInTransaction(t *testing.T) {
	c := &enrollingClaimer{t: t}
	k := newKit(t, WithClaims(c))
	c.k = k
	k.addUser(t, "sara", User{ID: "u1", Name: "sara"}, goodPassword, saraMail)
	f := passwordOnly(t, k, "sara")
	k.clock.advance(time.Minute)
	_, err := k.Challenge(k.ctx, f.Token, MethodEmailCode)
	if err == nil {
		f, err = k.Prove(k.ctx, f.Token, EmailCode(k.lastCode(t, saraMail)))
	}
	if err != nil || !f.Ready {
		t.Fatalf("two proofs: %+v %v", f, err)
	}
	c.armed = true
	if res, err := k.Finish(k.ctx, f.Token); err == nil {
		t.Errorf("a sign-in finished by a code past an app enrolled meanwhile: %+v", res.Session)
	}
}

// Review 0019, finding 2 (re-check): a code proved from a mailbox doesn't
// reset the guesses at a password. Wrong passwords, a recovery proved by
// an emailed code, then more wrong passwords still meet a wait after
// throttle.free, each from a new address.
func TestCodeDoesNotResetPasswordGuesses(t *testing.T) {
	k := newKit(t)
	k.addUser(t, "sara", User{ID: "u1", Name: "sara"}, goodPassword, saraMail)
	n := 0
	guess := func() error {
		n++
		ctx := k.from(fmt.Sprintf("198.51.100.%d", n))
		f, err := k.SignIn(ctx, "sara", Cookie())
		if err != nil {
			t.Fatal(err)
		}
		_, err = k.Prove(ctx, f.Token, Password("wrong horse battery staple"))
		return err
	}
	for range 4 {
		if err := guess(); !errors.Is(err, ErrBadCredentials) {
			t.Fatalf("guess %d: %v", n, err)
		}
	}
	ctx := k.from("203.0.113.9")
	f, err := k.Recover(ctx, "sara")
	if err == nil {
		_, err = k.Challenge(ctx, f.Token, MethodEmailCode)
	}
	if err == nil {
		_, err = k.Prove(ctx, f.Token, EmailCode(k.lastCode(t, saraMail)))
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := guess(); !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("guess %d: %v", n, err)
	}
	if err := guess(); !errors.Is(err, ErrTooManyAttempts) {
		t.Errorf("guess %d, after a code from the mailbox: %v", n, err)
	}
}
