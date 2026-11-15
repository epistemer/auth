package auth

import (
	"strings"
	"testing"
	"time"

	"github.com/epistemer/errors"
	bolt "go.etcd.io/bbolt"

	"github.com/epistemer/auth/internal/store"
	"github.com/epistemer/auth/internal/storepb"
)

// addTOTP stores a TOTP credential for a user, as M4.2's Enroll will.
func (k *kit) addTOTP(t *testing.T, id UserID, label string) string {
	t.Helper()
	key := credentialKey(id, MethodTOTP, []byte(label))
	err := k.db.Update(func(tx *bolt.Tx) error {
		return store.Put(tx, store.Credentials, key, &storepb.Credential{Method: MethodTOTP, Key: []byte(label), Label: label, Added: k.clock.now().UnixNano()})
	})
	if err != nil {
		t.Fatal(err)
	}
	return factorID(MethodTOTP, key)
}

// withFactor adds a proof to a session's record, as a step-up would.
func (k *kit) withFactor(t *testing.T, s *Session, method string) *Session {
	t.Helper()
	var out *Session
	err := k.db.Update(func(tx *bolt.Tx) error {
		var rec storepb.Session
		if err := store.Get(tx, store.Sessions, []byte(s.ID), &rec); err != nil {
			return err
		}
		rec.Factors = append(rec.Factors, &storepb.Factor{Method: method, At: k.clock.now().UnixNano()})
		rec.Verified = true
		out = toSession(&rec)
		return store.Put(tx, store.Sessions, []byte(s.ID), &rec)
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// §5.1.9, §5.1.10: changing the password through Enroll keeps the session
// that made the change, ends the others, forgets the devices and sends
// MsgPasswordChanged.
func TestEnrollPassword(t *testing.T) {
	k := newDeviceKit(t)
	other := twoFactorSignIn(t, k, nil, RememberDevice("laptop"))
	k.clock.advance(time.Minute)
	me := twoFactorSignIn(t, k, nil)
	ctx := withSession(k.ctx, me.Session)
	f, err := k.Enroll(ctx, me.Session, MethodPassword)
	if err != nil || !f.Ready || f.Purpose != PurposeEnroll {
		t.Fatalf("Enroll: %+v %v", f, err)
	}
	if _, err := k.Finish(ctx, f.Token); !errors.Is(err, ErrPasswordRequired) {
		t.Errorf("without a password: %v", err)
	}
	if _, err := k.Finish(ctx, f.Token, NewPassword("password1234")); !errors.Is(err, ErrPasswordCommon) {
		t.Errorf("a weak password: %v", err)
	}
	n := k.sentCount()
	res, err := k.Finish(ctx, f.Token, NewPassword(newPassword))
	if err != nil || res.Session == nil || res.Session.ID != me.Session.ID {
		t.Fatalf("Finish: %+v %v", res, err)
	}
	if k.sentCount() != n+1 || k.lastMessage(t, saraMail).Kind != MsgPasswordChanged {
		t.Error("no MsgPasswordChanged")
	}
	if _, err := k.StepUp(k.ctx, me.Session); err != nil {
		t.Errorf("the session that made the change ended: %v", err)
	}
	if _, err := k.StepUp(k.ctx, other.Session); !errors.Is(err, ErrNoSession) {
		t.Errorf("another session survived: %v", err)
	}
	if ds, _ := k.Devices(k.ctx, "u1"); len(ds) != 0 {
		t.Errorf("devices kept: %+v", ds)
	}
	if _, err := k.signIn(t, "sara", newPassword); err != nil {
		t.Errorf("the new password: %v", err)
	}
	if _, err := k.signIn(t, "sara", goodPassword); !errors.Is(err, ErrBadCredentials) {
		t.Errorf("the old password: %v", err)
	}
}

// M4.1's done-when and §7: a factor change without a proof inside
// fresh.window is ErrStale, at Enroll and again at Finish; an unverified
// session is ErrNotVerified.
func TestEnrollFresh(t *testing.T) {
	k := newDeviceKit(t)
	res := twoFactorSignIn(t, k, nil)
	ctx := withSession(k.ctx, res.Session)
	k.clock.advance(11 * time.Minute)
	if _, err := k.Enroll(ctx, res.Session, MethodPassword); !errors.Is(err, ErrStale) {
		t.Errorf("Enroll with an old proof: %v", err)
	}
	k.clock.advance(-9 * time.Minute)
	f, err := k.Enroll(ctx, res.Session, MethodPassword)
	if err != nil {
		t.Fatal(err)
	}
	k.clock.advance(9 * time.Minute)
	if _, err := k.Finish(ctx, f.Token, NewPassword(newPassword)); !errors.Is(err, ErrStale) {
		t.Errorf("Finish once the proof is old: %v", err)
	}

	loose := newDeviceKit(t, WithPolicy(allowUnverified))
	f2 := passwordOnly(t, loose, "sara")
	unv, _ := loose.Finish(loose.ctx, f2.Token)
	if _, err := loose.Enroll(withSession(loose.ctx, unv.Session), unv.Session, MethodPassword); !errors.Is(err, ErrNotVerified) {
		t.Errorf("Enroll from an unverified session: %v", err)
	}
}

// §7: for a user with TOTP, RemoveFactor and Enroll after a fresh password
// alone, from a session a device verified, are ErrStale; so after a fresh
// emailed code, which no longer counts. A fresh TOTP proof is enough.
func TestEnrollWithTOTP(t *testing.T) {
	k := newDeviceKit(t)
	dev := twoFactorSignIn(t, k, nil, RememberDevice("laptop"))
	byCode := twoFactorSignIn(t, k, nil)
	id := k.addTOTP(t, "u1", "phone")
	k.clock.advance(time.Minute)
	f := passwordOnly(t, k, "sara", Device(dev.device))
	byDevice, err := k.Finish(k.ctx, f.Token)
	if err != nil || !byDevice.Session.Verified {
		t.Fatalf("a device sign-in: %+v %v", byDevice, err)
	}
	for name, s := range map[string]*Session{"device": byDevice.Session, "emailed code": byCode.Session} {
		ctx := withSession(k.ctx, s)
		if _, err := k.Enroll(ctx, s, MethodPassword); !errors.Is(err, ErrStale) {
			t.Errorf("Enroll after a fresh password and a %s: %v", name, err)
		}
		if err := k.RemoveFactor(ctx, s, id); !errors.Is(err, ErrStale) {
			t.Errorf("RemoveFactor after a fresh password and a %s: %v", name, err)
		}
	}
	fresh := k.withFactor(t, byDevice.Session, MethodTOTP)
	if _, err := k.Enroll(withSession(k.ctx, fresh), fresh, MethodPassword); err != nil {
		t.Errorf("Enroll after a fresh TOTP proof: %v", err)
	}
}

// Factors lists a user's second factors; RemoveFactor removes one of the
// session's user's, and sends MsgFactorRemoved; ResetFactors removes all.
func TestFactors(t *testing.T) {
	k := newDeviceKit(t)
	res := twoFactorSignIn(t, k, nil)
	phone := k.addTOTP(t, "u1", "phone")
	k.addTOTP(t, "u1", "tablet")
	omars := k.addTOTP(t, "u2", "omar's")
	omarsPhone := k.addTOTP(t, "u2", "phone") // the same key as sara's
	fs, err := k.Factors(k.ctx, "u1")
	if err != nil || len(fs) != 2 || fs[0].Method != MethodTOTP {
		t.Fatalf("Factors: %+v %v", fs, err)
	}
	s := k.withFactor(t, res.Session, MethodTOTP)
	ctx := withSession(k.ctx, s)
	if err := k.RemoveFactor(ctx, s, omars); !errors.Is(err, ErrMethodUnavailable) {
		t.Errorf("another user's factor: %v", err)
	}
	if err := k.RemoveFactor(ctx, s, "totp:not-hex"); !errors.Is(err, ErrMethodUnavailable) {
		t.Errorf("a made-up ID: %v", err)
	}
	n := k.sentCount()
	if err := k.RemoveFactor(ctx, s, phone); err != nil {
		t.Fatal(err)
	}
	if k.sentCount() != n+1 || k.lastMessage(t, saraMail).Kind != MsgFactorRemoved {
		t.Error("no MsgFactorRemoved")
	}
	if fs, _ := k.Factors(k.ctx, "u1"); len(fs) != 1 || fs[0].Label != "tablet" {
		t.Errorf("after RemoveFactor: %+v", fs)
	}
	if fs, _ := k.Factors(k.ctx, "u2"); len(fs) != 2 {
		t.Errorf("omar's factors after sara's removal: %+v", fs)
	}
	if fs[0].Used.IsZero() == false {
		t.Errorf("an unused factor's Used: %v", fs[0].Used)
	}
	n = k.sentCount()
	if err := k.ResetFactors(k.ctx, "u1"); err != nil {
		t.Fatal(err)
	}
	if fs, _ := k.Factors(k.ctx, "u1"); len(fs) != 0 {
		t.Errorf("after ResetFactors: %+v", fs)
	}
	if k.sentCount() != n+1 || k.lastMessage(t, saraMail).Kind != MsgFactorRemoved {
		t.Error("ResetFactors sent no MsgFactorRemoved")
	}
	if fs, _ := k.Factors(k.ctx, "u2"); len(fs) != 2 || omarsPhone == "" {
		t.Errorf("omar's factors after sara's reset: %+v", fs)
	}
	// With no factor left, a fresh password and an emailed code are enough
	// again.
	k.clock.advance(time.Minute)
	fresh := twoFactorSignIn(t, k, nil)
	if _, err := k.Enroll(withSession(k.ctx, fresh.Session), fresh.Session, MethodPassword); err != nil {
		t.Errorf("Enroll after the reset: %v", err)
	}
}

// An Enroll flow is bound to its session: another session can't finish it.
func TestEnrollBound(t *testing.T) {
	k := newDeviceKit(t)
	a := twoFactorSignIn(t, k, nil)
	k.clock.advance(time.Minute)
	b := twoFactorSignIn(t, k, nil)
	f, err := k.Enroll(withSession(k.ctx, a.Session), a.Session, MethodPassword)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := k.Finish(withSession(k.ctx, b.Session), f.Token, NewPassword(newPassword)); !errors.Is(err, ErrFlowExpired) {
		t.Errorf("Finish from another session: %v", err)
	}
	if _, err := k.Finish(k.ctx, f.Token, NewPassword(newPassword)); !errors.Is(err, ErrNoSession) {
		t.Errorf("Finish from no session: %v", err)
	}
	if _, err := k.Enroll(withSession(k.ctx, a.Session), a.Session, "telepathy"); !errors.Is(err, ErrMethodUnavailable) {
		t.Errorf("an unknown method: %v", err)
	}
}

// Review 0013, finding 1: a factor enrolled while a new password hashes
// is seen: the change is refused, judged on the state it would be made on.
func TestEnrollRecheckedInTransaction(t *testing.T) {
	k := newDeviceKit(t)
	res := twoFactorSignIn(t, k, nil)
	ctx := withSession(k.ctx, res.Session)
	f, err := k.Enroll(ctx, res.Session, MethodPassword)
	if err != nil {
		t.Fatal(err)
	}
	whileHashing = func() { k.addTOTP(t, "u1", "phone") }
	defer func() { whileHashing = nil }()
	if _, err := k.Finish(ctx, f.Token, NewPassword(newPassword)); !errors.Is(err, ErrStale) {
		t.Errorf("a password change past a factor enrolled meanwhile: %v", err)
	}
	if _, err := k.signIn(t, "sara", goodPassword); err != nil {
		t.Errorf("the password changed: %v", err)
	}
}

// A first password set through Enroll is a change too: the user's other
// sessions end and MsgPasswordChanged goes out.
func TestEnrollFirstPassword(t *testing.T) {
	k := newKit(t, WithFirst(MethodPassword, MethodEmailCode))
	k.addUser(t, "sara", User{ID: "u1", Name: "sara"}, "", saraMail, saraPhone)
	codes := func() Result {
		f, _ := k.SignIn(k.ctx, "sara", Cookie())
		k.clock.advance(time.Minute)
		k.Challenge(k.ctx, f.Token, MethodEmailCode)
		k.Prove(k.ctx, f.Token, EmailCode(k.lastCode(t, saraMail)))
		k.Challenge(k.ctx, f.Token, MethodSMSCode)
		f, _ = k.Prove(k.ctx, f.Token, SMSCode(k.lastCode(t, saraPhone)))
		r, err := k.Finish(k.ctx, f.Token)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	other, me := codes(), codes()
	ctx := withSession(k.ctx, me.Session)
	f, err := k.Enroll(ctx, me.Session, MethodPassword)
	if err != nil {
		t.Fatal(err)
	}
	n := k.sentCount()
	if _, err := k.Finish(ctx, f.Token, NewPassword(newPassword)); err != nil {
		t.Fatal(err)
	}
	if k.sentCount() != n+1 || k.lastMessage(t, saraMail).Kind != MsgPasswordChanged {
		t.Error("no MsgPasswordChanged for a first password")
	}
	if _, err := k.StepUp(k.ctx, other.Session); !errors.Is(err, ErrNoSession) {
		t.Errorf("another session survived a first password: %v", err)
	}
	if _, err := k.StepUp(k.ctx, me.Session); err != nil {
		t.Errorf("the session that set it ended: %v", err)
	}
}

// addRecoveryCode stores a recovery code credential, as M4.3 will.
func (k *kit) addRecoveryCode(t *testing.T, id UserID, code string) {
	t.Helper()
	key := credentialKey(id, MethodRecoveryCode, []byte(code))
	if err := k.db.Update(func(tx *bolt.Tx) error {
		return store.Put(tx, store.Credentials, key, &storepb.Credential{Method: MethodRecoveryCode})
	}); err != nil {
		t.Fatal(err)
	}
}

// Recovery codes: alone they are no factor; they aren't listed or removable
// as one; a fresh recovery code proof counts as a second proof; removing
// the last factor removes them, and so does ResetFactors.
func TestRecoveryCodesAndFactors(t *testing.T) {
	k := newDeviceKit(t)
	res := twoFactorSignIn(t, k, nil)
	k.addRecoveryCode(t, "u1", "ABCD")
	if f := passwordOnly(t, k, "sara"); strings.Join(f.Offers, ",") != "email_code" {
		t.Errorf("recovery codes alone made a factor: %v", f.Offers)
	}
	phone := k.addTOTP(t, "u1", "phone")
	fs, _ := k.Factors(k.ctx, "u1")
	if len(fs) != 1 || fs[0].Method != MethodTOTP {
		t.Errorf("Factors listed a recovery code: %+v", fs)
	}
	rc := factorID(MethodRecoveryCode, credentialKey("u1", MethodRecoveryCode, []byte("ABCD")))
	s := k.withFactor(t, res.Session, MethodRecoveryCode)
	ctx := withSession(k.ctx, s)
	if err := k.RemoveFactor(ctx, s, rc); !errors.Is(err, ErrMethodUnavailable) {
		t.Errorf("RemoveFactor of a recovery code: %v", err)
	}
	if _, err := k.Enroll(ctx, s, MethodPassword); err != nil {
		t.Errorf("a fresh recovery code as the second proof: %v", err)
	}
	if err := k.RemoveFactor(ctx, s, phone); err != nil {
		t.Fatal(err)
	}
	count := func() int {
		n := 0
		k.db.View(func(tx *bolt.Tx) error {
			return store.Scan(tx, store.Credentials, store.Prefix([]byte("u1"), []byte(MethodRecoveryCode)), func(_, _ []byte) error { n++; return nil })
		})
		return n
	}
	if count() != 0 {
		t.Error("the last factor left its recovery codes")
	}
	k.addTOTP(t, "u1", "phone")
	k.addRecoveryCode(t, "u1", "EFGH")
	k.ResetFactors(k.ctx, "u1")
	if count() != 0 {
		t.Error("ResetFactors left recovery codes")
	}
}
