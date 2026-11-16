package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/epistemer/errors"
	bolt "go.etcd.io/bbolt"

	"github.com/epistemer/auth/internal/store"
)

// twoFactorSignIn signs sara in with her password and an emailed code, with
// opts at Finish, and returns the result.
func twoFactorSignIn(t *testing.T, k *kit, start []StartOption, opts ...FinishOption) Result {
	t.Helper()
	f, err := k.SignIn(k.ctx, "sara", Cookie(), start...)
	if err != nil {
		t.Fatal(err)
	}
	if f, err = k.Prove(k.ctx, f.Token, Password(goodPassword)); err != nil && !errors.Is(err, ErrCannotVerify) {
		t.Fatal(err)
	}
	if !f.Verified {
		k.clock.advance(time.Minute) // past code.resend
		k.Challenge(k.ctx, f.Token, MethodEmailCode)
		if f, err = k.Prove(k.ctx, f.Token, EmailCode(k.lastCode(t, saraMail))); err != nil {
			t.Fatal(err)
		}
	}
	res, err := k.Finish(k.ctx, f.Token, opts...)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// passwordOnly signs in with the password alone, and returns the flow.
func passwordOnly(t *testing.T, k *kit, login string, start ...StartOption) Flow {
	t.Helper()
	f, err := k.SignIn(k.ctx, login, Cookie(), start...)
	if err != nil {
		t.Fatal(err)
	}
	f, err = k.Prove(k.ctx, f.Token, Password(goodPassword))
	if err != nil && !errors.Is(err, ErrCannotVerify) {
		t.Fatal(err)
	}
	return f
}

func newDeviceKit(t *testing.T, opts ...Option) *kit {
	k := newKit(t, opts...)
	k.addUser(t, "sara", User{ID: "u1", Name: "sara"}, goodPassword, saraMail)
	k.addUser(t, "omar", User{ID: "u2", Name: "omar"}, goodPassword, "omar@toyshop.example")
	return k
}

// §5.7.1, §5.7.5, §5.7.8: a flow that proved a second method registers the
// device; the device then stands for the second proof; MsgNewDevice goes
// out the first time; Within isn't met by a device.
func TestRememberDevice(t *testing.T) {
	k := newDeviceKit(t)
	res := twoFactorSignIn(t, k, nil, RememberDevice("Sara's laptop"))
	if res.device == "" || res.Session.Device == "" || res.deviceExpires.IsZero() {
		t.Fatalf("no device: %+v", res)
	}
	if m := k.lastMessage(t, saraMail); m.Kind != MsgNewDevice {
		t.Errorf("last message %v", m.Kind)
	}
	ds, _ := k.Devices(k.ctx, "u1")
	if len(ds) != 1 || ds[0].Label != "Sara's laptop" || ds[0].ID != res.Session.Device || !ds[0].Expires.Equal(k.clock.now().Add(2160*time.Hour)) {
		t.Fatalf("Devices: %+v", ds)
	}
	w := httptest.NewRecorder()
	res.Write(w)
	if c := cookieOf(t, w, "__Host-device"); c == nil || c.Value != res.device || !c.Secure || !c.HttpOnly {
		t.Errorf("device cookie %+v", c)
	}

	k.clock.advance(time.Hour)
	n := k.sentCount()
	f := passwordOnly(t, k, "sara", Device(res.device))
	if !f.Verified || !f.Ready {
		t.Fatalf("a password and a registered device: %+v", f)
	}
	k.clock.advance(6 * time.Minute) // the password is six minutes old at Finish
	again, err := k.Finish(k.ctx, f.Token)
	if err != nil || !again.Session.Verified || again.Session.Device != res.Session.Device {
		t.Fatalf("Finish: %+v %v", again.Session, err)
	}
	for _, fac := range again.Session.Factors {
		if fac.Method != MethodPassword {
			t.Errorf("a device became a factor: %+v", fac)
		}
	}
	if k.sentCount() != n {
		t.Error("a device used again sent a message")
	}
	// The device was used at Finish, just now; the password is six minutes
	// old. Within(5m) counts only the password.
	ctx := withSession(k.ctx, again.Session)
	if err := k.Check(ctx, Within(5*time.Minute)); !errors.Is(err, ErrStale) {
		t.Errorf("Within met by a device: %v", err)
	}
	if err := k.Check(ctx, Within(10*time.Minute)); err != nil {
		t.Errorf("the password within ten minutes: %v", err)
	}
}

// §7, devices: a device token is replaced by Finish and not by an abandoned
// flow.
func TestDeviceTokenReplaced(t *testing.T) {
	k := newDeviceKit(t)
	res := twoFactorSignIn(t, k, nil, RememberDevice("laptop"))
	old := res.device
	passwordOnly(t, k, "sara", Device(old)) // abandoned
	if f := passwordOnly(t, k, "sara", Device(old)); !f.Verified {
		t.Fatal("an abandoned flow replaced the token")
	}
	f := passwordOnly(t, k, "sara", Device(old))
	next, err := k.Finish(k.ctx, f.Token)
	if err != nil || next.device == "" || next.device == old {
		t.Fatalf("Finish: %+v %v", next, err)
	}
	if f := passwordOnly(t, k, "sara", Device(old)); f.Verified {
		t.Error("the old token still verifies")
	}
	if f := passwordOnly(t, k, "sara", Device(next.device)); !f.Verified {
		t.Error("the new token doesn't verify")
	}
}

// §7, devices: a device token of one user doesn't verify a session for
// another; a made-up one verifies nothing; with TrustDevices false a device
// doesn't verify.
func TestDeviceRefusals(t *testing.T) {
	k := newDeviceKit(t)
	res := twoFactorSignIn(t, k, nil, RememberDevice("laptop"))
	if f := passwordOnly(t, k, "omar", Device(res.device)); f.Verified {
		t.Error("sara's device verified omar")
	}
	if f := passwordOnly(t, k, "sara", Device("made-up")); f.Verified {
		t.Error("a made-up token verified")
	}
	strict := newDeviceKit(t, WithPolicy(func(context.Context, User) Policy { return Policy{} }))
	r2 := twoFactorSignIn(t, strict, nil, RememberDevice("laptop"))
	if f := passwordOnly(t, strict, "sara", Device(r2.device)); f.Verified {
		t.Error("a device verified with TrustDevices false")
	}
	// Two factors with the device presented and TrustDevices false: the
	// device wasn't used, so it is neither replaced nor attached.
	strict.clock.advance(time.Minute)
	r3 := twoFactorSignIn(t, strict, []StartOption{Device(r2.device)})
	if r3.device != "" || r3.Session.Device != "" {
		t.Errorf("an untrusted device was used: %+v", r3)
	}
	if f := passwordOnly(t, k, "sara", Device(res.device)); !f.Verified {
		t.Error("the trusted kit's device stopped verifying")
	}
	// Unverified sessions allowed, devices not trusted: the same.
	loose := newDeviceKit(t, WithPolicy(func(context.Context, User) Policy { return Policy{AllowUnverified: true} }))
	r4 := twoFactorSignIn(t, loose, nil, RememberDevice("laptop"))
	f := passwordOnly(t, loose, "sara", Device(r4.device))
	r5, err := loose.Finish(loose.ctx, f.Token)
	if err != nil || r5.device != "" || r5.Session.Device != "" || r5.Session.Verified {
		t.Errorf("an untrusted device at Finish: %+v %v", r5, err)
	}
}

// §7, devices: RememberDevice in a flow with one proof registers nothing.
func TestRememberDeviceNeedsSecondProof(t *testing.T) {
	k := newDeviceKit(t, WithPolicy(allowUnverified))
	f := passwordOnly(t, k, "sara")
	res, err := k.Finish(k.ctx, f.Token, RememberDevice("laptop"))
	if err != nil || res.device != "" || res.Session.Device != "" {
		t.Fatalf("Finish: %+v %v", res, err)
	}
	if ds, _ := k.Devices(k.ctx, "u1"); len(ds) != 0 {
		t.Errorf("devices %+v", ds)
	}
}

// A step-up that proves a second method may register the device too.
func TestStepUpRemembersDevice(t *testing.T) {
	k := newDeviceKit(t, WithPolicy(allowUnverified))
	f := passwordOnly(t, k, "sara")
	res, _ := k.Finish(k.ctx, f.Token)
	ctx := withSession(k.ctx, res.Session)
	up, _ := k.StepUp(ctx, res.Session)
	k.Challenge(ctx, up.Token, MethodEmailCode)
	if _, err := k.Prove(ctx, up.Token, EmailCode(k.lastCode(t, saraMail))); err != nil {
		t.Fatal(err)
	}
	r2, err := k.Finish(ctx, up.Token, RememberDevice("phone"))
	if err != nil || r2.device == "" || !r2.Session.Verified || r2.Session.Device == "" {
		t.Fatalf("step-up: %+v %v", r2, err)
	}
}

// ForgetDevice removes only the named user's device; a recovery and a
// password change forget them all (§5.1.10).
func TestForgetDevices(t *testing.T) {
	k := newDeviceKit(t)
	res := twoFactorSignIn(t, k, nil, RememberDevice("laptop"))
	if err := k.ForgetDevice(k.ctx, "u2", res.Session.Device); err != nil {
		t.Fatal(err)
	}
	if ds, _ := k.Devices(k.ctx, "u1"); len(ds) != 1 {
		t.Fatal("another user forgot sara's device")
	}
	if err := k.ForgetDevice(k.ctx, "u1", res.Session.Device); err != nil {
		t.Fatal(err)
	}
	if f := passwordOnly(t, k, "sara", Device(res.device)); f.Verified {
		t.Error("a forgotten device verifies")
	}

	k.clock.advance(time.Hour)
	res = twoFactorSignIn(t, k, nil, RememberDevice("laptop"))
	if err := k.SetPassword(k.ctx, "u1", newPassword); err != nil {
		t.Fatal(err)
	}
	if ds, _ := k.Devices(k.ctx, "u1"); len(ds) != 0 {
		t.Errorf("a password change kept devices: %+v", ds)
	}
	f, _ := k.SignIn(k.ctx, "sara", Cookie(), Device(res.device))
	if f, _ = k.Prove(k.ctx, f.Token, Password(newPassword)); f.Verified {
		t.Error("a device verifies after a password change")
	}

	k2 := newDeviceKit(t)
	twoFactorSignIn(t, k2, nil, RememberDevice("laptop"))
	recoverLink(t, k2, "sara")
	r, _ := k2.Follow(k2.ctx, k2.lastMessage(t, saraMail).Token)
	if _, err := k2.Finish(k2.ctx, r.Token, NewPassword(newPassword)); err != nil {
		t.Fatal(err)
	}
	if ds, _ := k2.Devices(k2.ctx, "u1"); len(ds) != 0 {
		t.Errorf("a recovery kept devices: %+v", ds)
	}
}

// A device forgotten while its flow is open no longer verifies it at Finish.
func TestDeviceForgottenMidFlow(t *testing.T) {
	k := newDeviceKit(t)
	res := twoFactorSignIn(t, k, nil, RememberDevice("laptop"))
	f := passwordOnly(t, k, "sara", Device(res.device))
	if !f.Verified {
		t.Fatal("not verified by the device")
	}
	rec, _ := k.loadFlow(hashOf(f.Token))
	v, _ := k.view(k.ctx, rec, nil)
	k.ForgetDevice(k.ctx, "u1", res.Session.Device)
	// Finish with the view from before, as a request racing the forget.
	if _, err := k.finishSignIn(k.ctx, hashOf(f.Token), rec, finishOptions{}); !errors.Is(err, ErrNotReady) {
		t.Errorf("Finish after the device was forgotten: %v", err)
	}
	_ = v
}

// §7, throttling: during a wait on a user, a request with that user's
// registered device still gets its tries (§5.8.6).
func TestThrottleDevice(t *testing.T) {
	k := newDeviceKit(t)
	res := twoFactorSignIn(t, k, nil, RememberDevice("laptop"))
	for i := range 5 {
		ctx := WithClient(k.ctx, Client{Addr: netip.AddrFrom4([4]byte{198, 51, 100, byte(i + 1)})})
		f, _ := k.SignIn(ctx, "sara", Cookie())
		k.Prove(ctx, f.Token, Password(wrongPassword))
	}
	home := k.from("192.0.2.1")
	if _, err := k.try(t, home, "sara", goodPassword); !errors.Is(err, ErrTooManyAttempts) {
		t.Fatalf("without the device during the wait: %v", err)
	}
	f, err := k.SignIn(home, "sara", Cookie(), Device(res.device))
	if err != nil {
		t.Fatal(err)
	}
	if f, err = k.Prove(home, f.Token, Password(goodPassword)); err != nil || !f.Verified {
		t.Errorf("with the device during the wait: %+v %v", f, err)
	}
}

// The cookie carrier reads the device cookie: a sign-in through Load with it
// is verified by the device.
func TestDeviceCookieThroughLoad(t *testing.T) {
	k := newDeviceKit(t)
	res := twoFactorSignIn(t, k, nil, RememberDevice("laptop"))
	w := httptest.NewRecorder()
	res.Write(w)
	dev := cookieOf(t, w, "__Host-device")
	var got Flow
	h := k.Load(Cookie())(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		f, err := k.SignIn(r.Context(), "sara", Cookie())
		if err == nil {
			got, _ = k.Prove(r.Context(), f.Token, Password(goodPassword))
		}
	}))
	r := httptest.NewRequest("POST", "https://shop.example/sign-in", nil)
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	r.AddCookie(dev)
	h.ServeHTTP(httptest.NewRecorder(), r)
	if !got.Verified {
		t.Errorf("the device cookie didn't verify: %+v", got)
	}
}

// Sweep removes devices past their lifetime, with their indexes.
func TestSweepDevices(t *testing.T) {
	k := newDeviceKit(t)
	twoFactorSignIn(t, k, nil, RememberDevice("laptop"))
	count := func(b []byte) int {
		n := 0
		k.db.View(func(tx *bolt.Tx) error { return store.B(tx, b).ForEach(func(_, _ []byte) error { n++; return nil }) })
		return n
	}
	k.Sweep(k.ctx)
	if count(store.Devices) != 1 {
		t.Fatal("a live device was swept")
	}
	k.clock.advance(2161 * time.Hour)
	k.Sweep(k.ctx)
	if count(store.Devices)+count(store.DeviceTokens)+count(store.DevicesByUser) != 0 {
		t.Error("an expired device was kept")
	}
}

// A recovery forgets the devices of a user who had no password too.
func TestRecoverForgetsDevicesWithoutPassword(t *testing.T) {
	k := newKit(t, WithFirst(MethodPassword, MethodEmailCode))
	k.addUser(t, "sara", User{ID: "u1", Name: "sara"}, "", saraMail)
	k.addUser(t, "sms", User{ID: "u1", Name: "sara"}, "", saraMail, saraPhone)
	f, _ := k.SignIn(k.ctx, "sara", Cookie())
	k.Challenge(k.ctx, f.Token, MethodEmailCode)
	f, _ = k.Prove(k.ctx, f.Token, EmailCode(k.lastCode(t, saraMail)))
	k.Challenge(k.ctx, f.Token, MethodSMSCode)
	f, err := k.Prove(k.ctx, f.Token, SMSCode(k.lastCode(t, saraPhone)))
	if err != nil || !f.Verified {
		t.Fatalf("two codes: %+v %v", f, err)
	}
	if _, err := k.Finish(k.ctx, f.Token, RememberDevice("laptop")); err != nil {
		t.Fatal(err)
	}
	k.clock.advance(time.Minute)
	recoverLink(t, k, "sara")
	r, _ := k.Follow(k.ctx, k.lastMessage(t, saraMail).Token)
	if _, err := k.Finish(k.ctx, r.Token, NewPassword(newPassword)); err != nil {
		t.Fatal(err)
	}
	if ds, _ := k.Devices(k.ctx, "u1"); len(ds) != 0 {
		t.Errorf("devices after a recovery: %+v", ds)
	}
}

// Any new password forgets devices, a passwordless user's first one too.
func TestFirstPasswordForgetsDevices(t *testing.T) {
	k := newKit(t, WithFirst(MethodPassword, MethodEmailCode))
	k.addUser(t, "sara", User{ID: "u1", Name: "sara"}, "", saraMail, saraPhone)
	f, _ := k.SignIn(k.ctx, "sara", Cookie())
	k.Challenge(k.ctx, f.Token, MethodEmailCode)
	k.Prove(k.ctx, f.Token, EmailCode(k.lastCode(t, saraMail)))
	k.Challenge(k.ctx, f.Token, MethodSMSCode)
	k.Prove(k.ctx, f.Token, SMSCode(k.lastCode(t, saraPhone)))
	res, err := k.Finish(k.ctx, f.Token, RememberDevice("laptop"))
	if err != nil || res.device == "" {
		t.Fatalf("Finish: %+v %v", res, err)
	}
	if err := k.SetPassword(k.ctx, "u1", newPassword); err != nil {
		t.Fatal(err)
	}
	if ds, _ := k.Devices(k.ctx, "u1"); len(ds) != 0 {
		t.Errorf("devices after a first password: %+v", ds)
	}
}

// Review 0010, finding 1: a flow that presented a token replaced since, by
// another Finish, isn't verified by it, and can't replace it again.
func TestReplacedTokenInOlderFlow(t *testing.T) {
	k := newDeviceKit(t)
	res := twoFactorSignIn(t, k, nil, RememberDevice("laptop"))
	older := passwordOnly(t, k, "sara", Device(res.device))
	newer := passwordOnly(t, k, "sara", Device(res.device))
	next, err := k.Finish(k.ctx, newer.Token)
	if err != nil || next.device == "" {
		t.Fatal(err)
	}
	f, _ := k.Flow(k.ctx, older.Token)
	if f.Verified {
		t.Error("a replaced token still verifies its flow")
	}
	if r, err := k.Finish(k.ctx, older.Token); err == nil {
		t.Errorf("the older flow finished: %+v", r)
	}
	if f := passwordOnly(t, k, "sara", Device(next.device)); !f.Verified {
		t.Error("the current token was replaced again")
	}
}

// Review 0010, finding 2: a step-up that proved only a password registers
// no device, whatever the session proved before.
func TestStepUpNeedsItsOwnSecondProof(t *testing.T) {
	k := newDeviceKit(t)
	res := twoFactorSignIn(t, k, nil)
	ctx := withSession(k.ctx, res.Session)
	up, _ := k.StepUp(ctx, res.Session)
	if _, err := k.Prove(ctx, up.Token, Password(goodPassword)); err != nil {
		t.Fatal(err)
	}
	r, err := k.Finish(ctx, up.Token, RememberDevice("kiosk"))
	if err != nil || r.device != "" || r.Session.Device != "" {
		t.Errorf("a password-only step-up registered a device: %+v %v", r, err)
	}
}

// A device the policy doesn't trust buys no throttle exemption.
func TestUntrustedDeviceThrottled(t *testing.T) {
	k := newDeviceKit(t, WithPolicy(func(context.Context, User) Policy { return Policy{} }))
	res := twoFactorSignIn(t, k, nil, RememberDevice("laptop"))
	for i := range 5 {
		ctx := WithClient(k.ctx, Client{Addr: netip.AddrFrom4([4]byte{198, 51, 100, byte(i + 1)})})
		f, _ := k.SignIn(ctx, "sara", Cookie())
		k.Prove(ctx, f.Token, Password(wrongPassword))
	}
	home := k.from("192.0.2.1")
	f, _ := k.SignIn(home, "sara", Cookie(), Device(res.device))
	if _, err := k.Prove(home, f.Token, Password(goodPassword)); !errors.Is(err, ErrTooManyAttempts) {
		t.Errorf("an untrusted device skipped the user's wait: %v", err)
	}
}

// A device forgotten after the view, with unverified sessions allowed,
// leaves an unverified session rather than failing.
func TestDeviceGoneUnverifiedAllowed(t *testing.T) {
	k := newDeviceKit(t, WithPolicy(func(context.Context, User) Policy { return Policy{AllowUnverified: true, TrustDevices: true} }))
	res := twoFactorSignIn(t, k, nil, RememberDevice("laptop"))
	f := passwordOnly(t, k, "sara", Device(res.device))
	if !f.Verified {
		t.Fatal("not verified by the device")
	}
	k.ForgetDevice(k.ctx, "u1", res.Session.Device)
	r, err := k.Finish(k.ctx, f.Token)
	if err != nil || r.Session.Verified || r.device != "" {
		t.Errorf("Finish: %+v %v", r, err)
	}
}

// A session whose device was forgotten can remember a new one at a step-up
// that proves a second method.
func TestStepUpReplacesStaleDevice(t *testing.T) {
	k := newDeviceKit(t)
	res := twoFactorSignIn(t, k, nil, RememberDevice("old"))
	k.ForgetDevice(k.ctx, "u1", res.Session.Device)
	ctx := withSession(k.ctx, res.Session)
	up, _ := k.StepUp(ctx, res.Session)
	k.clock.advance(time.Minute)
	k.Challenge(ctx, up.Token, MethodEmailCode)
	k.Prove(ctx, up.Token, EmailCode(k.lastCode(t, saraMail)))
	r, err := k.Finish(ctx, up.Token, RememberDevice("new"))
	if err != nil || r.device == "" {
		t.Errorf("Finish: %+v %v", r, err)
	}
}

// A device that expires while its flow is open stops verifying it.
func TestDeviceExpiresMidFlow(t *testing.T) {
	k := newDeviceKit(t)
	res := twoFactorSignIn(t, k, nil, RememberDevice("laptop"))
	k.clock.advance(2160*time.Hour - time.Minute)
	f, err := k.SignIn(k.ctx, "sara", Cookie(), Device(res.device))
	if err != nil {
		t.Fatal(err)
	}
	k.clock.advance(2 * time.Minute)
	f, _ = k.Prove(k.ctx, f.Token, Password(goodPassword))
	if f.Verified {
		t.Error("an expired device verified")
	}
}
