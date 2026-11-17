package passkey_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/epistemer/auth"
	"github.com/epistemer/auth/authtest"

	"github.com/epistemer/auth/passkey"
	"github.com/epistemer/auth/passkey/internal/softauth"
	"github.com/epistemer/auth/passkey/passkeytest"
)

// The module through the engine (interface §6.6, §7): authtest's kit, with
// the passkey method.

const (
	origin = "https://toyshop.example"
	pw     = "orange tiger juggles 47 lamps"
	mail   = "sara@toyshop.example"
)

type config struct{}

func (config) AuthIssuer() string           { return "Toy Shop" }
func (config) AuthPasskeyDomain() string    { return "toyshop.example" }
func (config) AuthPasskeyOrigins() []string { return nil }

func newKit(t *testing.T, opts ...auth.Option) *authtest.Kit {
	t.Helper()
	pk, err := passkey.New(config{})
	if err != nil {
		t.Fatal(err)
	}
	k := authtest.New(t, append([]auth.Option{auth.WithMethods(pk), auth.WithFirst(auth.MethodPassword, auth.MethodPasskey)}, opts...)...)
	k.AddUser("sara", auth.User{ID: "u1", Name: "sara"}, mail)
	if err := k.Auth.SetPassword(context.Background(), "u1", pw); err != nil {
		t.Fatal(err)
	}
	return k
}

func options(t *testing.T, ch auth.Challenge) json.RawMessage {
	t.Helper()
	o, ok := ch.Options.(json.RawMessage)
	if !ok || ch.Method != auth.MethodPasskey {
		t.Fatalf("Challenge: %+v", ch)
	}
	return o
}

// sessionCtx is the context a request carrying res's cookies has inside
// Load, as the app's handlers see it.
func sessionCtx(t *testing.T, k *authtest.Kit, res auth.Result) context.Context {
	t.Helper()
	w := httptest.NewRecorder()
	res.Write(w)
	r := httptest.NewRequest(http.MethodGet, origin+"/", nil)
	for _, c := range w.Result().Cookies() {
		r.AddCookie(c)
	}
	var ctx context.Context
	k.Auth.Load(auth.Cookie())(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { ctx = r.Context() })).ServeHTTP(httptest.NewRecorder(), r)
	if _, ok := auth.From(ctx); !ok {
		t.Fatal("no session in the request")
	}
	return ctx
}

// passwordAndCode signs sara in with her password and an emailed code.
func passwordAndCode(t *testing.T, k *authtest.Kit) auth.Result {
	t.Helper()
	ctx := context.Background()
	f, err := k.Auth.SignIn(ctx, "sara", auth.Cookie())
	if err == nil {
		f, err = k.Auth.Prove(ctx, f.Token, auth.Password(pw))
	}
	if err != nil && !errors.Is(err, auth.ErrCannotVerify) {
		t.Fatal(err)
	}
	if _, err := k.Auth.Challenge(ctx, f.Token, auth.MethodEmailCode); err != nil {
		t.Fatal(err)
	}
	m, _ := k.LastMessage(mail)
	if f, err = k.Auth.Prove(ctx, f.Token, auth.EmailCode(m.Code)); err != nil || !f.Ready {
		t.Fatalf("code: %+v %v", f, err)
	}
	res, err := k.Auth.Finish(ctx, f.Token)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// passkeySignIn signs in with a passkey alone, through SignInWithout.
func passkeySignIn(t *testing.T, k *authtest.Kit, get func(json.RawMessage) []byte) (auth.Result, error) {
	t.Helper()
	ctx := context.Background()
	f, err := k.Auth.SignInWithout(ctx, auth.Cookie())
	if err != nil {
		t.Fatal(err)
	}
	ch, err := k.Auth.Challenge(ctx, f.Token, auth.MethodPasskey)
	if err != nil {
		t.Fatal(err)
	}
	if f, err = k.Auth.Prove(ctx, f.Token, passkey.Response(get(options(t, ch)))); err != nil {
		return auth.Result{}, err
	}
	return k.Auth.Finish(ctx, f.Token)
}

// enroll adds a passkey from a fresh session, and returns Finish's result.
func enroll(t *testing.T, k *authtest.Kit, fresh auth.Result, create func(json.RawMessage) []byte, opts ...auth.FinishOption) (auth.Result, error) {
	t.Helper()
	ctx := sessionCtx(t, k, fresh)
	f, err := k.Auth.Enroll(ctx, fresh.Session, auth.MethodPasskey)
	if err != nil {
		return auth.Result{}, err
	}
	ch, err := k.Auth.Challenge(ctx, f.Token, auth.MethodPasskey)
	if err != nil {
		t.Fatal(err)
	}
	if f, err = k.Auth.Prove(ctx, f.Token, passkey.Response(create(options(t, ch)))); err != nil {
		return auth.Result{}, err
	}
	return k.Auth.Finish(ctx, f.Token, opts...)
}

// §6.6, §7: enrolled through passkeytest, a passkey signs in alone and is
// verified; the first one brings recovery codes and is a factor; it then
// stands as the second proof after the password; a code to the address no
// longer does.
func TestPasskey(t *testing.T) {
	k := newKit(t)
	pk := passkeytest.New(t, origin)
	res, err := enroll(t, k, passwordAndCode(t, k), pk.Create, auth.FactorLabel("Sara's phone"))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.RecoveryCodes) == 0 {
		t.Error("no recovery codes")
	}
	fs, _ := k.Auth.Factors(context.Background(), "u1")
	if len(fs) != 1 || fs[0].Method != auth.MethodPasskey || fs[0].Label != "Sara's phone" {
		t.Errorf("factors: %+v", fs)
	}
	res, err = passkeySignIn(t, k, pk.Get)
	if err != nil || res.Session.User != "u1" || !res.Session.Verified {
		t.Fatalf("passkey alone: %+v %v", res.Session, err)
	}

	ctx := context.Background()
	f, _ := k.Auth.SignIn(ctx, "sara", auth.Cookie())
	f, err = k.Auth.Prove(ctx, f.Token, auth.Password(pw))
	if err != nil && !errors.Is(err, auth.ErrCannotVerify) {
		t.Fatal(err)
	}
	if slices.Contains(f.Offers, auth.MethodEmailCode) || !slices.Contains(f.Offers, auth.MethodPasskey) {
		t.Fatalf("offers after the password: %v", f.Offers)
	}
	ch, _ := k.Auth.Challenge(ctx, f.Token, auth.MethodPasskey)
	if !bytes.Contains(options(t, ch), []byte(`"allowCredentials":[{`)) {
		t.Errorf("the second proof's options name no passkey: %s", options(t, ch))
	}
	if f, err = k.Auth.Prove(ctx, f.Token, passkey.Response(pk.Get(options(t, ch)))); err != nil || !f.Verified {
		t.Errorf("password and passkey: %+v %v", f, err)
	}
}

// §6.6: a second passkey, enrolled from a session the first one made, and a
// step-up by passkey.
func TestStepUpAndSecondPasskey(t *testing.T) {
	k := newKit(t, auth.WithPolicy(func(context.Context, auth.User) auth.Policy { return auth.Policy{AllowUnverified: true} }))
	one, two := passkeytest.New(t, origin), passkeytest.New(t, origin)
	if _, err := enroll(t, k, passwordAndCode(t, k), one.Create); err != nil {
		t.Fatal(err)
	}
	k.Clock.Advance(time.Minute)
	fresh, err := passkeySignIn(t, k, one.Get)
	if err != nil {
		t.Fatal(err)
	}
	if res, err := enroll(t, k, fresh, two.Create); err != nil || res.RecoveryCodes != nil {
		t.Fatalf("second: %v %v", res.RecoveryCodes, err)
	}
	if res, err := passkeySignIn(t, k, two.Get); err != nil || !res.Session.Verified {
		t.Errorf("the second passkey: %v", err)
	}

	// An unverified session, stepped up by passkey.
	ctx := context.Background()
	f, _ := k.Auth.SignIn(ctx, "sara", auth.Cookie())
	f, _ = k.Auth.Prove(ctx, f.Token, auth.Password(pw))
	res, err := k.Auth.Finish(ctx, f.Token)
	if err != nil || res.Session.Verified {
		t.Fatalf("unverified: %+v %v", res.Session, err)
	}
	sctx := sessionCtx(t, k, res)
	f, err = k.Auth.StepUp(sctx, res.Session)
	if err != nil {
		t.Fatal(err)
	}
	ch, _ := k.Auth.Challenge(sctx, f.Token, auth.MethodPasskey)
	if f, err = k.Auth.Prove(sctx, f.Token, passkey.Response(one.Get(options(t, ch)))); err != nil || !f.Ready {
		t.Fatalf("step-up proof: %+v %v", f, err)
	}
	up, err := k.Auth.Finish(sctx, f.Token)
	if err != nil || !up.Session.Verified {
		t.Errorf("step-up: %+v %v", up.Session, err)
	}
}

// §7 enumeration: before the first proof the options differ only in their
// challenge for a known login with passkeys, an unknown login, and no
// login.
func TestOptionsAlike(t *testing.T) {
	k := newKit(t)
	pk := passkeytest.New(t, origin)
	if _, err := enroll(t, k, passwordAndCode(t, k), pk.Create); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	var seen []string
	for _, start := range []func() (auth.Flow, error){
		func() (auth.Flow, error) { return k.Auth.SignIn(ctx, "sara", auth.Cookie()) },
		func() (auth.Flow, error) { return k.Auth.SignIn(ctx, "nobody", auth.Cookie()) },
		func() (auth.Flow, error) { return k.Auth.SignInWithout(ctx, auth.Cookie()) },
	} {
		f, err := start()
		if err != nil {
			t.Fatal(err)
		}
		ch, err := k.Auth.Challenge(ctx, f.Token, auth.MethodPasskey)
		if err != nil {
			t.Fatal(err)
		}
		var o map[string]any
		json.Unmarshal(options(t, ch), &o)
		delete(o, "challenge")
		j, _ := json.Marshal(o)
		seen = append(seen, string(j))
	}
	if seen[0] != seen[1] || seen[1] != seen[2] {
		t.Errorf("options differ: %v", seen)
	}
}

// §5.13.6, §7: a clone of an authenticator presenting the same counter as
// the original, racing it, gets one of the two accepted; the stored
// counter then refuses the other.
func TestClonedCounter(t *testing.T) {
	k := newKit(t)
	a := softauth.New(origin)
	if _, err := enroll(t, k, passwordAndCode(t, k), func(o json.RawMessage) []byte {
		b, err := a.Create(o)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}); err != nil {
		t.Fatal(err)
	}
	clone := *a
	ctx := context.Background()
	var flows []auth.Flow
	var proofs []auth.Proof
	for _, x := range []*softauth.Authenticator{a, &clone} {
		f, _ := k.Auth.SignInWithout(ctx, auth.Cookie())
		ch, _ := k.Auth.Challenge(ctx, f.Token, auth.MethodPasskey)
		b, err := x.Get(options(t, ch))
		if err != nil {
			t.Fatal(err)
		}
		flows, proofs = append(flows, f), append(proofs, passkey.Response(b))
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok := 0
	for i := range flows {
		wg.Go(func() {
			if _, err := k.Auth.Prove(ctx, flows[i].Token, proofs[i]); err == nil {
				mu.Lock()
				ok++
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	if ok != 1 {
		t.Errorf("%d of the two accepted", ok)
	}
}

// §5.13.8 through the engine: options expire five minutes after Challenge,
// by the engine's clock.
func TestExpiresByTheEnginesClock(t *testing.T) {
	k := newKit(t)
	pk := passkeytest.New(t, origin)
	if _, err := enroll(t, k, passwordAndCode(t, k), pk.Create); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	f, _ := k.Auth.SignInWithout(ctx, auth.Cookie())
	ch, _ := k.Auth.Challenge(ctx, f.Token, auth.MethodPasskey)
	resp := pk.Get(options(t, ch))
	k.Clock.Advance(5 * time.Minute)
	if _, err := k.Auth.Prove(ctx, f.Token, passkey.Response(resp)); !errors.Is(err, auth.ErrBadCredentials) {
		t.Errorf("after five minutes: %v", err)
	}
	if !slices.ContainsFunc(k.Events(), func(e auth.Event) bool { return e.Kind == "proof.refused" && e.Reason == "expired" }) {
		t.Error("no expired event")
	}
}

// §5.13.13, §5.11: no event, and no error, holds the response, the
// challenge, the credential ID or the public key.
func TestNoSecretsOut(t *testing.T) {
	k := newKit(t)
	a := softauth.New(origin)
	var created []byte
	if _, err := enroll(t, k, passwordAndCode(t, k), func(o json.RawMessage) []byte {
		b, _ := a.Create(o)
		created = b
		return b
	}); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	var secrets []string
	var errs []error
	for _, knob := range []func(){func() {}, func() { a.Origin = "https://evil.example" }, func() { a.NoUV = true }} {
		knob()
		f, _ := k.Auth.SignInWithout(ctx, auth.Cookie())
		ch, _ := k.Auth.Challenge(ctx, f.Token, auth.MethodPasskey)
		var o struct{ Challenge string }
		json.Unmarshal(options(t, ch), &o)
		b, _ := a.Get(options(t, ch))
		_, err := k.Auth.Prove(ctx, f.Token, passkey.Response(b))
		errs = append(errs, err)
		secrets = append(secrets, o.Challenge, string(b))
	}
	var resp map[string]any
	json.Unmarshal(created, &resp)
	secrets = append(secrets, resp["id"].(string), resp["response"].(map[string]any)["attestationObject"].(string)[:40])
	out := fmt.Sprintf("%+v %v", k.Events(), errs)
	for _, s := range secrets {
		if s != "" && strings.Contains(out, s) {
			t.Errorf("%q is out", s)
		}
	}
}

// §5.13.2 through the engine: a user with 20 passkeys can't start a 21st.
func TestTwentyPasskeys(t *testing.T) {
	k := newKit(t)
	first := passkeytest.New(t, origin)
	if _, err := enroll(t, k, passwordAndCode(t, k), first.Create); err != nil {
		t.Fatal(err)
	}
	k.Clock.Advance(time.Minute)
	fresh, err := passkeySignIn(t, k, first.Get)
	if err != nil {
		t.Fatal(err)
	}
	for i := range 19 {
		if _, err := enroll(t, k, fresh, passkeytest.New(t, origin).Create); err != nil {
			t.Fatalf("passkey %d: %v", i+2, err)
		}
	}
	if _, err := enroll(t, k, fresh, passkeytest.New(t, origin).Create); !errors.Is(err, auth.ErrMethodUnavailable) {
		t.Errorf("the 21st: %v", err)
	}
}

// §5.13.11 through the engine: failed passkey proofs make their address
// wait, and hold up neither the user's passkey nor their password from
// another address.
func TestPasskeyThrottledByAddress(t *testing.T) {
	k := newKit(t)
	pk := passkeytest.New(t, origin)
	if _, err := enroll(t, k, passwordAndCode(t, k), pk.Create); err != nil {
		t.Fatal(err)
	}
	stranger := passkeytest.New(t, origin)
	bad := auth.WithClient(context.Background(), auth.Client{Addr: netip.MustParseAddr("198.51.100.1")})
	var err error
	for i := 0; i < 40 && !errors.Is(err, auth.ErrTooManyAttempts); i++ {
		f, _ := k.Auth.SignIn(bad, "sara", auth.Cookie())
		ch, _ := k.Auth.Challenge(bad, f.Token, auth.MethodPasskey)
		resp := []byte("{}")
		if i == 0 {
			resp = stranger.Create(json.RawMessage(`{"rp":{"id":"toyshop.example"},"user":{"id":"dTk"},"challenge":"AAAA"}`))
		}
		_, err = k.Auth.Prove(bad, f.Token, passkey.Response(resp))
		_ = ch
	}
	if !errors.Is(err, auth.ErrTooManyAttempts) {
		t.Fatalf("the address never waited: %v", err)
	}
	good := auth.WithClient(context.Background(), auth.Client{Addr: netip.MustParseAddr("192.0.2.2")})
	f, _ := k.Auth.SignInWithout(good, auth.Cookie())
	ch, _ := k.Auth.Challenge(good, f.Token, auth.MethodPasskey)
	if _, err := k.Auth.Prove(good, f.Token, passkey.Response(pk.Get(options(t, ch)))); err != nil {
		t.Errorf("her passkey from another address: %v", err)
	}
	f, _ = k.Auth.SignIn(good, "sara", auth.Cookie())
	if _, err := k.Auth.Prove(good, f.Token, auth.Password(pw)); err != nil && !errors.Is(err, auth.ErrCannotVerify) {
		t.Errorf("her password from another address: %v", err)
	}
}
