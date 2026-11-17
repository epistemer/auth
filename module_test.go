package auth

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/epistemer/errors"
	bolt "go.etcd.io/bbolt"

	"github.com/epistemer/auth/internal/secrets"
	"github.com/epistemer/auth/internal/store"
	"github.com/epistemer/auth/internal/storepb"
)

// Methods from modules (interface §4.9, §5.5, A21), tested with a fake
// method: no real passkey is needed for the engine's rules.

// fakeMethod is a module method. Start makes a random challenge, which is
// its state; a fakeProof answers it with a credential key. A real passkey's
// signature is replaced by holding the challenge.
type fakeMethod struct {
	name     string
	verified bool // its proofs count as two factors
	addrOnly bool // AddressOnly answers true

	mu       sync.Mutex
	starts   []MethodInput
	verifies int
	stateN   int    // when set, Start keeps this many bytes of state
	onStart  func() // when set, runs inside Start
	// verify, when set, replaces Verify's own answer after the challenge
	// check.
	verify func(in MethodInput, p fakeProof) (MethodResult, error)
}

type fakeOptions struct {
	Challenge []byte
	Creds     int
}

type fakeProof struct {
	method    string
	challenge []byte
	key       string
	data      string // the credential's new data; empty keeps it
}

func (p fakeProof) Method() string { return p.method }

func (m *fakeMethod) Name() string      { return m.name }
func (m *fakeMethod) AddressOnly() bool { return m.addrOnly }

func (m *fakeMethod) Start(_ context.Context, in MethodInput) (any, []byte, error) {
	m.mu.Lock()
	m.starts = append(m.starts, in)
	n, hook := m.stateN, m.onStart
	m.mu.Unlock()
	if hook != nil {
		hook()
	}
	if n == 0 {
		n = 16
	}
	ch := make([]byte, n)
	rand.Read(ch)
	return fakeOptions{Challenge: ch, Creds: len(in.Credentials)}, ch, nil
}

func (m *fakeMethod) Verify(_ context.Context, in MethodInput, state []byte, p Proof) (MethodResult, error) {
	m.mu.Lock()
	m.verifies++
	m.mu.Unlock()
	fp, ok := p.(fakeProof)
	if !ok {
		return MethodResult{}, Refuse("malformed")
	}
	if !bytes.Equal(fp.challenge, state) {
		return MethodResult{}, Refuse("challenge")
	}
	m.mu.Lock()
	hook := m.verify
	m.mu.Unlock()
	if hook != nil {
		return hook(in, fp)
	}
	if in.Purpose == PurposeEnroll {
		return MethodResult{Credential: &Credential{Key: []byte(fp.key), Data: []byte("v1")}}, nil
	}
	owner, c, err := in.Find([]byte(fp.key))
	if err != nil {
		return MethodResult{}, err
	}
	if c == nil {
		return MethodResult{}, Refuse("unknown_credential")
	}
	if fp.data != "" {
		c.Data = []byte(fp.data)
	}
	return MethodResult{User: owner, Credential: c, Verified: m.verified}, nil
}

func (m *fakeMethod) lastStart(t *testing.T) MethodInput {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.starts) == 0 {
		t.Fatal("Start wasn't called")
	}
	return m.starts[len(m.starts)-1]
}

func newPasskeyKit(t *testing.T, opts ...Option) (*kit, *fakeMethod) {
	t.Helper()
	m := &fakeMethod{name: MethodPasskey, verified: true, addrOnly: true}
	k := newKit(t, append([]Option{WithMethods(m), WithFirst(MethodPassword, MethodPasskey)}, opts...)...)
	k.addUser(t, "sara", User{ID: "u1", Name: "sara"}, goodPassword, saraMail)
	k.addUser(t, "omar", User{ID: "u2", Name: "omar"}, goodPassword, "omar@toyshop.example")
	return k, m
}

// addKey stores a credential of method for a user, with its index, as an
// Enroll would.
func (k *kit) addKey(t *testing.T, user UserID, method, key string) {
	t.Helper()
	err := k.db.Update(func(tx *bolt.Tx) error {
		c := &storepb.Credential{Method: method, Key: []byte(key), Data: []byte("v1"), Label: "Passkey", Added: k.clock.now().UnixNano()}
		if err := store.Put(tx, store.Credentials, credentialKey(user, method, []byte(key)), c); err != nil {
			return err
		}
		return store.B(tx, store.CredentialKeys).Put(credentialIndex(method, []byte(key)), []byte(user))
	})
	if err != nil {
		t.Fatal(err)
	}
}

// keyData reads a stored credential's data.
func (k *kit) keyData(t *testing.T, user UserID, method, key string) []byte {
	t.Helper()
	var c storepb.Credential
	err := k.db.View(func(tx *bolt.Tx) error {
		return store.Get(tx, store.Credentials, credentialKey(user, method, []byte(key)), &c)
	})
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	return c.Data
}

// challenge asks for a module challenge and returns what a proof answers.
func (k *kit) challenge(t *testing.T, ctx context.Context, token, method string) []byte {
	t.Helper()
	ch, err := k.Challenge(ctx, token, method)
	if err != nil {
		t.Fatalf("Challenge: %v", err)
	}
	o, ok := ch.Options.(fakeOptions)
	if !ok || ch.Method != method || ch.SentTo != "" || !ch.Resend.IsZero() {
		t.Fatalf("Challenge: %+v", ch)
	}
	return o.Challenge
}

// proveKey challenges and proves a key in one go.
func (k *kit) proveKey(t *testing.T, ctx context.Context, token, method, key string) (Flow, error) {
	t.Helper()
	ch := k.challenge(t, ctx, token, method)
	return k.Prove(ctx, token, fakeProof{method: method, challenge: ch, key: key})
}

func (k *kit) reasons(kind string) []string {
	k.events.mu.Lock()
	defer k.events.mu.Unlock()
	var out []string
	for _, e := range k.events.all {
		if e.Kind == kind {
			out = append(out, e.Reason)
		}
	}
	return out
}

func (k *kit) lastReason(t *testing.T, kind string) string {
	t.Helper()
	r := k.reasons(kind)
	if len(r) == 0 {
		t.Fatalf("no %s event", kind)
	}
	return r[len(r)-1]
}

// §4.2, A21: New takes modules, and refuses nil ones, two of one name, one
// named like a built-in method, and a name outside [a-z0-9_]{1,32}.
func TestNewMethods(t *testing.T) {
	db, err := bolt.Open(t.TempDir()+"/auth.db", 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var nilFake *fakeMethod
	for name, opts := range map[string][]Option{
		"nil":           {WithMethods(nil)},
		"nil pointer":   {WithMethods(nilFake)},
		"two of a name": {WithMethods(&fakeMethod{name: "magic"}, &fakeMethod{name: "magic"})},
		"password":      {WithMethods(&fakeMethod{name: MethodPassword})},
		"totp":          {WithMethods(&fakeMethod{name: MethodTOTP})},
		"email link":    {WithMethods(&fakeMethod{name: MethodEmailLink})},
		"invitation":    {WithMethods(&fakeMethod{name: methodInvitation})},
		"recovery code": {WithMethods(&fakeMethod{name: MethodRecoveryCode})},
		"empty name":    {WithMethods(&fakeMethod{name: ""})},
		"capitals":      {WithMethods(&fakeMethod{name: "Passkey"})},
		"dash":          {WithMethods(&fakeMethod{name: "pass-key"})},
		"too long":      {WithMethods(&fakeMethod{name: strings.Repeat("a", 33)})},
		"first unknown": {WithMethods(&fakeMethod{name: "magic"}), WithFirst("passkey")},
	} {
		if _, err := New(db, defaults(), &directory{}, &outbox{}, opts...); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	for name, opts := range map[string][]Option{
		"passkey":        {WithMethods(&fakeMethod{name: MethodPasskey})},
		"32 characters":  {WithMethods(&fakeMethod{name: strings.Repeat("a", 32)})},
		"two, as first":  {WithMethods(&fakeMethod{name: "a1"}, &fakeMethod{name: "b_2"}), WithFirst("a1", "b_2", MethodPassword)},
		"over two calls": {WithMethods(&fakeMethod{name: "a1"}), WithMethods(&fakeMethod{name: "b2"})},
	} {
		if _, err := New(db, defaults(), &directory{}, &outbox{}, opts...); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// §4.3, §6.6, §7: a SignInWithout, then a passkey, finishes a verified
// session for its owner under a policy that trusts nothing; a password on
// it is ErrMethodUnavailable; with no module in WithFirst, so is starting.
func TestSignInWithout(t *testing.T) {
	k, m := newPasskeyKit(t, WithPolicy(func(context.Context, User) Policy { return Policy{} }))
	k.addKey(t, "u1", MethodPasskey, "sara-1")
	f, err := k.SignInWithout(k.ctx, Cookie())
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(f.Offers, []string{MethodPasskey}) || f.Ready {
		t.Fatalf("flow: %+v", f)
	}
	if _, err := k.Prove(k.ctx, f.Token, Password(goodPassword)); !errors.Is(err, ErrMethodUnavailable) {
		t.Errorf("a password: %v", err)
	}
	f, err = k.proveKey(t, k.ctx, f.Token, MethodPasskey, "sara-1")
	if err != nil || !f.Ready || !f.Verified {
		t.Fatalf("Prove: %+v %v", f, err)
	}
	if in := m.lastStart(t); in.User != nil || in.Credentials != nil || in.Purpose != PurposeSignIn || !in.Now.Equal(k.clock.now()) {
		t.Errorf("Start was told %+v", in)
	}
	res, err := k.Finish(k.ctx, f.Token)
	if err != nil || res.Session == nil || res.Session.User != "u1" || !res.Session.Verified {
		t.Fatalf("Finish: %+v %v", res.Session, err)
	}
	if len(res.Session.Factors) != 1 || res.Session.Factors[0].Method != MethodPasskey {
		t.Errorf("factors: %+v", res.Session.Factors)
	}

	plain := newKit(t, WithMethods(&fakeMethod{name: MethodPasskey}))
	if _, err := plain.SignInWithout(plain.ctx, Cookie()); !errors.Is(err, ErrMethodUnavailable) {
		t.Errorf("no module first: %v", err)
	}
	if _, err := plain.SignInWithout(plain.ctx, Carrier{}); err == nil {
		t.Error("no carrier: accepted")
	}
}

// §4.9, §5.1.3, §7 enumeration: before the first proof a method is told no
// user and no credentials, whatever the login, so its options differ only
// in their challenge; after the password it gets the user's credentials. A
// passkey proved on another login's flow, or an unknown one's, is
// ErrBadCredentials and changes nothing of its owner's.
func TestModuleEnumeration(t *testing.T) {
	k, m := newPasskeyKit(t)
	k.addKey(t, "u1", MethodPasskey, "sara-1")
	k.addKey(t, "u2", MethodPasskey, "omar-1")
	starts := map[string]func() (Flow, error){
		"known":   func() (Flow, error) { return k.SignIn(k.ctx, "sara", Cookie()) },
		"unknown": func() (Flow, error) { return k.SignIn(k.ctx, "nobody", Cookie()) },
		"empty":   func() (Flow, error) { return k.SignIn(k.ctx, "", Cookie()) },
		"without": func() (Flow, error) { return k.SignInWithout(k.ctx, Cookie()) },
	}
	for name, start := range starts {
		f, err := start()
		if err != nil {
			t.Fatal(err)
		}
		ch, err := k.Challenge(k.ctx, f.Token, MethodPasskey)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		in := m.lastStart(t)
		if in.User != nil || in.Credentials != nil || ch.Options.(fakeOptions).Creds != 0 {
			t.Errorf("%s: Start was told %+v", name, in)
		}
	}
	// Proved on omar's flow, and on an unknown login's: refused alike.
	for _, login := range []string{"omar", "nobody", ""} {
		f, _ := k.SignIn(k.ctx, login, Cookie())
		if _, err := k.proveKey(t, k.ctx, f.Token, MethodPasskey, "sara-1"); !errors.Is(err, ErrBadCredentials) || errors.Is(err, ErrUserDisabled) {
			t.Errorf("%q: %v", login, err)
		}
		if k.lastReason(t, "proof.refused") != "user_mismatch" {
			t.Errorf("%q: reason %q", login, k.lastReason(t, "proof.refused"))
		}
	}
	// A proof the module would have updated the credential with.
	f, _ := k.SignIn(k.ctx, "omar", Cookie())
	ch := k.challenge(t, k.ctx, f.Token, MethodPasskey)
	if _, err := k.Prove(k.ctx, f.Token, fakeProof{method: MethodPasskey, challenge: ch, key: "sara-1", data: "v2"}); !errors.Is(err, ErrBadCredentials) {
		t.Fatal(err)
	}
	if got := k.keyData(t, "u1", MethodPasskey, "sara-1"); string(got) != "v1" {
		t.Errorf("sara's credential became %q", got)
	}
	// After the password, the user's own credentials.
	f = passwordOnly(t, k, "sara")
	if !slices.Contains(f.Offers, MethodPasskey) {
		t.Fatalf("offers after the password: %v", f.Offers)
	}
	k.challenge(t, k.ctx, f.Token, MethodPasskey)
	if in := m.lastStart(t); in.User == nil || in.User.ID != "u1" || len(in.Credentials) != 1 || string(in.Credentials[0].Key) != "sara-1" {
		t.Errorf("after the password Start was told %+v", in)
	}
}

// §5.5.6 (d): a response is accepted once. Proved again, by two requests at
// once, after a refused proof, after a second Challenge, and with no
// Challenge at all, it is refused; without a Challenge nothing is counted.
func TestModuleProofOnce(t *testing.T) {
	k, m := newPasskeyKit(t)
	k.addKey(t, "u1", MethodPasskey, "sara-1")
	ctx := WithClient(k.ctx, Client{Addr: netip.MustParseAddr("192.0.2.7")})

	// No Challenge: refused, and no counter is touched.
	f, _ := k.SignInWithout(ctx, Cookie())
	if _, err := k.Prove(ctx, f.Token, fakeProof{method: MethodPasskey, key: "sara-1"}); !errors.Is(err, ErrBadCredentials) || k.lastReason(t, "proof.refused") != "no_challenge" {
		t.Fatalf("no challenge: %v", err)
	}
	if n := k.counters(t); n != 0 {
		t.Errorf("no challenge counted %d", n)
	}
	if m.verifies != 0 {
		t.Errorf("no challenge called Verify %d times", m.verifies)
	}

	// Twice in a row.
	ch := k.challenge(t, ctx, f.Token, MethodPasskey)
	p := fakeProof{method: MethodPasskey, challenge: ch, key: "sara-1"}
	if _, err := k.Prove(ctx, f.Token, p); err != nil {
		t.Fatal(err)
	}
	if _, err := k.Prove(ctx, f.Token, p); err == nil {
		t.Error("again: accepted")
	}

	// Two at once: one is accepted.
	f, _ = k.SignInWithout(ctx, Cookie())
	ch = k.challenge(t, ctx, f.Token, MethodPasskey)
	p = fakeProof{method: MethodPasskey, challenge: ch, key: "sara-1"}
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok := 0
	for range 8 {
		wg.Go(func() {
			if _, err := k.Prove(ctx, f.Token, p); err == nil {
				mu.Lock()
				ok++
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	if ok != 1 {
		t.Errorf("%d of 8 accepted", ok)
	}

	// After a refused proof the state is gone.
	f, _ = k.SignInWithout(ctx, Cookie())
	ch = k.challenge(t, ctx, f.Token, MethodPasskey)
	if _, err := k.Prove(ctx, f.Token, fakeProof{method: MethodPasskey, challenge: ch, key: "nobody's"}); !errors.Is(err, ErrBadCredentials) {
		t.Fatal(err)
	}
	if _, err := k.Prove(ctx, f.Token, fakeProof{method: MethodPasskey, challenge: ch, key: "sara-1"}); !errors.Is(err, ErrBadCredentials) || k.lastReason(t, "proof.refused") != "no_challenge" {
		t.Errorf("after a refusal: %v", err)
	}

	// A second Challenge replaces the first.
	old := k.challenge(t, ctx, f.Token, MethodPasskey)
	k.challenge(t, ctx, f.Token, MethodPasskey)
	if _, err := k.Prove(ctx, f.Token, fakeProof{method: MethodPasskey, challenge: old, key: "sara-1"}); !errors.Is(err, ErrBadCredentials) {
		t.Errorf("an older challenge: %v", err)
	}
}

// counters counts the throttle bucket's counters.
func (k *kit) counters(t *testing.T) int {
	t.Helper()
	n := 0
	err := k.db.View(func(tx *bolt.Tx) error {
		return store.B(tx, store.Throttle).ForEach(func(key, _ []byte) error {
			if !bytes.HasPrefix(key, []byte("sent_")) {
				n++
			}
			return nil
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// §5.5.9: a flow takes at most ten Challenges and five refused proofs per
// module method; past either, the method is ErrMethodUnavailable in it and
// no longer offered.
func TestModuleCaps(t *testing.T) {
	k, _ := newPasskeyKit(t)
	k.addKey(t, "u1", MethodPasskey, "sara-1")
	f, _ := k.SignInWithout(k.ctx, Cookie())
	for range maxChallenges {
		k.challenge(t, k.ctx, f.Token, MethodPasskey)
	}
	if _, err := k.Challenge(k.ctx, f.Token, MethodPasskey); !errors.Is(err, ErrMethodUnavailable) {
		t.Errorf("an eleventh Challenge: %v", err)
	}
	// Offered until the last state is used (review 0021, finding 4).
	if f, _ = k.Flow(k.ctx, f.Token); !slices.Contains(f.Offers, MethodPasskey) {
		t.Errorf("the tenth state can't be proved: %v", f.Offers)
	}
	if _, err := k.Prove(k.ctx, f.Token, fakeProof{method: MethodPasskey, key: "wrong"}); !errors.Is(err, ErrBadCredentials) {
		t.Fatal(err)
	}
	if f, _ = k.Flow(k.ctx, f.Token); slices.Contains(f.Offers, MethodPasskey) {
		t.Errorf("still offered: %v", f.Offers)
	}

	// Concurrent Challenges stop at the cap too.
	f, _ = k.SignInWithout(k.ctx, Cookie())
	var wg sync.WaitGroup
	var mu sync.Mutex
	n := 0
	for range 3 * maxChallenges {
		wg.Go(func() {
			if _, err := k.Challenge(k.ctx, f.Token, MethodPasskey); err == nil {
				mu.Lock()
				n++
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	if n != maxChallenges {
		t.Errorf("%d concurrent Challenges went through", n)
	}

	f, _ = k.SignInWithout(k.ctx, Cookie())
	for i := range maxRefusals {
		if _, err := k.proveKey(t, k.ctx, f.Token, MethodPasskey, fmt.Sprint("wrong-", i)); !errors.Is(err, ErrBadCredentials) {
			t.Fatal(err)
		}
	}
	if _, err := k.Challenge(k.ctx, f.Token, MethodPasskey); !errors.Is(err, ErrMethodUnavailable) {
		t.Errorf("a Challenge after five refusals: %v", err)
	}
	if _, err := k.Prove(k.ctx, f.Token, fakeProof{method: MethodPasskey, key: "sara-1"}); !errors.Is(err, ErrMethodUnavailable) {
		t.Errorf("a proof after five refusals: %v", err)
	}
}

// §5.5.8: the credential an accepted proof used must be one that was
// handed to Verify, and the store must still hold it with the data handed
// out: removed or changed while Verify ran, it is refused; a credential the
// method made up outside an Enroll is refused and stores nothing; one
// handed out for another user is refused.
func TestModuleCredentialChecked(t *testing.T) {
	k, m := newPasskeyKit(t)
	k.addKey(t, "u1", MethodPasskey, "sara-1")
	k.addKey(t, "u2", MethodPasskey, "omar-1")
	try := func(name string, hook func(in MethodInput, p fakeProof) (MethodResult, error), want string) {
		t.Helper()
		m.mu.Lock()
		m.verify = hook
		m.mu.Unlock()
		defer func() { m.mu.Lock(); m.verify = nil; m.mu.Unlock() }()
		f, _ := k.SignInWithout(k.ctx, Cookie())
		if _, err := k.proveKey(t, k.ctx, f.Token, MethodPasskey, "sara-1"); !errors.Is(err, ErrBadCredentials) {
			t.Errorf("%s: %v", name, err)
			return
		}
		if r := k.lastReason(t, "proof.refused"); r != want {
			t.Errorf("%s: reason %q", name, r)
		}
	}
	found := func(in MethodInput, key string) (UserID, *Credential) {
		owner, c, err := in.Find([]byte(key))
		if err != nil || c == nil {
			t.Fatalf("Find(%s): %v", key, err)
		}
		return owner, c
	}
	try("removed", func(in MethodInput, p fakeProof) (MethodResult, error) {
		owner, c := found(in, p.key)
		k.db.Update(func(tx *bolt.Tx) error {
			return k.deleteCredential(tx, owner, MethodPasskey, credentialKey(owner, MethodPasskey, c.Key))
		})
		return MethodResult{User: owner, Credential: c, Verified: true}, nil
	}, "changed")
	k.addKey(t, "u1", MethodPasskey, "sara-1")
	try("changed", func(in MethodInput, p fakeProof) (MethodResult, error) {
		owner, c := found(in, p.key)
		k.db.Update(func(tx *bolt.Tx) error {
			key := credentialKey(owner, MethodPasskey, c.Key)
			var rec storepb.Credential
			store.Get(tx, store.Credentials, key, &rec)
			rec.Data = []byte("raced")
			return store.Put(tx, store.Credentials, key, &rec)
		})
		return MethodResult{User: owner, Credential: c, Verified: true}, nil
	}, "changed")
	k.addKey(t, "u1", MethodPasskey, "sara-1")
	try("made up", func(in MethodInput, p fakeProof) (MethodResult, error) {
		return MethodResult{User: "u1", Credential: &Credential{Key: []byte("new"), Data: []byte("x")}, Verified: true}, nil
	}, "changed")
	if k.keyData(t, "u1", MethodPasskey, "new") != nil {
		t.Error("a made-up credential was stored")
	}
	try("another's", func(in MethodInput, p fakeProof) (MethodResult, error) {
		_, c := found(in, "omar-1")
		return MethodResult{User: "u1", Credential: c, Verified: true}, nil
	}, "user_mismatch")
	try("nobody", func(in MethodInput, p fakeProof) (MethodResult, error) {
		return MethodResult{Verified: true}, nil
	}, "user_mismatch")
	try("gone user", func(in MethodInput, p fakeProof) (MethodResult, error) {
		return MethodResult{User: "u9", Verified: true}, nil
	}, "user_mismatch")

	// Removing another passkey of the user's doesn't refuse this one.
	k.addKey(t, "u1", MethodPasskey, "sara-2")
	m.mu.Lock()
	m.verify = func(in MethodInput, p fakeProof) (MethodResult, error) {
		owner, c := found(in, p.key)
		k.db.Update(func(tx *bolt.Tx) error {
			return k.deleteCredential(tx, "u1", MethodPasskey, credentialKey("u1", MethodPasskey, []byte("sara-2")))
		})
		return MethodResult{User: owner, Credential: c, Verified: true}, nil
	}
	m.mu.Unlock()
	f, _ := k.SignInWithout(k.ctx, Cookie())
	if _, err := k.proveKey(t, k.ctx, f.Token, MethodPasskey, "sara-1"); err != nil {
		t.Errorf("another passkey removed: %v", err)
	}
}

// §5.5.6 (f), §7: a disabled user's right passkey is ErrUserDisabled, and
// the credential isn't updated.
func TestModuleDisabled(t *testing.T) {
	k, _ := newPasskeyKit(t)
	k.addKey(t, "u1", MethodPasskey, "sara-1")
	k.dir.mu.Lock()
	k.dir.users["sara"] = User{ID: "u1", Name: "sara", Disabled: true}
	k.dir.mu.Unlock()
	f, _ := k.SignInWithout(k.ctx, Cookie())
	ch := k.challenge(t, k.ctx, f.Token, MethodPasskey)
	if _, err := k.Prove(k.ctx, f.Token, fakeProof{method: MethodPasskey, challenge: ch, key: "sara-1", data: "v2"}); !errors.Is(err, ErrUserDisabled) {
		t.Fatalf("disabled: %v", err)
	}
	if got := k.keyData(t, "u1", MethodPasskey, "sara-1"); string(got) != "v1" {
		t.Errorf("credential became %q", got)
	}
}

// An accepted proof stores the credential's new data and when it was used.
func TestModuleCredentialUpdated(t *testing.T) {
	k, _ := newPasskeyKit(t)
	k.addKey(t, "u1", MethodPasskey, "sara-1")
	f, _ := k.SignInWithout(k.ctx, Cookie())
	ch := k.challenge(t, k.ctx, f.Token, MethodPasskey)
	if _, err := k.Prove(k.ctx, f.Token, fakeProof{method: MethodPasskey, challenge: ch, key: "sara-1", data: "v2"}); err != nil {
		t.Fatal(err)
	}
	if got := k.keyData(t, "u1", MethodPasskey, "sara-1"); string(got) != "v2" {
		t.Errorf("credential is %q", got)
	}
	fs, _ := k.Factors(k.ctx, "u1")
	if len(fs) != 1 || !fs[0].Used.Equal(k.clock.now()) {
		t.Errorf("factors: %+v", fs)
	}
}

// §4.9, §5.5.6 (d): a Verify that fails on its own returns that error, takes
// back the attempt's count, and uses up the state.
func TestModuleOwnFailure(t *testing.T) {
	k, m := newPasskeyKit(t)
	ctx := WithClient(k.ctx, Client{Addr: netip.MustParseAddr("192.0.2.7")})
	own := errors.New("fake: broken")
	m.verify = func(MethodInput, fakeProof) (MethodResult, error) { return MethodResult{}, own }
	f, _ := k.SignInWithout(ctx, Cookie())
	ch := k.challenge(t, ctx, f.Token, MethodPasskey)
	if _, err := k.Prove(ctx, f.Token, fakeProof{method: MethodPasskey, challenge: ch}); err != own {
		t.Fatalf("own failure: %v", err)
	}
	if n := k.counters(t); n != 0 {
		t.Errorf("%d counters left", n)
	}
	if _, err := k.Prove(ctx, f.Token, fakeProof{method: MethodPasskey, challenge: ch}); !errors.Is(err, ErrBadCredentials) || k.lastReason(t, "proof.refused") != "no_challenge" {
		t.Errorf("the state again: %v", err)
	}
}

// §4.3, A21: Refuse wraps ErrBadCredentials with a fixed text; the engine
// records its reason, or "refused" for one outside [a-z][a-z0-9_]{0,31},
// and answers plain ErrBadCredentials.
func TestRefuse(t *testing.T) {
	for reason, want := range map[string]string{
		"counter": "counter", "a1_b": "a1_b", "": "refused", "Bad": "refused",
		"1st": "refused", "with space": "refused", strings.Repeat("a", 33): "refused", strings.Repeat("a", 32): strings.Repeat("a", 32),
	} {
		err := Refuse(reason)
		if !errors.Is(err, ErrBadCredentials) || strings.Contains(err.Error(), reason) && reason != "" {
			t.Errorf("Refuse(%q): %v", reason, err)
		}
		k, m := newPasskeyKit(t)
		m.verify = func(MethodInput, fakeProof) (MethodResult, error) { return MethodResult{}, err }
		f, _ := k.SignInWithout(k.ctx, Cookie())
		_, perr := k.proveKey(t, k.ctx, f.Token, MethodPasskey, "x")
		if perr != ErrBadCredentials {
			t.Errorf("Refuse(%q): Prove returned %v", reason, perr)
		}
		if got := k.lastReason(t, "proof.refused"); got != want {
			t.Errorf("Refuse(%q): recorded %q", reason, got)
		}
	}
}

// §4.9: a method's state is at most 4 KiB.
func TestModuleStateSize(t *testing.T) {
	k, m := newPasskeyKit(t)
	m.stateN = maxModuleState
	f, _ := k.SignInWithout(k.ctx, Cookie())
	k.challenge(t, k.ctx, f.Token, MethodPasskey)
	m.stateN = maxModuleState + 1
	if _, err := k.Challenge(k.ctx, f.Token, MethodPasskey); err == nil || errors.Is(err, ErrMethodUnavailable) {
		t.Errorf("over 4 KiB: %v", err)
	}
}

// freshSession signs sara in with two factors: her password and an emailed
// code, or with via, a passkey she holds.
func freshSession(t *testing.T, k *kit, via string) (context.Context, *Session) {
	t.Helper()
	k.clock.advance(time.Minute)
	if via == "" {
		res := twoFactorSignIn(t, k, nil)
		return withSession(k.ctx, res.Session), res.Session
	}
	f, err := k.SignInWithout(k.ctx, Cookie())
	if err != nil {
		t.Fatal(err)
	}
	if f, err = k.proveKey(t, k.ctx, f.Token, MethodPasskey, via); err != nil {
		t.Fatal(err)
	}
	res, err := k.Finish(k.ctx, f.Token)
	if err != nil {
		t.Fatal(err)
	}
	return withSession(k.ctx, res.Session), res.Session
}

// enrollKey enrolls a passkey for sara from a fresh two-factor session.
func enrollKey(t *testing.T, k *kit, key string, opts ...FinishOption) (Result, error) {
	t.Helper()
	return enrollKeyVia(t, k, "", key, opts...)
}

// enrollKeyVia is enrollKey, signing in with the passkey via.
func enrollKeyVia(t *testing.T, k *kit, via, key string, opts ...FinishOption) (Result, error) {
	t.Helper()
	ctx, sess := freshSession(t, k, via)
	res := Result{Session: sess}
	f, err := k.Enroll(ctx, res.Session, MethodPasskey)
	if err != nil {
		return Result{}, err
	}
	if f, err = k.proveKey(t, ctx, f.Token, MethodPasskey, key); err != nil {
		return Result{}, err
	}
	if !f.Ready {
		t.Fatalf("not ready: %+v", f)
	}
	return k.Finish(ctx, f.Token, opts...)
}

// §5.13.12, §4.3 FactorLabel, A17: the first passkey enrolled returns
// recovery codes, is a factor with its label, cut and cleaned, and then a
// code to an address is no second method; ResetFactors makes it one again.
func TestModuleEnroll(t *testing.T) {
	k, m := newPasskeyKit(t)
	label := "Sara's\x07 phone " + strings.Repeat("é", 70)
	res, err := enrollKey(t, k, "sara-1", FactorLabel(label))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.RecoveryCodes) != recoveryCodes {
		t.Errorf("recovery codes: %d", len(res.RecoveryCodes))
	}
	if in := m.lastStart(t); in.User == nil || in.User.ID != "u1" || in.Purpose != PurposeEnroll {
		t.Errorf("Enroll's Start was told %+v", in)
	}
	fs, _ := k.Factors(k.ctx, "u1")
	want := []rune("Sara's phone " + strings.Repeat("é", 70))[:64]
	if len(fs) != 1 || fs[0].Method != MethodPasskey || fs[0].Label != string(want) {
		t.Fatalf("factors: %+v", fs)
	}
	if k.lastReason(t, "factor.added") != "" || !slices.ContainsFunc(k.events.all, func(e Event) bool { return e.Kind == "factor.added" && e.Method == MethodPasskey }) {
		t.Error("no factor.added for the passkey")
	}
	f := passwordOnly(t, k, "sara")
	if slices.Contains(f.Offers, MethodEmailCode) || !slices.Contains(f.Offers, MethodPasskey) || !slices.Contains(f.Offers, MethodRecoveryCode) {
		t.Errorf("offers with a passkey: %v", f.Offers)
	}
	// A second passkey brings no codes, and takes the method's own label.
	res, err = enrollKeyVia(t, k, "sara-1", "sara-2")
	if err != nil || res.RecoveryCodes != nil {
		t.Fatalf("second: %v %v", res.RecoveryCodes, err)
	}
	fs, _ = k.Factors(k.ctx, "u1")
	if len(fs) != 2 || !slices.ContainsFunc(fs, func(f FactorInfo) bool { return f.Label == "Passkey" }) {
		t.Errorf("factors: %+v", fs)
	}
	// The second factor after a password proof counts: a verified session.
	f = passwordOnly(t, k, "sara")
	if f, err = k.proveKey(t, k.ctx, f.Token, MethodPasskey, "sara-2"); err != nil || !f.Verified {
		t.Errorf("password and passkey: %+v %v", f, err)
	}
	if err := k.ResetFactors(k.ctx, "u1"); err != nil {
		t.Fatal(err)
	}
	if f = passwordOnly(t, k, "sara"); !slices.Contains(f.Offers, MethodEmailCode) || slices.Contains(f.Offers, MethodPasskey) {
		t.Errorf("after ResetFactors: %v", f.Offers)
	}
}

// §4.3 FactorLabel: an authenticator app takes a label too.
func TestFactorLabelTOTP(t *testing.T) {
	k := newDeviceKit(t)
	k.clock.advance(time.Minute)
	res := twoFactorSignIn(t, k, nil)
	ctx := withSession(k.ctx, res.Session)
	f, _ := k.Enroll(ctx, res.Session, MethodTOTP)
	ch, _ := k.Challenge(ctx, f.Token, MethodTOTP)
	secret, _ := b32.DecodeString(ch.TOTP.Secret)
	if f, err := k.Prove(ctx, f.Token, TOTP(k.code(secret, 0))); err != nil || !f.Ready {
		t.Fatal(err)
	}
	if _, err := k.Finish(ctx, f.Token, FactorLabel("Work phone")); err != nil {
		t.Fatal(err)
	}
	if fs, _ := k.Factors(k.ctx, "u1"); len(fs) != 1 || fs[0].Label != "Work phone" {
		t.Errorf("factors: %+v", fs)
	}
}

// §5.5.10: enrolling a key anyone holds already, the same user included,
// stores nothing; two enrollments of one key at once store it once, and the
// loser's flow offers the method again.
func TestModuleEnrollDuplicate(t *testing.T) {
	k, _ := newPasskeyKit(t)
	k.addKey(t, "u2", MethodPasskey, "omar-1")
	if _, err := enrollKey(t, k, "omar-1"); !errors.Is(err, ErrBadCredentials) || k.lastReason(t, "proof.refused") != "duplicate" {
		t.Errorf("omar's key: %v", err)
	}
	if _, err := enrollKey(t, k, "sara-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := enrollKeyVia(t, k, "sara-1", "sara-1"); !errors.Is(err, ErrBadCredentials) {
		t.Errorf("her own key again: %v", err)
	}
	// Two flows prove one new key; the second Finish is refused.
	start := func() (context.Context, Flow) {
		ctx, sess := freshSession(t, k, "sara-1")
		f, err := k.Enroll(ctx, sess, MethodPasskey)
		if err != nil {
			t.Fatal(err)
		}
		f, err = k.proveKey(t, ctx, f.Token, MethodPasskey, "sara-new")
		if err != nil || !f.Ready {
			t.Fatalf("%+v %v", f, err)
		}
		return ctx, f
	}
	c1, f1 := start()
	c2, f2 := start()
	if _, err := k.Finish(c1, f1.Token); err != nil {
		t.Fatal(err)
	}
	if _, err := k.Finish(c2, f2.Token); !errors.Is(err, ErrBadCredentials) || k.lastReason(t, "factor.refused") != "duplicate" {
		t.Fatalf("the second Finish: %v", err)
	}
	f2, err := k.Flow(c2, f2.Token)
	if err != nil || f2.Ready || !slices.Equal(f2.Offers, []string{MethodPasskey}) {
		t.Errorf("the loser's flow: %+v %v", f2, err)
	}
	if fs, _ := k.Factors(k.ctx, "u1"); len(fs) != 2 {
		t.Errorf("factors: %+v", fs)
	}
}

// §5.13.2: a user with 20 passkeys can't start another; two enrollments at
// once by a user with 19 store one.
func TestModuleEnrollLimit(t *testing.T) {
	k, _ := newPasskeyKit(t)
	for i := range 19 {
		k.addKey(t, "u1", MethodPasskey, fmt.Sprint("sara-", i))
	}
	start := func(key string) (context.Context, Flow) {
		ctx, sess := freshSession(t, k, "sara-0")
		f, err := k.Enroll(ctx, sess, MethodPasskey)
		if err != nil {
			t.Fatal(err)
		}
		f, err = k.proveKey(t, ctx, f.Token, MethodPasskey, key)
		if err != nil {
			t.Fatal(err)
		}
		return ctx, f
	}
	c1, f1 := start("a")
	c2, f2 := start("b")
	if _, err := k.Finish(c1, f1.Token); err != nil {
		t.Fatal(err)
	}
	if _, err := k.Finish(c2, f2.Token); !errors.Is(err, ErrBadCredentials) || k.lastReason(t, "factor.refused") != "limit" {
		t.Errorf("the 21st: %v", err)
	}
	ctx, sess := freshSession(t, k, "sara-0")
	if _, err := k.Enroll(ctx, sess, MethodPasskey); !errors.Is(err, ErrMethodUnavailable) {
		t.Errorf("Enroll with 20: %v", err)
	}
}

// §5.13.11, §5.8.6, §7: failed passkey proofs make their address wait; the
// user signs in by password from another at once, and by passkey from
// another; behind the waiting address a registered device signs in by
// passkey, through SignInWithout too.
func TestPasskeyThrottle(t *testing.T) {
	k, _ := newPasskeyKit(t)
	bad := WithClient(k.ctx, Client{Addr: netip.MustParseAddr("198.51.100.1")})
	good := WithClient(k.ctx, Client{Addr: netip.MustParseAddr("192.0.2.2")})
	// A device registered from the good address.
	res := twoFactorSignIn(t, k, nil, RememberDevice("laptop"))
	if res.device == "" {
		t.Fatal("no device")
	}
	k.addKey(t, "u1", MethodPasskey, "sara-1")
	// Fail on sara's own flow from the bad address until it waits.
	var err error
	for i := 0; i < 40 && !errors.Is(err, ErrTooManyAttempts); i++ {
		f, _ := k.SignIn(bad, "sara", Cookie())
		_, err = k.proveKey(t, bad, f.Token, MethodPasskey, "wrong")
	}
	if !errors.Is(err, ErrTooManyAttempts) {
		t.Fatalf("the address never waited: %v", err)
	}
	f, _ := k.SignIn(good, "sara", Cookie())
	if _, err := k.Prove(good, f.Token, Password(goodPassword)); err != nil && !errors.Is(err, ErrCannotVerify) {
		t.Errorf("password from another address: %v", err)
	}
	f, _ = k.SignInWithout(good, Cookie())
	if _, err := k.proveKey(t, good, f.Token, MethodPasskey, "sara-1"); err != nil {
		t.Errorf("passkey from another address: %v", err)
	}
	// Behind the waiting address, with the device.
	withDevice := context.WithValue(bad, deviceTokenKey{}, res.device)
	f, _ = k.SignInWithout(withDevice, Cookie())
	if _, err := k.proveKey(t, withDevice, f.Token, MethodPasskey, "sara-1"); err != nil {
		t.Errorf("SignInWithout with the device: %v", err)
	}
	f, _ = k.SignIn(withDevice, "sara", Cookie(), Device(res.device))
	if _, err := k.proveKey(t, withDevice, f.Token, MethodPasskey, "sara-1"); err != nil {
		t.Errorf("SignIn with the device: %v", err)
	}
	// And without it, still waiting.
	f, _ = k.SignInWithout(bad, Cookie())
	if _, err := k.proveKey(t, bad, f.Token, MethodPasskey, "sara-1"); !errors.Is(err, ErrTooManyAttempts) {
		t.Errorf("without the device: %v", err)
	}
}

// §5.5.9: another module's attempts have a user's and a pair's counter of
// its own kind: failures from many addresses hold up that method for the
// user, not their password.
func TestModuleThrottleKinds(t *testing.T) {
	m := &fakeMethod{name: "magic"}
	k := newKit(t, WithMethods(m), WithFirst(MethodPassword, "magic"), WithPolicy(allowUnverified))
	k.addUser(t, "sara", User{ID: "u1", Name: "sara"}, goodPassword, saraMail)
	k.addKey(t, "u1", "magic", "sara-1")
	var err error
	for i := 0; i < 40 && !errors.Is(err, ErrTooManyAttempts); i++ {
		ctx := WithClient(k.ctx, Client{Addr: netip.AddrFrom4([4]byte{198, 51, 100, byte(i)})})
		f, _ := k.SignIn(ctx, "sara", Cookie())
		_, err = k.proveKey(t, ctx, f.Token, "magic", "wrong")
	}
	if !errors.Is(err, ErrTooManyAttempts) {
		t.Fatalf("the user's magic counter never waited: %v", err)
	}
	ctx := WithClient(k.ctx, Client{Addr: netip.MustParseAddr("192.0.2.9")})
	f, _ := k.SignIn(ctx, "sara", Cookie())
	if _, err := k.Prove(ctx, f.Token, Password(goodPassword)); err != nil {
		t.Errorf("password: %v", err)
	}
	f, _ = k.SignIn(ctx, "sara", Cookie())
	if _, err := k.proveKey(t, ctx, f.Token, "magic", "sara-1"); !errors.Is(err, ErrTooManyAttempts) {
		t.Errorf("magic from a new address: %v", err)
	}
	if !slices.Contains(k.reasons("proof.refused"), "throttled") {
		t.Error("no throttled event")
	}
}

// A SignInWithout names no login, so it has no user's counter before its
// proof: failures on such flows from many addresses hold up no one else's
// from a new address.
func TestSignInWithoutThrottle(t *testing.T) {
	m := &fakeMethod{name: "magic"}
	k := newKit(t, WithMethods(m), WithFirst(MethodPassword, "magic"), WithPolicy(allowUnverified))
	k.addUser(t, "sara", User{ID: "u1", Name: "sara"}, goodPassword, saraMail)
	k.addKey(t, "u1", "magic", "sara-1")
	for i := range 40 {
		ctx := WithClient(k.ctx, Client{Addr: netip.AddrFrom4([4]byte{198, 51, 100, byte(i)})})
		f, _ := k.SignInWithout(ctx, Cookie())
		if _, err := k.proveKey(t, ctx, f.Token, "magic", "wrong"); !errors.Is(err, ErrBadCredentials) {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	ctx := WithClient(k.ctx, Client{Addr: netip.MustParseAddr("192.0.2.9")})
	f, _ := k.SignInWithout(ctx, Cookie())
	if _, err := k.proveKey(t, ctx, f.Token, "magic", "sara-1"); err != nil {
		t.Errorf("from a new address: %v", err)
	}
}

// A device presented to a SignInWithout stands for nothing if the proof
// names another user (§4.3).
func TestSignInWithoutOthersDevice(t *testing.T) {
	m := &fakeMethod{name: "magic"} // not verified on its own
	k := newKit(t, WithMethods(m), WithFirst(MethodPassword, "magic"))
	k.addUser(t, "sara", User{ID: "u1", Name: "sara"}, goodPassword, saraMail)
	k.addUser(t, "omar", User{ID: "u2", Name: "omar"}, goodPassword, "omar@toyshop.example")
	k.addKey(t, "u1", "magic", "sara-1")
	k.addKey(t, "u2", "magic", "omar-1")
	res := twoFactorSignIn(t, k, nil, RememberDevice("sara's laptop"))
	ctx := context.WithValue(k.ctx, deviceTokenKey{}, res.device)
	f, _ := k.SignInWithout(ctx, Cookie())
	f, err := k.proveKey(t, ctx, f.Token, "magic", "omar-1")
	if !errors.Is(err, ErrCannotVerify) && err != nil || f.Verified {
		t.Errorf("omar on sara's device: %+v %v", f, err)
	}
	// Sara's own device stands for her second proof.
	f, _ = k.SignInWithout(ctx, Cookie())
	if f, err = k.proveKey(t, ctx, f.Token, "magic", "sara-1"); err != nil || !f.Verified {
		t.Errorf("sara on her device: %+v %v", f, err)
	}
}

// §7: StepUp with a passkey upgrades the session and replaces its token;
// Recover accepts a passkey after the link, and the passkey survives the new
// password.
func TestModuleStepUpAndRecover(t *testing.T) {
	k, _ := newPasskeyKit(t, WithPolicy(allowUnverified))
	if _, err := enrollKey(t, k, "sara-1"); err != nil {
		t.Fatal(err)
	}
	f := passwordOnly(t, k, "sara")
	res, err := k.Finish(k.ctx, f.Token)
	if err != nil || res.Session.Verified {
		t.Fatalf("unverified sign-in: %+v %v", res.Session, err)
	}
	ctx := withSession(k.ctx, res.Session)
	f, err = k.StepUp(ctx, res.Session)
	if err != nil {
		t.Fatal(err)
	}
	if f, err = k.proveKey(t, ctx, f.Token, MethodPasskey, "sara-1"); err != nil || !f.Ready {
		t.Fatalf("step-up proof: %+v %v", f, err)
	}
	up, err := k.Finish(ctx, f.Token)
	if err != nil || !up.Session.Verified || up.Session.ID != res.Session.ID {
		t.Fatalf("step-up: %+v %v", up.Session, err)
	}
	if !res.Session.superseded(k.sessionRecord(t, res.Session.ID)) {
		t.Error("the old token wasn't replaced")
	}

	f = recoverLink(t, k, "sara")
	link := k.lastMessage(t, saraMail).Token
	if f, err = k.Follow(k.ctx, link); err != nil || f.Ready || !slices.Contains(f.Offers, MethodPasskey) {
		t.Fatalf("Follow: %+v %v", f, err)
	}
	if f, err = k.proveKey(t, k.ctx, f.Token, MethodPasskey, "sara-1"); err != nil || !f.Ready {
		t.Fatalf("recover proof: %+v %v", f, err)
	}
	if _, err := k.Finish(k.ctx, f.Token, NewPassword(newPassword)); err != nil {
		t.Fatal(err)
	}
	if fs, _ := k.Factors(k.ctx, "u1"); len(fs) != 1 || fs[0].Method != MethodPasskey {
		t.Errorf("factors after recovery: %+v", fs)
	}
}

func (k *kit) sessionRecord(t *testing.T, id SessionID) *storepb.Session {
	t.Helper()
	var s storepb.Session
	if err := k.db.View(func(tx *bolt.Tx) error { return store.Get(tx, store.Sessions, []byte(id), &s) }); err != nil {
		t.Fatal(err)
	}
	return &s
}

// §7: after DeleteUser the user's passkey is refused, also once another
// user has the same ID.
func TestModuleDeleteUser(t *testing.T) {
	k, _ := newPasskeyKit(t)
	if _, err := enrollKey(t, k, "sara-1"); err != nil {
		t.Fatal(err)
	}
	k.dir.mu.Lock()
	delete(k.dir.users, "sara")
	k.dir.mu.Unlock()
	if err := k.DeleteUser(k.ctx, "u1"); err != nil {
		t.Fatal(err)
	}
	f, _ := k.SignInWithout(k.ctx, Cookie())
	if _, err := k.proveKey(t, k.ctx, f.Token, MethodPasskey, "sara-1"); !errors.Is(err, ErrBadCredentials) {
		t.Errorf("after DeleteUser: %v", err)
	}
	k.addUser(t, "sara2", User{ID: "u1", Name: "new sara"}, goodPassword, "new@toyshop.example")
	f, _ = k.SignInWithout(k.ctx, Cookie())
	if _, err := k.proveKey(t, k.ctx, f.Token, MethodPasskey, "sara-1"); !errors.Is(err, ErrBadCredentials) {
		t.Errorf("with the ID reused: %v", err)
	}
}

// A factor of a module that isn't given is offered nowhere.
func TestModuleFactorWithoutModule(t *testing.T) {
	k := newDeviceKit(t)
	k.addKey(t, "u1", MethodPasskey, "sara-1")
	k.addRecoveryCode(t, "u1", "ABCD-EFGH")
	f := passwordOnly(t, k, "sara")
	if slices.Contains(f.Offers, MethodPasskey) || slices.Contains(f.Offers, MethodEmailCode) {
		t.Errorf("offers: %v", f.Offers)
	}
}

// §4.9: Lookup returns a zero User and no credentials, with a nil error,
// for a user who is gone; what it hands out counts for rule 8 of §5.5.
func TestModuleLookup(t *testing.T) {
	k, m := newPasskeyKit(t)
	k.addKey(t, "u1", MethodPasskey, "sara-1")
	m.verify = func(in MethodInput, p fakeProof) (MethodResult, error) {
		if u, cs, err := in.Lookup("u9"); err != nil || u.ID != "" || cs != nil {
			t.Errorf("Lookup of a gone user: %+v %v %v", u, cs, err)
		}
		if _, _, err := in.Lookup(""); err == nil {
			t.Error("Lookup of an empty ID: no error")
		}
		u, cs, err := in.Lookup("u1")
		if err != nil || u.ID != "u1" || len(cs) != 1 {
			t.Fatalf("Lookup: %+v %+v %v", u, cs, err)
		}
		return MethodResult{User: u.ID, Credential: &cs[0], Verified: true}, nil
	}
	f, _ := k.SignInWithout(k.ctx, Cookie())
	if f, err := k.proveKey(t, k.ctx, f.Token, MethodPasskey, "sara-1"); err != nil || !f.Verified {
		t.Errorf("a credential from Lookup: %+v %v", f, err)
	}
}

// §5.11: no event holds a module's response, challenge or credential key.
func TestModuleEventsHoldNoSecret(t *testing.T) {
	k, _ := newPasskeyKit(t)
	if _, err := enrollKey(t, k, "sara-secret-key"); err != nil {
		t.Fatal(err)
	}
	f, _ := k.SignInWithout(k.ctx, Cookie())
	k.proveKey(t, k.ctx, f.Token, MethodPasskey, "sara-secret-key")
	f, _ = k.SignInWithout(k.ctx, Cookie())
	k.proveKey(t, k.ctx, f.Token, MethodPasskey, "wrong-secret-key")
	for _, e := range k.events.all {
		if s := fmt.Sprintf("%+v", e); strings.Contains(s, "secret-key") {
			t.Errorf("event holds a key: %s", s)
		}
	}
}

// Review 0021, finding 4: the tenth Challenge can still be proved.
func TestModuleTenthChallenge(t *testing.T) {
	k, _ := newPasskeyKit(t)
	k.addKey(t, "u1", MethodPasskey, "sara-1")
	f, _ := k.SignInWithout(k.ctx, Cookie())
	for range maxChallenges - 1 {
		k.challenge(t, k.ctx, f.Token, MethodPasskey)
	}
	if f, err := k.proveKey(t, k.ctx, f.Token, MethodPasskey, "sara-1"); err != nil || !f.Ready {
		t.Errorf("the tenth: %+v %v", f, err)
	}
}

// Review 0021, finding 2: a method told no user must name one; the flow's
// login doesn't stand in, so a known and an unknown login answer alike.
func TestModuleMustNameUser(t *testing.T) {
	k, m := newPasskeyKit(t)
	m.verify = func(MethodInput, fakeProof) (MethodResult, error) { return MethodResult{Verified: true}, nil }
	for _, login := range []string{"sara", "nobody"} {
		f, _ := k.SignIn(k.ctx, login, Cookie())
		if _, err := k.proveKey(t, k.ctx, f.Token, MethodPasskey, "x"); !errors.Is(err, ErrBadCredentials) || k.lastReason(t, "proof.refused") != "user_mismatch" {
			t.Errorf("%s: %v", login, err)
		}
	}
}

// Review 0021, finding 1: in a SignInWithout, a device presented by
// someone else counts their failures against the device's owner's pair
// only while the policy trusts it, and their success clears nothing of
// the owner's.
func TestSignInWithoutDeviceCounters(t *testing.T) {
	setup := func(t *testing.T, opts ...Option) (*kit, context.Context) {
		m := &fakeMethod{name: "magic"}
		k := newKit(t, append([]Option{WithMethods(m), WithFirst(MethodPassword, "magic")}, opts...)...)
		k.addUser(t, "sara", User{ID: "u1", Name: "sara"}, goodPassword, saraMail)
		k.addUser(t, "omar", User{ID: "u2", Name: "omar"}, goodPassword, "omar@toyshop.example")
		k.addKey(t, "u1", "magic", "sara-1")
		k.addKey(t, "u2", "magic", "omar-1")
		res := twoFactorSignIn(t, k, nil, RememberDevice("sara's laptop"))
		if res.device == "" {
			t.Fatal("no device")
		}
		return k, context.WithValue(k.ctx, deviceTokenKey{}, res.device)
	}
	t.Run("success clears nothing of the owner's", func(t *testing.T) {
		k, dev := setup(t)
		ctx := WithClient(dev, Client{Addr: netip.MustParseAddr("192.0.2.5")})
		for range 3 {
			f, _ := k.SignInWithout(ctx, Cookie())
			k.proveKey(t, ctx, f.Token, "magic", "wrong")
		}
		before := k.counters(t)
		f, _ := k.SignInWithout(ctx, Cookie())
		if _, err := k.proveKey(t, ctx, f.Token, "magic", "omar-1"); err != nil && !errors.Is(err, ErrCannotVerify) {
			t.Fatal(err)
		}
		if after := k.counters(t); after != before || before == 0 {
			t.Errorf("counters %d before omar's success, %d after", before, after)
		}
	})
	t.Run("an untrusted device stands for no one", func(t *testing.T) {
		k, dev := setup(t, WithPolicy(allowUnverified))
		for i := range 40 {
			ctx := WithClient(dev, Client{Addr: netip.AddrFrom4([4]byte{198, 51, 100, byte(i)})})
			f, _ := k.SignInWithout(ctx, Cookie())
			k.proveKey(t, ctx, f.Token, "magic", "wrong")
		}
		ctx := WithClient(k.ctx, Client{Addr: netip.MustParseAddr("192.0.2.9")})
		f, _ := k.SignIn(ctx, "sara", Cookie())
		if _, err := k.proveKey(t, ctx, f.Token, "magic", "sara-1"); err != nil {
			t.Errorf("sara's own magic: %v", err)
		}
	})
}

// Review 0021, finding 7: a label the method gives is cleaned and cut too.
func TestModuleOwnLabelCleaned(t *testing.T) {
	k, m := newPasskeyKit(t)
	m.verify = func(in MethodInput, p fakeProof) (MethodResult, error) {
		return MethodResult{Credential: &Credential{Key: []byte(p.key), Data: []byte("v1"), Label: "Phone\x1b" + strings.Repeat("a", 100)}}, nil
	}
	if _, err := enrollKey(t, k, "sara-1"); err != nil {
		t.Fatal(err)
	}
	fs, _ := k.Factors(k.ctx, "u1")
	if len(fs) != 1 || fs[0].Label != ("Phone" + strings.Repeat("a", 100))[:64] {
		t.Errorf("label %q", fs[0].Label)
	}
}

// Review 0023, finding 1: a proof made while Start ran makes its options
// stale, and the Challenge is refused, storing nothing; past its caps the
// method isn't asked.
func TestModuleChallengeRacesProof(t *testing.T) {
	k, m := newPasskeyKit(t)
	k.addKey(t, "u1", MethodPasskey, "sara-1")
	f, _ := k.SignIn(k.ctx, "sara", Cookie())
	m.onStart = func() {
		m.onStart = nil
		if _, err := k.Prove(k.ctx, f.Token, Password(goodPassword)); err != nil && !errors.Is(err, ErrCannotVerify) {
			t.Error(err)
		}
	}
	if _, err := k.Challenge(k.ctx, f.Token, MethodPasskey); !errors.Is(err, ErrMethodUnavailable) {
		t.Fatalf("a Challenge raced by a proof: %v", err)
	}
	rec, _ := k.loadFlow(secrets.Hash(f.Token))
	if _, ok := rec.MethodState[stateKey(MethodPasskey)]; ok || rec.Challenges[MethodPasskey] != 0 {
		t.Errorf("stale state stored: %+v", rec.Challenges)
	}
	// Asked again, it is told the user.
	k.challenge(t, k.ctx, f.Token, MethodPasskey)
	if in := m.lastStart(t); in.User == nil || len(in.Credentials) != 1 {
		t.Errorf("then Start was told %+v", in)
	}

	g, _ := k.SignInWithout(k.ctx, Cookie())
	for range maxChallenges {
		k.challenge(t, k.ctx, g.Token, MethodPasskey)
	}
	n := len(m.starts)
	if _, err := k.Challenge(k.ctx, g.Token, MethodPasskey); !errors.Is(err, ErrMethodUnavailable) || len(m.starts) != n {
		t.Errorf("past the cap: %v, Start called %d more", err, len(m.starts)-n)
	}
}
