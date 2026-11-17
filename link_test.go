package auth

import (
	"bytes"
	"context"
	"crypto/rand"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/epistemer/errors"
	bolt "go.etcd.io/bbolt"

	"github.com/epistemer/auth/internal/secrets"
	"github.com/epistemer/auth/internal/store"
	"github.com/epistemer/auth/internal/storepb"
)

// Identities (interface §4.3, §4.5, §5.5.8, §5.5.9, §5.7.2, §5.14.7,
// §5.14.11, A25), with a fake identity provider: a proof names a subject,
// which signs in its user when linked and comes back unlinked otherwise.

const idpIssuer = "https://idp.test"

type fakeIdP struct {
	name       string
	twoFactors bool
	email      string // the identity's email, verified
	addrOnly   bool
	noCred     bool   // an unlinked result carries no credential
	both       bool   // an unlinked result names a user too
	afterFind  func() // runs after Find, before Verify returns
}

type idpProof struct {
	method    string
	challenge []byte
	subject   string
}

func (p idpProof) Method() string { return p.method }

func (m *fakeIdP) Name() string      { return m.name }
func (m *fakeIdP) AddressOnly() bool { return m.addrOnly }

func (m *fakeIdP) Start(context.Context, MethodInput) (any, []byte, error) {
	ch := make([]byte, 16)
	rand.Read(ch)
	return fakeOptions{Challenge: ch}, ch, nil
}

func (m *fakeIdP) Verify(_ context.Context, in MethodInput, state []byte, p Proof) (MethodResult, error) {
	ip, ok := p.(idpProof)
	if !ok || !bytes.Equal(ip.challenge, state) {
		return MethodResult{}, Refuse("state")
	}
	if ip.subject == "" {
		return MethodResult{}, Refuse("token")
	}
	key := []byte(idpIssuer + "\x00" + ip.subject)
	cred := &Credential{Key: key, Data: []byte("v1"), Label: m.email}
	if in.Purpose == PurposeEnroll {
		return MethodResult{Credential: cred}, nil
	}
	owner, c, err := in.Find(key)
	if err != nil {
		return MethodResult{}, err
	}
	if m.afterFind != nil {
		m.afterFind()
	}
	if c == nil {
		if m.noCred {
			cred = nil
		}
		if m.both {
			return MethodResult{User: "u1", Unlinked: &Identity{Issuer: idpIssuer, Subject: ip.subject}, Credential: cred}, nil
		}
		return MethodResult{
			Unlinked:   &Identity{Issuer: idpIssuer, Subject: ip.subject, Email: m.email, EmailVerified: m.email != ""},
			Credential: cred, Verified: m.twoFactors, Address: m.email,
		}, nil
	}
	return MethodResult{User: owner, Credential: c, Verified: m.twoFactors, Address: m.email}, nil
}

func newIdPKit(t *testing.T, m *fakeIdP, opts ...Option) *kit {
	t.Helper()
	if m.name == "" {
		m.name = "oidc_test"
	}
	k := newKit(t, append([]Option{WithMethods(m), WithFirst(MethodPassword, m.name)}, opts...)...)
	k.addUser(t, "sara", User{ID: "u1", Name: "sara"}, goodPassword, saraMail)
	// u8 and u9 are new: the directory knows them, auth holds nothing.
	k.addUser(t, "new8", User{ID: "u8", Name: "eight"}, "")
	k.addUser(t, "new9", User{ID: "u9", Name: "nine"}, "")
	return k
}

// proveIdP challenges and proves a subject on a flow.
func (k *kit) proveIdP(t *testing.T, ctx context.Context, token, method, subject string) (Flow, error) {
	t.Helper()
	ch := k.challenge(t, ctx, token, method)
	return k.Prove(ctx, token, idpProof{method: method, challenge: ch, subject: subject})
}

func (k *kit) unlinked(t *testing.T, method, subject string) Flow {
	t.Helper()
	f, err := k.SignInWithout(k.ctx, Cookie())
	if err != nil {
		t.Fatal(err)
	}
	f, err = k.proveIdP(t, k.ctx, f.Token, method, subject)
	if err != nil || f.Unlinked == nil {
		t.Fatalf("unlinked: %+v %v", f, err)
	}
	return f
}

// §5.14.7, D42: an unknown identity comes back unlinked, takes no other
// proof, and Link signs in the new user and links it; the next sign-in by
// it is that user's.
func TestLink(t *testing.T) {
	k := newIdPKit(t, &fakeIdP{email: "nine@idp.test"}, WithPolicy(allowUnverified))
	f := k.unlinked(t, "oidc_test", "sub-9")
	if f.Ready || len(f.Offers) != 0 || f.Unlinked.Issuer != idpIssuer || f.Unlinked.Subject != "sub-9" ||
		f.Unlinked.Email != "nine@idp.test" || !f.Unlinked.EmailVerified {
		t.Fatalf("unlinked flow: %+v %+v", f, f.Unlinked)
	}
	if _, err := k.Prove(k.ctx, f.Token, Password(goodPassword)); !errors.Is(err, ErrMethodUnavailable) {
		t.Errorf("a password on an unlinked flow: %v", err)
	}
	if ids, _ := k.Identities(k.ctx, "u9"); len(ids) != 0 {
		t.Fatalf("stored before Link: %+v", ids)
	}
	f, err := k.Link(k.ctx, f.Token, "u9")
	if err != nil || !f.Ready || f.Unlinked != nil {
		t.Fatalf("Link: %+v %v", f, err)
	}
	res, err := k.Finish(k.ctx, f.Token)
	if err != nil || res.Session.User != "u9" {
		t.Fatalf("Finish: %+v %v", res.Session, err)
	}
	ids, _ := k.Identities(k.ctx, "u9")
	if len(ids) != 1 || ids[0].Method != "oidc_test" || ids[0].Label != "nine@idp.test" || ids[0].Added.IsZero() {
		t.Errorf("identities: %+v", ids)
	}
	if fs, _ := k.Factors(k.ctx, "u9"); len(fs) != 0 {
		t.Errorf("an identity listed as a factor: %+v", fs)
	}
	g, _ := k.SignInWithout(k.ctx, Cookie())
	g, err = k.proveIdP(t, k.ctx, g.Token, "oidc_test", "sub-9")
	if err != nil || g.Unlinked != nil || !g.Ready {
		t.Errorf("signing in again: %+v %v", g, err)
	}
	if _, err := k.Link(k.ctx, g.Token, "u8"); !errors.Is(err, ErrMethodUnavailable) {
		t.Errorf("Link with nothing unlinked: %v", err)
	}
}

// §5.14.7: Link names a user new to auth, or stores nothing.
func TestLinkNotNew(t *testing.T) {
	cases := map[string]func(k *kit){
		"a password":       func(k *kit) { k.SetPassword(k.ctx, "u9", goodPassword) },
		"a passkey":        func(k *kit) { k.addKey(t, "u9", MethodPasskey, "k") },
		"recovery codes":   func(k *kit) { k.addRecoveryCode(t, "u9", "ABCD-EFGH") },
		"another identity": func(k *kit) { k.addKey(t, "u9", "oidc_test", idpIssuer+"\x00other") },
		"a device": func(k *kit) {
			k.db.Update(func(tx *bolt.Tx) error { _, _, err := k.registerDevice(tx, "u9", "laptop"); return err })
		},
		"an ended session": func(k *kit) {
			k.db.Update(func(tx *bolt.Tx) error {
				return putSession(tx, &storepb.Session{Id: "s9", UserId: "u9", TokenHash: []byte("h"), Ended: k.clock.now().UnixNano(), Expires: k.clock.now().Add(time.Hour).UnixNano()})
			})
		},
		"an invitation": func(k *kit) {
			k.dir.mu.Lock()
			k.dir.addrs["u9"][ChannelEmail] = "nine@toyshop.example"
			k.dir.mu.Unlock()
			if _, err := k.Invite(k.ctx, "u9"); err != nil {
				t.Fatal(err)
			}
		},
		"a recovery": func(k *kit) { k.Recover(k.ctx, "new9") },
	}
	for name, setup := range cases {
		k := newIdPKit(t, &fakeIdP{}, WithPolicy(allowUnverified))
		setup(k)
		f := k.unlinked(t, "oidc_test", "sub-x")
		if _, err := k.Link(k.ctx, f.Token, "u9"); !errors.Is(err, ErrBadCredentials) || k.lastReason(t, "proof.refused") != "not_new" {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if ids, _ := k.Identities(k.ctx, "u9"); slices.ContainsFunc(ids, func(i IdentityInfo) bool { return i.Label == "" && i.Method == "oidc_test" && len(ids) > 1 }) {
			t.Errorf("%s: stored: %+v", name, ids)
		}
		if owner, c := k.findIdentity(t, "sub-x"); c {
			t.Errorf("%s: sub-x linked to %s", name, owner)
		}
		// The flow still holds it: a new user takes it.
		if _, err := k.Link(k.ctx, f.Token, "u8"); err != nil {
			t.Errorf("%s: then a new user: %v", name, err)
		}
	}
	k := newIdPKit(t, &fakeIdP{})
	f := k.unlinked(t, "oidc_test", "sub-y")
	if _, err := k.Link(k.ctx, f.Token, "u1"); !errors.Is(err, ErrBadCredentials) {
		t.Errorf("sara, who has a password: %v", err)
	}
	if _, err := k.Link(k.ctx, f.Token, "u404"); !errors.Is(err, ErrBadCredentials) {
		t.Errorf("a user the directory doesn't know: %v", err)
	}
	k.dir.mu.Lock()
	k.dir.users["new9"] = User{ID: "u9", Name: "nine", Disabled: true}
	k.dir.mu.Unlock()
	if _, err := k.Link(k.ctx, f.Token, "u9"); !errors.Is(err, ErrUserDisabled) {
		t.Errorf("a disabled user: %v", err)
	}
}

func (k *kit) findIdentity(t *testing.T, subject string) (UserID, bool) {
	t.Helper()
	var owner UserID
	var c *storepb.Credential
	k.db.View(func(tx *bolt.Tx) (err error) {
		owner, c, err = findCredentialTx(tx, "oidc_test", []byte(idpIssuer+"\x00"+subject))
		return err
	})
	return owner, c != nil
}

// §5.14.7: two flows proving one unknown identity link it once; the second
// Link is duplicate, and its flow starts again.
func TestLinkDuplicate(t *testing.T) {
	k := newIdPKit(t, &fakeIdP{}, WithPolicy(allowUnverified))
	a, b := k.unlinked(t, "oidc_test", "sub-z"), k.unlinked(t, "oidc_test", "sub-z")
	if _, err := k.Link(k.ctx, a.Token, "u8"); err != nil {
		t.Fatal(err)
	}
	if _, err := k.Link(k.ctx, b.Token, "u9"); !errors.Is(err, ErrBadCredentials) || k.lastReason(t, "proof.refused") != "duplicate" {
		t.Fatalf("the second Link: %v", err)
	}
	if owner, _ := k.findIdentity(t, "sub-z"); owner != "u8" {
		t.Errorf("owner %q", owner)
	}
	if f, _ := k.Flow(k.ctx, b.Token); f.Unlinked != nil || !slices.Contains(f.Offers, "oidc_test") {
		t.Errorf("the loser's flow: %+v", f)
	}
	// Proved again, the identity now signs in its owner.
	if f, err := k.proveIdP(t, k.ctx, b.Token, "oidc_test", "sub-z"); err != nil || f.Unlinked != nil {
		t.Errorf("proved again: %+v %v", f, err)
	}
}

// §5.14.7: an unlinked identity is kept only in a flow started by
// SignInWithout; elsewhere it is refused, and nothing waits for Link.
func TestUnlinkedElsewhere(t *testing.T) {
	k := newIdPKit(t, &fakeIdP{}, WithPolicy(allowUnverified))
	f, _ := k.SignIn(k.ctx, "sara", Cookie())
	if _, err := k.proveIdP(t, k.ctx, f.Token, "oidc_test", "sub-u"); !errors.Is(err, ErrBadCredentials) || k.lastReason(t, "proof.refused") != "unlinked" {
		t.Errorf("a sign-in with a login: %v", err)
	}
	if f, _ = k.Flow(k.ctx, f.Token); f.Unlinked != nil {
		t.Error("kept for Link")
	}
	if _, err := k.Link(k.ctx, f.Token, "u9"); !errors.Is(err, ErrMethodUnavailable) {
		t.Errorf("Link on it: %v", err)
	}
}

// §5.14.11, D44: Identities lists, Unlink removes under §5.1.9 and refuses
// the last way in; ResetFactors leaves identities; DeleteUser removes them.
func TestIdentitiesAndUnlink(t *testing.T) {
	k := newIdPKit(t, &fakeIdP{twoFactors: true})
	k.addKey(t, "u1", "oidc_test", idpIssuer+"\x00sara")
	ids, err := k.Identities(k.ctx, "u1")
	if err != nil || len(ids) != 1 {
		t.Fatalf("identities: %+v %v", ids, err)
	}
	if err := k.ResetFactors(k.ctx, "u1"); err != nil {
		t.Fatal(err)
	}
	if ids, _ := k.Identities(k.ctx, "u1"); len(ids) != 1 {
		t.Errorf("ResetFactors removed an identity: %+v", ids)
	}
	if err := k.RemoveFactor(k.ctx, &Session{}, ids[0].ID); err == nil {
		t.Error("RemoveFactor took an identity")
	}
	k.clock.advance(time.Minute)
	res := twoFactorSignIn(t, k, nil)
	ctx := withSession(k.ctx, res.Session)
	if err := k.Unlink(ctx, res.Session, "oidc_test:00"); !errors.Is(err, ErrMethodUnavailable) {
		t.Errorf("a bad ID: %v", err)
	}
	if err := k.Unlink(ctx, res.Session, ids[0].ID); err != nil {
		t.Fatalf("Unlink: %v", err)
	}
	if ids, _ := k.Identities(k.ctx, "u1"); len(ids) != 0 {
		t.Errorf("still linked: %+v", ids)
	}
	if !slices.Contains(k.reasons("identity.unlinked"), "") {
		t.Error("no identity.unlinked event")
	}

	// u9 has the identity alone: Unlink refuses the last way in.
	f := k.unlinked(t, "oidc_test", "sub-9")
	f, err = k.Link(k.ctx, f.Token, "u9")
	if err != nil {
		t.Fatal(err)
	}
	res9, err := k.Finish(k.ctx, f.Token)
	if err != nil || !res9.Session.Verified {
		t.Fatalf("u9's sign-in: %+v %v", res9.Session, err)
	}
	ids9, _ := k.Identities(k.ctx, "u9")
	ctx9 := withSession(k.ctx, res9.Session)
	if err := k.Unlink(ctx9, res9.Session, ids9[0].ID); !errors.Is(err, ErrMethodUnavailable) || k.lastReason(t, "factor.refused") != "last" {
		t.Errorf("the last way in: %v", err)
	}
	k.dir.mu.Lock()
	delete(k.dir.users, "new9")
	k.dir.mu.Unlock()
	if err := k.DeleteUser(k.ctx, "u9"); err != nil {
		t.Fatal(err)
	}
	if _, linked := k.findIdentity(t, "sub-9"); linked {
		t.Error("DeleteUser left the identity")
	}
}

// §5.7.2, D45: a proof that shows control of an address and a code sent
// to that address are one factor; to another address, two.
func TestOneMailboxOneFactor(t *testing.T) {
	for _, tc := range []struct {
		email    string
		verified bool
	}{{saraMail, false}, {"other@idp.test", true}, {"", true}} {
		k := newIdPKit(t, &fakeIdP{email: tc.email})
		k.addKey(t, "u1", "oidc_test", idpIssuer+"\x00sara")
		f, _ := k.SignInWithout(k.ctx, Cookie())
		f, err := k.proveIdP(t, k.ctx, f.Token, "oidc_test", "sara")
		if err != nil && !errors.Is(err, ErrCannotVerify) {
			t.Fatal(err)
		}
		if !slices.Contains(f.Offers, MethodEmailCode) {
			t.Fatalf("%q: offers %v", tc.email, f.Offers)
		}
		k.clock.advance(time.Minute)
		k.Challenge(k.ctx, f.Token, MethodEmailCode)
		f, err = k.Prove(k.ctx, f.Token, EmailCode(k.lastCode(t, saraMail)))
		if err != nil && !errors.Is(err, ErrCannotVerify) || f.Verified != tc.verified {
			t.Errorf("identity email %q: verified %v, %v", tc.email, f.Verified, err)
		}
	}
}

// §5.5.9, D43: a method that implements AddressOnly counts by address
// alone, whatever its name; one that doesn't has a user's counter, a
// method named passkey too.
func TestAddressOnly(t *testing.T) {
	for _, tc := range []struct {
		name     string
		addrOnly bool
		waits    bool // the user's own sign-in from a fresh address waits
	}{{"oidc_test", true, false}, {MethodPasskey, false, true}, {"oidc_test", false, true}} {
		m := &fakeIdP{name: tc.name, addrOnly: tc.addrOnly}
		k := newIdPKit(t, m, WithPolicy(allowUnverified))
		k.addKey(t, "u1", tc.name, idpIssuer+"\x00sara")
		for i := range 40 {
			ctx := WithClient(k.ctx, Client{Addr: netip.AddrFrom4([4]byte{198, 51, 100, byte(i)})})
			f, _ := k.SignIn(ctx, "sara", Cookie())
			k.proveIdP(t, ctx, f.Token, tc.name, "")
		}
		ctx := WithClient(k.ctx, Client{Addr: netip.MustParseAddr("192.0.2.9")})
		f, _ := k.SignIn(ctx, "sara", Cookie())
		_, err := k.proveIdP(t, ctx, f.Token, tc.name, "sara")
		if waits := errors.Is(err, ErrTooManyAttempts); waits != tc.waits {
			t.Errorf("%s, AddressOnly %v: waits %v (%v)", tc.name, tc.addrOnly, waits, err)
		}
	}
}

// Enrolling an identity (§5.14.6): it is linked, and isn't a factor.
func TestEnrollIdentity(t *testing.T) {
	k := newIdPKit(t, &fakeIdP{email: "sara@idp.test"})
	k.clock.advance(time.Minute)
	res := twoFactorSignIn(t, k, nil)
	ctx := withSession(k.ctx, res.Session)
	f, err := k.Enroll(ctx, res.Session, "oidc_test")
	if err != nil {
		t.Fatal(err)
	}
	if f, err = k.proveIdP(t, ctx, f.Token, "oidc_test", "sara"); err != nil || !f.Ready {
		t.Fatalf("Prove: %+v %v", f, err)
	}
	r, err := k.Finish(ctx, f.Token)
	if err != nil || r.RecoveryCodes != nil {
		t.Fatalf("Finish: %v %v", r.RecoveryCodes, err)
	}
	if ids, _ := k.Identities(k.ctx, "u1"); len(ids) != 1 || ids[0].Label != "sara@idp.test" {
		t.Errorf("identities: %+v", ids)
	}
	if fs, _ := k.Factors(k.ctx, "u1"); len(fs) != 0 {
		t.Errorf("factors: %+v", fs)
	}
	// Still a code to the address is a second proof: an identity is no factor.
	if f := passwordOnly(t, k, "sara"); !slices.Contains(f.Offers, MethodEmailCode) {
		t.Errorf("offers: %v", f.Offers)
	}
}

// The survivors' tests: each rule of M8.1 fails without its check.
func TestLinkEdges(t *testing.T) {
	// An unlinked result without a credential is the method's own failure.
	m := &fakeIdP{noCred: true}
	k := newIdPKit(t, m)
	f, _ := k.SignInWithout(k.ctx, Cookie())
	if _, err := k.proveIdP(t, k.ctx, f.Token, "oidc_test", "sub-n"); err == nil || errors.Is(err, ErrBadCredentials) {
		t.Errorf("no credential: %v", err)
	}

	// Linked by someone else while Verify ran: duplicate, nothing kept.
	m = &fakeIdP{}
	k = newIdPKit(t, m)
	m.afterFind = func() { m.afterFind = nil; k.addKey(t, "u8", "oidc_test", idpIssuer+"\x00sub-d") }
	f, _ = k.SignInWithout(k.ctx, Cookie())
	if g, err := k.proveIdP(t, k.ctx, f.Token, "oidc_test", "sub-d"); !errors.Is(err, ErrBadCredentials) || g.Unlinked != nil || k.lastReason(t, "proof.refused") != "duplicate" {
		t.Errorf("linked meanwhile: %+v %v", g, err)
	}

	// An unlinked flow takes no Challenge.
	k = newIdPKit(t, &fakeIdP{})
	f = k.unlinked(t, "oidc_test", "sub-c")
	if _, err := k.Challenge(k.ctx, f.Token, "oidc_test"); !errors.Is(err, ErrMethodUnavailable) {
		t.Errorf("a Challenge on an unlinked flow: %v", err)
	}
	if g, _ := k.Flow(k.ctx, f.Token); len(g.Offers) != 0 || g.Unlinked == nil {
		t.Errorf("the unlinked flow: %+v", g)
	}

	// A new user's linked proof keeps its address: with a code to that
	// mailbox it is one factor.
	k = newIdPKit(t, &fakeIdP{email: "nine@toyshop.example"})
	k.dir.mu.Lock()
	k.dir.addrs["u9"][ChannelEmail] = "nine@toyshop.example"
	k.dir.mu.Unlock()
	f = k.unlinked(t, "oidc_test", "sub-9")
	f, err := k.Link(k.ctx, f.Token, "u9")
	if err != nil && !errors.Is(err, ErrCannotVerify) {
		t.Fatal(err)
	}
	k.clock.advance(time.Minute)
	k.Challenge(k.ctx, f.Token, MethodEmailCode)
	if f, _ = k.Prove(k.ctx, f.Token, EmailCode(k.lastCode(t, "nine@toyshop.example"))); f.Verified {
		t.Error("a linked proof and a code to its mailbox made two factors")
	}

	// The flow started again and proved another identity while Link read
	// the directory: Link refuses, linking neither.
	k = newIdPKit(t, &fakeIdP{}, WithPolicy(allowUnverified))
	k.addUser(t, "new7", User{ID: "u7", Name: "seven"}, "")
	f = k.unlinked(t, "oidc_test", "sub-1")
	g := k.unlinked(t, "oidc_test", "sub-1")
	if _, err := k.Link(k.ctx, g.Token, "u8"); err != nil {
		t.Fatal(err)
	}
	k.dir.onGet = func() {
		if _, err := k.Link(k.ctx, f.Token, "u7"); !errors.Is(err, ErrBadCredentials) {
			t.Errorf("the inner Link: %v", err)
		}
		if h, err := k.proveIdP(t, k.ctx, f.Token, "oidc_test", "sub-2"); err != nil || h.Unlinked == nil {
			t.Errorf("proving sub-2: %+v %v", h, err)
		}
	}
	if _, err := k.Link(k.ctx, f.Token, "u9"); !errors.Is(err, ErrMethodUnavailable) {
		t.Errorf("Link after the flow changed: %v", err)
	}
	if owner, linked := k.findIdentity(t, "sub-2"); linked {
		t.Errorf("sub-2 linked to %s", owner)
	}
}

// Identities lists identities alone; Unlink takes only an identity of the
// user's, from a session fresh enough to change factors.
func TestUnlinkEdges(t *testing.T) {
	k := newIdPKit(t, &fakeIdP{})
	k.clock.advance(time.Minute)
	res := twoFactorSignIn(t, k, nil)
	ctx := withSession(k.ctx, res.Session)
	k.addKey(t, "u1", "oidc_test", idpIssuer+"\x00sara")
	absent := "oidc_test:" + strings.Repeat("ab", 32)
	if err := k.Unlink(ctx, res.Session, absent); !errors.Is(err, ErrMethodUnavailable) {
		t.Errorf("an absent identity: %v", err)
	}
	k.addKey(t, "u1", MethodPasskey, "sara-key")
	ids, _ := k.Identities(k.ctx, "u1")
	if len(ids) != 1 || ids[0].Method != "oidc_test" {
		t.Fatalf("identities: %+v", ids)
	}
	fs, _ := k.Factors(k.ctx, "u1")
	if err := k.Unlink(ctx, res.Session, fs[0].ID); !errors.Is(err, ErrMethodUnavailable) {
		t.Errorf("a passkey through Unlink: %v", err)
	}
	if fs2, _ := k.Factors(k.ctx, "u1"); len(fs2) != 1 {
		t.Errorf("the passkey went: %+v", fs2)
	}
	k.clock.advance(time.Hour)
	if err := k.Unlink(ctx, res.Session, ids[0].ID); !errors.Is(err, ErrStale) || k.lastReason(t, "factor.refused") != "stale" {
		t.Errorf("a stale session: %v", err)
	}
}

// Review 0025: a proof racing an unlinked one can't leave another user's
// proof for Link; a result naming a user and an unlinked identity is the
// method's own failure; Link refuses a flow that knows someone.
func TestLinkRaces(t *testing.T) {
	idp := &fakeIdP{name: "oidc_test"}
	pk := &fakeMethod{name: MethodPasskey, verified: true, addrOnly: true}
	k := newKit(t, WithMethods(idp, pk), WithFirst(MethodPassword, MethodPasskey, "oidc_test"), WithPolicy(allowUnverified))
	k.addUser(t, "sara", User{ID: "u1", Name: "sara"}, goodPassword, saraMail)
	k.addUser(t, "new9", User{ID: "u9", Name: "nine"}, "")
	k.addKey(t, "u1", MethodPasskey, "sara-1")

	// Sara's passkey lands while the unlinked identity is verified.
	f, _ := k.SignInWithout(k.ctx, Cookie())
	pch := k.challenge(t, k.ctx, f.Token, MethodPasskey)
	idp.afterFind = func() {
		idp.afterFind = nil
		if _, err := k.Prove(k.ctx, f.Token, fakeProof{method: MethodPasskey, challenge: pch, key: "sara-1"}); err != nil {
			t.Errorf("sara's passkey: %v", err)
		}
	}
	if g, err := k.proveIdP(t, k.ctx, f.Token, "oidc_test", "sub-r"); !errors.Is(err, ErrMethodUnavailable) || g.Unlinked != nil {
		t.Errorf("an unlinked proof after another user's: %+v %v", g, err)
	}
	if _, err := k.Link(k.ctx, f.Token, "u9"); !errors.Is(err, ErrMethodUnavailable) {
		t.Errorf("Link: %v", err)
	}

	// The other way round: the identity is kept while the passkey is
	// verified; the passkey is then refused.
	f, _ = k.SignInWithout(k.ctx, Cookie())
	pch = k.challenge(t, k.ctx, f.Token, MethodPasskey)
	ich := k.challenge(t, k.ctx, f.Token, "oidc_test")
	pk.verify = func(in MethodInput, p fakeProof) (MethodResult, error) {
		pk.verify = nil
		if g, err := k.Prove(k.ctx, f.Token, idpProof{method: "oidc_test", challenge: ich, subject: "sub-s"}); err != nil || g.Unlinked == nil {
			t.Errorf("the identity: %+v %v", g, err)
		}
		owner, c, _ := in.Find([]byte(p.key))
		return MethodResult{User: owner, Credential: c, Verified: true}, nil
	}
	if _, err := k.Prove(k.ctx, f.Token, fakeProof{method: MethodPasskey, challenge: pch, key: "sara-1"}); !errors.Is(err, ErrMethodUnavailable) {
		t.Errorf("a passkey on a flow holding an identity: %v", err)
	}
	if g, _ := k.Flow(k.ctx, f.Token); g.Unlinked == nil {
		t.Error("the identity went")
	}

	// A result naming a user and an unlinked identity.
	idp.both = true
	f, _ = k.SignInWithout(k.ctx, Cookie())
	if _, err := k.proveIdP(t, k.ctx, f.Token, "oidc_test", "sub-b"); err == nil || errors.Is(err, ErrBadCredentials) {
		t.Errorf("both: %v", err)
	}
	idp.both = false

	// Link refuses a flow holding an identity that knows someone.
	f = k.unlinked(t, "oidc_test", "sub-p")
	k.db.Update(func(tx *bolt.Tx) error {
		var rec storepb.Flow
		key := secrets.Hash(f.Token)
		store.Get(tx, store.Flows, key, &rec)
		rec.UserId = "u1"
		return store.Put(tx, store.Flows, key, &rec)
	})
	if _, err := k.Link(k.ctx, f.Token, "u9"); !errors.Is(err, ErrMethodUnavailable) {
		t.Errorf("Link on a flow that knows someone: %v", err)
	}
}
