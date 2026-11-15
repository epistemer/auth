package auth

import (
	"bytes"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/epistemer/errors"
	bolt "go.etcd.io/bbolt"

	"github.com/epistemer/auth/internal/store"
	"github.com/epistemer/auth/internal/storepb"
)

const newPassword = "violet comet hums 83 bells"

// lastMessage returns the last message sent to an address.
func (k *kit) lastMessage(t *testing.T, to string) Message {
	t.Helper()
	k.out.mu.Lock()
	defer k.out.mu.Unlock()
	for i := len(k.out.sent) - 1; i >= 0; i-- {
		if k.out.sent[i].To == to {
			return k.out.sent[i]
		}
	}
	t.Fatalf("nothing sent to %s", to)
	return Message{}
}

// recoverLink starts a recovery for login and asks for a link.
func recoverLink(t *testing.T, k *kit, login string) Flow {
	t.Helper()
	f, err := k.Recover(k.ctx, login)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := k.Challenge(k.ctx, f.Token, MethodEmailLink); err != nil {
		t.Fatal(err)
	}
	return f
}

// §5.1.7, §5.1.10, §5.3.6, §7: a recovery by link. Follow twice returns
// the same flow; a weak password leaves it usable; Finish sets the password,
// makes no session, ends the user's sessions and sends MsgPasswordChanged;
// then the link is ErrBadCode.
func TestRecoverByLink(t *testing.T) {
	k := newKit(t, WithPolicy(allowUnverified))
	k.addUser(t, "sara", User{ID: "u1", Name: "sara"}, goodPassword, saraMail)
	f, _ := k.signIn(t, "sara", goodPassword)
	old, err := k.Finish(k.ctx, f.Token)
	if err != nil {
		t.Fatal(err)
	}

	r, err := k.Recover(k.ctx, "sara")
	if err != nil || r.Ready || strings.Join(r.Offers, ",") != "email_link,email_code,sms_code" {
		t.Fatalf("Recover: %+v %v", r, err)
	}
	c, err := k.Challenge(k.ctx, r.Token, MethodEmailLink)
	if err != nil || c.SentTo != "" {
		t.Fatalf("Challenge: %+v %v", c, err)
	}
	m := k.lastMessage(t, saraMail)
	if m.Kind != MsgRecoveryLink || m.Token == "" || m.Code != "" || !m.Expires.Equal(k.clock.now().Add(30*time.Minute)) {
		t.Fatalf("message %+v", m)
	}
	got, err := k.Follow(k.ctx, m.Token)
	if err != nil || got.Token == "" || got.Token == r.Token || !got.Ready || got.Purpose != PurposeRecover {
		t.Fatalf("Follow: %+v %v", got, err)
	}
	again, err := k.Follow(k.ctx, m.Token)
	if err != nil || again.Token != got.Token {
		t.Fatalf("Follow twice: %+v %v", again, err)
	}
	// Whoever started the recovery holds a token that no longer works.
	if _, err := k.Finish(k.ctx, r.Token, NewPassword(newPassword)); !errors.Is(err, ErrFlowExpired) {
		t.Errorf("Finish with the starter's token: %v", err)
	}
	r = got
	if _, err := k.Finish(k.ctx, r.Token); !errors.Is(err, ErrPasswordRequired) {
		t.Errorf("Finish without a password: %v", err)
	}
	if _, err := k.Finish(k.ctx, r.Token, NewPassword("password1234")); !errors.Is(err, ErrPasswordCommon) {
		t.Errorf("Finish with a weak password: %v", err)
	}
	if _, err := k.Flow(k.ctx, r.Token); err != nil {
		t.Errorf("a weak password spent the flow: %v", err)
	}
	n := k.sentCount()
	res, err := k.Finish(k.ctx, r.Token, NewPassword(newPassword))
	if err != nil || res.Session != nil || res.cookie != "" {
		t.Fatalf("Finish: %+v %v", res, err)
	}
	if k.sentCount() != n+1 || k.lastMessage(t, saraMail).Kind != MsgPasswordChanged {
		t.Error("no MsgPasswordChanged")
	}
	if _, err := k.StepUp(k.ctx, old.Session); !errors.Is(err, ErrNoSession) {
		t.Errorf("the old session lives on: %v", err)
	}
	if _, err := k.signIn(t, "sara", newPassword); err != nil {
		t.Errorf("signing in with the new password: %v", err)
	}
	if _, err := k.Follow(k.ctx, m.Token); !errors.Is(err, ErrBadCode) {
		t.Errorf("the link after Finish: %v", err)
	}
	if _, err := k.Finish(k.ctx, r.Token, NewPassword(newPassword)); !errors.Is(err, ErrFlowExpired) {
		t.Errorf("the flow after Finish: %v", err)
	}
	if _, err := k.Follow(k.ctx, "made-up"); !errors.Is(err, ErrBadCode) {
		t.Errorf("a made-up link: %v", err)
	}
	r2 := recoverLink(t, k, "sara")
	_ = r2
	link := k.lastMessage(t, saraMail).Token
	k.clock.advance(31 * time.Minute)
	if _, err := k.Follow(k.ctx, link); !errors.Is(err, ErrBadCode) {
		t.Errorf("an expired link: %v", err)
	}
}

// A recovery by code: the code is the first proof.
func TestRecoverByCode(t *testing.T) {
	k := newKit(t)
	k.addUser(t, "sara", User{ID: "u1", Name: "sara"}, goodPassword, saraMail, saraPhone)
	r, _ := k.Recover(k.ctx, "sara")
	k.Challenge(k.ctx, r.Token, MethodSMSCode)
	m := k.lastMessage(t, saraPhone)
	if m.Kind != MsgRecoveryCode {
		t.Fatalf("message %+v", m)
	}
	r, err := k.Prove(k.ctx, r.Token, SMSCode(m.Code))
	if err != nil || !r.Ready {
		t.Fatalf("Prove: %+v %v", r, err)
	}
	if res, err := k.Finish(k.ctx, r.Token, NewPassword(newPassword)); err != nil || res.Session != nil {
		t.Fatalf("Finish: %+v %v", res, err)
	}
}

// §7, enumeration: Recover and Challenge answer alike for a known and an
// unknown login, and only the known one is sent a message.
func TestRecoverEnumeration(t *testing.T) {
	k := newKit(t)
	k.addUser(t, "sara", User{ID: "u1", Name: "sara"}, goodPassword, saraMail)
	k.addUser(t, "noaddr", User{ID: "u2", Name: "noaddr"}, goodPassword)
	type answer struct {
		ready     bool
		offers    string
		life      time.Duration
		challenge Challenge
	}
	ask := func(login string) (answer, int) {
		r, err := k.Recover(k.ctx, login)
		if err != nil {
			t.Fatal(err)
		}
		n := k.sentCount()
		c, err := k.Challenge(k.ctx, r.Token, MethodEmailLink)
		if err != nil {
			t.Fatal(err)
		}
		return answer{r.Ready, strings.Join(r.Offers, ","), r.Expires.Sub(k.clock.now()), c}, k.sentCount() - n
	}
	want, sent := ask("sara")
	if sent != 1 {
		t.Fatal("sara was sent nothing")
	}
	for _, login := range []string{"ghost", "noaddr"} {
		if got, sent := ask(login); got != want || sent != 0 {
			t.Errorf("%s: %+v, %d sent; sara %+v", login, got, sent, want)
		}
	}
}

// M2.2's done-when: a recovery for a user with a second factor enrolled
// doesn't finish on the emailed proof alone, link or code; a second message
// to an address isn't offered.
func TestRecoverNeedsEnrolledFactor(t *testing.T) {
	k := newKit(t)
	k.addUser(t, "sara", User{ID: "u1", Name: "sara"}, goodPassword, saraMail, saraPhone)
	// A TOTP credential, as M4 will store one.
	key := append(store.Key([]byte("u1"), []byte(MethodTOTP)), append([]byte{0}, store.CredKey([]byte("app"))...)...)
	if err := k.db.Update(func(tx *bolt.Tx) error {
		return store.Put(tx, store.Credentials, key, &storepb.Credential{Method: MethodTOTP})
	}); err != nil {
		t.Fatal(err)
	}
	// Ask for a link and a code before any proof, as an attacker with the
	// mailbox could; neither alone, nor both, makes the flow ready.
	r, _ := k.Recover(k.ctx, "sara")
	k.Challenge(k.ctx, r.Token, MethodEmailLink)
	link := k.lastMessage(t, saraMail).Token
	k.Challenge(k.ctx, r.Token, MethodSMSCode)
	f, err := k.Follow(k.ctx, link)
	if err != nil || f.Ready || strings.Join(f.Offers, ",") != MethodTOTP {
		t.Fatalf("after the link: %+v %v", f, err)
	}
	if _, err := k.Challenge(k.ctx, f.Token, MethodSMSCode); !errors.Is(err, ErrMethodUnavailable) {
		t.Errorf("a second message offered: %v", err)
	}
	if _, err := k.Prove(k.ctx, f.Token, SMSCode(k.lastCode(t, saraPhone))); !errors.Is(err, ErrMethodUnavailable) {
		t.Errorf("a texted code after the link: %v", err)
	}
	if _, err := k.Finish(k.ctx, f.Token, NewPassword(newPassword)); !errors.Is(err, ErrNotReady) {
		t.Errorf("Finish on the link alone: %v", err)
	}
	// By code, the same.
	r2, _ := k.Recover(k.ctx, "sara")
	k.clock.advance(time.Minute)
	k.Challenge(k.ctx, r2.Token, MethodEmailCode)
	f2, err := k.Prove(k.ctx, r2.Token, EmailCode(k.lastCode(t, saraMail)))
	if err != nil || f2.Ready {
		t.Errorf("after an emailed code: %+v %v", f2, err)
	}
	// An invitation is held to the same rule.
	inv, _ := k.Invite(k.ctx, "u1")
	if a, err := k.Accept(k.ctx, inv); err != nil || a.Ready {
		t.Errorf("an invitation for a user with a factor: %+v %v", a, err)
	}
}

// A new link cancels the last; a link outlives its flow, which it starts
// again, up to its own lifetime.
func TestLinkLifecycle(t *testing.T) {
	k := newKit(t)
	k.addUser(t, "sara", User{ID: "u1", Name: "sara"}, goodPassword, saraMail)
	r := recoverLink(t, k, "sara")
	first := k.lastMessage(t, saraMail).Token
	k.clock.advance(time.Minute)
	k.Challenge(k.ctx, r.Token, MethodEmailLink)
	second := k.lastMessage(t, saraMail).Token
	if _, err := k.Follow(k.ctx, first); !errors.Is(err, ErrBadCode) {
		t.Errorf("a replaced link: %v", err)
	}
	f0, err := k.Follow(k.ctx, second)
	if err != nil || !f0.Ready {
		t.Fatalf("the newer link: %+v %v", f0, err)
	}
	// Following again refreshes the flow's lifetime, up to the link's.
	k.clock.advance(10 * time.Minute)
	if f1, err := k.Follow(k.ctx, second); err != nil || f1.Token != f0.Token || !f1.Expires.Equal(k.clock.now().Add(15*time.Minute)) {
		t.Fatalf("following again: %+v %v", f1, err)
	}
	k.clock.advance(16 * time.Minute) // the flow is gone; the link isn't
	f, err := k.Follow(k.ctx, second)
	if err != nil || f.Token == f0.Token || !f.Ready {
		t.Fatalf("a link past its flow: %+v %v", f, err)
	}
	// The link sent at 1m lives to 31m: the flow it starts at 27m ends then.
	if !f.Expires.Equal(time.Date(2026, 11, 15, 9, 31, 0, 0, time.UTC)) {
		t.Errorf("a flow outliving its link: %v", f.Expires)
	}
	again, err := k.Follow(k.ctx, second)
	if err != nil || again.Token != f.Token {
		t.Errorf("Follow twice after a new flow: %+v %v", again, err)
	}
	if _, err := k.Finish(k.ctx, f.Token, NewPassword(newPassword)); err != nil {
		t.Fatal(err)
	}
	if _, err := k.Follow(k.ctx, second); !errors.Is(err, ErrBadCode) {
		t.Errorf("the link after Finish: %v", err)
	}
}

// §5.1.8: an invitation. Accept twice returns the same flow; Finish sets the
// password and makes no session; then the invitation is ErrBadCode. An
// invitation isn't a recovery link, nor the other way round.
func TestInviteAccept(t *testing.T) {
	k := newKit(t, WithPolicy(allowUnverified))
	k.addUser(t, "sara", User{ID: "u1", Name: "sara"}, "", saraMail)
	token, err := k.Invite(k.ctx, "u1")
	if err != nil {
		t.Fatal(err)
	}
	m := k.lastMessage(t, saraMail)
	if m.Kind != MsgInvitation || m.Token != token || !m.Expires.Equal(k.clock.now().Add(72*time.Hour)) {
		t.Fatalf("message %+v", m)
	}
	if _, err := k.Follow(k.ctx, token); !errors.Is(err, ErrBadCode) {
		t.Errorf("Follow of an invitation: %v", err)
	}
	f, err := k.Accept(k.ctx, token)
	if err != nil || !f.Ready || f.Purpose != PurposeAccept {
		t.Fatalf("Accept: %+v %v", f, err)
	}
	if again, err := k.Accept(k.ctx, token); err != nil || again.Token != f.Token {
		t.Fatalf("Accept twice: %+v %v", again, err)
	}
	n := k.sentCount()
	res, err := k.Finish(k.ctx, f.Token, NewPassword(newPassword))
	if err != nil || res.Session != nil {
		t.Fatalf("Finish: %+v %v", res, err)
	}
	if k.sentCount() != n {
		t.Error("a first password sent a notice")
	}
	if _, err := k.signIn(t, "sara", newPassword); err != nil {
		t.Errorf("signing in: %v", err)
	}
	if _, err := k.Accept(k.ctx, token); !errors.Is(err, ErrBadCode) {
		t.Errorf("Accept after Finish: %v", err)
	}
	// A recovery link isn't an invitation.
	recoverLink(t, k, "sara")
	if _, err := k.Accept(k.ctx, k.lastMessage(t, saraMail).Token); !errors.Is(err, ErrBadCode) {
		t.Errorf("Accept of a recovery link: %v", err)
	}
	// An invitation past its lifetime.
	late, _ := k.Invite(k.ctx, "u1")
	k.clock.advance(73 * time.Hour)
	if _, err := k.Accept(k.ctx, late); !errors.Is(err, ErrBadCode) {
		t.Errorf("an expired invitation: %v", err)
	}
}

// A disabled user is refused at Follow, Accept and Finish, after the proof.
func TestRecoverDisabled(t *testing.T) {
	k := newKit(t)
	k.addUser(t, "sara", User{ID: "u1", Name: "sara", Disabled: true}, goodPassword, saraMail)
	r := recoverLink(t, k, "sara")
	if f, err := k.Follow(k.ctx, k.lastMessage(t, saraMail).Token); !errors.Is(err, ErrUserDisabled) || f.Token != "" {
		t.Errorf("Follow: %+v %v", f, err)
	}
	// Finish of a recovery proved by code, for a user disabled since.
	r2, _ := k.Recover(k.ctx, "sara")
	k.clock.advance(time.Minute)
	k.Challenge(k.ctx, r2.Token, MethodEmailCode)
	k.dir.mu.Lock()
	k.dir.users["sara"] = User{ID: "u1", Name: "sara"}
	k.dir.mu.Unlock()
	if _, err := k.Prove(k.ctx, r2.Token, EmailCode(k.lastCode(t, saraMail))); err != nil {
		t.Fatal(err)
	}
	k.dir.mu.Lock()
	k.dir.users["sara"] = User{ID: "u1", Name: "sara", Disabled: true}
	k.dir.mu.Unlock()
	if _, err := k.Finish(k.ctx, r2.Token, NewPassword(newPassword)); !errors.Is(err, ErrUserDisabled) {
		t.Errorf("Finish: %v", err)
	}
	_ = r
	token, _ := k.Invite(k.ctx, "u1")
	if _, err := k.Accept(k.ctx, token); !errors.Is(err, ErrUserDisabled) {
		t.Errorf("Accept: %v", err)
	}
}

// §7: the store holds no link or invitation token as it was sent, and no
// flow token.
func TestStoreHoldsNoLink(t *testing.T) {
	k := newKit(t)
	k.addUser(t, "sara", User{ID: "u1", Name: "sara"}, goodPassword, saraMail)
	r := recoverLink(t, k, "sara")
	link := k.lastMessage(t, saraMail).Token
	f, _ := k.Follow(k.ctx, link)
	k.addUser(t, "omar", User{ID: "u2", Name: "omar"}, "", "omar@toyshop.example")
	inv, _ := k.Invite(k.ctx, "u2")
	a, _ := k.Accept(k.ctx, inv)
	k.db.View(func(tx *bolt.Tx) error {
		return tx.ForEach(func(_ []byte, b *bolt.Bucket) error {
			return walk(b, func(key, v []byte) {
				for _, s := range []string{link, inv, r.Token, f.Token, a.Token} {
					if bytes.Contains(key, []byte(s)) || bytes.Contains(v, []byte(s)) {
						t.Errorf("the store holds a token")
					}
				}
			})
		})
	})
}

// Of two Finishes of one recovery, one wins.
func TestRecoverFinishOnce(t *testing.T) {
	k := newKit(t)
	k.addUser(t, "sara", User{ID: "u1", Name: "sara"}, goodPassword, saraMail)
	recoverLink(t, k, "sara")
	r, err := k.Follow(k.ctx, k.lastMessage(t, saraMail).Token)
	if err != nil {
		t.Fatal(err)
	}
	errs := make(chan error, 2)
	for _, pw := range []string{newPassword, "amber falcon sings 52 hymns"} {
		go func() {
			_, err := k.Finish(k.ctx, r.Token, NewPassword(pw))
			errs <- err
		}()
	}
	got := []error{<-errs, <-errs}
	if slices.IndexFunc(got, func(e error) bool { return e == nil }) < 0 || got[0] == nil && got[1] == nil {
		t.Errorf("Finish twice: %v", got)
	}
}

// Review 0009, finding 1: whoever starts a recovery can't finish it when
// someone else, or their mail scanner, follows the link.
func TestRecoverStarterCantFinish(t *testing.T) {
	k := newKit(t)
	k.addUser(t, "sara", User{ID: "u1", Name: "sara"}, goodPassword, saraMail)
	attacker := recoverLink(t, k, "sara")
	k.Follow(k.ctx, k.lastMessage(t, saraMail).Token) // the mail scanner
	if _, err := k.Finish(k.ctx, attacker.Token, NewPassword(newPassword)); !errors.Is(err, ErrFlowExpired) {
		t.Errorf("the starter finished: %v", err)
	}
	if f, err := k.Flow(k.ctx, attacker.Token); err == nil {
		t.Errorf("the starter can still see the flow: %+v", f)
	}
}

// A link or a recovery flow older than the user's password is stale: one
// finished recovery or invitation ends the others.
func TestStaleLinks(t *testing.T) {
	k := newKit(t)
	k.addUser(t, "sara", User{ID: "u1", Name: "sara"}, goodPassword, saraMail)
	inv, _ := k.Invite(k.ctx, "u1")
	recoverLink(t, k, "sara")
	old := k.lastMessage(t, saraMail).Token
	held, _ := k.Follow(k.ctx, old)
	k.clock.advance(time.Minute)
	recoverLink(t, k, "sara")
	f, _ := k.Follow(k.ctx, k.lastMessage(t, saraMail).Token)
	if _, err := k.Finish(k.ctx, f.Token, NewPassword(newPassword)); err != nil {
		t.Fatal(err)
	}
	if _, err := k.Follow(k.ctx, old); !errors.Is(err, ErrBadCode) {
		t.Errorf("an older link: %v", err)
	}
	if _, err := k.Finish(k.ctx, held.Token, NewPassword("amber falcon sings 52 hymns")); !errors.Is(err, ErrNotReady) {
		t.Errorf("an older flow: %v", err)
	}
	if _, err := k.Accept(k.ctx, inv); !errors.Is(err, ErrBadCode) {
		t.Errorf("an older invitation: %v", err)
	}
}

// §5.1.10: a recovery ends the user's sessions also when they had no
// password to replace.
func TestRecoverEndsSessionsWithoutPassword(t *testing.T) {
	k := newKit(t, WithPolicy(allowUnverified), WithFirst(MethodPassword, MethodEmailCode))
	k.addUser(t, "sara", User{ID: "u1", Name: "sara"}, "", saraMail)
	f, _ := k.SignIn(k.ctx, "sara", Cookie())
	k.Challenge(k.ctx, f.Token, MethodEmailCode)
	f, err := k.Prove(k.ctx, f.Token, EmailCode(k.lastCode(t, saraMail)))
	if err != nil {
		t.Fatal(err)
	}
	s, err := k.Finish(k.ctx, f.Token)
	if err != nil {
		t.Fatal(err)
	}
	k.clock.advance(time.Minute)
	recoverLink(t, k, "sara")
	r, _ := k.Follow(k.ctx, k.lastMessage(t, saraMail).Token)
	if _, err := k.Finish(k.ctx, r.Token, NewPassword(newPassword)); err != nil {
		t.Fatal(err)
	}
	if _, err := k.StepUp(k.ctx, s.Session); !errors.Is(err, ErrNoSession) {
		t.Errorf("a session outlived the recovery: %v", err)
	}
}

// A flow a link started can't be finished once the link has expired.
func TestFinishAfterLinkExpiry(t *testing.T) {
	k := newKitWith(t, func(c *config) { c.flow = time.Hour })
	k.addUser(t, "sara", User{ID: "u1", Name: "sara"}, goodPassword, saraMail)
	recoverLink(t, k, "sara")
	f, _ := k.Follow(k.ctx, k.lastMessage(t, saraMail).Token)
	if !f.Expires.Equal(k.clock.now().Add(30 * time.Minute)) {
		t.Errorf("flow expires %v; want the link's 30m", f.Expires)
	}
	k.clock.advance(31 * time.Minute)
	if _, err := k.Finish(k.ctx, f.Token, NewPassword(newPassword)); err == nil {
		t.Error("finished after the link expired")
	}
}

// An invitation that couldn't be sent says so.
func TestInviteNotSent(t *testing.T) {
	k := newKit(t)
	k.addUser(t, "sara", User{ID: "u1", Name: "sara"}, "")
	if _, err := k.Invite(k.ctx, "u1"); err != nil {
		t.Fatal(err)
	}
	if e := k.events.all[len(k.events.all)-1]; e.Kind != "message.not_sent" || e.Reason != "no_address" {
		t.Errorf("event %+v", e)
	}
}

// Finish needs the link a flow was proved by: gone, it refuses.
func TestFinishNeedsItsLink(t *testing.T) {
	k := newKit(t)
	k.addUser(t, "sara", User{ID: "u1", Name: "sara"}, goodPassword, saraMail)
	recoverLink(t, k, "sara")
	link := k.lastMessage(t, saraMail).Token
	f, _ := k.Follow(k.ctx, link)
	k.db.Update(func(tx *bolt.Tx) error { return store.Delete(tx, store.Links, hashOf(link)) })
	if _, err := k.Finish(k.ctx, f.Token, NewPassword(newPassword)); !errors.Is(err, ErrNotReady) {
		t.Errorf("Finish without its link: %v", err)
	}
}

// A Challenge that read the offers before the first proof sends nothing
// once the proof is made: the transaction checks again.
func TestChallengeRechecksOffers(t *testing.T) {
	k := newKit(t)
	k.addUser(t, "sara", User{ID: "u1", Name: "sara"}, goodPassword, saraMail, saraPhone)
	r, _ := k.Recover(k.ctx, "sara")
	hash := hashOf(r.Token)
	stale, _ := k.loadFlow(hash)
	k.Challenge(k.ctx, r.Token, MethodEmailCode)
	if _, err := k.Prove(k.ctx, r.Token, EmailCode(k.lastCode(t, saraMail))); err != nil {
		t.Fatal(err)
	}
	n := k.sentCount()
	if _, err := k.challengeCode(k.ctx, r.Token, hash, stale, MethodSMSCode, ChannelSMS); !errors.Is(err, ErrMethodUnavailable) {
		t.Errorf("a Challenge read before the proof: %v", err)
	}
	if k.sentCount() != n {
		t.Error("it sent a message")
	}
}

// Sweep removes links and invitations past their lifetime.
func TestSweepLinks(t *testing.T) {
	k := newKit(t)
	k.addUser(t, "sara", User{ID: "u1", Name: "sara"}, goodPassword, saraMail)
	recoverLink(t, k, "sara")
	k.Invite(k.ctx, "u1")
	count := func() int {
		n := 0
		k.db.View(func(tx *bolt.Tx) error {
			return store.B(tx, store.Links).ForEach(func(_, _ []byte) error { n++; return nil })
		})
		return n
	}
	k.clock.advance(time.Hour)
	k.Sweep(k.ctx)
	if count() != 1 {
		t.Errorf("%d links after an hour; want the invitation", count())
	}
	k.clock.advance(72 * time.Hour)
	k.Sweep(k.ctx)
	if count() != 0 {
		t.Errorf("%d links after the invitation's lifetime", count())
	}
}
