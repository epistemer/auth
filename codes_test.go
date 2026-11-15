package auth

import (
	"bytes"
	"fmt"
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

const (
	saraMail  = "sara@toyshop.example"
	saraPhone = "+1 555 010 0042"
)

// lastCode returns the code last sent to an address.
func (k *kit) lastCode(t *testing.T, to string) string {
	t.Helper()
	k.out.mu.Lock()
	defer k.out.mu.Unlock()
	for i := len(k.out.sent) - 1; i >= 0; i-- {
		if k.out.sent[i].To == to {
			return k.out.sent[i].Code
		}
	}
	t.Fatalf("nothing sent to %s", to)
	return ""
}

func (k *kit) sentCount() int {
	k.out.mu.Lock()
	defer k.out.mu.Unlock()
	return len(k.out.sent)
}

// passwordFirst signs sara in with her password and returns the flow,
// which waits for a second proof.
func passwordFirst(t *testing.T, k *kit) Flow {
	t.Helper()
	f, err := k.signIn(t, "sara", goodPassword)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// §5.7.2: a user with no enrolled factor proves a code sent to an address
// as the second proof, and the session is verified.
func TestCodeAsSecondProof(t *testing.T) {
	k := newKit(t)
	k.addUser(t, "sara", User{ID: "u1", Name: "sara"}, goodPassword, saraMail, saraPhone)
	f := passwordFirst(t, k)
	if f.Ready || f.Verified || strings.Join(f.Offers, ",") != "email_code,sms_code" {
		t.Fatalf("after the password: %+v", f)
	}
	c, err := k.Challenge(k.ctx, f.Token, MethodEmailCode)
	if err != nil {
		t.Fatal(err)
	}
	if c.SentTo != "s•••@toyshop.example" || !c.Resend.Equal(k.clock.now().Add(time.Minute)) {
		t.Errorf("challenge %+v", c)
	}
	m := k.out.sent[len(k.out.sent)-1]
	if m.Kind != MsgSignInCode || m.Channel != ChannelEmail || m.User != "u1" || len(m.Code) != 6 || !m.Expires.Equal(k.clock.now().Add(5*time.Minute)) {
		t.Errorf("message %+v", m)
	}
	wrongOne := "000000"
	if m.Code == wrongOne {
		wrongOne = "000001"
	}
	if _, err := k.Prove(k.ctx, f.Token, EmailCode(wrongOne)); !errors.Is(err, ErrBadCode) {
		t.Errorf("a wrong code: %v", err)
	}
	f, err = k.Prove(k.ctx, f.Token, EmailCode(m.Code))
	if err != nil || !f.Ready || !f.Verified {
		t.Fatalf("the right code: %+v %v", f, err)
	}
	res, err := k.Finish(k.ctx, f.Token)
	if err != nil || !res.Session.Verified {
		t.Fatalf("Finish: %+v %v", res.Session, err)
	}
	// A phone's code works the same way.
	f = passwordFirst(t, k)
	if c, _ := k.Challenge(k.ctx, f.Token, MethodSMSCode); c.SentTo != "•••42" {
		t.Errorf("SMS SentTo %q", c.SentTo)
	}
	if f, err = k.Prove(k.ctx, f.Token, SMSCode(k.lastCode(t, saraPhone))); err != nil || !f.Verified {
		t.Errorf("SMS code: %+v %v", f, err)
	}
}

// §5.7.2: two proofs that reach the user through one address count as one.
// A sign-in by an emailed code offers no emailed code second.
func TestOneAddressOneFactor(t *testing.T) {
	k := newKit(t, WithFirst(MethodPassword, MethodEmailCode))
	k.addUser(t, "sara", User{ID: "u1", Name: "sara"}, goodPassword, saraMail)
	f, err := k.SignIn(k.ctx, "sara", Cookie())
	if err != nil {
		t.Fatal(err)
	}
	c, err := k.Challenge(k.ctx, f.Token, MethodEmailCode)
	if err != nil || c.SentTo != "" {
		t.Fatalf("before the first proof: %+v %v", c, err)
	}
	f, err = k.Prove(k.ctx, f.Token, EmailCode(k.lastCode(t, saraMail)))
	if !errors.Is(err, ErrCannotVerify) || f.Verified || len(f.Offers) != 0 {
		t.Errorf("an emailed code with only that address: %+v %v", f, err)
	}
	ch := channelKey(saraMail)
	same := []*storepb.Factor{{Method: MethodEmailCode, Channel: ch}, {Method: MethodSMSCode, Channel: ch}}
	if k.twoFactors(same) {
		t.Error("two proofs through one address made two factors")
	}
	same[1].Channel = channelKey(saraPhone)
	if !k.twoFactors(same) {
		t.Error("two addresses made one factor")
	}
}

// §7, codes: a code is refused after code.tries wrong tries, in another
// flow, after its lifetime, and the second time.
func TestCodeRefusals(t *testing.T) {
	k := newKitWith(t, func(c *config) { c.free = 20 })
	k.addUser(t, "sara", User{ID: "u1", Name: "sara"}, goodPassword, saraMail)
	wrongCode := func(c string) string {
		if c == "123456" {
			return "654321"
		}
		return "123456"
	}

	f := passwordFirst(t, k)
	k.Challenge(k.ctx, f.Token, MethodEmailCode)
	code := k.lastCode(t, saraMail)
	for i := range 5 {
		if _, err := k.Prove(k.ctx, f.Token, EmailCode(wrongCode(code))); !errors.Is(err, ErrBadCode) {
			t.Fatalf("wrong try %d: %v", i+1, err)
		}
	}
	if _, err := k.Prove(k.ctx, f.Token, EmailCode(code)); !errors.Is(err, ErrBadCode) {
		t.Errorf("the right code after code.tries wrong ones: %v", err)
	}

	a, b := passwordFirst(t, k), passwordFirst(t, k)
	k.clock.advance(time.Minute)
	k.Challenge(k.ctx, a.Token, MethodEmailCode)
	codeA := k.lastCode(t, saraMail)
	if _, err := k.Prove(k.ctx, b.Token, EmailCode(codeA)); !errors.Is(err, ErrBadCode) {
		t.Errorf("a code in another flow: %v", err)
	}

	k.clock.advance(5 * time.Minute)
	if _, err := k.Prove(k.ctx, a.Token, EmailCode(codeA)); !errors.Is(err, ErrBadCode) {
		t.Errorf("a code after its lifetime: %v", err)
	}

	c := passwordFirst(t, k)
	k.Challenge(k.ctx, c.Token, MethodEmailCode)
	codeC := k.lastCode(t, saraMail)
	// Prove with the view from before the first use, as a second request
	// racing the first would: it reaches the code, which is burnt.
	hc := hashOf(c.Token)
	recC, _ := k.loadFlow(hc)
	vC, _ := k.view(k.ctx, recC, nil)
	if _, err := k.proveCode(k.ctx, c.Token, hc, recC, vC, MethodEmailCode, codeC); err != nil {
		t.Fatal(err)
	}
	if _, err := k.proveCode(k.ctx, c.Token, hc, recC, vC, MethodEmailCode, codeC); !errors.Is(err, ErrBadCode) {
		t.Errorf("a code accepted the second time: %v", err)
	}
	if _, err := k.Prove(k.ctx, c.Token, EmailCode(codeC)); err == nil {
		t.Error("Prove accepted a used code's method again")
	}
	// The record says why: the code is burnt.
	rec, _ := k.loadFlow(hashOf(c.Token))
	if len(rec.Codes) != 1 || !rec.Codes[0].Burnt {
		t.Errorf("code state %+v", rec.Codes)
	}
}

// §7, codes: a second Challenge inside code.resend sends nothing; a later
// one cancels the first code.
func TestCodeResend(t *testing.T) {
	k := newKit(t)
	k.addUser(t, "sara", User{ID: "u1", Name: "sara"}, goodPassword, saraMail)
	f := passwordFirst(t, k)
	first, _ := k.Challenge(k.ctx, f.Token, MethodEmailCode)
	code := k.lastCode(t, saraMail)
	n := k.sentCount()
	k.clock.advance(30 * time.Second)
	again, err := k.Challenge(k.ctx, f.Token, MethodEmailCode)
	if err != nil || k.sentCount() != n || !again.Resend.Equal(first.Resend) || again.SentTo != first.SentTo {
		t.Fatalf("inside code.resend: %+v %v, %d sent", again, err, k.sentCount()-n)
	}
	k.clock.advance(31 * time.Second)
	if _, err := k.Challenge(k.ctx, f.Token, MethodEmailCode); err != nil || k.sentCount() != n+1 {
		t.Fatalf("after code.resend: %v", err)
	}
	next := k.lastCode(t, saraMail)
	if next == code {
		t.Skip("two draws of a 6-digit code matched, a one-in-a-million event")
	}
	if _, err := k.Prove(k.ctx, f.Token, EmailCode(code)); !errors.Is(err, ErrBadCode) {
		t.Errorf("the cancelled code: %v", err)
	}
	if _, err := k.Prove(k.ctx, f.Token, EmailCode(next)); err != nil {
		t.Errorf("the new code: %v", err)
	}
}

// §7, codes: a hundred concurrent guesses at one code get code.tries
// between them.
func TestCodeConcurrentGuesses(t *testing.T) {
	k := newKitWith(t, func(c *config) { c.free = 20 })
	k.addUser(t, "sara", User{ID: "u1", Name: "sara"}, goodPassword, saraMail)
	f := passwordFirst(t, k)
	k.Challenge(k.ctx, f.Token, MethodEmailCode)
	code := k.lastCode(t, saraMail)
	guess := "000000"
	if code == guess {
		guess = "000001"
	}
	var wg sync.WaitGroup
	for range 100 {
		wg.Go(func() { k.Prove(k.ctx, f.Token, EmailCode(guess)) })
	}
	wg.Wait()
	compared := 0
	for _, e := range k.events.all {
		if e.Kind == "proof.refused" && e.Method == MethodEmailCode && (e.Reason == "bad_code" || e.Reason == "tries") {
			compared++
		}
	}
	rec, _ := k.loadFlow(hashOf(f.Token))
	if compared != 5 || rec.Codes[0].Tries != 5 || !rec.Codes[0].Burnt {
		t.Errorf("%d guesses compared; code %+v", compared, rec.Codes[0])
	}
	k.clock.advance(2 * time.Second) // past the throttle's wait
	if _, err := k.Prove(k.ctx, f.Token, EmailCode(code)); !errors.Is(err, ErrBadCode) {
		t.Errorf("the right code after the guesses: %v", err)
	}
}

// §7, codes: the store holds no code as it was sent.
func TestStoreHoldsNoCode(t *testing.T) {
	// Ten digits, so a code can't turn up by chance in a key's hex.
	k := newKitWith(t, func(c *config) { c.codeLen = 10 })
	k.addUser(t, "sara", User{ID: "u1", Name: "sara"}, goodPassword, saraMail)
	f := passwordFirst(t, k)
	k.Challenge(k.ctx, f.Token, MethodEmailCode)
	code := k.lastCode(t, saraMail)
	k.db.View(func(tx *bolt.Tx) error {
		return tx.ForEach(func(name []byte, b *bolt.Bucket) error {
			return walk(b, func(k, v []byte) {
				for _, s := range []string{code, saraMail, f.Token} {
					if bytes.Contains(k, []byte(s)) || bytes.Contains(v, []byte(s)) {
						t.Errorf("the store holds %q", s)
					}
				}
			})
		})
	})
}

func walk(b *bolt.Bucket, f func(k, v []byte)) error {
	return b.ForEach(func(k, v []byte) error {
		if v == nil {
			return walk(b.Bucket(k), f)
		}
		f(k, v)
		return nil
	})
}

// §7, enumeration: Challenge answers alike for a known and an unknown login,
// and only the known one is sent a message. Before the first proof SentTo
// is empty, and past code.hourly it answers the same and sends nothing.
func TestChallengeEnumeration(t *testing.T) {
	k := newKit(t, WithFirst(MethodPassword, MethodEmailCode))
	k.addUser(t, "sara", User{ID: "u1", Name: "sara"}, goodPassword, saraMail)
	k.addUser(t, "noaddr", User{ID: "u2", Name: "noaddr"}, goodPassword)
	answer := func(login string) (Challenge, int) {
		f, err := k.SignIn(k.ctx, login, Cookie())
		if err != nil {
			t.Fatal(err)
		}
		n := k.sentCount()
		c, err := k.Challenge(k.ctx, f.Token, MethodEmailCode)
		if err != nil {
			t.Fatalf("%s: %v", login, err)
		}
		return c, k.sentCount() - n
	}
	want, sent := answer("sara")
	if sent != 1 || want.SentTo != "" {
		t.Fatalf("sara: %+v, %d sent", want, sent)
	}
	for _, login := range []string{"ghost", "noaddr"} {
		if c, sent := answer(login); c != want || sent != 0 {
			t.Errorf("%s: %+v, %d sent; sara %+v", login, c, sent, want)
		}
	}
	for range 4 {
		answer("sara")
	}
	if c, sent := answer("sara"); c != want || sent != 0 {
		t.Errorf("past code.hourly: %+v, %d sent", c, sent)
	}
	reasons := map[string]int{}
	for _, e := range k.events.all {
		if e.Kind == "code.not_sent" {
			reasons[e.Reason]++
		}
	}
	if reasons["no_user"] != 1 || reasons["no_address"] != 1 || reasons["hourly"] != 1 {
		t.Errorf("code.not_sent reasons %v", reasons)
	}
	// An hour later sara is sent codes again.
	k.clock.advance(time.Hour)
	if _, sent := answer("sara"); sent != 1 {
		t.Error("code.hourly didn't start again after an hour")
	}
}

// §5.3.5: code.hourly holds per address too: two users who share one get
// that many between them.
func TestHourlyPerAddress(t *testing.T) {
	k := newKit(t, WithFirst(MethodPassword, MethodEmailCode))
	shared := "family@toyshop.example"
	k.addUser(t, "sara", User{ID: "u1", Name: "sara"}, goodPassword, shared)
	k.addUser(t, "omar", User{ID: "u2", Name: "omar"}, goodPassword, shared)
	n := k.sentCount()
	for i := range 6 {
		login := []string{"sara", "omar"}[i%2]
		f, _ := k.SignIn(k.ctx, login, Cookie())
		k.Challenge(k.ctx, f.Token, MethodEmailCode)
	}
	if got := k.sentCount() - n; got != 5 {
		t.Errorf("%d sent to a shared address", got)
	}
}

// Sweep keeps a send counter for its hour, whatever throttle.window is.
func TestSweepKeepsSendCounters(t *testing.T) {
	k := newKitWith(t, func(c *config) { c.window = time.Minute }, WithFirst(MethodPassword, MethodEmailCode))
	k.addUser(t, "sara", User{ID: "u1", Name: "sara"}, goodPassword, saraMail)
	for range 5 {
		f, _ := k.SignIn(k.ctx, "sara", Cookie())
		k.Challenge(k.ctx, f.Token, MethodEmailCode)
	}
	k.clock.advance(30 * time.Minute)
	if err := k.Sweep(k.ctx); err != nil {
		t.Fatal(err)
	}
	n := k.sentCount()
	f, _ := k.SignIn(k.ctx, "sara", Cookie())
	k.Challenge(k.ctx, f.Token, MethodEmailCode)
	if k.sentCount() != n {
		t.Error("Sweep reset code.hourly within its hour")
	}
}

// A disabled user is refused with ErrUserDisabled only after the right
// code; a wrong one is ErrBadCode.
func TestCodeDisabled(t *testing.T) {
	k := newKit(t, WithFirst(MethodPassword, MethodEmailCode))
	k.addUser(t, "sara", User{ID: "u1", Name: "sara", Disabled: true}, goodPassword, saraMail)
	f, _ := k.SignIn(k.ctx, "sara", Cookie())
	k.Challenge(k.ctx, f.Token, MethodEmailCode)
	code := k.lastCode(t, saraMail)
	bad := "111111"
	if code == bad {
		bad = "222222"
	}
	if _, err := k.Prove(k.ctx, f.Token, EmailCode(bad)); !errors.Is(err, ErrBadCode) {
		t.Errorf("wrong code: %v", err)
	}
	if _, err := k.Prove(k.ctx, f.Token, EmailCode(code)); !errors.Is(err, ErrUserDisabled) {
		t.Errorf("right code: %v", err)
	}
	rec, _ := k.loadFlow(hashOf(f.Token))
	if len(rec.Proofs) != 0 {
		t.Error("a disabled user's code became a proof")
	}
}

// A code no one is sent stands in for one: an unknown login's flow has a
// code that every guess misses, counted like any other.
func TestUnknownLoginCode(t *testing.T) {
	k := newKit(t, WithFirst(MethodPassword, MethodEmailCode))
	f, _ := k.SignIn(k.ctx, "ghost", Cookie())
	k.Challenge(k.ctx, f.Token, MethodEmailCode)
	if _, err := k.Prove(k.ctx, f.Token, EmailCode("123456")); !errors.Is(err, ErrBadCode) {
		t.Errorf("a guess at no one's code: %v", err)
	}
	rec, _ := k.loadFlow(hashOf(f.Token))
	if len(rec.Codes) != 1 || rec.Codes[0].Tries != 1 || len(rec.Codes[0].Mac) != 32 {
		t.Errorf("code state %+v", rec.Codes)
	}
}

func TestMaskAndCodes(t *testing.T) {
	for in, want := range map[string]string{
		"sara@toyshop.example":  "s•••@toyshop.example",
		"شيماء@toyshop.example": "ش•••@toyshop.example",
		"+1 (555) 010-0042":     "•••42",
		"7":                     "•••",
		" Sara@ToyShop.example": "S•••@ToyShop.example",
		"sara@":                 "•••",
	} {
		ch := ChannelSMS
		if strings.Contains(in, "@") {
			ch = ChannelEmail
		}
		if got := mask(in, ch); got != want {
			t.Errorf("mask(%q) = %q; want %q", in, got, want)
		}
	}
	if !bytes.Equal(channelKey(" Sara@ToyShop.example"), channelKey("sara@toyshop.example")) ||
		!bytes.Equal(channelKey("+1 (555) 010-0042"), channelKey("+15550100042")) || channelKey("") != nil || channelKey("  ") != nil {
		t.Error("channelKey doesn't fold an address")
	}
	seen := map[byte]bool{}
	for range 200 {
		c, err := newCode(8)
		if err != nil || len(c) != 8 || strings.Trim(c, "0123456789") != "" {
			t.Fatalf("code %q, %v", c, err)
		}
		seen[c[0]] = true
	}
	if len(seen) < 8 {
		t.Errorf("first digits %v", seen)
	}
}

func hashOf(token string) []byte { return secrets.Hash(token) }

// A code is bound to its flow: its record moved into another flow verifies
// nothing there.
func TestCodeBoundToFlow(t *testing.T) {
	k := newKit(t)
	k.addUser(t, "sara", User{ID: "u1", Name: "sara"}, goodPassword, saraMail)
	a, b := passwordFirst(t, k), passwordFirst(t, k)
	k.Challenge(k.ctx, a.Token, MethodEmailCode)
	code := k.lastCode(t, saraMail)
	ra, _ := k.loadFlow(hashOf(a.Token))
	err := k.db.Update(func(tx *bolt.Tx) error {
		rb := new(storepb.Flow)
		if err := store.Get(tx, store.Flows, hashOf(b.Token), rb); err != nil {
			return err
		}
		rb.Codes = ra.Codes
		return store.Put(tx, store.Flows, hashOf(b.Token), rb)
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := k.Prove(k.ctx, b.Token, EmailCode(code)); !errors.Is(err, ErrBadCode) {
		t.Errorf("a code's record in another flow: %v", err)
	}
}

// code.tries lowered while a code lives holds at once.
func TestCodeTriesLowered(t *testing.T) {
	k := newKitWith(t, func(c *config) { c.free, c.tries = 20, 10 })
	k.addUser(t, "sara", User{ID: "u1", Name: "sara"}, goodPassword, saraMail)
	f := passwordFirst(t, k)
	k.Challenge(k.ctx, f.Token, MethodEmailCode)
	code := k.lastCode(t, saraMail)
	bad := "000000"
	if code == bad {
		bad = "000001"
	}
	for range 4 {
		k.Prove(k.ctx, f.Token, EmailCode(bad))
	}
	k.cfg.(*config).tries = 3
	if _, err := k.Prove(k.ctx, f.Token, EmailCode(code)); !errors.Is(err, ErrBadCode) {
		t.Errorf("the right code past the lowered code.tries: %v", err)
	}
}

// matchable reports whether any code of n digits matches the flow's stored
// code for method: whether it could be guessed.
func (k *kit) matchable(t *testing.T, token, method string, n int) bool {
	t.Helper()
	hash := hashOf(token)
	rec, err := k.loadFlow(hash)
	if err != nil {
		t.Fatal(err)
	}
	i := slices.IndexFunc(rec.Codes, func(c *storepb.CodeState) bool { return c.Method == method })
	if i < 0 {
		t.Fatal("no code")
	}
	limit := 1
	for range n {
		limit *= 10
	}
	for c := range limit {
		if k.keys.Verify(secrets.Codes, rec.Codes[i].Mac, hash, []byte{byte(rec.Purpose)}, []byte(method), []byte(fmt.Sprintf("%0*d", n, c))) {
			return true
		}
	}
	return false
}

// A code no one was sent can't be guessed: for a user with no address and
// past code.hourly, no code matches it. A code that was sent does match
// one, so the check works.
func TestUnsentCodesUnguessable(t *testing.T) {
	k := newKit(t, WithFirst(MethodPassword, MethodEmailCode))
	// Four digits, below what New accepts, so trying every code is quick;
	// auth reads the config each time.
	k.cfg.(*config).codeLen = 4
	k.addUser(t, "sara", User{ID: "u1", Name: "sara"}, goodPassword, saraMail)
	k.addUser(t, "noaddr", User{ID: "u2", Name: "noaddr"}, goodPassword)
	start := func(login string) string {
		f, err := k.SignIn(k.ctx, login, Cookie())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := k.Challenge(k.ctx, f.Token, MethodEmailCode); err != nil {
			t.Fatal(err)
		}
		return f.Token
	}
	if !k.matchable(t, start("sara"), MethodEmailCode, 4) {
		t.Fatal("a sent code matched nothing")
	}
	if k.matchable(t, start("noaddr"), MethodEmailCode, 4) {
		t.Error("a user with no address has a guessable code")
	}
	for range 4 {
		start("sara")
	}
	if k.matchable(t, start("sara"), MethodEmailCode, 4) {
		t.Error("past code.hourly a guessable code was stored")
	}
}

// code.hourly is a sliding hour: sends late in one hour still count early
// in the next.
func TestHourlySliding(t *testing.T) {
	k := newKit(t, WithFirst(MethodPassword, MethodEmailCode))
	k.addUser(t, "sara", User{ID: "u1", Name: "sara"}, goodPassword, saraMail)
	send := func() bool {
		f, _ := k.SignIn(k.ctx, "sara", Cookie())
		n := k.sentCount()
		k.Challenge(k.ctx, f.Token, MethodEmailCode)
		return k.sentCount() > n
	}
	send()
	k.clock.advance(59 * time.Minute)
	for range 4 {
		send()
	}
	k.clock.advance(time.Minute + time.Second)
	if !send() {
		t.Fatal("the send from an hour ago still counted")
	}
	if send() {
		t.Error("five sends within the last hour, and a sixth went")
	}
}

// A send that fails doesn't count toward code.hourly.
func TestFailedSendRefunded(t *testing.T) {
	k := newKit(t, WithFirst(MethodPassword, MethodEmailCode))
	k.addUser(t, "sara", User{ID: "u1", Name: "sara"}, goodPassword, saraMail)
	k.out.fail = errors.New("gateway down")
	for range 6 {
		f, _ := k.SignIn(k.ctx, "sara", Cookie())
		k.Challenge(k.ctx, f.Token, MethodEmailCode)
	}
	k.out.fail = nil
	f, _ := k.SignIn(k.ctx, "sara", Cookie())
	k.Challenge(k.ctx, f.Token, MethodEmailCode)
	if k.sentCount() != 1 {
		t.Errorf("after six failed sends: %d sent", k.sentCount())
	}
}

// Past code.hourly, a later Challenge still cancels the code before it.
func TestHourlyCancels(t *testing.T) {
	k := newKit(t)
	k.addUser(t, "sara", User{ID: "u1", Name: "sara"}, goodPassword, saraMail)
	f := passwordFirst(t, k)
	for range 5 {
		k.Challenge(k.ctx, f.Token, MethodEmailCode)
		k.clock.advance(time.Minute)
	}
	last := k.lastCode(t, saraMail)
	n := k.sentCount()
	k.Challenge(k.ctx, f.Token, MethodEmailCode)
	if k.sentCount() != n {
		t.Fatal("sent past code.hourly")
	}
	if _, err := k.Prove(k.ctx, f.Token, EmailCode(last)); !errors.Is(err, ErrBadCode) {
		t.Errorf("the code before a Challenge past code.hourly: %v", err)
	}
}

func TestFirstProven(t *testing.T) {
	k := newKit(t)
	for _, c := range []struct {
		rec  *storepb.Flow
		want bool
	}{
		{&storepb.Flow{Purpose: int32(PurposeSignIn)}, false},
		{&storepb.Flow{Purpose: int32(PurposeSignIn), Proofs: []*storepb.Factor{{Method: MethodPassword}}}, true},
		{&storepb.Flow{Purpose: int32(PurposeRecover)}, false},
		{&storepb.Flow{Purpose: int32(PurposeRecover), Proofs: []*storepb.Factor{{Method: MethodEmailCode}}}, true},
		{&storepb.Flow{Purpose: int32(PurposeStepUp), SessionId: "s1"}, true},
	} {
		if got := k.firstProven(c.rec); got != c.want {
			t.Errorf("%v: %v", c.rec, got)
		}
	}
}
