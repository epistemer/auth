package auth

import (
	"context"
	"fmt"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/epistemer/cfgx"
	"github.com/epistemer/errors"
	bolt "go.etcd.io/bbolt"
	"golang.org/x/text/unicode/norm"

	"github.com/epistemer/auth/internal/password"
	"github.com/epistemer/auth/internal/secrets"
	"github.com/epistemer/auth/internal/store"
	"github.com/epistemer/auth/internal/storepb"
)

// The tests use a toy shop's users. authtest (M1.6) will replace this kit.

type config struct {
	issuer           string
	secret, previous cfgx.Secret
	idle, remembered time.Duration
	lifetime         time.Duration
	flow             time.Duration
	minLength        int
	memory, passes   int
	insecure         bool
}

func defaults() *config {
	return &config{
		issuer: "toyshop", secret: cfgx.NewSecret(strings.Repeat("k", 32)),
		idle: 24 * time.Hour, remembered: 720 * time.Hour, lifetime: 2160 * time.Hour,
		flow: 15 * time.Minute, minLength: 12, memory: 19, passes: 1,
	}
}

func (c *config) AuthIssuer() string                       { return c.issuer }
func (c *config) AuthSecret() cfgx.Secret                  { return c.secret }
func (c *config) AuthSecretPrevious() cfgx.Secret          { return c.previous }
func (c *config) AuthSessionIdle() time.Duration           { return c.idle }
func (c *config) AuthSessionRememberedIdle() time.Duration { return c.remembered }
func (c *config) AuthSessionLifetime() time.Duration       { return c.lifetime }
func (c *config) AuthAccessLifetime() time.Duration        { return 10 * time.Minute }
func (c *config) AuthRefreshGrace() time.Duration          { return 10 * time.Second }
func (c *config) AuthFlowLifetime() time.Duration          { return c.flow }
func (c *config) AuthFreshWindow() time.Duration           { return 10 * time.Minute }
func (c *config) AuthCodeLength() int                      { return 6 }
func (c *config) AuthCodeLifetime() time.Duration          { return 5 * time.Minute }
func (c *config) AuthCodeTries() int                       { return 5 }
func (c *config) AuthCodeResend() time.Duration            { return time.Minute }
func (c *config) AuthCodeHourly() int                      { return 5 }
func (c *config) AuthLinkLifetime() time.Duration          { return 30 * time.Minute }
func (c *config) AuthInvitationLifetime() time.Duration    { return 72 * time.Hour }
func (c *config) AuthDeviceLifetime() time.Duration        { return 2160 * time.Hour }
func (c *config) AuthPasswordMinLength() int               { return c.minLength }
func (c *config) AuthPasswordMinScore() int                { return 4 }
func (c *config) AuthPasswordMemory() int                  { return c.memory }
func (c *config) AuthPasswordTime() int                    { return c.passes }
func (c *config) AuthPasswordConcurrency() int             { return 4 }
func (c *config) AuthThrottleFree() int                    { return 5 }
func (c *config) AuthThrottleCeiling() time.Duration       { return 15 * time.Minute }
func (c *config) AuthThrottleWindow() time.Duration        { return time.Hour }
func (c *config) AuthCookieInsecure() bool                 { return c.insecure }
func (c *config) AuthTrustedOrigins() []string             { return nil }

type directory struct {
	mu    sync.Mutex
	users map[string]User // by login
	addrs map[UserID]map[Channel]string
}

func (d *directory) Find(_ context.Context, login string) (User, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if u, ok := d.users[login]; ok {
		return u, nil
	}
	return User{}, ErrNoUser
}

func (d *directory) Get(_ context.Context, id UserID) (User, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, u := range d.users {
		if u.ID == id {
			return u, nil
		}
	}
	return User{}, ErrNoUser
}

func (d *directory) Address(_ context.Context, id UserID, ch Channel) (string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.addrs[id][ch], nil
}

type outbox struct {
	mu   sync.Mutex
	sent []Message
}

func (o *outbox) Send(_ context.Context, m Message) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.sent = append(o.sent, m)
	return nil
}

type events struct {
	mu  sync.Mutex
	all []Event
}

func (e *events) Record(_ context.Context, ev Event) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.all = append(e.all, ev)
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

type kit struct {
	*Auth
	dir    *directory
	out    *outbox
	events *events
	clock  *clock
	ctx    context.Context
}

var cheap = password.Params{MemoryKiB: 64, Time: 1}

const goodPassword = "orange tiger juggles 47 lamps"

func newKit(t *testing.T, opts ...Option) *kit {
	t.Helper()
	db, err := bolt.Open(filepath.Join(t.TempDir(), "auth.db"), 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	k := &kit{
		dir:    &directory{users: map[string]User{}, addrs: map[UserID]map[Channel]string{}},
		out:    &outbox{},
		events: &events{},
		clock:  &clock{t: time.Date(2026, 11, 15, 9, 0, 0, 0, time.UTC)},
		ctx:    context.Background(),
	}
	opts = append([]Option{WithRecorder(k.events), WithClock(k.clock.now)}, opts...)
	k.Auth, err = New(db, defaults(), k.dir, k.out, opts...)
	if err != nil {
		t.Fatal(err)
	}
	if k.hasher, err = password.New(cheap, 4); err != nil {
		t.Fatal(err)
	}
	return k
}

func allowUnverified(context.Context, User) Policy { return Policy{AllowUnverified: true} }

// addUser adds a user to the directory and, with a password, sets it.
func (k *kit) addUser(t *testing.T, login string, u User, pw string, addrs ...string) {
	t.Helper()
	k.dir.mu.Lock()
	k.dir.users[login] = u
	k.dir.addrs[u.ID] = map[Channel]string{}
	for i, a := range addrs {
		k.dir.addrs[u.ID][Channel(i+1)] = a
	}
	k.dir.mu.Unlock()
	if pw != "" {
		if err := k.SetPassword(k.ctx, u.ID, pw); err != nil {
			t.Fatal(err)
		}
	}
}

func (k *kit) signIn(t *testing.T, login, pw string) (Flow, error) {
	t.Helper()
	f, err := k.SignIn(k.ctx, login, Cookie())
	if err != nil {
		t.Fatal(err)
	}
	return k.Prove(k.ctx, f.Token, Password(pw))
}

func TestNewRefusesBadConfig(t *testing.T) {
	db, err := bolt.Open(filepath.Join(t.TempDir(), "auth.db"), 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for name, edit := range map[string]func(*config){
		"short secret":   func(c *config) { c.secret = cfgx.NewSecret("short") },
		"short previous": func(c *config) { c.previous = cfgx.NewSecret("short") },
		"no issuer":      func(c *config) { c.issuer = "" },
		"idle":           func(c *config) { c.idle = time.Minute },
		"flow":           func(c *config) { c.flow = 2 * time.Hour },
		"memory":         func(c *config) { c.memory = 4097 },
		"passes":         func(c *config) { c.passes = 65 },
		"min length":     func(c *config) { c.minLength = 7 },
		"remembered":     func(c *config) { c.remembered = time.Hour },
	} {
		c := defaults()
		edit(c)
		if _, err := New(db, c, &directory{}, &outbox{}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := New(db, defaults(), &directory{}, &outbox{}, WithFirst("telepathy")); err == nil {
		t.Error("an unknown first method was accepted")
	}
}

// §7, enumeration: a wrong password answers alike for a known and an
// unknown login, with one password hash each, and so does a known user
// with no password.
func TestEnumeration(t *testing.T) {
	k := newKit(t, WithPolicy(allowUnverified))
	k.addUser(t, "sara", User{ID: "u1", Name: "sara"}, goodPassword, "sara@toyshop.example")
	k.addUser(t, "nopass", User{ID: "u2", Name: "nopass"}, "")
	type answer struct {
		ready, verified bool
		offers          []string
		expiresIn       time.Duration
		err             error
		hashes          int64
	}
	try := func(login string) (answer, answer) {
		start, err := k.SignIn(k.ctx, login, Cookie())
		if err != nil {
			t.Fatal(err)
		}
		a := answer{start.Ready, start.Verified, start.Offers, start.Expires.Sub(k.clock.now()), nil, 0}
		n := k.hasher.Count()
		f, err := k.Prove(k.ctx, start.Token, Password("wrong horse battery"))
		b := answer{f.Ready, f.Verified, f.Offers, f.Expires.Sub(k.clock.now()), err, k.hasher.Count() - n}
		return a, b
	}
	known0, known := try("sara")
	for _, login := range []string{"nobody", "nopass"} {
		start, wrong := try(login)
		if fmt.Sprint(start) != fmt.Sprint(known0) {
			t.Errorf("%s: start %+v, known %+v", login, start, known0)
		}
		if !errors.Is(wrong.err, ErrBadCredentials) || fmt.Sprint(wrong) != fmt.Sprint(known) {
			t.Errorf("%s: %+v, known %+v", login, wrong, known)
		}
	}
	if known.hashes != 1 || !errors.Is(known.err, ErrBadCredentials) {
		t.Errorf("known: %+v", known)
	}
	if !slices.Equal(known0.offers, []string{MethodPassword}) {
		t.Errorf("offers %v", known0.offers)
	}
}

// §7, enumeration: a disabled user is refused only after a correct proof.
func TestDisabled(t *testing.T) {
	k := newKit(t, WithPolicy(allowUnverified))
	k.addUser(t, "sara", User{ID: "u1", Name: "sara"}, goodPassword)
	k.dir.mu.Lock()
	k.dir.users["sara"] = User{ID: "u1", Name: "sara", Disabled: true}
	k.dir.mu.Unlock()
	if _, err := k.signIn(t, "sara", "wrong horse battery"); !errors.Is(err, ErrBadCredentials) {
		t.Errorf("wrong: %v", err)
	}
	if _, err := k.signIn(t, "sara", goodPassword); !errors.Is(err, ErrUserDisabled) {
		t.Errorf("right: %v", err)
	}
}

// A user disabled between the proof and Finish is refused at Finish.
func TestDisabledAtFinish(t *testing.T) {
	k := newKit(t, WithPolicy(allowUnverified))
	k.addUser(t, "sara", User{ID: "u1", Name: "sara"}, goodPassword)
	f, err := k.signIn(t, "sara", goodPassword)
	if err != nil {
		t.Fatal(err)
	}
	k.dir.mu.Lock()
	k.dir.users["sara"] = User{ID: "u1", Name: "sara", Disabled: true}
	k.dir.mu.Unlock()
	if _, err := k.Finish(k.ctx, f.Token); !errors.Is(err, ErrUserDisabled) {
		t.Fatalf("got %v", err)
	}
}

func TestSignIn(t *testing.T) {
	k := newKit(t, WithPolicy(allowUnverified))
	k.addUser(t, "sara", User{ID: "u1", Name: "sara"}, goodPassword)
	start, err := k.SignIn(k.ctx, "sara", Cookie())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := k.Finish(k.ctx, start.Token); !errors.Is(err, ErrNotReady) {
		t.Fatalf("Finish before a proof: %v", err)
	}
	if _, err := k.Prove(k.ctx, start.Token, TOTP("123456")); !errors.Is(err, ErrMethodUnavailable) {
		t.Fatalf("a method not on offer: %v", err)
	}
	f, err := k.Prove(k.ctx, start.Token, Password(goodPassword))
	if err != nil || !f.Ready || f.Verified {
		t.Fatalf("%+v %v", f, err)
	}
	res, err := k.Finish(k.ctx, f.Token, Remember())
	if err != nil {
		t.Fatal(err)
	}
	s := res.Session
	if s.User != "u1" || s.Verified || len(s.Factors) != 1 || s.Factors[0].Method != MethodPassword {
		t.Fatalf("session %+v", s)
	}
	w := httptest.NewRecorder()
	res.Write(w)
	cookies := w.Result().Cookies()
	if len(cookies) != 2 || cookies[0].Name != "__Host-session" || !cookies[0].Secure || !cookies[0].HttpOnly ||
		cookies[0].Path != "/" || cookies[0].Expires.IsZero() || cookies[1].Name != "__Host-flow" || cookies[1].MaxAge >= 0 {
		t.Fatalf("cookies %v", cookies)
	}
	// The store holds the token's hash, never the token.
	var rec storepb.Session
	k.db.View(func(tx *bolt.Tx) error { return store.Get(tx, store.Sessions, []byte(s.ID), &rec) })
	if !secrets.Equal(rec.TokenHash, secrets.Hash(cookies[0].Value)) {
		t.Fatal("the stored hash isn't the token's")
	}
	// A spent flow is gone.
	if _, err := k.Finish(k.ctx, f.Token); !errors.Is(err, ErrFlowExpired) {
		t.Fatalf("second Finish: %v", err)
	}
}

// Without AllowUnverified and with no second method, a correct password
// says so, and the flow never becomes ready (§5.7.4).
func TestCannotVerify(t *testing.T) {
	k := newKit(t)
	k.addUser(t, "sara", User{ID: "u1", Name: "sara"}, goodPassword)
	f, err := k.signIn(t, "sara", goodPassword)
	if !errors.Is(err, ErrCannotVerify) || f.Ready || f.Verified {
		t.Fatalf("%+v %v", f, err)
	}
	if _, err := k.Finish(k.ctx, f.Token); !errors.Is(err, ErrNotReady) {
		t.Fatalf("Finish: %v", err)
	}
}

// §7, flows: refused after flow.lifetime and after Finish; of two
// concurrent Finishes, one wins.
func TestFlowLifetime(t *testing.T) {
	k := newKit(t, WithPolicy(allowUnverified))
	k.addUser(t, "sara", User{ID: "u1", Name: "sara"}, goodPassword)
	f, err := k.signIn(t, "sara", goodPassword)
	if err != nil {
		t.Fatal(err)
	}
	k.clock.advance(15 * time.Minute)
	if _, err := k.Finish(k.ctx, f.Token); !errors.Is(err, ErrFlowExpired) {
		t.Fatalf("after its lifetime: %v", err)
	}
	if _, err := k.Flow(k.ctx, f.Token); !errors.Is(err, ErrFlowExpired) {
		t.Fatalf("Flow: %v", err)
	}
	f, err = k.signIn(t, "sara", goodPassword)
	if err != nil {
		t.Fatal(err)
	}
	var wins, expired int
	var mu sync.Mutex
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := k.Finish(k.ctx, f.Token)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				wins++
			case errors.Is(err, ErrFlowExpired):
				expired++
			}
		}()
	}
	wg.Wait()
	if wins != 1 || expired != 19 {
		t.Fatalf("%d finished, %d expired", wins, expired)
	}
}

// §7, flows: a StepUp flow can't be finished for another session. Finished
// for its own, it replaces the token and raises the generation.
func TestStepUp(t *testing.T) {
	k := newKit(t, WithPolicy(allowUnverified))
	k.addUser(t, "sara", User{ID: "u1", Name: "sara"}, goodPassword)
	k.addUser(t, "omar", User{ID: "u2", Name: "omar"}, "violet engine sings 93 rivers")
	session := func(login, pw string) (*Session, string) {
		f, err := k.signIn(t, login, pw)
		if err != nil {
			t.Fatal(err)
		}
		res, err := k.Finish(k.ctx, f.Token)
		if err != nil {
			t.Fatal(err)
		}
		return res.Session, res.cookie
	}
	sara, saraToken := session("sara", goodPassword)
	omar, _ := session("omar", "violet engine sings 93 rivers")
	if _, err := k.StepUp(k.ctx, nil); !errors.Is(err, ErrNoSession) {
		t.Fatalf("no session: %v", err)
	}
	f, err := k.StepUp(k.ctx, sara)
	if err != nil {
		t.Fatal(err)
	}
	if f.Ready || !slices.Equal(f.Offers, []string{MethodPassword}) {
		t.Fatalf("start %+v", f)
	}
	f, err = k.Prove(k.ctx, f.Token, Password(goodPassword))
	if err != nil || !f.Ready {
		t.Fatalf("%+v %v", f, err)
	}
	if _, err := k.Finish(k.ctx, f.Token); !errors.Is(err, ErrNoSession) {
		t.Fatalf("without a session: %v", err)
	}
	if _, err := k.Finish(withSession(k.ctx, omar), f.Token); !errors.Is(err, ErrFlowExpired) {
		t.Fatalf("for another session: %v", err)
	}
	res, err := k.Finish(withSession(k.ctx, sara), f.Token)
	if err != nil {
		t.Fatal(err)
	}
	if res.cookie == saraToken || len(res.Session.Factors) != 2 {
		t.Fatalf("result %+v", res.Session)
	}
	var rec storepb.Session
	err = k.db.View(func(tx *bolt.Tx) error {
		if store.B(tx, store.SessionTokens).Get(secrets.Hash(saraToken)) != nil {
			t.Error("the old token still resolves")
		}
		return store.Get(tx, store.Sessions, []byte(sara.ID), &rec)
	})
	if err != nil || rec.Generation != 2 {
		t.Fatalf("generation %d %v", rec.Generation, err)
	}
	// A step-up of an ended session is refused.
	k.clock.advance(25 * time.Hour)
	if _, err := k.StepUp(k.ctx, sara); !errors.Is(err, ErrNoSession) {
		t.Fatalf("idle session: %v", err)
	}
}

// §5.6.3: a sign-in ends the session the request carries.
func TestSignInEndsCarriedSession(t *testing.T) {
	k := newKit(t, WithPolicy(allowUnverified))
	k.addUser(t, "sara", User{ID: "u1", Name: "sara"}, goodPassword)
	f, _ := k.signIn(t, "sara", goodPassword)
	first, err := k.Finish(k.ctx, f.Token)
	if err != nil {
		t.Fatal(err)
	}
	f, _ = k.signIn(t, "sara", goodPassword)
	if _, err := k.Finish(withSession(k.ctx, first.Session), f.Token); err != nil {
		t.Fatal(err)
	}
	k.db.View(func(tx *bolt.Tx) error {
		if store.B(tx, store.SessionTokens).Get(secrets.Hash(first.cookie)) != nil {
			t.Error("the carried session's token still resolves")
		}
		return nil
	})
}

// §7, passwords.
func TestPasswords(t *testing.T) {
	k := newKit(t, WithPolicy(allowUnverified))
	arabic := strings.Repeat("كلمة سر طويلة ", 73)[:1022] + "ab"
	letters := "the quick brown fox jumps over a lazy dog while seven zebras quietly hum " +
		"jazz tunes near old harbor walls and purple kites drift above green fields " +
		"as twelve monks bake rye bread for the long winter fair in town"
	if len(letters) < 200 {
		t.Fatalf("%d bytes", len(letters))
	}
	for i, pw := range []string{arabic, letters[:200], "  " + goodPassword + "  "} {
		login := fmt.Sprintf("user%d", i)
		k.addUser(t, login, User{ID: UserID(login), Name: login}, pw)
		if _, err := k.signIn(t, login, pw); err != nil {
			t.Errorf("%d bytes: %v", len(pw), err)
		}
	}
	// Leading and trailing spaces are part of the password.
	if _, err := k.signIn(t, "user2", goodPassword); !errors.Is(err, ErrBadCredentials) {
		t.Errorf("trimmed: %v", err)
	}
	if err := k.CheckPassword(k.ctx, strings.Repeat("x", 1025)); !errors.Is(err, ErrPasswordTooLong) {
		t.Errorf("1025 bytes: %v", err)
	}
	// Composed and decomposed are one password.
	composed := "café crème brûlée 1987 ﬁnest"
	k.addUser(t, "nfc", User{ID: "nfc", Name: "nfc"}, composed)
	if _, err := k.signIn(t, "nfc", norm.NFD.String(composed)); err != nil {
		t.Errorf("decomposed: %v", err)
	}
	for pw, want := range map[string]error{
		"short":               ErrPasswordTooShort,
		"password1234":        ErrPasswordCommon,
		"sara-is-the-best-99": ErrPasswordPersonal,
		"aaaaaaaaaaaa":        ErrPasswordSimple,
		"P@ssw0rd2024":        ErrPasswordCommon,
		"Summer2024!!":        ErrPasswordCommon,
		"14/02/1990!!!!":      ErrPasswordSimple,
		"toyshop-is-great-77": ErrPasswordPersonal, // the issuer
	} {
		if err := k.CheckPassword(k.ctx, pw, "sara"); !errors.Is(err, want) {
			t.Errorf("%q: %v, want %v", pw, err, want)
		}
	}
	// SetPassword holds the user's own words against them.
	k.addUser(t, "sara", User{ID: "u1", Name: "sara"}, "", "sara.ali@toyshop.example")
	if err := k.SetPassword(k.ctx, "u1", "sara-likes-blue-kites"); !errors.Is(err, ErrPasswordPersonal) {
		t.Errorf("name: %v", err)
	}
}

// §7, passwords: a hash made with cheaper parameters is replaced at the
// next sign-in.
func TestRehash(t *testing.T) {
	k := newKit(t, WithPolicy(allowUnverified))
	k.addUser(t, "sara", User{ID: "u1", Name: "sara"}, goodPassword)
	old, _ := k.passwordHash("u1")
	var err error
	if k.hasher, err = password.New(password.Params{MemoryKiB: 128, Time: 1}, 4); err != nil {
		t.Fatal(err)
	}
	if _, err := k.signIn(t, "sara", goodPassword); err != nil {
		t.Fatal(err)
	}
	cur, _ := k.passwordHash("u1")
	if cur == old || !strings.Contains(cur, "m=128,") {
		t.Fatalf("not rehashed: %s", cur)
	}
}

// §5.1.10: replacing a password ends the user's sessions and says so;
// setting the first one doesn't.
func TestSetPasswordEndsSessions(t *testing.T) {
	k := newKit(t, WithPolicy(allowUnverified))
	k.addUser(t, "sara", User{ID: "u1", Name: "sara"}, goodPassword, "sara@toyshop.example")
	if len(k.out.sent) != 0 {
		t.Fatalf("first password sent %v", k.out.sent)
	}
	f, _ := k.signIn(t, "sara", goodPassword)
	res, err := k.Finish(k.ctx, f.Token)
	if err != nil {
		t.Fatal(err)
	}
	if err := k.SetPassword(k.ctx, "u1", "violet engine sings 93 rivers"); err != nil {
		t.Fatal(err)
	}
	if len(k.out.sent) != 1 || k.out.sent[0].Kind != MsgPasswordChanged || k.out.sent[0].To != "sara@toyshop.example" {
		t.Fatalf("sent %+v", k.out.sent)
	}
	if _, err := k.StepUp(k.ctx, res.Session); !errors.Is(err, ErrNoSession) {
		t.Fatalf("the old session lives: %v", err)
	}
	if _, err := k.signIn(t, "sara", goodPassword); !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("the old password works: %v", err)
	}
}

func TestBearerArrivesLater(t *testing.T) {
	k := newKit(t)
	if _, err := k.SignIn(k.ctx, "sara", Bearer()); !errors.Is(err, errors.ErrUnsupported) {
		t.Fatalf("got %v", err)
	}
}

// §7, secrets: no event holds a password or a token the test used.
func TestEventsHoldNoSecret(t *testing.T) {
	k := newKit(t, WithPolicy(allowUnverified))
	k.addUser(t, "sara", User{ID: "u1", Name: "sara"}, goodPassword)
	k.signIn(t, "sara", "wrong horse battery")
	f, _ := k.signIn(t, "sara", goodPassword)
	res, err := k.Finish(k.ctx, f.Token)
	if err != nil {
		t.Fatal(err)
	}
	secretsUsed := []string{goodPassword, "wrong horse battery", f.Token, res.cookie}
	kinds := map[string]bool{}
	for _, e := range k.events.all {
		kinds[e.Kind] = true
		s := fmt.Sprintf("%+v", e)
		for _, x := range secretsUsed {
			if strings.Contains(s, x) {
				t.Errorf("event %s holds a secret", e.Kind)
			}
		}
	}
	for _, want := range []string{"flow.started", "proof.refused", "proof.accepted", "session.created", "password.set"} {
		if !kinds[want] {
			t.Errorf("no %s event", want)
		}
	}
	if s := fmt.Sprint(Password(goodPassword)); strings.Contains(s, goodPassword) {
		t.Errorf("a proof prints its secret: %s", s)
	}
}
