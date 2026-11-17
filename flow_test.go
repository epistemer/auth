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
	origins          []string
	free, tries      int
	codeLen          int
	grace            time.Duration
	window           time.Duration
}

func defaults() *config {
	return &config{
		issuer: "toyshop", secret: cfgx.NewSecret(strings.Repeat("k", 32)),
		idle: 24 * time.Hour, remembered: 720 * time.Hour, lifetime: 2160 * time.Hour,
		flow: 15 * time.Minute, minLength: 12, memory: 19, passes: 1,
		free: 5, tries: 5, window: time.Hour, codeLen: 6, grace: 10 * time.Second,
	}
}

func (c *config) AuthIssuer() string                       { return c.issuer }
func (c *config) AuthSecret() cfgx.Secret                  { return c.secret }
func (c *config) AuthSecretPrevious() cfgx.Secret          { return c.previous }
func (c *config) AuthSessionIdle() time.Duration           { return c.idle }
func (c *config) AuthSessionRememberedIdle() time.Duration { return c.remembered }
func (c *config) AuthSessionLifetime() time.Duration       { return c.lifetime }
func (c *config) AuthAccessLifetime() time.Duration        { return 10 * time.Minute }
func (c *config) AuthRefreshGrace() time.Duration          { return c.grace }
func (c *config) AuthFlowLifetime() time.Duration          { return c.flow }
func (c *config) AuthFreshWindow() time.Duration           { return 10 * time.Minute }
func (c *config) AuthCodeLength() int                      { return c.codeLen }
func (c *config) AuthCodeLifetime() time.Duration          { return 5 * time.Minute }
func (c *config) AuthCodeTries() int                       { return c.tries }
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
func (c *config) AuthThrottleFree() int                    { return c.free }
func (c *config) AuthThrottleCeiling() time.Duration       { return 15 * time.Minute }
func (c *config) AuthThrottleWindow() time.Duration        { return c.window }
func (c *config) AuthCookieInsecure() bool                 { return c.insecure }
func (c *config) AuthTrustedOrigins() []string             { return c.origins }

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
	fail error // when set, Send fails and keeps nothing
}

func (o *outbox) Send(_ context.Context, m Message) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.fail != nil {
		return o.fail
	}
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
	return newKitWith(t, nil, opts...)
}

// newKitWith is newKit with the config edited first.
func newKitWith(t *testing.T, edit func(*config), opts ...Option) *kit {
	t.Helper()
	cfg := defaults()
	if edit != nil {
		edit(cfg)
	}
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
	k.Auth, err = New(db, cfg, k.dir, k.out, opts...)
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
	// A module's method is accepted since v0.2.0 (A21); TestNewMethods has
	// what New refuses.
	if _, err := New(db, defaults(), &directory{}, &outbox{}, WithMethods(stubMethod{})); err != nil {
		t.Errorf("a module's method: %v", err)
	}
}

type stubMethod struct{}

func (stubMethod) Name() string { return "stub" }
func (stubMethod) Start(context.Context, MethodInput) (any, []byte, error) {
	return nil, nil, nil
}
func (stubMethod) Verify(context.Context, MethodInput, []byte, Proof) (MethodResult, error) {
	return MethodResult{}, nil
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

// Review 0004, finding 1: a flow proved with the old password can't finish
// after the password changes.
func TestPasswordChangeStalesFlows(t *testing.T) {
	k := newKit(t, WithPolicy(allowUnverified))
	k.addUser(t, "sara", User{ID: "u1", Name: "sara"}, goodPassword)
	f, err := k.signIn(t, "sara", goodPassword)
	if err != nil || !f.Ready {
		t.Fatalf("%+v %v", f, err)
	}
	k.clock.advance(time.Second)
	if err := k.SetPassword(k.ctx, "u1", "violet engine sings 93 rivers"); err != nil {
		t.Fatal(err)
	}
	if g, _ := k.Flow(k.ctx, f.Token); g.Ready {
		t.Error("the flow is still ready")
	}
	if _, err := k.Finish(k.ctx, f.Token); !errors.Is(err, ErrNotReady) {
		t.Fatalf("Finish: %v", err)
	}
}

// Review 0004, finding 2: a rehash replaces only the hash it verified.
func TestRehashKeepsAChangedPassword(t *testing.T) {
	k := newKit(t, WithPolicy(allowUnverified))
	k.addUser(t, "sara", User{ID: "u1", Name: "sara"}, goodPassword)
	old, _ := k.passwordHash("u1")
	if err := k.SetPassword(k.ctx, "u1", "violet engine sings 93 rivers"); err != nil {
		t.Fatal(err)
	}
	changed, _ := k.passwordHash("u1")
	// The sign-in that verified the old hash finishes its rehash late.
	if _, _, err := k.storePassword("u1", "$argon2id$late", old); err != nil {
		t.Fatal(err)
	}
	if cur, _ := k.passwordHash("u1"); cur != changed {
		t.Fatal("a late rehash overwrote the changed password")
	}
}

// Review 0004, finding 3: one proof of a method that may be first or
// second is one factor.
func TestOneProofIsOneFactor(t *testing.T) {
	k := newKit(t)
	k.first = []string{MethodPassword, MethodEmailCode}
	at := k.clock.now().UnixNano()
	code := &storepb.Factor{Method: MethodEmailCode, At: at}
	pw := &storepb.Factor{Method: MethodPassword, At: at}
	if k.twoFactors([]*storepb.Factor{code}, nil) {
		t.Error("an emailed code alone counts twice")
	}
	if !k.twoFactors([]*storepb.Factor{pw, code}, nil) {
		t.Error("a password and a code don't count as two")
	}
}

// Review 0004, finding 5: concurrent proofs of one method make one factor.
func TestConcurrentProofsOneFactor(t *testing.T) {
	k := newKit(t, WithPolicy(allowUnverified))
	k.addUser(t, "sara", User{ID: "u1", Name: "sara"}, goodPassword)
	f, err := k.SignIn(k.ctx, "sara", Cookie())
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() { defer wg.Done(); k.Prove(k.ctx, f.Token, Password(goodPassword)) }()
	}
	wg.Wait()
	res, err := k.Finish(k.ctx, f.Token)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Session.Factors) != 1 {
		t.Fatalf("factors %+v", res.Session.Factors)
	}
}

// Review 0004, finding 6: a malformed stored hash costs the same one hash.
func TestMalformedHashCostsOneHash(t *testing.T) {
	k := newKit(t, WithPolicy(allowUnverified))
	k.addUser(t, "sara", User{ID: "u1", Name: "sara"}, goodPassword)
	k.db.Update(func(tx *bolt.Tx) error {
		return store.Put(tx, store.Credentials, passwordKey("u1"), &storepb.Credential{Method: MethodPassword, Data: []byte("$broken")})
	})
	n := k.hasher.Count()
	if _, err := k.signIn(t, "sara", goodPassword); !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("got %v", err)
	}
	if d := k.hasher.Count() - n; d != 1 {
		t.Fatalf("%d hashes", d)
	}
}

// Review 0004, findings 7 and 8: the directory must answer for the ID it
// was asked, and SetPassword checks the ID.
func TestUserIDs(t *testing.T) {
	k := newKit(t)
	for _, id := range []UserID{"", "u1\x00spoof", UserID(strings.Repeat("x", 65))} {
		if err := k.SetPassword(k.ctx, id, goodPassword); err == nil {
			t.Errorf("%q accepted", id)
		}
	}
}

// Review 0004, finding 12: the disabled user's wrong password answers as
// any other, with one hash.
func TestDisabledAnswersAlike(t *testing.T) {
	k := newKit(t, WithPolicy(allowUnverified))
	k.addUser(t, "sara", User{ID: "u1", Name: "sara"}, goodPassword)
	k.dir.mu.Lock()
	k.dir.users["sara"] = User{ID: "u1", Name: "sara", Disabled: true}
	k.dir.mu.Unlock()
	n := k.hasher.Count()
	f, err := k.signIn(t, "sara", "wrong horse battery")
	if !errors.Is(err, ErrBadCredentials) || k.hasher.Count()-n != 1 || !slices.Equal(f.Offers, []string{MethodPassword}) || f.Ready {
		t.Fatalf("%+v %v", f, err)
	}
}

// §5.6.2: a session ends at its idle lifetime, the remembered one, and
// session.lifetime.
func TestSessionLifetimes(t *testing.T) {
	k := newKit(t, WithPolicy(allowUnverified))
	k.addUser(t, "sara", User{ID: "u1", Name: "sara"}, goodPassword)
	start := func(opts ...FinishOption) *Session {
		f, err := k.signIn(t, "sara", goodPassword)
		if err != nil {
			t.Fatal(err)
		}
		res, err := k.Finish(k.ctx, f.Token, opts...)
		if err != nil {
			t.Fatal(err)
		}
		return res.Session
	}
	alive := func(s *Session) bool {
		_, err := k.StepUp(k.ctx, s)
		return err == nil
	}
	plain, kept := start(), start(Remember())
	k.clock.advance(23 * time.Hour)
	if !alive(plain) || !alive(kept) {
		t.Fatal("ended early")
	}
	k.clock.advance(2 * time.Hour)
	if alive(plain) || !alive(kept) {
		t.Fatal("idle lifetimes")
	}
	// session.lifetime ends even a remembered session that is kept in use.
	k.db.Update(func(tx *bolt.Tx) error {
		var s storepb.Session
		store.Get(tx, store.Sessions, []byte(kept.ID), &s)
		s.Seen = k.clock.now().UnixNano()
		s.Expires = k.clock.now().Add(time.Hour).UnixNano()
		return store.Put(tx, store.Sessions, []byte(kept.ID), &s)
	})
	k.clock.advance(time.Hour)
	if alive(kept) {
		t.Fatal("session.lifetime")
	}
}

// A step-up offers what is left to prove, and refuses a disabled user at
// Finish.
func TestStepUpOffersAndDisabled(t *testing.T) {
	k := newKit(t, WithPolicy(allowUnverified))
	k.addUser(t, "sara", User{ID: "u1", Name: "sara"}, goodPassword)
	f, _ := k.signIn(t, "sara", goodPassword)
	res, err := k.Finish(k.ctx, f.Token)
	if err != nil {
		t.Fatal(err)
	}
	up, _ := k.StepUp(k.ctx, res.Session)
	up, err = k.Prove(k.ctx, up.Token, Password(goodPassword))
	if err != nil || len(up.Offers) != 0 {
		t.Fatalf("offers after the password: %v %v", up.Offers, err)
	}
	k.dir.mu.Lock()
	k.dir.users["sara"] = User{ID: "u1", Name: "sara", Disabled: true}
	k.dir.mu.Unlock()
	if _, err := k.Finish(withSession(k.ctx, res.Session), up.Token); !errors.Is(err, ErrUserDisabled) {
		t.Fatalf("got %v", err)
	}
}

// §5.1.11 and §5.6.4: the flow cookie, and both cookies' names with
// cookie.insecure.
func TestCookies(t *testing.T) {
	f := Flow{Token: "t", Expires: time.Now().Add(time.Minute)}
	w := httptest.NewRecorder()
	f.Write(w)
	c := w.Result().Cookies()[0]
	if c.Name != "__Host-flow" || !c.Secure || !c.HttpOnly || c.Path != "/" || c.SameSite != 2 {
		t.Fatalf("flow cookie %+v", c)
	}
	f.insecure = true
	w = httptest.NewRecorder()
	f.Write(w)
	if c := w.Result().Cookies()[0]; c.Name != "flow" || c.Secure {
		t.Fatalf("insecure flow cookie %+v", c)
	}
	w = httptest.NewRecorder()
	Result{cookie: "s", insecure: true}.Write(w)
	if c := w.Result().Cookies()[0]; c.Name != "session" || c.Secure || !c.Expires.IsZero() {
		t.Fatalf("insecure session cookie %+v", c)
	}
}

// Review 0004, finding 4: spending a flow checks its lifetime again, under
// the write lock.
func TestSpendChecksExpiry(t *testing.T) {
	k := newKit(t, WithPolicy(allowUnverified))
	k.addUser(t, "sara", User{ID: "u1", Name: "sara"}, goodPassword)
	f, _ := k.signIn(t, "sara", goodPassword)
	k.clock.advance(15 * time.Minute)
	err := k.db.Update(func(tx *bolt.Tx) error {
		_, err := k.spend(tx, secrets.Hash(f.Token))
		return err
	})
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("got %v", err)
	}
}

type swapping struct{ *directory }

func (s swapping) Get(ctx context.Context, id UserID) (User, error) {
	return User{ID: id + "x", Name: "someone"}, nil
}

// A directory that answers for another ID than the one asked is refused.
func TestDirectoryAnswersForTheID(t *testing.T) {
	k := newKit(t)
	k.dir2(swapping{k.dir})
	if err := k.SetPassword(k.ctx, "u1", goodPassword); err == nil {
		t.Fatal("accepted another user's record")
	}
}

func (k *kit) dir2(d Directory) { k.Auth.dir = d }
