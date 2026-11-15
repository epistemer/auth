// Package authtest gives an app's tests an *auth.Auth on a temporary store,
// with a fake clock, an in-memory directory, a sender that keeps what it was
// given, and cheap password hashing (interface §4.10).
//
//	k := authtest.New(t)
//	k.AddUser("sara@toyshop.example", auth.User{ID: "u1", Name: "sara"}, "sara@toyshop.example")
//	k.Auth.SetPassword(ctx, "u1", "orange tiger juggles 47 lamps")
//	k.Clock.Advance(time.Hour)
package authtest

import (
	"context"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/epistemer/cfgx"
	bolt "go.etcd.io/bbolt"

	"github.com/epistemer/auth"
	"github.com/epistemer/auth/internal/testhook"
)

// Kit is an Auth for tests and what it was given.
type Kit struct {
	Auth  *auth.Auth
	Clock *Clock

	dir    *directory
	sender *sender
	events *recorder
}

// New returns a Kit on a store in tb's temporary directory, with Config's
// values. opts are applied after the kit's own (its Recorder and clock), so
// they may replace them; password hashing stays cheap.
func New(tb testing.TB, opts ...auth.Option) *Kit {
	tb.Helper()
	if !testing.Testing() {
		panic("authtest: New outside go test")
	}
	cfg := Config()
	db, err := bolt.Open(filepath.Join(tb.TempDir(), "auth.db"), 0o600, nil)
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { db.Close() })
	k := &Kit{
		Clock:  &Clock{t: time.Date(2026, 11, 15, 9, 0, 0, 0, time.UTC)},
		dir:    &directory{byLogin: map[string]auth.UserID{}, byID: map[auth.UserID]auth.User{}, addrs: map[auth.UserID][]string{}},
		sender: &sender{},
		events: &recorder{},
	}
	all := append([]auth.Option{auth.WithRecorder(k.events), auth.WithClock(k.Clock.Now)}, opts...)
	all = append(all, testhook.CheapHashing.(auth.Option))
	if k.Auth, err = auth.New(db, cfg, k.dir, k.sender, all...); err != nil {
		tb.Fatal(err)
	}
	return k
}

// AddUser adds a user to the directory under login, exactly as written, or
// adds a login to a user and replaces what the directory knew of them. Its
// addresses are its email, then its phone; an empty one is none. It sets no
// password.
func (k *Kit) AddUser(login string, u auth.User, addresses ...string) {
	k.dir.mu.Lock()
	defer k.dir.mu.Unlock()
	k.dir.byLogin[login] = u.ID
	k.dir.byID[u.ID] = u
	k.dir.addrs[u.ID] = slices.Clone(addresses)
}

// LastMessage returns the last message sent to an address.
func (k *Kit) LastMessage(to string) (auth.Message, bool) {
	k.sender.mu.Lock()
	defer k.sender.mu.Unlock()
	for i := len(k.sender.sent) - 1; i >= 0; i-- {
		if k.sender.sent[i].To == to {
			return k.sender.sent[i], true
		}
	}
	return auth.Message{}, false
}

// Events returns every event recorded, oldest first.
func (k *Kit) Events() []auth.Event {
	k.events.mu.Lock()
	defer k.events.mu.Unlock()
	return slices.Clone(k.events.all)
}

// Clock is the kit's clock. It moves only when told.
type Clock struct {
	mu sync.Mutex
	t  time.Time
}

// Now returns the clock's time.
func (c *Clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

// Advance moves the clock forward by d.
func (c *Clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// Values are a config's values, one field per key of interface §4.8.
type Values struct {
	Issuer                 string
	Secret, SecretPrevious cfgx.Secret
	SessionIdle            time.Duration
	SessionRememberedIdle  time.Duration
	SessionLifetime        time.Duration
	AccessLifetime         time.Duration
	RefreshGrace           time.Duration
	FlowLifetime           time.Duration
	FreshWindow            time.Duration
	CodeLength             int
	CodeLifetime           time.Duration
	CodeTries              int
	CodeResend             time.Duration
	CodeHourly             int
	LinkLifetime           time.Duration
	InvitationLifetime     time.Duration
	DeviceLifetime         time.Duration
	PasswordMinLength      int
	PasswordMinScore       int
	PasswordMemory         int
	PasswordTime           int
	PasswordConcurrency    int
	ThrottleFree           int
	ThrottleCeiling        time.Duration
	ThrottleWindow         time.Duration
	CookieInsecure         bool
	TrustedOrigins         []string
}

// Config returns interface §4.8's defaults, with a fixed secret, the issuer
// "toyshop" and the cheapest hashing a config may ask for, after each edit.
// Its secret is public, so it panics outside go test.
func Config(edit ...func(*Values)) auth.Config {
	if !testing.Testing() {
		panic("authtest: Config outside go test")
	}
	v := Values{
		Issuer: "toyshop", Secret: cfgx.NewSecret(strings.Repeat("authtest", 4)),
		SessionIdle: 24 * time.Hour, SessionRememberedIdle: 720 * time.Hour, SessionLifetime: 2160 * time.Hour,
		AccessLifetime: 10 * time.Minute, RefreshGrace: 10 * time.Second,
		FlowLifetime: 15 * time.Minute, FreshWindow: 10 * time.Minute,
		CodeLength: 6, CodeLifetime: 5 * time.Minute, CodeTries: 5, CodeResend: time.Minute, CodeHourly: 5,
		LinkLifetime: 30 * time.Minute, InvitationLifetime: 72 * time.Hour, DeviceLifetime: 2160 * time.Hour,
		PasswordMinLength: 12, PasswordMinScore: 4, PasswordMemory: 19, PasswordTime: 1, PasswordConcurrency: runtime.NumCPU(),
		ThrottleFree: 5, ThrottleCeiling: 15 * time.Minute, ThrottleWindow: time.Hour,
	}
	for _, e := range edit {
		e(&v)
	}
	v.TrustedOrigins = slices.Clone(v.TrustedOrigins)
	return config{v}
}

type config struct{ v Values }

func (c config) AuthIssuer() string                       { return c.v.Issuer }
func (c config) AuthSecret() cfgx.Secret                  { return c.v.Secret }
func (c config) AuthSecretPrevious() cfgx.Secret          { return c.v.SecretPrevious }
func (c config) AuthSessionIdle() time.Duration           { return c.v.SessionIdle }
func (c config) AuthSessionRememberedIdle() time.Duration { return c.v.SessionRememberedIdle }
func (c config) AuthSessionLifetime() time.Duration       { return c.v.SessionLifetime }
func (c config) AuthAccessLifetime() time.Duration        { return c.v.AccessLifetime }
func (c config) AuthRefreshGrace() time.Duration          { return c.v.RefreshGrace }
func (c config) AuthFlowLifetime() time.Duration          { return c.v.FlowLifetime }
func (c config) AuthFreshWindow() time.Duration           { return c.v.FreshWindow }
func (c config) AuthCodeLength() int                      { return c.v.CodeLength }
func (c config) AuthCodeLifetime() time.Duration          { return c.v.CodeLifetime }
func (c config) AuthCodeTries() int                       { return c.v.CodeTries }
func (c config) AuthCodeResend() time.Duration            { return c.v.CodeResend }
func (c config) AuthCodeHourly() int                      { return c.v.CodeHourly }
func (c config) AuthLinkLifetime() time.Duration          { return c.v.LinkLifetime }
func (c config) AuthInvitationLifetime() time.Duration    { return c.v.InvitationLifetime }
func (c config) AuthDeviceLifetime() time.Duration        { return c.v.DeviceLifetime }
func (c config) AuthPasswordMinLength() int               { return c.v.PasswordMinLength }
func (c config) AuthPasswordMinScore() int                { return c.v.PasswordMinScore }
func (c config) AuthPasswordMemory() int                  { return c.v.PasswordMemory }
func (c config) AuthPasswordTime() int                    { return c.v.PasswordTime }
func (c config) AuthPasswordConcurrency() int             { return c.v.PasswordConcurrency }
func (c config) AuthThrottleFree() int                    { return c.v.ThrottleFree }
func (c config) AuthThrottleCeiling() time.Duration       { return c.v.ThrottleCeiling }
func (c config) AuthThrottleWindow() time.Duration        { return c.v.ThrottleWindow }
func (c config) AuthCookieInsecure() bool                 { return c.v.CookieInsecure }
func (c config) AuthTrustedOrigins() []string             { return slices.Clone(c.v.TrustedOrigins) }

type directory struct {
	mu      sync.Mutex
	byLogin map[string]auth.UserID
	byID    map[auth.UserID]auth.User
	addrs   map[auth.UserID][]string
}

func (d *directory) Find(_ context.Context, login string) (auth.User, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if id, ok := d.byLogin[login]; ok {
		return d.byID[id], nil
	}
	return auth.User{}, auth.ErrNoUser
}

func (d *directory) Get(_ context.Context, id auth.UserID) (auth.User, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if u, ok := d.byID[id]; ok {
		return u, nil
	}
	return auth.User{}, auth.ErrNoUser
}

func (d *directory) Address(_ context.Context, id auth.UserID, ch auth.Channel) (string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	a := d.addrs[id]
	if i := int(ch) - 1; i >= 0 && i < len(a) {
		return a[i], nil
	}
	return "", nil
}

type sender struct {
	mu   sync.Mutex
	sent []auth.Message
}

func (s *sender) Send(_ context.Context, m auth.Message) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sent = append(s.sent, m)
	return nil
}

type recorder struct {
	mu  sync.Mutex
	all []auth.Event
}

func (r *recorder) Record(_ context.Context, e auth.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.all = append(r.all, e)
}
