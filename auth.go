package auth

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"time"

	"github.com/epistemer/cfgx"
	"github.com/epistemer/errors"
	bolt "go.etcd.io/bbolt"

	"github.com/epistemer/auth/internal/password"
	"github.com/epistemer/auth/internal/secrets"
	"github.com/epistemer/auth/internal/store"
)

// UserID is the app's identifier for a user. It is opaque, at most 64 bytes,
// and never a login or an address: it is stored in every record and becomes
// a passkey's user handle.
type UserID string

// User is what auth needs to know of a user.
type User struct {
	ID       UserID
	Name     string // shown by authenticator apps and passkey managers; usually the login
	Disabled bool   // may not sign in
}

// Channel is a way a message reaches a user.
type Channel int

const (
	ChannelEmail Channel = iota + 1
	ChannelSMS
)

// ErrNoUser is what a Directory returns for a login or an ID it doesn't
// know. It is private: it has no message for people, and a sign-in never
// answers with it, so an unknown login looks like a wrong password.
var ErrNoUser = errors.New("auth: no such user")

// Directory is the app's user table, as auth sees it.
type Directory interface {
	// Find returns the user a login belongs to, or ErrNoUser.
	Find(ctx context.Context, login string) (User, error)
	Get(ctx context.Context, id UserID) (User, error)
	// Address returns where a message on ch reaches the user, or "" when
	// the user has none.
	Address(ctx context.Context, id UserID, ch Channel) (string, error)
}

// MessageKind says what a message is for.
type MessageKind int

const (
	MsgSignInCode MessageKind = iota + 1
	MsgRecoveryCode
	MsgRecoveryLink
	MsgInvitation
	MsgPasswordChanged
	MsgNewDevice
	MsgFactorAdded
	MsgFactorRemoved
)

// Message is what the app's Sender renders and delivers.
type Message struct {
	Kind    MessageKind
	Channel Channel
	To      string
	User    UserID
	Code    string // for a code
	Token   string // for a link or an invitation; the app builds the URL
	Expires time.Time
}

// Sender delivers messages. Auth sends nothing itself.
type Sender interface {
	Send(ctx context.Context, m Message) error
}

// Claimer gives the app's claims for a session. Optional.
type Claimer interface {
	Claims(ctx context.Context, u User) (map[string]any, error)
}

// Recorder receives every decision auth makes. Optional: without one,
// events go to log/slog.
type Recorder interface {
	Record(ctx context.Context, e Event)
}

// Event is one decision. It never holds a password, a code, a token or a
// key, and Reason is a fixed word.
type Event struct {
	At      time.Time
	Kind    string // "signin.succeeded", "code.sent", … (§5.11)
	User    UserID
	Session SessionID
	Client  Client
	Method  string
	Reason  string
}

// Client is who made a request.
type Client struct {
	Addr      netip.Addr
	UserAgent string
}

// Policy is what a user's sessions need.
type Policy struct {
	AllowUnverified bool // Finish may issue an unverified session
	TrustDevices    bool // a registered device stands for the second proof
}

// Config is auth's configuration, one getter per key of interface §4.8.
// authschema declares the keys for a cfgx app; any type with these getters
// will do.
type Config interface {
	AuthIssuer() string
	AuthSecret() cfgx.Secret
	AuthSecretPrevious() cfgx.Secret
	AuthSessionIdle() time.Duration
	AuthSessionRememberedIdle() time.Duration
	AuthSessionLifetime() time.Duration
	AuthAccessLifetime() time.Duration
	AuthRefreshGrace() time.Duration
	AuthFlowLifetime() time.Duration
	AuthFreshWindow() time.Duration
	AuthCodeLength() int
	AuthCodeLifetime() time.Duration
	AuthCodeTries() int
	AuthCodeResend() time.Duration
	AuthCodeHourly() int
	AuthLinkLifetime() time.Duration
	AuthInvitationLifetime() time.Duration
	AuthDeviceLifetime() time.Duration
	AuthPasswordMinLength() int
	AuthPasswordMinScore() int
	AuthPasswordMemory() int
	AuthPasswordTime() int
	AuthPasswordConcurrency() int
	AuthThrottleFree() int
	AuthThrottleCeiling() time.Duration
	AuthThrottleWindow() time.Duration
	AuthCookieInsecure() bool
	AuthTrustedOrigins() []string
}

// Auth is the package's entry point. It is safe for concurrent use.
type Auth struct {
	db     *bolt.DB
	cfg    Config
	dir    Directory
	sender Sender
	keys   *secrets.Keys
	hasher *password.Hasher
	cop    *http.CrossOriginProtection

	claimer    Claimer
	recorder   Recorder
	policy     func(ctx context.Context, u User) Policy
	first      []string
	methods    map[string]Method
	clientAddr func(r *http.Request) netip.Addr
	reject     func(w http.ResponseWriter, r *http.Request, err error)
	now        func() time.Time
}

// Option changes how New builds an Auth.
type Option func(*Auth)

// WithClaims sets the Claimer.
func WithClaims(c Claimer) Option { return func(a *Auth) { a.claimer = c } }

// WithRecorder sets the Recorder.
func WithRecorder(r Recorder) Option { return func(a *Auth) { a.recorder = r } }

// WithPolicy decides each user's policy. Without it, every user gets
// Policy{TrustDevices: true}: no unverified sessions.
func WithPolicy(f func(ctx context.Context, u User) Policy) Option {
	return func(a *Auth) { a.policy = f }
}

// WithFirst names the methods accepted as a first proof; the password
// without it. They are the same for every login, known or not.
func WithFirst(methods ...string) Option {
	return func(a *Auth) { a.first = append([]string(nil), methods...) }
}

// WithMethods adds methods from modules. The engine drives them from
// v0.2.0, with auth/passkey; until then New refuses any, so that no flow
// offers a method it can't prove.
func WithMethods(ms ...Method) Option {
	return func(a *Auth) {
		for _, m := range ms {
			a.methods[m.Name()] = m
		}
	}
}

// WithClientAddr tells Load how to read the client's address from a
// request, for an app behind proxies.
func WithClientAddr(f func(r *http.Request) netip.Addr) Option {
	return func(a *Auth) { a.clientAddr = f }
}

// WithReject sets how Require answers a request it refuses, and Load a
// forged one. Without it the answer is the error's status and its message
// in the request's locale.
func WithReject(f func(w http.ResponseWriter, r *http.Request, err error)) Option {
	return func(a *Auth) { a.reject = f }
}

// WithClock sets the clock, for tests.
func WithClock(now func() time.Time) Option { return func(a *Auth) { a.now = now } }

type clientKey struct{}

// WithClient sets the client for code that isn't serving a request.
func WithClient(ctx context.Context, c Client) context.Context {
	return context.WithValue(ctx, clientKey{}, c)
}

func clientFrom(ctx context.Context) Client {
	c, _ := ctx.Value(clientKey{}).(Client)
	return c
}

// builtIn are the methods the core implements, by the milestone that adds
// them. A method named in WithFirst must be one of these or a module's.
var builtIn = map[string]bool{MethodPassword: true, MethodEmailCode: true, MethodSMSCode: true}

// New returns an Auth over db. It refuses a master secret shorter than 32
// bytes and a config whose values fall outside interface §4.8's ranges.
func New(db *bolt.DB, cfg Config, dir Directory, sender Sender, opts ...Option) (*Auth, error) {
	if db == nil || cfg == nil || dir == nil || sender == nil {
		return nil, errors.New("auth: New needs a database, a config, a directory and a sender")
	}
	if err := validate(cfg); err != nil {
		return nil, err
	}
	var prev []byte
	if cfg.AuthSecretPrevious().IsSet() {
		prev = []byte(cfg.AuthSecretPrevious().Reveal())
	}
	keys, err := secrets.New([]byte(cfg.AuthSecret().Reveal()), prev)
	if err != nil {
		return nil, fmt.Errorf("auth: %w", err)
	}
	hasher, err := password.New(password.Params{
		MemoryKiB: uint32(cfg.AuthPasswordMemory()) << 10,
		Time:      uint32(cfg.AuthPasswordTime()),
	}, cfg.AuthPasswordConcurrency())
	if err != nil {
		return nil, fmt.Errorf("auth: %w", err)
	}
	cop := http.NewCrossOriginProtection()
	for _, o := range cfg.AuthTrustedOrigins() {
		if err := cop.AddTrustedOrigin(o); err != nil {
			return nil, fmt.Errorf("auth: trusted_origins: %w", err)
		}
	}
	a := &Auth{
		db: db, cfg: cfg, dir: dir, sender: sender, keys: keys, hasher: hasher, cop: cop,
		policy:  func(context.Context, User) Policy { return Policy{TrustDevices: true} },
		first:   []string{MethodPassword},
		methods: map[string]Method{},
		now:     time.Now,
	}
	for _, o := range opts {
		o(a)
	}
	if len(a.methods) > 0 {
		return nil, errors.New("auth: methods from modules aren't driven before v0.2.0")
	}
	if len(a.first) == 0 {
		return nil, errors.New("auth: WithFirst names no method")
	}
	for _, m := range a.first {
		if !builtIn[m] && a.methods[m] == nil {
			return nil, fmt.Errorf("auth: WithFirst names %q, which isn't available", m)
		}
	}
	if err := store.Init(db); err != nil {
		return nil, fmt.Errorf("auth: %w", err)
	}
	stale, lost, err := a.staleSecrets()
	if err != nil {
		return nil, fmt.Errorf("auth: %w", err)
	}
	logStale(stale, lost)
	if cfg.AuthCookieInsecure() {
		slog.Warn("auth: cookie.insecure is set: cookies lose Secure and their __Host- prefix; for development only")
	}
	return a, nil
}

// validate checks every key against interface §4.8's range, and reports
// them all at once.
func validate(c Config) error {
	var errs []error
	bad := func(key, want string) { errs = append(errs, fmt.Errorf("auth: %s must be %s", key, want)) }
	dur := func(key string, d, lo, hi time.Duration) {
		if d < lo || hi > 0 && d > hi {
			if hi > 0 {
				bad(key, fmt.Sprintf("from %v to %v", lo, hi))
			} else {
				bad(key, fmt.Sprintf("at least %v", lo))
			}
		}
	}
	num := func(key string, n, lo, hi int) {
		if n < lo || hi > 0 && n > hi {
			if hi > 0 {
				bad(key, fmt.Sprintf("from %d to %d", lo, hi))
			} else {
				bad(key, fmt.Sprintf("at least %d", lo))
			}
		}
	}
	if c.AuthIssuer() == "" {
		bad("issuer", "set")
	}
	if s := c.AuthSecret(); !s.IsSet() || len(s.Reveal()) < secrets.MinSecret {
		bad("secret", "at least 32 bytes")
	}
	if s := c.AuthSecretPrevious(); s.IsSet() && len(s.Reveal()) < secrets.MinSecret {
		bad("secret_previous", "at least 32 bytes when set")
	}
	dur("session.idle", c.AuthSessionIdle(), 5*time.Minute, 0)
	dur("session.remembered_idle", c.AuthSessionRememberedIdle(), max(c.AuthSessionIdle(), 5*time.Minute), 0)
	dur("session.lifetime", c.AuthSessionLifetime(), max(c.AuthSessionRememberedIdle(), 5*time.Minute), 0)
	dur("access.lifetime", c.AuthAccessLifetime(), time.Minute, time.Hour)
	if g := c.AuthRefreshGrace(); g < 0 || g > time.Minute {
		bad("refresh.grace", "from 0 to 1m0s")
	}
	dur("flow.lifetime", c.AuthFlowLifetime(), time.Minute, time.Hour)
	dur("fresh.window", c.AuthFreshWindow(), time.Minute, time.Hour)
	num("code.length", c.AuthCodeLength(), 6, 10)
	dur("code.lifetime", c.AuthCodeLifetime(), time.Minute, 15*time.Minute)
	num("code.tries", c.AuthCodeTries(), 1, 10)
	dur("code.resend", c.AuthCodeResend(), 10*time.Second, 0)
	num("code.hourly", c.AuthCodeHourly(), 1, 20)
	dur("link.lifetime", c.AuthLinkLifetime(), 5*time.Minute, 24*time.Hour)
	dur("invitation.lifetime", c.AuthInvitationLifetime(), time.Hour, 720*time.Hour)
	dur("device.lifetime", c.AuthDeviceLifetime(), 24*time.Hour, 0)
	num("password.min_length", c.AuthPasswordMinLength(), 8, 0)
	num("password.min_score", c.AuthPasswordMinScore(), 3, 4)
	num("password.memory", c.AuthPasswordMemory(), 19, 4096)
	num("password.time", c.AuthPasswordTime(), 1, 64)
	num("password.concurrency", c.AuthPasswordConcurrency(), 1, 0)
	num("throttle.free", c.AuthThrottleFree(), 1, 20)
	dur("throttle.ceiling", c.AuthThrottleCeiling(), time.Minute, 24*time.Hour)
	dur("throttle.window", c.AuthThrottleWindow(), time.Minute, 24*time.Hour)
	return errors.Join(errs...)
}
