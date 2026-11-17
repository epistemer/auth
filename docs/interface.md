# auth — Interface (v1, locked)

> Status: **locked on 2026-11-14** by epistemer, as revised after
> [review 0001](reviews/0001-design.md), with every decision of §3 as it
> stands. Written that day from [brief.md](brief.md) and spikes S1–S3. Any
> change to what an app writes or gets back, or any looser rule of §5, needs
> an explicit amendment, recorded in §10.
>
> The design and the options it rejected are in
> [ADR 0001](adr/0001-one-flow.md). This file is the contract.
>
> **Passkeys** (§4.11, §5.13, §6.6, and the changes to §4.2, §4.3, §4.9,
> §5.1.3, §5.5, §7 and §9) were locked by epistemer on 2026-11-17 as
> amendment A21, with decisions D27–D36 as recommended. The reasons are in
> [ADR 0008](adr/0008-passkeys.md).

## 1. Scope

`github.com/epistemer/auth` is neozp's authentication package. It covers:

- proving who a user is: passwords, emailed or texted codes and links,
  authenticator apps, recovery codes, and, in later modules, passkeys and
  OpenID Connect;
- sessions for browsers (a cookie) and for apps (a bearer token pair);
- registered devices, and the difference between a verified and an
  unverified session;
- permissions, in `auth/access`.

It doesn't cover the user table, sending messages, pages or handlers. The app
writes those over the API of §4. What `v0.1.0` leaves out is in §9.

## 2. Principles

1. **The app owns users; auth owns proofs.** Auth has no user table. It asks
   the app's `Directory` who a login belongs to and where a code goes.
2. **Every way in is one flow.** A flow is a short-lived record that collects
   proofs. Only `Finish` makes or upgrades a session, and only when the
   user's policy is met.
3. **A session records what was proven.** It is verified or unverified, and
   it lists its factors with their times.
4. **Routes fail closed.** `Require` needs a verified session unless a
   requirement says `auth.Unverified`.
5. **Nothing secret is stored as it travels.** Tokens and codes are stored as
   hashes, passwords as argon2id, authenticator secrets encrypted.
6. **One answer for unknown accounts.** A flow behaves the same whether or
   not the login exists, until a correct first proof.
7. **Auth sends nothing and builds no URL.** The app's `Sender` does.
8. **The core depends on** bbolt, protobuf, `golang.org/x/crypto`,
   `golang.org/x/text`, cfgx (for `cfgx.Secret`), i18n and errors. Passkeys,
   OIDC and the cfgx schema fragment are modules of their own.

## 3. Decisions

| # | Topic | Decision | Who |
|---|---|---|---|
| D1 | Scope | Authentication, sessions, devices and authorization. No SAML | epistemer |
| D2 | Users | The app owns the user table. Auth sees users through `Directory` | Claude |
| D3 | Store | bbolt, passed in as a `*bbolt.DB`. Records are protobuf. No storage interface | epistemer |
| D4 | Flows | One engine: five starters, then `Challenge`, `Prove`, `Finish`. Only `SignIn` makes a session | Claude |
| D5 | Sessions | One model, two carriers: an opaque cookie, and a bearer pair | epistemer |
| D6 | Bearer | The access token is a JWT with the app's claims. The refresh token is opaque and rotates | epistemer |
| D7 | Liveness | The access token names its session, and every request checks it | epistemer |
| D8 | Claims | The app implements `Claimer`; auth calls it at `Finish`, `Refresh` and `Reissue` | Claude |
| D9 | Assurance | Sessions are verified or unverified. `Require` needs a verified one by default | epistemer |
| D10 | Devices | A registered device is a server-issued token. Whether it stands for the second proof is the policy's `TrustDevices` | Claude |
| D11 | Authorization | `auth/access`: permissions declared in code; groups and memberships in bbolt. No casbin | epistemer |
| D12 | Scoping | Resource-scoped permissions are out of `v0.1` | epistemer |
| D13 | CSRF | `http.CrossOriginProtection` and `SameSite` cookies. No per-form token | epistemer |
| D14 | Modules | `auth/passkey`, `auth/oidc` and `auth/authschema` are nested modules ([ADR 0004](adr/0004-methods-as-modules.md)) | epistemer |
| D15 | Passwords | argon2id at 64 MiB and two passes, bounded ([ADR 0003](adr/0003-argon2-cost.md)). No composition rules, no trimming | Claude |
| D16 | Authenticator apps | TOTP written in the core, with recovery codes | Claude |
| D17 | Messages | The app's `Sender` renders, delivers and builds URLs | Claude |
| D18 | Throttling | Growing waits by account, client address and the pair; no permanent lockout. Counters are written with `Batch` ([ADR 0002](adr/0002-throttle-writes.md)) | Claude |
| D19 | Audit | Every decision is an `Event` given to the app's `Recorder` | Claude |
| D20 | Secrets | One master secret; HKDF derives a key per use | Claude |
| D21 | HTTP | `net/http` middleware only | sibling convention |
| D22 | `UserID` | A string: opaque, at most 64 bytes, never a login or an address | Claude |
| D23 | Token signing | HS256 under a derived key, by an encoder written in the core for that one fixed format | Claude |
| D24 | Names | Constants carry their kind as a prefix (`MethodTOTP`, `MsgNewDevice`, `PurposeSignIn`); proofs are bare (`auth.TOTP(code)`) | Claude |
| D25 | Recovery | `Recover` and `Accept` set a password and make no session; the user then signs in | Claude, after review 0001 |
| D26 | Address codes | A code sent to an address is a second proof only for a user with no enrolled second factor | Claude, after review 0001 |
| D27 | The method's name | `auth.MethodPasskey = "passkey"` in the core, beside `MethodTOTP`: an app compares `Offers` and calls `Enroll` and `WithFirst` with `auth.Method…` constants only (D24), and §5.7.2 already names passkeys among the core's second methods | epistemer (A21) |
| D28 | The constructor | `passkey.New(cfg passkey.Config) (auth.Method, error)`: nothing else of the module is a value an app holds | epistemer (A21) |
| D29 | Config | A fragment an app opts into: `authschema.Group(authschema.Passkey())`, which needs `Group(members ...dsl.Member)` (variadic, so every existing call compiles). Its `domain` is required, so an app has passkeys configured or none at all | epistemer (A21) |
| D30 | `Challenge.Options` | A `json.RawMessage`: WebAuthn Level 3's options object, unwrapped (no `publicKey` member around it), which `parseCreationOptionsFromJSON` and `parseRequestOptionsFromJSON` take as it is | epistemer (A21) |
| D31 | The proof | `passkey.Response(credential []byte) auth.Proof`: the JSON of the browser's `PublicKeyCredential.toJSON()` | epistemer (A21) |
| D32 | Signing in without a login | A starter of its own, `SignInWithout(ctx, c Carrier) (Flow, error)`. `SignIn(ctx, "", c)` keeps answering as for an unknown login (§5.1.3), so a blank form field changes nothing | epistemer (A21) |
| D33 | A factor's label | `auth.FactorLabel(label string) FinishOption`, for any `Enroll` ("Sara's phone"); without it, or empty, a passkey is "Passkey" | epistemer (A21) |
| D34 | Why a proof was refused | `auth.Refuse(reason string) error`, which a module's `Verify` returns; the engine records the reason and answers plain `ErrBadCredentials` | epistemer (A21) |
| D35 | A test authenticator for apps | `passkey/passkeytest`: `New(tb, origin string) *Authenticator`, `Create(options json.RawMessage) []byte` and `Get(options json.RawMessage) []byte`. One authenticator holds one passkey; a test with two makes two | epistemer (A21) |
| D36 | The clock a module reads | `MethodInput.Now time.Time`, the engine's clock (`WithClock`), so `authtest`'s clock moves passkeys too | epistemer (A21) |

Claude's calls, D4, D10 and D22–D26, were accepted with the lock. For D23,
the alternative is Ed25519 with a key file, which an amendment can add if
another service must verify tokens.

D27–D36 were locked with A21, each as recommended. Claude's calls for
passkeys are in ADR 0008: the library (go-webauthn), conveyance `none`,
UV required, every proof `Verified`, counters as WebAuthn §7.2 says, the
handle is the `UserID`, three algorithms, at most 20 passkeys a user, and
throttling by address (or a registered device's pair).

## 4. API

Every declaration below compiles: the spike of ADR 0004 holds them as stubs.

### 4.1 What the app provides

```go
// UserID is the app's identifier for a user. It is opaque, at most 64 bytes,
// and never a login or an address: it is stored in every record and becomes
// a passkey's user handle.
type UserID string

type User struct {
	ID       UserID
	Name     string // shown by authenticator apps and passkey managers; usually the login
	Disabled bool   // may not sign in
}

type Channel int

const (
	ChannelEmail Channel = iota + 1
	ChannelSMS
)

type Directory interface {
	// Find returns the user a login belongs to, or ErrNoUser.
	Find(ctx context.Context, login string) (User, error)
	Get(ctx context.Context, id UserID) (User, error)
	// Address returns where a message on ch reaches the user, or "" when
	// the user has none.
	Address(ctx context.Context, id UserID, ch Channel) (string, error)
}

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

type Message struct {
	Kind    MessageKind
	Channel Channel
	To      string
	User    UserID
	Code    string    // for a code
	Token   string    // for a link or an invitation; the app builds the URL
	Expires time.Time
}

type Sender interface {
	Send(ctx context.Context, m Message) error
}

// Optional.

type Claimer interface {
	Claims(ctx context.Context, u User) (map[string]any, error)
}

type Recorder interface {
	Record(ctx context.Context, e Event)
}

type Event struct {
	At      time.Time
	Kind    string // "signin.succeeded", "code.sent", … (§5.11)
	User    UserID
	Session SessionID
	Client  Client
	Method  string
	Reason  string
}

type Client struct {
	Addr      netip.Addr
	UserAgent string
}

type Policy struct {
	AllowUnverified bool // Finish may issue an unverified session
	TrustDevices    bool // a registered device stands for the second proof
}
```

### 4.2 New

```go
func New(db *bbolt.DB, cfg Config, dir Directory, sender Sender, opts ...Option) (*Auth, error)

func WithClaims(c Claimer) Option
func WithRecorder(r Recorder) Option
func WithPolicy(f func(ctx context.Context, u User) Policy) Option
func WithFirst(methods ...string) Option // the methods accepted as a first proof; the password without it
func WithMethods(ms ...Method) Option
func WithClientAddr(f func(r *http.Request) netip.Addr) Option
func WithReject(f func(w http.ResponseWriter, r *http.Request, err error)) Option
func WithClock(now func() time.Time) Option

// WithClient sets the client for code that isn't serving a request.
func WithClient(ctx context.Context, c Client) context.Context
```

`New` refuses a master secret shorter than 32 bytes and a config whose values
fall outside §4.8's ranges. Without `WithPolicy`, every user gets
`Policy{TrustDevices: true}`: no unverified sessions. The first methods are
the same for every login, known or not, so they can't be part of a user's
policy.

**A21:** `New` accepts `WithMethods` (A19 is withdrawn). It refuses a nil
method, two methods of one name, a module method named like a built-in
one, and a name outside `[a-z0-9_]{1,32}`. `WithFirst` may name a module's
method, and still refuses a name that is neither built in nor given to
`WithMethods`.

### 4.3 Flows

```go
type Purpose int

const (
	PurposeSignIn Purpose = iota + 1
	PurposeStepUp
	PurposeRecover
	PurposeAccept
	PurposeEnroll
)

const (
	MethodPassword     = "password"
	MethodEmailCode    = "email_code"
	MethodSMSCode      = "sms_code"
	MethodEmailLink    = "email_link"
	MethodTOTP         = "totp"
	MethodRecoveryCode = "recovery_code"
)

type Flow struct {
	Token    string
	Purpose  Purpose
	Ready    bool     // Finish will succeed
	Verified bool     // a SignIn or StepUp would end in a verified session
	Offers   []string // the methods the UI may show next
	Expires  time.Time
}

// Write keeps the flow's token in the cookie carrier's flow cookie, and
// FlowToken reads it back from a request that went through Load. An app
// may carry the token another way; it is a secret either way (§5.1).
func (f Flow) Write(w http.ResponseWriter)
func FlowToken(ctx context.Context) (string, bool)

// Starters. Only SignIn makes a session, so only it takes the carrier.
func (a *Auth) SignIn(ctx context.Context, login string, c Carrier, opts ...StartOption) (Flow, error)
func (a *Auth) StepUp(ctx context.Context, s *Session) (Flow, error)
func (a *Auth) Recover(ctx context.Context, login string) (Flow, error)
func (a *Auth) Accept(ctx context.Context, invitation string) (Flow, error)
func (a *Auth) Enroll(ctx context.Context, s *Session, method string) (Flow, error)

// Device passes the device token an app stored. The cookie carrier reads
// its own.
func Device(token string) StartOption

// Follow returns the flow an emailed link belongs to. Holding the link is
// the proof. It changes nothing a second call wouldn't, so it is safe on a
// GET that a mail scanner may fetch first.
func (a *Auth) Follow(ctx context.Context, link string) (Flow, error)

// Flow returns a flow's current state.
func (a *Auth) Flow(ctx context.Context, token string) (Flow, error)

// Challenge prepares a proof: it sends a code or a link, or returns what
// the client needs.
func (a *Auth) Challenge(ctx context.Context, token, method string) (Challenge, error)

type Challenge struct {
	Method  string
	SentTo  string     // a masked address; empty before the first proof
	Resend  time.Time  // when another may be asked for
	TOTP    *TOTPSetup // when enrolling an authenticator app
	Options any        // a module's own answer: passkey options, a redirect URL
}

type TOTPSetup struct {
	Secret string // base32
	URI    string // otpauth://
}

func (a *Auth) Prove(ctx context.Context, token string, p Proof) (Flow, error)

type Proof interface{ Method() string }

func Password(pw string) Proof
func EmailCode(code string) Proof
func SMSCode(code string) Proof
func TOTP(code string) Proof
func RecoveryCode(code string) Proof

// Finish ends the flow. For a SignIn it makes the session; for a StepUp it
// upgrades the flow's session; for an Enroll it stores the factor; for a
// Recover or an Accept it sets the password and makes no session.
func (a *Auth) Finish(ctx context.Context, token string, opts ...FinishOption) (Result, error)

func Cookie() Carrier
func Bearer() Carrier

func NewPassword(pw string) FinishOption       // Recover, Accept, and Enroll of the password
func Remember() FinishOption                   // SignIn: the longer idle lifetime
func RememberDevice(label string) FinishOption // SignIn, StepUp: register this device

type Result struct {
	Session       *Session // SignIn and StepUp
	Access        string   // bearer
	Refresh       string   // bearer
	Device        string   // bearer: the device's token, new or replaced
	RecoveryCodes []string // shown once, when the first second factor was enrolled
}

// Write sets the cookie carrier's cookies (session, device) and clears the
// flow cookie.
func (r Result) Write(w http.ResponseWriter)
```

Added by A21:

```go
const MethodPasskey = "passkey" // D27

// SignInWithout starts a sign-in that names no login, for a method that
// finds the user from its proof, such as a passkey in autofill (D32).
func (a *Auth) SignInWithout(ctx context.Context, c Carrier) (Flow, error)

// FactorLabel names the factor an Enroll adds, as Factors shows it (D33).
// It is cut at 64 characters, control characters are dropped, and an
// empty label gives the method's own. The password and recovery codes
// ignore it.
func FactorLabel(label string) FinishOption

// Refuse is what a module's Verify returns for a proof it refuses (D34).
// It wraps ErrBadCredentials and its Error() is fixed: the reason is in
// no message. reason is the event's Reason and matches [a-z][a-z0-9_]{0,31};
// any other is recorded as "refused".
func Refuse(reason string) error
```

Adds `SignInWithout` (D32): a flow that knows no user, whose
`Offers` are `WithFirst`'s module methods; with none it is
`ErrMethodUnavailable`. The `Directory` isn't asked. A device token the
request presents is read at the start: it serves throttling (§5.13.11),
and stands for nothing if the proof names another user. `SignIn` with an empty login is
unchanged. `Enroll` takes a module's method. Adds `FactorLabel` (D33) and
`MethodPasskey` (D27).

What `Challenge` returns for a passkey: `Method` is `"passkey"`, `SentTo`
and `Resend` are empty, and `Options` is the `json.RawMessage` of D30.

### 4.4 Sessions and requests

```go
type SessionID string
type DeviceID string

type Session struct {
	ID       SessionID
	User     UserID
	Verified bool
	Factors  []Factor
	Device   DeviceID
	Created  time.Time
	Seen     time.Time
	Expires  time.Time
	Client   Client // as seen when it was made
	Claims   map[string]any
}

type Factor struct {
	Method string
	At     time.Time
}

// Load attaches the request's session, when it has a live one, and its
// client. It rejects nothing.
func (a *Auth) Load(carriers ...Carrier) func(http.Handler) http.Handler

// Require rejects a request whose session doesn't meet every requirement.
// With no requirement that names a level, it needs a verified session.
func (a *Auth) Require(reqs ...Requirement) func(http.Handler) http.Handler

// Check is Require for code that isn't a route.
func (a *Auth) Check(ctx context.Context, reqs ...Requirement) error

func From(ctx context.Context) (*Session, bool)

type Requirement interface {
	Check(ctx context.Context, s *Session) error
}

type Level int

const (
	Verified Level = iota
	Unverified
)

func Within(d time.Duration) Requirement // a proof made no longer ago than d

func (a *Auth) Refresh(ctx context.Context, refresh string) (Result, error)
func (a *Auth) Reissue(ctx context.Context, s *Session) (access string, err error)
func (a *Auth) SignOut(ctx context.Context, w http.ResponseWriter) error
func (a *Auth) Revoke(ctx context.Context, user UserID, id SessionID) error
func (a *Auth) RevokeUser(ctx context.Context, id UserID) error
func (a *Auth) Sessions(ctx context.Context, id UserID) ([]Session, error)
func (a *Auth) Devices(ctx context.Context, id UserID) ([]DeviceInfo, error)
func (a *Auth) ForgetDevice(ctx context.Context, user UserID, id DeviceID) error
```

`Revoke` and `ForgetDevice` take the user as well as the ID and do nothing
for an ID that isn't that user's, so an ID from a request can't reach
someone else's session.

`Level` is a `Requirement`. `DeviceInfo` has an ID, a label and three times
(created, used, expires).

### 4.5 Management

```go
func (a *Auth) CheckPassword(ctx context.Context, pw string, hints ...string) error
func (a *Auth) SetPassword(ctx context.Context, id UserID, pw string) error // seeding and admin tools
func (a *Auth) Invite(ctx context.Context, id UserID) (token string, err error)
func (a *Auth) Factors(ctx context.Context, id UserID) ([]FactorInfo, error)
func (a *Auth) RemoveFactor(ctx context.Context, s *Session, factorID string) error
func (a *Auth) ResetFactors(ctx context.Context, id UserID) error // an admin's answer to a lost phone
func (a *Auth) DeleteUser(ctx context.Context, id UserID) error   // everything auth holds for the user
func (a *Auth) Sweep(ctx context.Context) error                   // removes what has expired
func (a *Auth) Rekey(ctx context.Context) error                   // re-encrypts under the current secret (§5.12)
```

`FactorInfo` has an ID, the method, a label and two times (added, used).

### 4.6 Errors

Each is an `errors.Key` under `errors.auth.<name>`. `ErrNoUser` is private:
it is what a `Directory` returns.

| Error | Kind | When |
|---|---|---|
| `ErrBadCredentials` | Unauthenticated | A wrong first proof, or an unknown login |
| `ErrBadCode` | Unauthenticated | A wrong, used or expired code or link |
| `ErrTooManyAttempts` | RateLimited | A wait is in force; `RetryAfter(err)` says how long |
| `ErrFlowExpired` | Invalid | The flow token is unknown or too old |
| `ErrNotReady` | Invalid | `Finish` before the policy is met |
| `ErrPasswordRequired` | Invalid | `Finish` of a flow that sets a password, without `NewPassword` |
| `ErrMethodUnavailable` | Invalid | The method isn't on offer in this flow |
| `ErrCannotVerify` | Forbidden | The policy needs a second proof and the user has no way to give one |
| `ErrUserDisabled` | Forbidden | After a correct first proof only |
| `ErrNoSession` | Unauthenticated | `Require` without a live session |
| `ErrNotVerified` | Forbidden | A verified session is needed; a step-up will fix it |
| `ErrStale` | Forbidden | `Within` wasn't met; a step-up will fix it |
| `ErrForbidden` | Forbidden | The user lacks the permission |
| `ErrPasswordTooShort` | Invalid | Takes the minimum as its argument |
| `ErrPasswordTooLong` | Invalid | Over 1024 bytes |
| `ErrPasswordCommon` | Invalid | Made mostly of common passwords, words or names (A3) |
| `ErrPasswordPersonal` | Invalid | Contains the login, a name or a hint, or is made mostly of them (A3) |
| `ErrPasswordSimple` | Invalid | Repeats, sequences, keyboard walks, dates and years, whole or mostly (A3) |

```go
func RetryAfter(err error) (time.Duration, bool)
```

### 4.7 `auth/access`

```go
// Permission declares a permission. Its key is permanent. It needs a
// verified session unless level says otherwise.
func Permission(key, text string, level ...auth.Level) *Perm

func (p *Perm) Key() string
func (p *Perm) T(ctx context.Context, args ...any) string // an i18n.Ter: key "permission.<key>"
func Permissions() []*Perm                                // every one declared

type GroupID string

const Root GroupID = "root"

type Group struct {
	ID   GroupID
	Name string
}

func New(db *bbolt.DB) (*Access, error)

func (ac *Access) Can(p *Perm) auth.Requirement
func (ac *Access) Check(ctx context.Context, id auth.UserID, p *Perm) error

func (ac *Access) CreateGroup(ctx context.Context, name string) (Group, error)
func (ac *Access) RenameGroup(ctx context.Context, id GroupID, name string) error
func (ac *Access) DeleteGroup(ctx context.Context, id GroupID) error
func (ac *Access) Grant(ctx context.Context, id GroupID, p *Perm) error
func (ac *Access) Withdraw(ctx context.Context, id GroupID, p *Perm) error
func (ac *Access) Join(ctx context.Context, u auth.UserID, id GroupID) error
func (ac *Access) Leave(ctx context.Context, u auth.UserID, id GroupID) error
func (ac *Access) RemoveUser(ctx context.Context, u auth.UserID) error // every membership; call it before auth's DeleteUser
func (ac *Access) Groups(ctx context.Context) ([]Group, error)
func (ac *Access) GroupsOf(ctx context.Context, u auth.UserID) ([]Group, error)
func (ac *Access) Members(ctx context.Context, id GroupID) ([]auth.UserID, error)
func (ac *Access) Granted(ctx context.Context, id GroupID) ([]*Perm, error)
func (ac *Access) Stale(ctx context.Context) ([]string, error) // granted keys no longer declared
```

### 4.8 Config

`auth.Config` is an interface with one getter per key. `authschema.Group()`
returns the cfgx group `auth`, pinned with `GoName("Auth")`. No key name holds
an initialism, so the getter names don't depend on the app's list.

| Key | Getter | Default | Range |
|---|---|---|---|
| `issuer` | `AuthIssuer() string` | required | – |
| `secret` | `AuthSecret() cfgx.Secret` | required | at least 32 bytes |
| `secret_previous` | `AuthSecretPrevious() cfgx.Secret` | unset | at least 32 bytes |
| `session.idle` | `AuthSessionIdle() time.Duration` | 24h | 5m and up |
| `session.remembered_idle` | `AuthSessionRememberedIdle()` | 720h | at least `session.idle` |
| `session.lifetime` | `AuthSessionLifetime()` | 2160h | at least `session.remembered_idle` |
| `access.lifetime` | `AuthAccessLifetime()` | 10m | 1m to 1h |
| `refresh.grace` | `AuthRefreshGrace()` | 10s | up to 1m |
| `flow.lifetime` | `AuthFlowLifetime()` | 15m | 1m to 1h |
| `fresh.window` | `AuthFreshWindow()` | 10m | 1m to 1h |
| `code.length` | `AuthCodeLength() int` | 6 | 6 to 10 |
| `code.lifetime` | `AuthCodeLifetime()` | 5m | 1m to 15m |
| `code.tries` | `AuthCodeTries() int` | 5 | 1 to 10 |
| `code.resend` | `AuthCodeResend()` | 60s | 10s and up |
| `code.hourly` | `AuthCodeHourly() int` | 5 | 1 to 20 |
| `link.lifetime` | `AuthLinkLifetime()` | 30m | 5m to 24h |
| `invitation.lifetime` | `AuthInvitationLifetime()` | 72h | 1h to 720h |
| `device.lifetime` | `AuthDeviceLifetime()` | 2160h | 24h and up |
| `password.min_length` | `AuthPasswordMinLength() int` | 12 | 8 and up |
| `password.min_score` | `AuthPasswordMinScore() int` | 4 | 3 to 4 (A3) |
| `password.memory` | `AuthPasswordMemory() int` (MiB) | 64 | 19 to 4096 (A4) |
| `password.time` | `AuthPasswordTime() int` | 2 | 1 to 64 (A4) |
| `password.concurrency` | `AuthPasswordConcurrency() int` | the number of CPUs | 1 and up |
| `throttle.free` | `AuthThrottleFree() int` | 5 | 1 to 20 |
| `throttle.ceiling` | `AuthThrottleCeiling()` | 15m | 1m to 24h |
| `throttle.window` | `AuthThrottleWindow()` | 1h | 1m to 24h |
| `cookie.insecure` | `AuthCookieInsecure() bool` | false | development only |
| `trusted_origins` | `AuthTrustedOrigins() []string` | none | – |

The ranges are checked by the schema and again by `New` (A9), so a hand-written
config can't set five hours where five minutes was meant. Every lifetime is a
duration with its unit written out. Lifetimes, lengths and thresholds may be
`Mutable`; auth reads the getter each time. The secrets and
`cookie.insecure` aren't.

### 4.9 For modules

```go
type Method interface {
	Name() string
	// Start makes what the client needs to produce a proof, and state the
	// flow keeps until Verify.
	Start(ctx context.Context, in MethodInput) (out any, state []byte, err error)
	Verify(ctx context.Context, in MethodInput, state []byte, proof Proof) (MethodResult, error)
}

type MethodInput struct {
	Purpose     Purpose
	User        *User        // nil when the flow doesn't know the user yet
	Credentials []Credential // the user's credentials for this method
	Find        func(key []byte) (UserID, *Credential, error)
	Lookup      func(id UserID) (User, []Credential, error)
	Now         time.Time // the engine's clock (A21)
}

type Credential struct {
	Key   []byte // unique within the method
	Data  []byte // the method's own record
	Label string
}

type MethodResult struct {
	User       UserID      // who the proof belongs to, when the flow didn't know
	Credential *Credential // to store, or to update
	Verified   bool        // the proof counts as two factors
	Unlinked   *Identity   // a valid identity that belongs to no user
}

type Identity struct {
	Issuer, Subject, Email string
	EmailVerified          bool
}
```

The engine, not the method, applies throttling, events, the policy and the
rules of §5.1 around these calls.

Added by A21 (`Refuse` is declared in §4.3):

- `Find` returns `""` and nil when no user holds the key. `Lookup` returns
  a zero `User` and no credentials, with a nil error, for a user who is
  gone. Each reads the store when called. The engine remembers every
  credential they and `Credentials` handed to `Verify`, with its data,
  for rule 8 of §5.5.
- `MethodResult.Credential` is, outside an `Enroll`, the stored credential
  the proof used, updated or not; it is set on every accepted proof that
  used one. In an `Enroll` it is the new credential.
- In a flow started without a session (`SignIn`, `SignInWithout`,
  `Recover`, `Accept`), until its first proof, `Start` and `Verify` get a
  nil `User` and no `Credentials`, whatever the login: a method can't
  answer differently for a known login. A flow bound to a session
  (`StepUp`, `Enroll`) gives them from the start.
- `Verify` returns `Refuse(reason)` (D34) for a proof it refuses. Any other
  error is the method's own failure, which `Prove` returns as is; a
  module's own failures carry its own fixed text, never a library's.
- The state `Start` returns is kept in the flow until a `Prove` passes it
  to `Verify`, once, whatever the outcome (the method's own failure
  included), or a new `Challenge` replaces it. It is at
  most 4 KiB.
- `MethodInput.Now` is the engine's clock (D36).

### 4.10 `auth/authtest`

```go
func New(tb testing.TB, opts ...auth.Option) *Kit

type Kit struct {
	Auth  *auth.Auth
	Clock *Clock // Advance(d)
}

func (k *Kit) AddUser(login string, u auth.User, addresses ...string)
func (k *Kit) LastMessage(to string) (auth.Message, bool)
func (k *Kit) Events() []auth.Event
func Config(edit ...func(*Values)) auth.Config // the defaults, with cheap password hashing
```

### 4.11 `auth/passkey` (A21)

A nested module, `github.com/epistemer/auth/passkey`.

```go
// Config is what the module reads. An app's generated settings implement
// it when its schema holds authschema.Group(authschema.Passkey()).
type Config interface {
	AuthIssuer() string           // the relying party's name, shown by passkey managers
	AuthPasskeyDomain() string    // the relying party ID: the site's domain
	AuthPasskeyOrigins() []string // the origins a client may report; https://<domain> when empty
}

// New returns the passkey method, to pass to auth.WithMethods. It refuses
// a nil config, an empty issuer, and a domain that isn't a lowercase DNS
// name of at least two labels (or localhost), with no trailing dot and no
// IP address. Each origin must be exactly https://<host>[:<port>], where
// host is the domain or a name under it, with nothing after: no path, no
// slash, no query, no user. Two exceptions: http://localhost[:<port>] when
// the domain is localhost; and android:apk-key-hash:<43 base64url
// characters>.
func New(cfg Config) (auth.Method, error)

// Response is a passkey proof: the JSON of the PublicKeyCredential the
// client returned, as its toJSON() gives it. It is the answer to the
// Challenge of the flow it is proved on, a registration in an Enroll and
// an assertion otherwise.
func Response(credential []byte) auth.Proof
```

The core's additions are in §4.3 and §4.9.

In `auth/authschema` (D29):

```go
// Group returns the cfgx group auth. members are nested in it, such as
// Passkey().
func Group(members ...dsl.Member) *dsl.GroupDef

// Passkey returns the group passkey: domain (required) and origins.
func Passkey() *dsl.GroupDef
```

In `auth/passkey/passkeytest` (D35):

```go
// Authenticator is a software authenticator for tests, answering as
// origin. It holds at most one ES256 passkey and keeps its counter; a
// second Create fails the test.
func New(tb testing.TB, origin string) *Authenticator

// Create answers a registration's options with a new passkey; Get answers
// an assertion's options with it. Each returns what passkey.Response takes.
func (a *Authenticator) Create(options json.RawMessage) []byte
func (a *Authenticator) Get(options json.RawMessage) []byte
```

## 5. Rules

### 5.1 Flows

1. A flow is a record found by the SHA-256 of a 256-bit random token. It
   lives for `flow.lifetime`. A successful `Finish` deletes it; a `Finish`
   that fails, on a weak new password for example, leaves it.
2. Only `Finish` makes or upgrades a session. It succeeds when `Ready` is
   true, and `Ready` follows from the user's policy and §5.7.
3. `SignIn` and `Recover` return a flow for an unknown login exactly as for a
   known one. Before the first proof, `Offers` is the set `WithFirst` names,
   never the user's own. A `SignInWithout` flow answers alike whether or
   not the proof will name a user; before the first proof nothing in it
   depends on any account (A21).
4. A wrong password, an unknown login and a known user with no password do
   the same hashing work and return `ErrBadCredentials`.
5. `Challenge` reports success whether or not a message was sent: for an
   unknown login, a user with no address, a failed send, and a user past
   `code.hourly`. Before the first proof its `SentTo` is empty. What happened
   is an event, not something the client sees.
6. A disabled user is refused, with `ErrUserDisabled`, only after a correct
   first proof.
7. **`Recover`.** The first proof is the emailed or texted link or code. A
   user with an enrolled second factor must then prove it, or a recovery
   code; a second message to an address never counts (§5.7.2). `Finish` sets
   the new password and makes no session: the user signs in with it.
8. **`Accept`.** Holding the invitation is the only proof. `Finish` sets the
   password and makes no session.
9. **Changing factors.** `Enroll` and `RemoveFactor` need a verified session
   and a proof made within `fresh.window`. For a user with an enrolled second
   factor, that proof must be of a second method: a device and a password
   alone don't count. For a user with none, a proof of the first method is
   enough to enroll the first. `Enroll` then needs proof of the new factor
   before it is stored.
10. Finishing `Recover`, or changing a password, ends all the user's sessions
    but the one that made the change, forgets their devices, and sends
    `MsgPasswordChanged`. Adding and removing a factor send `MsgFactorAdded`
    and `MsgFactorRemoved`.
11. A flow token is a secret for its lifetime: whoever holds a ready flow can
    finish it. `Flow.Write` keeps it in the cookie `__Host-flow` (`Secure`,
    `HttpOnly`, `SameSite=Lax`); an app keeps it in memory.
12. A flow started from a session (`StepUp`, `Enroll`) is bound to that
    session and can only be finished for it. A session remembers its
    carrier, and `Finish` answers through the same one.

### 5.2 Passwords

1. argon2id, stored as a PHC string with its parameters. A hash made with
   other parameters is replaced at the next successful sign-in.
2. Concurrent hashes are bounded by `password.concurrency`. Requests beyond
   it wait; a request whose context ends while waiting is refused.
3. The password is normalized to NFKC and never trimmed. Input over 1024
   bytes is `ErrPasswordTooLong`. Nothing is truncated.
4. `CheckPassword` is the one judge of a new password, and every path that
   sets one calls it. It checks, in order: the length; the login, the
   user's name, the parts of their addresses, the issuer and the caller's
   hints; a password that is one trivial pattern as a whole; and zxcvbn's
   estimate of its guesses, over the embedded lists and the hints, whose
   score must reach `password.min_score` (A3, ADR 0006).
5. There are no rules about character classes, and no expiry by age.

### 5.3 Codes and links

1. A code is `code.length` decimal digits drawn uniformly from `crypto/rand`.
2. It is stored as HMAC-SHA256, under a derived key, over the flow, the
   purpose, the method and the code.
3. It is valid for one flow, for `code.lifetime`. A flow has one live code
   per method; a new one cancels the old.
4. A try is counted before the code is compared: one write transaction adds
   one to the code's tries and refuses when that passes `code.tries`. Any
   number of concurrent guesses get `code.tries` between them, and then the
   code is burnt.
5. Another code can be asked for after `code.resend`, and at most
   `code.hourly` are sent per user and per address in an hour. Past either
   limit nothing is sent, and `Challenge` answers as it always does (§5.1.5).
6. A link or an invitation carries a 256-bit token, stored as SHA-256. It is
   spent by the `Finish` of its flow, not by `Follow` or `Accept`, which may
   run more than once. They return the same `ErrBadCode` for a wrong, spent
   and expired one.
7. Codes and tokens are compared in constant time.

### 5.4 Authenticator apps and recovery codes

1. TOTP per RFC 6238 as authenticator apps implement it: HMAC-SHA1, six
   digits, thirty-second steps.
2. A code from the step before or after the current one is accepted. The
   last accepted step is stored, and a code for that step or an earlier one
   is refused. The comparison and the update are one write transaction, so
   one code can't be accepted twice by concurrent requests.
3. The secret is 160 random bits, encrypted at rest with AES-256-GCM under a
   derived key, with the user's ID as additional data.
4. The factor is stored only after `Prove` accepts one code for it.
5. Wrong codes count toward throttling like wrong passwords.
6. Ten recovery codes are made when a user's first second factor is
   enrolled. Each is sixteen base32 characters (80 bits), stored as SHA-256,
   used once. They don't depend on the master secret, so rotating it never
   loses them. A new set cancels the old. A recovery code counts as a second
   proof.

### 5.5 Methods from modules

1. A method's proof counts as two factors only when its `MethodResult` says
   `Verified`.
2. An identity is found by its key alone. Nothing is ever linked by matching
   an email address.
3. A proof that names a user other than the flow's is refused.
4. A credential whose key already belongs to another user is not stored.
5. Each module has a section of its own: passkeys §5.13 (A21); OIDC's is
   added by amendment when its milestone starts. How an app learns of an
   `Unlinked` identity is part of the OIDC one; a new field on `Flow` is a
   compatible change.

Rules 6–11 were added by A21. They hold for every module method; §5.13 and
the OIDC section add their own.

6. **Order.** `Prove` with a module's proof:
   (a) without counting anything: a flow that is gone is
   `ErrFlowExpired`; a method past rule 9's caps is
   `ErrMethodUnavailable`; a flow with no state for the method is
   `ErrBadCredentials` (reason `no_challenge`);
   (b) the attempt is counted (rule 9), or refused with
   `ErrTooManyAttempts`, leaving the state;
   (c) `Verify` runs on the state;
   (d) one write transaction takes the state from the flow; if it was
   replaced or used meanwhile, or the flow went, the proof is refused
   (`no_challenge`, or `ErrFlowExpired` with the count taken back, A20);
   on `Verify`'s own failure the count is taken back and that error
   returned;
   (e) in the same transaction, a refusal by `Verify`, or by rules 3, 7,
   8 and, in an `Enroll`, 10, is `ErrBadCredentials`, records
   `proof.refused` with its reason, and counts toward rule 9's cap;
   (f) then the flow's own checks answer as for any proof:
   `ErrUserDisabled` (§5.1.6; nothing about the credential is updated),
   `ErrFlowExpired` (A20), `ErrCannotVerify` (§5.7.4);
   (g) otherwise the proof is recorded. Outside an `Enroll` the
   credential's update is written with it. In an `Enroll` the new
   credential is kept in the flow until `Finish` stores it (§5.1.9),
   under the label `Finish` is given (`FactorLabel`).
7. A proof that names a user when the flow knew none sets the flow's
   user. One that names a user when the login didn't resolve is refused
   (rule 3).
8. **The credential used is checked.** Outside an `Enroll`, the
   `MethodResult.Credential` of an accepted proof must be one that
   `Find`, `Lookup` or `Credentials` handed to `Verify`, by its key, and
   the store must still hold it, with the data handed out, in the
   transaction of rule 6; else the proof is refused (reason `changed`).
   Other credentials the user holds aren't checked: removing one in
   another tab doesn't refuse a proof by another.
9. **Throttling.** A module's attempts count toward the address's counter
   and the pair's and user's counters of a kind of the method's own
   (A20), unless its section says otherwise (§5.13.11 does). §5.8.6 holds
   as for any proof. A flow takes at most ten `Challenge`s and five
   refused proofs per module method; past either, the method is
   `ErrMethodUnavailable` in that flow.
10. **Enrolling.** `Prove` in an `Enroll` refuses a credential whose key
    anyone holds already, the same user included (reason `duplicate`),
    and `Finish` checks it again in its transaction, with any limit the
    method's section sets on how many a user holds. A `Finish` refused
    for either is `ErrBadCredentials`, records `factor.refused` with the
    reason, drops the pending credential and its proof, and leaves the
    flow, which isn't `Ready` and offers the method again.
11. Whether a module's credential is an enrolled factor (§5.7.2) is its
    section's to say. A passkey is one (§5.13.12).

### 5.6 Sessions and tokens

1. Session, refresh, device, flow and link tokens are 256 random bits. Only
   their SHA-256 is stored.
2. A session ends at its idle lifetime (`session.idle`, or
   `session.remembered_idle` with `Remember`) or at `session.lifetime`,
   whichever comes first. `Seen` is written at most once a minute.
3. A session's token is replaced when its privilege changes: at `Finish` of
   a `StepUp`, and at every `Refresh`. `SignIn` never continues a session the
   request already carries. A session also has a generation number, which a
   `StepUp` raises.
4. **Cookie carrier.** The cookie is `__Host-session`: `Secure`, `HttpOnly`,
   `SameSite=Lax`, path `/`. With `cookie.insecure` it loses the prefix and
   `Secure`, and `New` logs a warning.
5. **Access token.** A JWT whose header is exactly
   `{"alg":"HS256","typ":"at+jwt"}`. Its claims are `iss`, `aud` (both the
   issuer), `sub`, `sid`, `gen` (the session's generation), `iat`, `exp` and
   `app` (the app's claims).
6. Verifying an access token compares the header's bytes, checks the
   signature in constant time, checks `exp`, `iss` and `aud`, then reads the
   session `sid` names. The token is refused unless that session is live,
   belongs to `sub` and has the generation `gen`. Whether the request is
   verified comes from the session, never from the token. So an access token
   issued before a step-up stops working at the step-up.
7. An access token issued before a `Refresh` or a `Reissue` keeps working
   until its `exp`, with the claims it was issued with. Claims are a display
   cache (rule 9), and requests already in flight shouldn't fail.
8. **Refresh token.** Opaque. `Refresh` replaces it and recomputes the
   claims. Presenting a replaced one ends the session and records
   `refresh.reused`. The exception is a client that never got the answer:
   for `refresh.grace` after a replacement, the replaced token returns the
   same successor. The successor is kept that long encrypted under a key
   derived from the replaced token, so the store alone can't produce it.
9. Claims are JSON values. Auth doesn't interpret them. They are a display
   cache: a decision about money reads the ledger.
10. `Finish`, `Refresh` and `Reissue` refuse a disabled user. The app ends a
    user's live sessions with `RevokeUser`.
11. With the cookie carrier, `Session.Claims` is what `Claimer` returned at
    `Finish` or at the last `Reissue`.

### 5.7 Verified sessions and devices

1. A session is **verified** when its flow proved a first method and one of:
   a second method; a method whose result is `Verified`; or, when the policy
   has `TrustDevices`, a registered device of that user.
2. The second methods are the user's enrolled factors (TOTP, and later a
   passkey) and a recovery code. A user with no enrolled factor has the code
   sent to an address instead, when the `Directory` returns one. Once a
   factor is enrolled, a code sent to an address is no longer a second proof
   for that user: a mailbox must not be a way around an authenticator. Two
   proofs that reach the user through one address count as one.
3. `Ready` is true when the session would be verified, or when the policy
   has `AllowUnverified` and the first method is proven.
4. When the policy needs verification and the user has no second method,
   `Prove` returns `ErrCannotVerify`.
5. `RememberDevice` registers a device only in a flow that proved a second
   method. The token lives for `device.lifetime`. It is replaced by the
   `Finish` of a sign-in that used it, and by nothing earlier, so an
   abandoned flow costs the user nothing. `Result` carries the new one.
6. A device token verifies only for the user it was issued to. An unknown or
   expired one changes nothing and reveals nothing.
7. `Finish` of a `StepUp` turns the session verified in place and replaces
   its token.
8. A device seen for the first time sends `MsgNewDevice`.
9. `Within(d)` is met by a proof of any method no older than `d`. A device
   never meets it.

### 5.8 Throttling

1. Three counters: per user, per client address, per pair. For a login that
   resolves, the key is the user's ID; otherwise it is the login normalized
   (NFKC, lower case, no surrounding space), so spelling a login differently
   buys no extra tries, and an unknown login is counted like a known one.
2. After `throttle.free` failures, each further failure doubles a wait that
   starts at one second and stops at `throttle.ceiling`.
3. **An attempt is counted before it is checked.** One write transaction
   refuses the attempt if any counter is in a wait, and otherwise adds one
   to each. Only then is the proof verified. Concurrent attempts therefore
   can't all read "no failures yet": the transaction orders them. A
   refused attempt changes no counter: it costs no hash and is no guess,
   and counting it would let an address already in a wait push other
   users' counters (A7).
4. A refused attempt returns `ErrTooManyAttempts` and does no hashing.
5. A success clears the pair's counter and the user's. A counter with no
   attempt for `throttle.window` starts again from zero; the address's
   counter only ever clears that way.
6. A request that presents a registered device of that user is held to the
   pair's counter only. So a stranger failing against an account can't keep
   its owner out of a device they have used before.
7. There is no permanent lockout. What remains: a user with no registered
   device can be slowed, up to the ceiling, by someone who keeps failing
   against their login from many addresses. That is the price of bounding
   distributed guessing, and the README says so.
8. Counters are written with `Batch` ([ADR 0002](adr/0002-throttle-writes.md)).
9. The client address is `WithClientAddr`'s answer, or the connection's peer
   address without it. A request with no address is throttled per user
   only.

### 5.9 CSRF

1. `Load` with the cookie carrier checks every request with
   `http.CrossOriginProtection`, with `trusted_origins` added, unless the
   request carries an `Authorization: Bearer` header. A request without a
   session is checked too: that is what stops a forged sign-in.
2. A request with a bearer token isn't checked: a browser doesn't attach one
   by itself.
3. So every route that starts or continues a flow in a browser goes through
   `Load(auth.Cookie())`, the sign-in page included.
4. The app must not change state on `GET`, `HEAD` or `OPTIONS`. `Follow` and
   `Accept` are safe there (§5.3.6).

### 5.10 Permissions

1. A permission's key is permanent. Declaring one registers the i18n key
   `permission.<key>` with its text. Two declarations of one key panic.
2. A user holds a permission when a group they belong to was granted it.
3. `Can(p)` needs a session, the level `p` declares, and the permission. It
   returns `ErrNoSession`, `ErrNotVerified` or `ErrForbidden`.
4. `root` holds every declared permission. It can't be deleted or renamed,
   and its last member can't leave or be removed by `RemoveUser`.
5. A grant whose key is no longer declared is ignored by checks, listed by
   `Stale` and never deleted by the package.
6. `Require` answers `ErrNoSession` with 401 and the others with 403, through
   `WithReject` when the app set one.

### 5.11 Events

1. Every decision records one event: a flow started, a proof accepted or
   refused, a message sent or not, a session made, upgraded, refreshed or
   ended, a factor or device added or removed, a permission or membership
   changed.
2. Kinds are dotted lowercase strings and are permanent.
3. An event never holds a password, a code, a token or a key. `Reason` is a
   fixed word, never a value from the request.
4. Without `WithRecorder`, events go to `log/slog`.

### 5.12 Keys

1. HKDF-SHA256 derives, from the master secret, one key each for code HMACs,
   token signing and encryption at rest (A1).
2. With `secret_previous` set, its keys are also tried for verifying and
   decrypting. New material uses `secret` only.
3. Only authenticator secrets outlive a rotation under the old key. `Rekey`
   re-encrypts every one under `secret`, and one is re-encrypted whenever it
   is used. `secret_previous` can be dropped once `Rekey` has run; `New`
   logs how many records still need it.
4. Codes, links and access tokens are short-lived, and recovery codes and
   stored tokens don't use the secret, so nothing else is lost.
5. `New` refuses a secret under 32 bytes.

### 5.13 Passkeys (A21)

1. WebAuthn Level 3 through go-webauthn (ADR 0008). The relying party ID is
   `auth.passkey.domain`, its name `auth.issuer`. An origin must equal one
   of `auth.passkey.origins`, or `https://<domain>` when it is empty;
   with the domain `localhost` the origins are required, since its port
   is the app's. A
   response with `crossOrigin: true` is refused (reason `cross_origin`),
   whatever the library allows.
2. Registration asks for a discoverable credential, user verification,
   attestation `none`, and the algorithms ES256, EdDSA and RS256. The user
   handle is the `UserID`'s bytes; the user's name and display name are
   `User.Name`, and an empty `Name` is the method's own failure. The
   user's passkeys are listed as `excludeCredentials`; a user with 20 is
   refused another: `ErrMethodUnavailable` at `Enroll`, and at `Finish`
   by rule 10 of §5.5, so concurrent enrollments can't pass it. The response's
   algorithm must be one of the three (reason `algorithm`). An
   attestation statement the library can't verify is refused (reason
   `attestation`); one it verifies decides nothing.
3. An assertion asks for user verification. Before a flow's first proof
   (§4.9) it names no credential; after it, it lists the user's passkeys
   with their transports.
4. The credential is found by its ID through `Find`, never by its user
   handle. When the options named no credential the response must carry
   a user handle, and whenever it carries one it must equal the
   credential's owner (reason `user_handle`). The ceremony type, the
   challenge, the origin, the relying party ID hash and the signature are
   checked as WebAuthn §7 says.
5. Every ceremony needs the user-present and user-verified flags (reason
   `flags`). Every accepted proof is `Verified` (§5.5.1).
6. **Counter.** When the stored counter or the presented one is above
   zero, the presented one must be greater than the stored one, or the
   proof is refused (reason `counter`) and the stored one kept. Two zeros
   pass. The presented one is stored.
7. **Backup flags.** Backup-eligible is fixed at registration; an
   assertion that differs is refused (reason `backup_flags`). Backup
   state without backup eligibility is refused in either ceremony
   (reason `backup_flags`). Backup state is stored as last seen.
8. **Limits.** Options expire five minutes after `Start`, by
   `MethodInput.Now` (reason `expired`). A response over 64 KiB is
   refused before it is parsed, and one that doesn't parse, a credential
   ID that is empty or over 1023 bytes, or a ceremony of the wrong kind
   is `malformed`. Only the transports WebAuthn names are kept, at most
   eight.
9. **State.** The flow keeps the challenge, the ceremony, the expiry and
   the user's ID; never the credential list, which rule 8 of §5.5 checks
   against the store instead.
10. **Record.** `Credential.Data` is the module's own protobuf record,
    with a version: the public key, the algorithm, the counter, both
    backup flags, the transports, the AAGUID and the attestation format.
    Nothing in it is a secret. Its `Key` is the credential ID.
11. **Throttling.** A passkey proves a signature over a challenge the
    server made, so there is nothing to guess: its attempts count toward
    the address's counter only, never the user's, which would let a
    stranger lock a user's passkeys from many addresses. A request that
    presents a registered device is held to that device's pair counter
    of kind `passkey` instead (§5.8.6), so a user's own device signs in
    behind an address in a wait, with `SignInWithout` too. The per-flow
    caps of §5.5.9 hold.
12. A passkey the user holds is an enrolled second factor (§5.7.2): it is
    offered as a second method, it stops a code to an address counting as
    one (A20), the first one brings recovery codes (A17), and `Factors`,
    `RemoveFactor`, `ResetFactors` and `DeleteUser` treat it as any
    factor. A passkey proof is a second method for §5.1.9 and §5.7.5, and
    meets `Within`. A passkey's label is `FactorLabel`'s, cut at 64
    characters (runes), or "Passkey".
13. **Refusals** give `Refuse` one of: `origin`, `cross_origin`, `rp`,
    `challenge`, `expired`, `signature`, `flags`, `counter`,
    `backup_flags`, `algorithm`, `attestation`, `unknown_credential`,
    `user_handle`, `malformed`. The engine adds `changed`, `duplicate`,
    `user_mismatch` (rule 3 of §5.5) and `no_challenge`. No library error
    text reaches an error the module returns, a log line or an event, in a
    refusal or a failure of its own. No event holds the
    response, the challenge, a credential ID or a key.

## 6. Examples

### 6.1 Wiring

```go
a, err := auth.New(db, cfg, dir, sender,
	auth.WithPolicy(func(ctx context.Context, u auth.User) auth.Policy {
		if isStaff(u) {
			return auth.Policy{} // verified sessions only, and no device shortcut
		}
		return auth.Policy{AllowUnverified: true, TrustDevices: true}
	}),
)
ac, err := access.New(db)

var (
	PayoutApprove = access.Permission("payout.approve", "Approve payouts")
	ReportView    = access.Permission("report.view", "View reports", auth.Unverified)
)

web := a.Load(auth.Cookie())
mux.Handle("/sign-in", web(signIn)) // flows go through Load too: it is the CSRF check
mux.Handle("/reports/", web(a.Require(ac.Can(ReportView))(reports)))
mux.Handle("POST /payouts/{id}/approve",
	web(a.Require(ac.Can(PayoutApprove), auth.Within(5*time.Minute))(approve)))
mux.Handle("/api/", a.Load(auth.Bearer())(a.Require()(api)))
```

### 6.2 Signing in

```go
flow, err := a.SignIn(ctx, login, auth.Cookie())
flow, err = a.Prove(ctx, flow.Token, auth.Password(pw))
if !flow.Verified && len(flow.Offers) > 0 {
	// Ask for a second proof even when flow.Ready: a policy that allows
	// unverified sessions would otherwise never offer one.
	flow.Write(w) // keep the token across requests, then show flow.Offers
	// … the next request reads auth.FlowToken(ctx) and the user's code …
	flow, err = a.Prove(ctx, flow.Token, auth.TOTP(code))
}
res, err := a.Finish(ctx, flow.Token, auth.RememberDevice("Sara's laptop"))
res.Write(w)
```

### 6.3 Stepping up before a dangerous action

```go
sess, _ := auth.From(ctx)
flow, err := a.StepUp(ctx, sess)
flow, err = a.Prove(ctx, flow.Token, auth.TOTP(code))
res, err := a.Finish(ctx, flow.Token) // new tokens; the session is now verified
```

### 6.4 Recovering an account

```go
flow, err := a.Recover(ctx, login)
_, err = a.Challenge(ctx, flow.Token, auth.MethodEmailLink) // the Sender builds the URL from Message.Token

// Later, from the link. The GET shows a form; Follow spends nothing.
flow, err = a.Follow(ctx, linkToken)
// flow.Offers lists the user's second factor when they have one.

// The POST sets the password. No session is made: the user signs in next.
_, err = a.Finish(ctx, flow.Token, auth.NewPassword(pw))
```

### 6.5 Adding an authenticator app

```go
flow, err := a.Enroll(ctx, sess, auth.MethodTOTP) // refused with ErrStale without a recent proof
ch, err := a.Challenge(ctx, flow.Token, auth.MethodTOTP)
// show ch.TOTP.URI as a QR code
flow, err = a.Prove(ctx, flow.Token, auth.TOTP(code))
res, err := a.Finish(ctx, flow.Token)
// res.RecoveryCodes is set the first time
```

### 6.6 Passkeys (A21)

```go
// schema
var Auth = authschema.Group(authschema.Passkey())

// main
pk, err := passkey.New(cfg)
a, err := auth.New(db, cfg, dir, mailer,
	auth.WithMethods(pk),
	auth.WithFirst(auth.MethodPassword, auth.MethodPasskey),
)

// The sign-in page, as it loads: a flow with no login, for autofill.
flow, err := a.SignInWithout(ctx, auth.Cookie())
ch, err := a.Challenge(ctx, flow.Token, auth.MethodPasskey)
flow.Write(w)
reply(w, ch.Options) // the page calls navigator.credentials.get

// The page posts what the browser returned.
flow, err = a.Prove(ctx, token, passkey.Response(body))
res, err := a.Finish(ctx, flow.Token) // verified: a passkey is two factors

// Adding one, from a verified session with a fresh second proof.
flow, err = a.Enroll(ctx, sess, auth.MethodPasskey)
ch, err = a.Challenge(ctx, flow.Token, auth.MethodPasskey) // navigator.credentials.create
flow, err = a.Prove(ctx, flow.Token, passkey.Response(body))
res, err = a.Finish(ctx, flow.Token, auth.FactorLabel("Sara's phone"))
```

## 7. Acceptance tests

Each line is a test in `acceptance_test.go`, written with `authtest` in the
milestone that makes it possible.

**Enumeration**
- `SignIn` then a wrong password returns the same error, the same `Offers`
  and one password hash, for a known and an unknown login.
- `Recover` and `Challenge` answer alike for a known and an unknown login,
  and only the known one is sent a message.
- A disabled user with a wrong password gets `ErrBadCredentials`; with the
  right one, `ErrUserDisabled`.
- A known user with no password costs one hash and returns
  `ErrBadCredentials`.
- `Challenge` before the first proof has an empty `SentTo`, and past
  `code.hourly` it answers the same and sends nothing.

**Flows**
- A flow is refused after `flow.lifetime` and after a successful `Finish`. A
  `Finish` refused for a weak new password leaves it usable.
- A `StepUp` flow can't be finished for another session.

**Passwords**
- A 1024-byte password in Arabic, and one of 200 spaces and letters, sign in
  after being set. One of 1025 bytes is `ErrPasswordTooLong`.
- A password with leading and trailing spaces needs them at sign-in.
- A password from the common list, one containing the login, and `aaaaaaaaaaaa`
  are each refused with their own error. So are `P@ssw0rd2024`,
  `Summer2024!!` and `14/02/1990!!!!`, which only the estimate catches (A3).
- A hash made with cheaper parameters is replaced at the next sign-in.
- A password typed in a composed and a decomposed Unicode form is the same
  password.

**Codes**
- A code is refused after `code.tries` wrong tries, in another flow, after
  its lifetime, and the second time.
- A second `Challenge` inside `code.resend` sends nothing; a later one
  cancels the first code.
- A hundred concurrent guesses at one code get `code.tries` between them.
- `Follow` twice returns the same flow; after `Finish` the link is
  `ErrBadCode`, as is a wrong and an expired one.
- The store holds no code and no token as it was sent.

**Throttling**
- The sixth wrong password returns `ErrTooManyAttempts` without hashing, and
  `RetryAfter` doubles with each further failure let through, up to the
  ceiling; refused attempts don't lengthen it (A7).
- A wait on one login from one address doesn't block that login from
  another address until the login's own counter is reached.
- Of a thousand concurrent failures, no more than `throttle.free` reach the
  hash, each of them is counted, and the refused ones change nothing (race
  detector on, A7).
- `Alice`, `alice` and ` alice ` share one counter.
- A counter with no attempt for `throttle.window` starts again.
- During a wait on a user, a request with that user's registered device
  still gets its tries.

**Sessions**
- A request with a session cookie that signs in again gets a new session
  token, and the old one is refused.
- `Require()` refuses an unverified session; `Require(auth.Unverified)`
  admits it.
- A cross-origin `POST` with the cookie is refused; a same-origin one isn't.
- `RevokeUser` refuses that user's next request on both carriers.
- A session ends at its idle lifetime, at the remembered one with
  `Remember`, and at `session.lifetime` whatever its use.
- A disabled user is refused at `Finish`, `Refresh` and `Reissue`.
- `Revoke` with another user's session ID does nothing.
- A cross-origin `POST` to the sign-in route is refused though it carries no
  session; one with a bearer token isn't checked.

**Devices**
- A device token of one user doesn't verify a session for another. A made-up
  token verifies nothing.
- With `Policy{TrustDevices: false}` a registered device doesn't verify.
- `Within` isn't met by a device.
- `RememberDevice` in a flow with one proof registers nothing.
- A device token is replaced by `Finish` and not by an abandoned flow.
- A device seen for the first time sends `MsgNewDevice`.

**Bearer**
- An access token is refused as soon as its session is revoked.
- A token with the header `{"alg":"none"}`, with reordered header fields, or
  signed with another key is refused.
- An access token issued before a step-up is refused after it.
- A token whose `sub` isn't its session's user, or whose `iss` or `aud`
  isn't the issuer, is refused.
- A replayed refresh token ends the session. Within the grace period it
  returns the same successor, and the store holds no token in the clear.
- `Refresh` and `Reissue` carry the claims `Claimer` returns at that moment.

**Recovery and factors**
- `Recover` for a user with TOTP isn't `Ready` after the link alone, and an
  emailed code doesn't make it so.
- Finishing `Recover` or `Accept` makes no session. `Recover` ends the
  user's sessions, forgets their devices and sends `MsgPasswordChanged`.
- `Enroll` without a proof inside `fresh.window` is `ErrStale`.
- For a user with TOTP, `RemoveFactor` and `Enroll` after a fresh password
  alone, from a session a device verified, are `ErrStale`.
- A user with TOTP is never offered a code sent to an address as the second
  proof.
- A TOTP code is refused the second time, also when both tries arrive at
  once; one from the next step is accepted and then the current one isn't.
- A recovery code works once, and a new set cancels the old.
- The RFC 6238 SHA-1 vectors pass.
- After the secret is rotated twice with `Rekey` in between, TOTP and
  recovery codes still work.

**Permissions**
- A user in a group granted `p` passes `Can(p)`; after `Withdraw` or `Leave`
  the next request is refused.
- A permission declared without a level refuses an unverified session with
  `ErrNotVerified`.
- `root` holds a permission declared after it was made, and its last member
  can't leave or be removed.
- A credential whose key belongs to another user isn't stored.

**Secrets**
- No event, log line or error from the whole suite contains a password, a
  code, a token or a key that the suite used.

**Passkeys: Enumeration** (A21)
- `Challenge` for a passkey before the first proof returns options that
  differ only in their challenge for a known login with passkeys, one
  without, an unknown login and `SignInWithout`.
- A passkey proved on a flow for another login, or for an unknown one, is
  `ErrBadCredentials`, as a wrong password is, and leaves its owner's
  counter and flags as they were.
- `SignIn` with an empty login answers as for an unknown login, with and
  without a module in `WithFirst`.

**Passkeys: Flows** (A21)
- `SignInWithout`, then a passkey, finishes a verified session for its
  owner, under a policy that trusts nothing. With no module in
  `WithFirst` it is `ErrMethodUnavailable`; a password on it is too.
- A password then a passkey makes a verified session; the passkey's
  options list the user's credentials only after the password.
- A disabled user's right passkey is `ErrUserDisabled`, and the counter
  isn't updated.
- A response is accepted once: proved again, or by two requests at once,
  one is accepted. After a refused proof, after a second `Challenge`, and
  with no `Challenge` at all, the old response is refused.
- Options past five minutes are refused (`authtest`'s clock).
- A flow refuses the method after ten `Challenge`s or five refused
  proofs.
- A credential removed between `Challenge` and `Prove`, or changed between
  `Verify` and its transaction, is refused; also when the proof had no
  login and the credential came from `Find`.
- After `DeleteUser`, the user's passkey is refused, also once another
  user has the same ID.
- `StepUp` with a passkey upgrades the session and replaces its token;
  `Recover` accepts a passkey as the second proof, and the passkey
  survives the new password.
- A `Verify` that fails on its own returns that error and takes back the
  attempt's count.

**Passkeys: Credentials** (A21)
- A counter not above the stored one is refused and the stored one kept,
  a presented zero against a stored ten included; two zeros are accepted
  every time; two flows racing with distinct assertions against one
  counter accept one.
- Each refusal of §5.13 is met with its reason: a changed backup-eligible
  flag, backup state without eligibility, a missing UV or UP flag,
  another origin, another relying party, a cross-origin response, a
  registration sent to an assertion and back, an algorithm outside the
  three, a missing or wrong user handle, a response over 64 KiB, an
  empty credential ID and one of 1024 bytes.
- ES256, EdDSA and RS256 each register and sign in.
- Enrolling a credential ID another user holds, or the same user, stores
  nothing and keeps the existing record; two users enrolling one ID at
  once store it once, and the loser's flow offers the method again. Two
  enrollments at once by a user with 19 passkeys store one.
- Removing one passkey in another tab doesn't refuse a step-up proved by
  another.
- `Enroll` options list the user's passkeys as `excludeCredentials`; a
  user with 20 can't start another.
- The first passkey enrolled returns recovery codes, and then a code to an
  address is no second method; `ResetFactors` makes it one again.
  `Factors` shows `FactorLabel`'s label, cut at 64 characters, and
  "Passkey" without one.
- A fake module whose `Verify` returns a new credential outside an
  `Enroll` is refused, and stores nothing.

**Passkeys: Throttling, startup and events** (A21)
- `throttle.free` failed passkey proofs from one address make that address
  wait; the user signs in by password from another at once, and a user's
  passkey is never held up by failures from addresses that aren't theirs.
  Behind an address in a wait, a request with the user's registered device
  signs in by passkey, through `SignInWithout` too.
- A `Prove` on a gone flow, past the caps or with no `Challenge` counts
  nothing; a proof that loses a race for the state is refused once.
- `passkey.New` refuses each bad config of §4.11, and `auth.New` each bad
  `WithMethods` and `WithFirst` of §4.2.
- No event, log line or error holds the response, the challenge, a
  credential ID, a public key or the library's error text.

## 8. Storage

- One top-level bucket, `auth`, in the bbolt file the app passes, and
  `auth_access` for `auth/access`. The buckets under them are listed in
  [ADR 0005](adr/0005-store-layout.md) (A2).
- Records are protobuf. The layout is private: an app reads through the API.
  It carries a version, and a store written by a newer version is refused.
- Reads use their own read transaction, and nothing is cached.
- `Sweep` removes expired flows, codes, links, sessions, devices and
  counters. The app schedules it; an hourly run is enough.
- An app runs as one process, as it already does with cfgx's store.
- The file holds credentials, so it is backed up like the database.
- Creating a user in the app's database and setting a credential here are
  not one transaction. The order is: create the user, commit, then `Invite`
  or `SetPassword`. A user left without a credential signs in through an
  invitation or recovery.

## 9. Out of v0.1

- OIDC (the module after `v0.2.0`); SAML (not planned).
- For passkeys (A21): attestation trust and metadata, AAGUID names, the
  signal API, related origins, conditional creation, extensions such as
  PRF, passkey-only accounts and security keys without UV.
- Resource-scoped permissions; API keys for machine clients.
- A breach-corpus lookup; drawing QR codes; delivering messages.
- Handlers, pages and a router integration.
- Signing in by emailed link alone.
- Moving another system's users over.

## 10. Amendments

Changes Claude made under the ownership terms, or on epistemer's choice where the row says so. Each can be overturned.

| # | Date | Section | Change |
|---|---|---|---|
| A1 | 2026-11-14 | §5.12.1 | No key is derived for recovery codes. Review 0001 moved them to plain SHA-256 (§5.4.6), and the rule still named their HMAC key |
| A2 | 2026-11-14 | §8 | The bucket list moved to ADR 0005, which M1.1 wrote with the code. It adds token indexes the draft didn't name, and gives `auth/access` a top-level bucket of its own. The layout was already private |
| A3 | 2026-11-14 | §4.6, §4.8, §5.2.4, §7 | Password strength is zxcvbn's estimate of guesses, ported with its lists ([ADR 0006](adr/0006-password-strength.md)), on epistemer's choice. It replaces the embedded list of common passwords as the third check and becomes the last; the hint check and the whole-password patterns stay. New key `password.min_score`, default 4. The three errors' descriptions widen to what the estimate finds |
| A4 | 2026-11-14 | §4.8 | `password.memory` and `password.time` get upper bounds, 4096 MiB and 64 passes: the bounds a stored hash is read with, so a damaged record can't ask for more. Without them a config past the bound made hashes nothing could verify (review 0003) |
| A5 | 2026-11-15 | §5.7.3, §5.1.12 | For a `StepUp`, `Ready` is true once the flow holds a proof and the session would be verified, or the policy has `AllowUnverified` (the step-up then only refreshes the proof `Within` reads). Its `Offers` are the user's own methods, the password included, less those it proved. `Finish` from another session is `ErrFlowExpired`, from none `ErrNoSession` |
| A6 | 2026-11-15 | §5.8 | How the counters count ([ADR 0007](adr/0007-throttle-counters.md)). The address's counter counts failures: a success takes back its own attempt's count and never clears the counter. An IPv6 address is counted by its /64, and an IPv4 address mapped into IPv6 as itself. A counter in a wait doesn't decay before the wait ends |
| A7 | 2026-11-15 | §5.8.3, §7 | On epistemer's choice: a refused attempt changes no counter. Counting it let an address already in a wait push any user's counter to the ceiling without hashing, and lengthened everyone's wait on a shared address; it bought nothing against a guesser, whose every guess is still counted before it is checked (review 0005, finding 2). The wait now doubles with each failure let through |
| A8 | 2026-11-15 | §4.4, §5.6, §5.9 | How `Load` and `Require` behave where the contract was silent. `Load` refuses a forged request through `WithReject`'s handler with `ErrForbidden`, and records `request.refused`. A request with a bearer header is never signed in through its cookies, but signing in or out still ends the cookie session it carried. A `Load` replaces what an outer one attached. A session whose `Seen` can't be written, or that the write finds ended, is no session. A `Level` other than the two is never met; `Require` panics on a nil requirement. `SignOut` keeps the cookie when ending the session fails. Without `WithReject`, a refusal answers with the error's status and its message in the request's locale |
| A9 | 2026-11-15 | §4.8, §4.10 | `authschema` checks each key's own range when cfgx loads. The secret's length and the ranges between keys (`session.remembered_idle` at least `session.idle`, and so on) are checked by `New` alone: cfgx can't express them without a validator exported for the generated code to call, which would be new API. An explicit `refresh.grace` of 0 can't override its default, since cfgx treats zero as unset. `password.concurrency` defaults to the number of CPUs. `authtest.New` and `authtest.Config` panic outside `go test`, since the config's secret is public |
| A10 | 2026-11-15 | §5.3, §5.7.2, §5.8 | How codes behave where the contract was silent. A wrong code counts toward throttling like a wrong password. Every `Challenge` past `code.resend` replaces the code, sent or not; a code that wasn't sent (no user, no address, a directory error, past `code.hourly`) is stored with a random MAC, so the flow behaves alike and nothing can match it. `code.hourly` is a sliding hour, and a send that fails doesn't count. An unknown login's code never verifies. `SentTo` is empty until the flow holds a proof, whatever its purpose. An address is folded (case, width, a phone's punctuation) before its hash, and one that folds to nothing has none. With no factor enrolled, the second methods are a code to each address the directory has, less those the flow proved |
| A11 | 2026-11-15 | §5.1.7–8, §5.1.10, §5.3.6 | How recovery and invitations behave where the contract was silent. A `Recover` offers the same first proofs to every login: `email_link`, `email_code`, `sms_code`; links are sent only in a `Recover`. The first `Follow` moves the flow to a new token that only the link's holder learns, so whoever started the recovery can't finish it (review 0009). `Follow` and `Accept` return that token again, refresh the flow's lifetime and never let it outlive the link; a link whose flow ended unspent starts a new one. A link, an invitation or a recovery flow older than the user's password is stale, so one finished recovery or invitation ends the others. An invitation needs a user's enrolled factor as a recovery does. A recovery ends every session, also where there was no password to replace. `Invite` sends `MsgInvitation` to the email, else the phone, and returns the token too |
| A12 | 2026-11-15 | §5.7, §5.8.6, §4.4 | How devices behave where the contract was silent. The cookie carrier keeps a device token in `__Host-device` (`Secure`, `HttpOnly`, `SameSite=Lax`, until the device expires); the bearer carrier gets it in `Result.Device`. A flow keeps the hash of the token it presented, and the device is checked with it when the flow starts, when it is proved against and at `Finish`: a token forgotten or replaced meanwhile verifies nothing. Its token is replaced, and its lifetime starts again, at the `Finish` of a sign-in that used it: one the policy trusts, that proved no second method. `RememberDevice` again, after two factors, replaces the token and label of the device presented. A step-up registers a device only if it proved a second method itself. The throttle's exemption (§5.8.6) needs a device the policy trusts. A device is never a factor of the session, so `Within` never counts it. Any new password forgets the user's devices, the first one too, as a recovery does. `MsgNewDevice` goes out when a device is registered; where a device gone since the view leaves a sign-in unverified, the policy decides whether it may finish |
| A13 | 2026-11-16 | §5.6.5–6, §4.4 | How the bearer carrier behaves where the contract was silent. An access token's claims must be one JSON object and nothing after it, with no field but those of §5.6.5, an `iat` no later than now and before `exp`, and an `app` claim that is an object; during a rotation both keys are tried, whichever matches. A request with more than one `Authorization` header is signed in by none. A bearer session's `Seen` is written at most once a minute, checking its generation. `Finish` of a bearer `SignIn` or `StepUp` issues an access token and a refresh token; a step-up and the end of a session end the session's refresh tokens. A bearer session is never found by a cookie, nor a cookie session by an access token |
| A14 | 2026-11-16 | §5.6.8, §5.6.10–11, §4.4 | How refresh tokens and `Reissue` behave where the contract was silent. Reuse is judged before the directory or the `Claimer` is asked, so neither failing spares a session. The grace returns the successor only while it is unused, also to a refresh racing another with the same token; rotating a successor wipes its predecessor's sealed copy, and `Sweep` wipes any past the grace. A step-up marks the session's refresh tokens used, so one of them used again is reuse and ends the session. A refresh writes the session's `Seen`, at most once a minute. An unknown refresh token, or one whose session isn't live, is `ErrNoSession`. `Reissue` reads the session from the store first: it must be live and the caller's user's; it sets the new claims on the `Session` it was given |
| A15 | 2026-11-16 | §5.1.9–10, §4.5 | How changing factors behaves where the contract was silent. §5.1.9 is checked at `Enroll`, at `Finish` and again inside the transaction that makes the change, and the same for `RemoveFactor`. A password set through `Enroll` is a change even if it is the first: it ends the user's other sessions, forgets their devices and sends `MsgPasswordChanged`. Recovery codes alone are no factor: `Factors` doesn't list them, `RemoveFactor` can't remove them, and removing a user's last factor removes them. A fresh recovery code proof counts as a second method. `Enroll` takes only the methods this release can finish: the password now, TOTP with M4.2. A factor's ID is its method and its key's hash; `Used` is the zero time for a factor never used |
| A16 | 2026-11-16 | §5.4, §5.12.3 | How authenticator apps behave where the contract was silent. Enrolling takes one code, ever, and the step it proved is the credential's last, so the enrolling code can't sign in. One flow takes one TOTP code; the code's step, its move and the flow's proof are one transaction, and a disabled user's code isn't spent. A credential is keyed by a random ID. The `otpauth` label escapes the issuer and the name. An enrollment in progress is sealed again with the rest: on use, at `Finish`, and by `Rekey`. `Rekey` returns an error counting secrets no configured key opens, and `New` logs both those and the ones still needing `secret_previous`. Wrong codes count toward throttling (§5.4.5) |
| A17 | 2026-11-16 | §5.4.6, §4.3 | How recovery codes behave where the contract was silent. The first factor's `Finish` returns the set in `Result.RecoveryCodes`; a later factor brings none. `Enroll(..., MethodRecoveryCode)`, for a user with a factor, makes a new set, which cancels the old. A code is typed in any case, with spaces or dashes. It is offered beside the user's factors while one is left, in a sign-in, a step-up and a recovery. It is spent only on a flow with no second proof yet, never burnt by a racing one; a second on one flow is `ErrMethodUnavailable` and isn't held against the user |
| A18 | 2026-11-16 | §4.7, §5.10 | How `auth/access` behaves where the contract was silent. A requirement may name its own level by a method `RequiredLevel() auth.Level`, as `Can` does, and `Require` enforces that level itself. A `Level` given outright decides the route's level; otherwise `Verified` holds unless every requirement names its own, so `Require(ac.Can(p))` for a permission declared `Unverified` admits an unverified session, and adding a requirement that names none brings `Verified` back. Only the handle `Permission` returned grants, withdraws or passes anything; any other is held to `Verified`. A refused change to `root` (deleting, renaming, its last member leaving) is `ErrForbidden`; `RemoveUser` is one change, so one that would empty `root` changes nothing. `Check` holds only a permission it knows: a handle for an undeclared key passes nothing. The package keeps its records in the top-level bucket `auth_access` (ADR 0005) and records no events, since `New(db)` takes no `Recorder` |
| A19 | 2026-11-16 | §4.5, §4.2, §4.9 | How `DeleteUser` behaves, and modules before v0.2.0, where the contract was silent. `DeleteUser` removes, in one transaction, every session of the user (ended ones too) with its refresh tokens, every credential and its index, every device, and the flows, links and invitations naming the user; it sends nothing, and records `session.ended` (reason `user_deleted`) for each live session and one `user.deleted`. Throttle counters hold only a digest and are left to `Sweep`. The app removes or disables the user in its `Directory` first: a flow under way then fails at its next lookup, and one already followed can't finish, since its record is gone. `New` refuses `WithMethods` until the engine drives modules (v0.2.0, §9), so no flow offers a method it can't prove; a module's proof was already refused with `ErrMethodUnavailable` |
| A20 | 2026-11-16 | §5.7.2, §5.8, §5.1.10, §5.1.7, §5.3.6, §5.6.3, A10, A11, A13 | From the security review of the whole package (review 0019). Once a user has enrolled a factor, a code to an address is no second method in any count of two factors, also one proved before the enrolment, and a step-up's `Finish` judges its factors again under the write lock. Each kind of secret (passwords; codes sent to an address; authenticator apps and recovery codes) has a user's and a pair's counter of its own, which only its own success clears, so a right password can't reset the guesses at a second factor, nor a code from a mailbox the guesses at a password; the address's counter counts every failure; an attempt that tried nothing, or found its flow gone, takes back its own count and clears nothing. A password proof is recorded only if the password is still the one it was checked against, and is dated when that was read. A recovery or invitation sets no password past a factor enrolled while it hashed, and a recovery or invitation that holds a proof and is older than the password takes no more (`ErrFlowExpired`); one with no proof yet looks the same as an unknown login's. A recovery proved by a code deletes the link still on its way. A `Session` read before a step-up, from the token it replaced, can't step up, enroll, remove a factor or be reissued (`ErrNoSession`). An address that folds to nothing is none. An access token's `app` claim may not be `null`. `RevokeUser` refuses an invalid ID; `Finish` clears the flow cookie under its insecure name too |
| A21 | 2026-11-17 | §3, §4.2, §4.3, §4.9, §4.11, §5.1.3, §5.5, §5.13, §6.6, §7, §9, A19 | On epistemer's lock: passkeys, as drafted in M7.0 ([ADR 0008](adr/0008-passkeys.md), [review 0020](reviews/0020-passkey-draft.md)), with D27–D36 as recommended. The nested module `auth/passkey` (§4.11, §5.13) and its test authenticator; in the core `MethodPasskey`, `SignInWithout`, `FactorLabel`, `Refuse` and `MethodInput.Now`; in `authschema` `Passkey()` and a variadic `Group`. The engine drives modules under §5.5's new rules 6–11, and A19's refusal of `WithMethods` is withdrawn with v0.2.0. Implemented by M7.1–M7.3 |
| A22 | 2026-11-17 | §5.5.6, §5.5.9, §5.7.2, §4.3, §4.9 | How the engine drives modules where A21 was silent (M7.1, [review 0021](reviews/0021-m7.1-engine.md)). A proof that loses the race for its method's state has its count taken back: its `Verify`'s answer is thrown away, so nothing was judged, and each state is still judged once. A `SignInWithout` has no user's counter until a proof names the user: a module's attempt on it counts toward the address's counter, or, with a registered device its owner's policy trusts, that owner's pair counter of the method's kind; a success clears counters only of the user the proof named. So a method served through `SignInWithout` must have nothing to guess: a signature over the server's challenge, or an external assertion, as passkeys and OIDC. A factor whose module isn't given to `WithMethods` is offered nowhere, and still keeps a code to an address from counting as a second method. A proof that names a user the `Directory` doesn't know, or names no one when the method was told no user, is refused (`user_mismatch`). A method stays offered past its ten `Challenge`s while its last state is unused. In an `Enroll`, a `MethodResult` with no credential, or a key over 1023 bytes, is the method's own failure. `Finish` refuses a credential past the method's limit with the reason `limit`. A label, `FactorLabel`'s or the method's own, is cleaned and cut at 64 runes; one empty once cleaned gives the method's own. Two proofs of one module method in a flow are one factor, verified if either was |
| A23 | 2026-11-17 | §5.13.2–4, §5.13.8 | How the passkey module behaves where §5.13 was silent (M7.2, [review 0022](reviews/0022-m7.2-passkey.md)). A registration's public key must parse and be usable: of the kind its algorithm names, on its curve, and for RS256 at least 2048 bits with an odd exponent from 3 to 2³¹−1; one that isn't, or names no algorithm, is `malformed`. The credential ID the client reports must equal the one the attestation holds (`malformed`). Options for a known user name that user, also when they hold no passkey, so another user's passkey is refused (`unknown_credential`). A user handle is 1 to 64 bytes. An origin matches one configured exactly, with no folding of case or default ports. A domain whose last label reads as a number, in any base, is refused. A state or a credential record of another version is the module's own failure |
| A24 | 2026-11-17 | §5.5.9, §5.13.2, A23 | From the security review of v0.2.0 ([review 0023](reviews/0023-m7.4-security.md)). A `Challenge` past its method's caps is refused before the method is asked. One whose flow gained a proof or a user while the method's `Start` ran is `ErrMethodUnavailable` and stores nothing, since the method was told less than it should have been. An RS256 key is at most 4096 bits |
