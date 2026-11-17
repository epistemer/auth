# auth — Interface: `auth/passkey` (draft, awaiting lock)

> Status: **draft of 2026-11-17, waiting for epistemer's lock.** Nothing
> here is implemented. API design is epistemer's
> ([ownership.md](ownership.md)); the rules are Claude's and were reviewed
> by the other model family ([review 0020](reviews/0020-passkey-draft.md)).
> The reasons are in [ADR 0008](adr/0008-passkeys.md).
>
> On the lock, this file is folded into [interface.md](interface.md) as
> §4.11 and §5.13, the changes to the locked sections below are made
> there, and the whole is recorded as amendment A21. §5.5.5 of the locked
> interface is what calls for it.

## Decisions to lock

Each row is an API choice, with Claude's recommendation first. **A row you
don't answer takes its default**, the recommendation.

| # | Choice | Default (recommended) | Alternatives |
|---|---|---|---|
| P1 | The method's name | `auth.MethodPasskey = "passkey"` in the core, beside `MethodTOTP`: an app compares `Offers` and calls `Enroll` and `WithFirst` with `auth.Method…` constants only (D24), and §5.7.2 already names passkeys among the core's second methods | `passkey.Name` in the module, so the core names no module (review 0020 preferred this) |
| P2 | The constructor | `passkey.New(cfg passkey.Config) (auth.Method, error)`: nothing else of the module is a value an app holds | Return a concrete `*passkey.Passkey`; or add `opts ...Option` now |
| P3 | Config | A fragment an app opts into: `authschema.Group(authschema.Passkey())`, which needs `Group(members ...dsl.Member)` (variadic, so every existing call compiles). Its `domain` is required, so an app has passkeys configured or none at all | Two keys always in the group, `domain` unset meaning no passkeys; every app then shows them |
| P4 | `Challenge.Options` | A `json.RawMessage`: WebAuthn Level 3's options object, unwrapped (no `publicKey` member around it), which `parseCreationOptionsFromJSON` and `parseRequestOptionsFromJSON` take as it is | A struct of the module's own; go-webauthn's types (rejected in ADR 0008: a third party's type in the API) |
| P5 | The proof | `passkey.Response(credential []byte) auth.Proof`: the JSON of the browser's `PublicKeyCredential.toJSON()` | `passkey.Credential(…)` or `passkey.Assertion(…)` |
| P6 | Signing in without a login | A starter of its own, `SignInWithout(ctx, c Carrier) (Flow, error)`. `SignIn(ctx, "", c)` keeps answering as for an unknown login (§5.1.3), so a blank form field changes nothing | `SignIn(ctx, "", c)` meaning no login: no new identifier, but a blank field would switch modes |
| P7 | A factor's label | `auth.FactorLabel(label string) FinishOption`, for any `Enroll` ("Sara's phone"); without it, or empty, a passkey is "Passkey" | No option: every passkey is "Passkey" |
| P8 | Why a proof was refused | `auth.Refuse(reason string) error`, which a module's `Verify` returns; the engine records the reason and answers plain `ErrBadCredentials` | Modules wrap `ErrBadCredentials` themselves and every module refusal is recorded as `refused` |
| P9 | A test authenticator for apps | `passkey/passkeytest`: `New(tb, origin string) *Authenticator`, `Create(options json.RawMessage) []byte` and `Get(options json.RawMessage) []byte`. One authenticator holds one passkey; a test with two makes two | Keep it internal: apps test passkeys in a browser |
| P10 | The clock a module reads | `MethodInput.Now time.Time`, the engine's clock (`WithClock`), so `authtest`'s clock moves passkeys too | `passkey.New(cfg, passkey.WithClock(…))` |

Claude's own calls, recorded here so they can be overturned: the library
(go-webauthn), conveyance `none`, UV required, every proof `Verified`,
counters as WebAuthn §7.2 says, the handle is the `UserID`, three
algorithms, at most 20 passkeys a user, throttling by address (or a registered device's pair)
(ADR 0008).

## 4.11 `auth/passkey` (new)

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

In the core (`auth`):

```go
const MethodPasskey = "passkey" // P1

// SignInWithout starts a sign-in that names no login, for a method that
// finds the user from its proof, such as a passkey in autofill (P6).
func (a *Auth) SignInWithout(ctx context.Context, c Carrier) (Flow, error)

// FactorLabel names the factor an Enroll adds, as Factors shows it (P7).
// It is cut at 64 characters, control characters are dropped, and an
// empty label gives the method's own. The password and recovery codes
// ignore it.
func FactorLabel(label string) FinishOption

// Refuse is what a module's Verify returns for a proof it refuses (P8).
// It wraps ErrBadCredentials and its Error() is fixed: the reason is in
// no message. reason is the event's Reason and matches [a-z][a-z0-9_]{0,31};
// any other is recorded as "refused".
func Refuse(reason string) error

type MethodInput struct {
	// … as in §4.9, and:
	Now time.Time // the engine's clock (P10)
}
```

In `auth/authschema` (P3):

```go
// Group returns the cfgx group auth. members are nested in it, such as
// Passkey().
func Group(members ...dsl.Member) *dsl.GroupDef

// Passkey returns the group passkey: domain (required) and origins.
func Passkey() *dsl.GroupDef
```

In `auth/passkey/passkeytest` (P9):

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

What `Challenge` returns for a passkey: `Method` is `"passkey"`, `SentTo`
and `Resend` are empty, and `Options` is the `json.RawMessage` of P4.

## Changes to the locked sections

**§4.2.** `New` accepts `WithMethods` (A19 is withdrawn). It refuses a nil
method, two methods of one name, a module method named like a built-in
one, and a name outside `[a-z0-9_]{1,32}`. `WithFirst` may name a module's
method, and still refuses a name that is neither built in nor given to
`WithMethods`.

**§4.3.** Adds `SignInWithout` (P6): a flow that knows no user, whose
`Offers` are `WithFirst`'s module methods; with none it is
`ErrMethodUnavailable`. The `Directory` isn't asked. A device token the
request presents is read at the start: it serves throttling (§5.13.11),
and stands for nothing if the proof names another user. `SignIn` with an empty login is
unchanged. `Enroll` takes a module's method. Adds `FactorLabel` (P7) and
`MethodPasskey` (P1).

**§4.9**, added after the declarations:

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
- `Verify` returns `Refuse(reason)` (P8) for a proof it refuses. Any other
  error is the method's own failure, which `Prove` returns as is; a
  module's own failures carry its own fixed text, never a library's.
- The state `Start` returns is kept in the flow until a `Prove` passes it
  to `Verify`, once, whatever the outcome (the method's own failure
  included), or a new `Challenge` replaces it. It is at
  most 4 KiB.
- `MethodInput.Now` is the engine's clock (P10).

**§5.1.3**, added: a `SignInWithout` flow answers alike whether or not
the proof will name a user; before the first proof nothing in it depends
on any account.

**§5.5**, rules added. They hold for every module method; §5.13 and the
OIDC section add their own.

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

**§9.** Removes passkeys; adds what ADR 0008 leaves out: attestation
trust and metadata, AAGUID names, the signal API, related origins,
conditional creation, extensions such as PRF, passkey-only accounts and
security keys without UV.

## 5.13 Passkeys (new)

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

## 6.6 Example: passkeys (new)

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

## 7. Acceptance tests (added)

**Enumeration**
- `Challenge` for a passkey before the first proof returns options that
  differ only in their challenge for a known login with passkeys, one
  without, an unknown login and `SignInWithout`.
- A passkey proved on a flow for another login, or for an unknown one, is
  `ErrBadCredentials`, as a wrong password is, and leaves its owner's
  counter and flags as they were.
- `SignIn` with an empty login answers as for an unknown login, with and
  without a module in `WithFirst`.

**Flows**
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

**Credentials**
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

**Throttling, startup and events**
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
