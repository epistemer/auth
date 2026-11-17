# auth — Interface: `auth/oidc` (draft, awaiting lock)

> Status: **draft of 2026-11-17, waiting for epistemer's lock.** Nothing
> here is implemented. API design is epistemer's
> ([ownership.md](ownership.md)); the rules are Claude's and were reviewed
> by the other model family ([review 0024](reviews/0024-oidc-draft.md)).
> The reasons are in [ADR 0009](adr/0009-oidc.md).
>
> On the lock, this file is folded into [interface.md](interface.md) as
> §4.12 and §5.14, the changes to the locked sections below are made
> there, and the whole is recorded as an amendment. §5.5.5 calls for it.

## Decisions to lock

Each row is an API choice, with Claude's recommendation first. **A row you
don't answer takes its default**, the recommendation.

| # | Choice | Default (recommended) | Alternatives |
|---|---|---|---|
| O1 | A provider's method | One method a provider, named `oidc_<provider>` (`oidc_google`): `Offers` lists each, so the app draws a button per provider, and `Challenge` needs no new argument. Each method's identities are its own, also for two methods on one issuer | One method `oidc` for all providers, with the provider chosen at `Challenge` (a new argument, or a new starter) |
| O2 | The constructor | `oidc.New(cfg oidc.Config) (auth.Method, error)`, as `passkey.New`; it reads the config once and makes no network call | `oidc.New(ctx, cfg)`, discovering at start, so a wrong issuer fails at start but an IdP that is down stops the app |
| O3 | Settings | `oidc.Config`, getters for one provider: `AuthOIDCProvider()`, `AuthOIDCIssuer()`, `AuthOIDCClientID()`, `AuthOIDCClientSecret() cfgx.Secret`, `AuthOIDCRedirectURL()`, `AuthOIDCScopes() []string`, `AuthOIDCTwoFactors() bool`. `authschema.OIDC()` declares them for the first provider; a second is a small adapter of the app's over its own keys | `oidc.Provider`, a struct of values, filled by the app from any source: one shape for any number of providers. Review 0024 preferred this; the getters follow your rule that libraries take getters |
| O4 | `Challenge.Options` | The authorization URL, a `string`: the app redirects to it, or hands it to a native client | A struct of the URL and its expiry |
| O5 | The proof | `oidc.Callback(provider string, query url.Values) auth.Proof`: the provider names the method (`oidc_<provider>`), and the whole query lets the module read `code`, `state`, `iss` and `error` and refuse duplicates. Each provider has its own callback route | `oidc.Callback(provider, code, state string)`: simpler, but drops `iss` and `error` |
| O6 | An identity linked to no one (sign-up) | `Prove` returns the flow with `Flow.Unlinked *Identity` set and no error; the app shows its sign-up step, creates the user, then calls `a.Link(ctx, token string, id UserID) (Flow, error)`, which links the identity the flow holds (never one the caller passes) and records the proof. Without a `Link`, nothing is stored. Only in a flow started by `SignInWithout` | `auth.WithSignUp(func(ctx, Identity) (UserID, error))`, called inside `Prove`: one step, but the app's user creation runs inside or beside the engine's transaction, and a refusal after it leaves an orphan user (review 0024) |
| O7 | Throttling by address | An optional interface in the core, `auth.AddressOnly` (`AddressOnly() bool`): a method whose proofs have nothing to guess implements it, and its attempts count toward the address alone (§5.13.11, A22). `auth/passkey` implements it too | A field in a new `MethodInfo` from a second optional method; or the core's list, which names modules in the core |
| O8 | Listing and unlinking identities | `a.Identities(ctx, id UserID) ([]IdentityInfo, error)` and `a.Unlink(ctx, s *Session, identityID string) error`, beside `Factors`: an identity is no factor, `ResetFactors` leaves identities, and `Unlink` refuses to remove a user's last way in | `Factors` lists them and `RemoveFactor` unlinks them: no new identifiers, but `Factors` stops meaning second factors and `ResetFactors` would lock out a user with no password |
| O9 | One mailbox, one factor | `MethodResult.Address string`: the address a proof shows control of (an identity's verified email). The engine treats the proof as one that came through that address, so with a code to the same mailbox it makes one factor, not two (§5.7.2) | None in the core: an app pairing a mail provider with emailed codes accepts that one mailbox gives both factors |

Claude's own calls, recorded here so they can be overturned: go-oidc and
x/oauth2, PKCE S256 with `state` and `nonce`, discovery on first use in
`Start` or `Verify`, ten-minute options, no `amr`, provider tokens
discarded, an identity is issuer and subject, `Link` only for a user new
to auth (ADR 0009).

## 4.12 `auth/oidc` (new)

A nested module, `github.com/epistemer/auth/oidc`.

```go
// Config is one provider's settings (O3), read once by New. An app's
// generated settings implement it when its schema holds
// authschema.Group(authschema.OIDC()).
type Config interface {
	AuthOIDCProvider() string          // [a-z0-9_]{1,27}; the method is oidc_<provider>
	AuthOIDCIssuer() string            // https://accounts.google.com
	AuthOIDCClientID() string
	AuthOIDCClientSecret() cfgx.Secret // empty for a public client, which PKCE alone protects
	AuthOIDCRedirectURL() string       // this provider's callback route
	AuthOIDCScopes() []string          // beyond openid; email and profile when empty
	AuthOIDCTwoFactors() bool          // the provider's sign-in counts as two factors (§5.14.9)
}

// New returns the provider's method, to pass to auth.WithMethods (O2). It
// refuses a nil config; a provider name outside [a-z0-9_]{1,27}; an issuer
// that isn't an absolute https URL of at most 767 bytes, with no user, query
// or fragment (http://localhost for development); a redirect URL that isn't
// https (or http://localhost), with no user or fragment; an empty client ID;
// and a scope that holds a space or a control character.
func New(cfg Config) (auth.Method, error)

// Callback is the proof a provider's redirect carries: the provider's name
// and the callback request's query, whole (O5). It prints as its method.
func Callback(provider string, query url.Values) auth.Proof
```

In the core (`auth`):

```go
// Flow gains (O6):
//	Unlinked *Identity // a proved identity no user holds; Link it, or start again

// Link links the identity the flow proved, and holds, to id, a user the
// app has just created for it, and records the proof (O6, §5.14.6).
func (a *Auth) Link(ctx context.Context, token string, id UserID) (Flow, error)

// Identities lists a user's linked identities (O8).
func (a *Auth) Identities(ctx context.Context, id UserID) ([]IdentityInfo, error)

// IdentityInfo is a linked identity as a user's list shows it.
type IdentityInfo struct {
	ID       string // to pass to Unlink
	Method   string // oidc_google
	Label    string // the provider's email when it gave one, else the provider
	Added    time.Time
	Used     time.Time
}

// Unlink removes one of the session's user's identities, under §5.1.9; it
// refuses the user's last way in (§5.14.11).
func (a *Auth) Unlink(ctx context.Context, s *Session, identityID string) error

// AddressOnly is an optional interface of a Method whose proofs have
// nothing to guess (O7).
type AddressOnly interface{ AddressOnly() bool }

type MethodResult struct {
	// … as in §4.9, and:
	Address string // an address the proof shows control of (O9)
}
```

In `auth/authschema` (O3):

```go
// OIDC returns the group oidc: provider, issuer, client_id, client_secret,
// redirect_url, scopes, two_factors.
func OIDC() *dsl.GroupDef
```

What `Challenge` returns for a provider: `Method` is `oidc_<provider>`,
`SentTo` and `Resend` are empty, and `Options` is the authorization URL,
a `string` (O4).

## Changes to the locked sections

**§4.3.** `Flow` gains `Unlinked`; adds `Link` (O6). **§4.5.** Adds
`Identities`, `IdentityInfo`, `Unlink` (O8); `DeleteUser` removes
identities; `ResetFactors` doesn't.

**§4.9.** Adds `AddressOnly` (O7) and `MethodResult.Address` (O9).
`MethodResult.Unlinked` is set by a method whose proof is valid but whose
identity `Find` didn't find; then `User` is empty and `Credential` is the
credential to store if the identity is linked. **§5.5.8** is amended to
match: outside an `Enroll`, an `Unlinked` result's `Credential` is a new
one, kept in the flow (sealed, as an enrollment's) until `Link` stores it,
checking rule 10 there. In an `Enroll` the method leaves `User` empty, so
an identity someone holds is rule 10's `duplicate` for everyone.

**§5.5.9**, its first sentence replaced: a method that implements
`AddressOnly` and answers true counts its attempts toward the address's
counter alone, or a trusted device's pair counter (§5.8.6); others count
as before. The per-flow caps (ten `Challenge`s, five refused proofs) stay.
The core's list, which named passkeys, goes.

**§5.7.2**, added: a proof with an `Address` counts as one that came
through that address: with a code sent to the same address it is one
factor (O9).

**§9.** Removes OIDC; adds what ADR 0009 keeps out.

## 5.14 OpenID Connect (new)

1. **Flow.** The authorization code flow with PKCE. `Challenge` makes
   `state`, `nonce` and the code verifier, 32 random bytes each, base64url
   without padding (43 characters), keeps them with an expiry of ten
   minutes (by `MethodInput.Now`) in the method's state, and returns the
   authorization URL with `response_type=code`, the client ID, the
   redirect URL, the scopes (`openid` always), `state`, `nonce`, the code
   challenge and `code_challenge_method=S256`; with `two_factors`, also
   `max_age=300` (§5.14.9).
2. **Discovery** runs when `Start` or `Verify` first needs it, once at a
   time (concurrent callers wait for one fetch), and only a success is
   cached. The document's `issuer` must equal the configured one, and its
   authorization, token and key-set endpoints must be absolute https URLs
   with no user (http on localhost when the issuer is). Discovery, key-set
   fetches and the exchange share one HTTP client: a 10-second timeout, no
   redirects, responses cut at 1 MiB. A failure to reach the provider, an
   HTTP 5xx or 429, and a refused client (`invalid_client`) are the
   method's own failures, which take back the attempt's count (§5.5.6).
3. **The callback**, checked in this order: over 8 KiB of query (keys and
   values counted) is `malformed`; so is a parameter given twice, and
   both or neither of `code` and `error`; options past ten minutes are
   `expired`; `state` must equal the flow's, compared in constant time
   (`state`); an `iss` parameter must equal the issuer, and is required
   when discovery says the provider sends one (RFC 9207) (`issuer`); then
   an `error` parameter is refused (`provider_error`), its text in no
   error, event or log.
4. **The exchange.** The code is exchanged with the verifier, and the
   client secret when set (in the request body for a public client). A
   refusal of the grant (HTTP 400) is reason `exchange`.
5. **The ID token** is checked by go-oidc against the clock of
   `MethodInput.Now`: signature by the provider's keys (RS256 with keys of
   2048 to 4096 bits, or ES256), `iss`, `aud` containing the client ID,
   `exp`. Then: `nonce` equals the flow's (`nonce`); `azp`, whenever
   present, equals the client ID, and is required when `aud` has several
   values (`audience`); `iat` is present and not more than a minute ahead;
   with `two_factors`, `auth_time` is present and within the last five
   minutes (`token`); `sub` is 1 to 255 bytes with no control character
   (`malformed`). Any other failure is reason `token`.
6. **The identity** is the issuer and the subject; the credential's key is
   `issuer \0 subject` (at most 1023 bytes, as §4.11's 767-byte issuer
   ensures). It is found through `Find`, never by email or any other claim
   (§5.5.2). Found, it names its user (rules 3 and 7 of §5.5).
7. **Unlinked.** Not found, in a flow started by `SignInWithout`, the
   method returns `Unlinked`; `Prove` keeps the identity and its
   credential in the flow and returns the flow with `Unlinked` set,
   `Ready` false and no offers. In any other flow it is refused
   (`unlinked`). `Link` stores the identity for the user named, and
   records the proof, in one transaction, if the user is one the
   `Directory` knows who is new to auth: no password, no credential, no
   recovery codes, no device, no session (ended ones included), no
   invitation or recovery under way; else `ErrBadCredentials` (reason
   `not_new`) and nothing is stored. An identity linked meanwhile is
   `duplicate`. The rule stops an app's sign-up from linking an identity
   to an account it found by email; it can't stop one that names an
   account it pre-provisioned, so `Link` must name a user created for
   this identity, in this request.
8. **Data.** `Credential.Data` is the module's protobuf record, with a
   version: the issuer, the subject, the email and whether it was
   verified, as last seen; rewritten only when they change. The label is
   the email when given, else the provider, cleaned as any label (A22),
   and kept once set. Nothing in it is a secret. Provider tokens are
   discarded. The proof prints as its method.
9. **Factors.** A provider's proof is `Verified` when `two_factors` is
   set, else one factor; `amr` is not read. With `two_factors` the
   request asks for a sign-in no older than five minutes and the token
   must show one (rule 5), so a stale session at the provider can't meet
   `Within`. An identity is no second factor (§5.7.2): it is offered only
   as a first proof, never in a step-up, a recovery or an invitation.
   Its `Address` is its email when `email_verified` is true (O9).
10. **Throttling.** The method implements `AddressOnly` (§5.5.9). The
    address counter is the one passwords share: callers behind one
    address share its waits, as for passwords (A20).
11. **Unlink** refuses a user's last way in: no password, no passkey and
    no other identity left (`ErrMethodUnavailable`).
12. **Refusals** give `Refuse` one of: `provider_error`, `state`,
    `issuer`, `expired`, `exchange`, `nonce`, `audience`, `token`,
    `unlinked`, `malformed`. The engine adds `not_new` and §5.5's. No
    provider or library text, code, token or claim reaches an error, an
    event or a log.

## 6.7 Example: signing in with a provider (new)

```go
// schema
var Auth = authschema.Group(authschema.OIDC())

// main
google, err := oidc.New(cfg)
a, err := auth.New(db, cfg, dir, mailer,
	auth.WithMethods(google),
	auth.WithFirst(auth.MethodPassword, "oidc_google"),
)

// GET /sign-in/google
flow, err := a.SignInWithout(ctx, auth.Cookie())
if err != nil { fail(w, r, err); return }
ch, err := a.Challenge(ctx, flow.Token, "oidc_google")
if err != nil { fail(w, r, err); return }
flow.Write(w)
http.Redirect(w, r, ch.Options.(string), http.StatusFound)

// GET /sign-in/google/callback
token, _ := auth.FlowToken(ctx)
flow, err = a.Prove(ctx, token, oidc.Callback("google", r.URL.Query()))
if err != nil { fail(w, r, err); return }
if flow.Unlinked != nil {
	// The app's sign-up step: terms, a name. Use the email only if
	// flow.Unlinked.EmailVerified, and only as the new user's address.
	id, err := users.Create(ctx, flow.Unlinked)
	if err == nil {
		flow, err = a.Link(ctx, token, id)
	}
	if err != nil { fail(w, r, err); return }
}
res, err := a.Finish(ctx, flow.Token) // unverified unless two_factors
```

## 7. Acceptance tests (added)

Against a provider of the tests' own (an `httptest` server with discovery,
keys and a token endpoint), in `oidc`'s tests:

- A sign-in by a linked identity finishes for its user; another issuer's
  identity with the same subject doesn't; a callback for one provider
  proved as another's is refused.
- An identity is never found by email.
- Each refusal of §5.14 is met with its reason, in §5.14.3's order: a
  query over 8 KiB, a parameter twice, `code` and `error` together,
  expired options, another `state`, another or a missing required `iss`,
  a provider error, a refused exchange, another `nonce`, another `azp`, a
  future `iat`, a stale `auth_time` with `two_factors`, a bad signature,
  an RSA key of 1024 bits, a subject of 256 bytes or with a control
  character.
- Discovery that names another issuer, or an endpoint over http or with a
  user, is refused; a provider down, a 503 and `invalid_client` are the
  method's own failures and take back the count; a failed discovery isn't
  cached; a redirect isn't followed.
- A callback is accepted once; after a second `Challenge` the first's is
  refused.
- An unlinked identity: `Prove` sets `Unlinked`; `Link` to a new user
  signs in and links; to a user with a password, a passkey, recovery
  codes, a device, an ended session or an invitation under way it is
  `not_new` and stores nothing; an identity linked meanwhile is
  `duplicate`; in a step-up or a sign-in with a login it is refused.
- Enrolling an identity someone holds is `duplicate`, the same user too.
- `two_factors` makes the proof verified; without it a staff policy needs
  a second proof, and an identity is no second factor; with a verified
  email equal to the user's, a code sent there doesn't make it two.
- `Identities` lists an identity, `Unlink` removes it, and refuses the last
  way in; `ResetFactors` leaves identities; `DeleteUser` removes them.
- Failed callbacks count toward the address alone; the caps of §5.5.9
  hold.
- No event, error or log holds a code, a token, `state`, `nonce` or the
  provider's error text.
