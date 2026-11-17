# ADR 0008: Passkeys (`auth/passkey`)

| | |
|---|---|
| Status | Accepted for what is Claude's to decide; the API it implies waits for epistemer's lock of [interface-passkey.md](../interface-passkey.md) |
| Date | 2026-11-17 |
| Roadmap item | M7.0 |
| Deciders | Claude, as owner. The API choices (§"What waits on epistemer") are epistemer's |

## Context

`v0.2.0` adds passkeys as the first module method (ADR 0004, interface
§4.9, §5.5). The core already holds the types a module needs, but the
engine never calls `Method.Start` or `Method.Verify`, and `New` refuses
`WithMethods` (A19). Before the module is written, these questions need
answers:

1. which WebAuthn library, if any;
2. discoverable credentials and the user handle;
3. what `Challenge.Options` holds;
4. attestation;
5. signature counters and backup flags;
6. how a passkey counts toward `Verified` (§5.5.1, §5.7);
7. what the engine must change to drive a module, without weakening §5.1,
   §5.7 or §5.8.

## Options and decisions

### 1. The library

| Option | For | Against |
|---|---|---|
| **`github.com/go-webauthn/webauthn` v0.18.2** (BSD-3-Clause) | Widely deployed, maintained, tested against FIDO's conformance tools; the spike of ADR 0004 already wrote a method on it; entry points take parsed data, not an `*http.Request` (`ValidateLogin`, `ValidatePasskeyLogin`, `CreateCredential`) | Eleven third-party modules compile in (CBOR, TPM and JWT for attestation and metadata, msgp, uuid, mapstructure); its API has moved between minors |
| Our own verifier on `fxamacker/cbor` | Two modules; only attestation `none` and three algorithms to support | About 600 lines of new parsing and signature code in security code: COSE keys, EC point checks, RSA sizes, authenticator data flags. Every edge case the library already met is ours to meet again |
| `github.com/descope/virtualwebauthn` and similar | – | Test tools, not verifiers |

**Decision: go-webauthn, pinned at v0.18.2.** Its modules join
`auth/passkey`'s graph only; the core's stays as it is (ADR 0004). The
module wraps it entirely: no go-webauthn type appears in the module's
API, so a later move to our own verifier is invisible to apps. Upgrades
are PRs with the module's tests, and Dependabot's alerts cover it.

Tests use **an authenticator of our own** in `passkey/passkeytest`, built
on the CBOR library go-webauthn already brings. It signs real ES256
assertions, and can be told to drop the UV flag, replay a counter, flip
the backup-eligible flag or answer for another origin, which a
third-party virtual authenticator doesn't all allow. It is no new
dependency.

### 2. Discoverable credentials and the user handle

- **Registration asks for a discoverable credential** (`residentKey:
  required`). A passkey is one; a credential that isn't can't sign in
  without a login.
- **The user handle is the `UserID`'s bytes**, as D22 and ADR 0004 set
  out: opaque, at most 64 bytes, never a login or an address. The
  alternative, a random handle per user kept in the credential's data, is
  what WebAuthn recommends when an RP's IDs could carry personal data.
  D22 already forbids that, the handle is never trusted on its own (the
  credential ID finds the credential, and the handle must then match its
  owner), and the app knows the handle for the browser's signal API
  later. A random handle would also need an API to tell the app.
- **A sign-in finds the credential by its ID**, through
  `MethodInput.Find`, never by the handle. The handle must equal the
  owner's ID; a credential deleted with its user (`DeleteUser`) is not
  found, so an app that reuses user IDs can't hand an old passkey a new
  account.
- **Before the first proof of a flow started without a session, a
  passkey's options name no credential**, for a known login, an unknown
  one and no login alike (§5.1.3): the method gets no user and no
  credentials. After it (a passkey as the second factor, a recovery's
  second proof), and from the start in a flow bound to a session (a
  step-up, an enrollment), the options list the user's credentials
  (`allowCredentials`) with their transports. Enrolling lists them as
  `excludeCredentials`. When the options named none, the response must
  carry a user handle.

### 3. `Challenge.Options`

| Option | For | Against |
|---|---|---|
| **`json.RawMessage`: WebAuthn Level 3's `PublicKeyCredentialCreationOptionsJSON` or `…RequestOptionsJSON`** | What browsers parse with `PublicKeyCredential.parseCreationOptionsFromJSON` and `parseRequestOptionsFromJSON`, and native platform APIs take as is; the app writes it out without knowing its fields; no type of the library leaks | The app can't inspect it without decoding |
| A struct of the module's own | Typed | Duplicates the spec's JSON, with field tags, for no caller that needs fields |
| go-webauthn's `protocol.CredentialAssertion` | No work | Puts a third party's type, and its version, in the API |

**Recommendation: `json.RawMessage`** (an API choice, below). The app
knows whether to call `create` or `get`: it started the `Enroll`.

### 4. Attestation

**Conveyance `none`, and no trust decision on attestation.** The module
asks for none, records the format it got and the AAGUID, and checks
nothing against a metadata service. Attestation proves the make of an
authenticator, which matters to an RP that restricts makes; this one
doesn't, and synced passkeys mostly return none. go-webauthn still checks
the signature of a self-attestation it is given. No list of AAGUID names
is embedded in `v0.2.0` (a licence, and data to keep current); the factor's
label comes from the app (below) or is "Passkey".

### 5. Counters and backup flags

- **Counters.** As WebAuthn §7.2 says: when the stored counter or the
  presented one is above zero, the presented one must be greater, or the
  proof is refused (reason `counter`) and the stored value left as it
  was. A presented zero against a stored ten is a clone signal, not a
  reset. Synced passkeys report zero every time, which passes. Refusing rather than
  warning is the stricter reading of WebAuthn §6.1.1: a cloned
  authenticator is a stolen key, and the user still has their other
  factors and recovery codes. A credential that ran ahead keeps refusing
  the authenticator left behind; that is the signal, and `RemoveFactor`
  ends it.
- **The counter update is one transaction with the proof** (below), so
  two assertions racing can't both be accepted against one stored value.
- **Backup flags.** Backup-eligible (BE) is fixed at registration: an
  assertion whose BE differs is refused (reason `backup_flags`). Backup
  state (BS) is stored as last seen; BS without BE is refused.
- **User presence and verification.** Both flags are required on every
  ceremony (`userVerification: required`).

### 6. `Verified`

**Every accepted passkey proof is `Verified`** (§5.5.1): it proves
possession of the key and, with UV required, a PIN or a biometric on the
device. So:

- a passkey as the first proof makes a verified session on its own
  (§5.7.1), whatever the policy;
- a passkey is an enrolled second factor (§5.7.2): enrolling one stops a
  code to an address counting as a second method (A20), and the first one
  enrolled brings recovery codes (A17);
- a passkey proof is a second method for §5.1.9 (enrolling and removing
  factors) and for `RememberDevice` (§5.7.5), and meets `Within`.

Review 0020 objected that a passkey alone then grants what §5.1.9
reserves for a second method: removing the user's app, enrolling a
factor, registering a device. That is the locked design: §5.7.2 already
names a passkey among the second methods, and a passkey with UV is two
factors (a device and a PIN or a biometric), as NIST SP 800-63B counts
synced passkeys at AAL2. Whoever holds a user's unlocked keychain is in
the position of whoever holds their password and phone. Gating on
device-bound passkeys (BE=0) was declined: it would refuse most passkeys
users have. Generic modules don't inherit this: whether a module's
credential is a factor is its own section's to say (OIDC's won't be by
default).

The alternative, `userVerification: preferred` with UV deciding
`Verified`, admits security keys without a PIN as one factor. It doubles
the cases to test for a device few users of a shop have. It can come
later as a module option without changing the core.

Authenticator algorithms: ES256, EdDSA and RS256 (Windows Hello), in that
order. Nothing else is offered or accepted.

### 7. What the engine changes (M7.1)

The engine, not the method, applies the rules (§4.9). For any module
method:

- **`New` accepts `WithMethods`.** It refuses a nil method, a duplicate
  name, a built-in name, and a name outside `[a-z0-9_]{1,32}`.
- **`Challenge`** calls `Start` and stores its state in the flow,
  replacing any earlier state for that method; `Options` is what `Start`
  returned. Before the first proof `Start` gets no user and no
  credentials.
- **`Prove`** counts the attempt (below), calls `Verify` with the stored
  state, then, in one write transaction: the state must be the one
  `Verify` was given, and is deleted whatever the outcome (a challenge is
  used once); a credential update must find the credential still there
  with the data `Verify` read, else the proof is refused; then the proof
  is recorded. Outside an `Enroll`, a `MethodResult.Credential` may only
  update a credential the user already holds, by the same key; a new
  credential is stored only by an `Enroll`'s `Finish`, which checks §5.5.4
  in its transaction.
- **§5.5.3.** A proof that names a user other than the flow's, or names
  one when the login didn't resolve, is refused with
  `ErrBadCredentials`, as a wrong proof.
- **Signing in without a login.** A starter of its own,
  `SignInWithout`, starts a flow that knows no user and offers only
  `WithFirst`'s module methods; the user comes from the first proof. This
  is what a passkey autofill needs: the page starts the flow before
  anyone types. Review 0020 showed that `SignIn(ctx, "", …)` for this
  would make a blank form field switch modes, so `SignIn` keeps answering
  an empty login as an unknown one.
- **Throttling.** By default a module's attempts count like any proof's,
  under counters of the method's own kind (A20). A passkey's proof is a
  signature over a challenge the server made: there is nothing to guess.
  Its attempts count toward the address's counter only; never the
  user's, which would only let a stranger lock a user's passkeys from
  many addresses. A request presenting a registered device is held to
  that device's pair counter instead (§5.8.6), so `SignInWithout` reads
  the device token at the start: a user behind an address in a wait
  still signs in from their own device. A flow takes at
  most ten `Challenge`s and five refused proofs per module method, so one
  flow can't be used to hammer the store.
- **Refusals.** `Verify` returns `Refuse(reason)` for a proof it refuses,
  and anything else for a failure of its own (a store error), which the
  engine returns as is, taking back the attempt's count. Every refusal
  answers plain `ErrBadCredentials`; the event alone carries the reason.
  No go-webauthn error text reaches an error, a log line or an event: it
  can hold the challenge or credential bytes.
- **The credential used is checked.** The engine remembers every
  credential `Find`, `Lookup` and `Credentials` gave `Verify`. An
  accepted proof names the one it used in `MethodResult.Credential`,
  updated or not, and the write transaction refuses the proof if that one
  changed or went. This covers the discoverable sign-in, where `Verify`
  found the credential itself.
- **Enrolling** refuses a credential ID anyone already holds, the same
  user included, at `Prove` and again at `Finish`, where the limit of 20
  is checked again too. With attestation
  `none` a client can send any ID, and `excludeCredentials` is only a
  hint to the browser.
- **The flow's state** holds the challenge, the ceremony, the expiry and
  the user's ID, never the credential list, so it stays under 4 KiB for
  any user; a user has at most 20 passkeys.
- **The clock.** `MethodInput.Now` is the engine's clock, so options
  expire by `WithClock` and `authtest`'s clock moves passkeys too.
- **Factors.** A passkey the user holds is an enrolled factor everywhere
  the core counts them: `Offers`, §5.7.2, A20, `Factors`, `RemoveFactor`,
  `ResetFactors`, `DeleteUser`. For other modules their section decides.

## Consequences

- The module's API (interface-passkey.md) is epistemer's to lock; nothing
  of M7.2 starts before.
- If the draft is locked as recommended, the core gains `MethodPasskey`,
  `SignInWithout`, `FactorLabel`, `Refuse` and `MethodInput.Now`, and
  `authschema` gains `Passkey()` with a variadic `Group`, so the core and
  authschema are tagged `v0.2.0` too.
- CI runs vet, staticcheck, the tidy check and the tests in `passkey/`.
- §9 keeps out: attestation trust and metadata, AAGUID names, the
  browser's signal API, related origins (`/.well-known/webauthn`),
  conditional creation (upgrading a password user automatically), PRF and
  other extensions, accounts with a passkey and no password, and security
  keys without UV.
