# Changelog

All notable changes to this module and its nested modules (`authschema`).
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Identities from modules (amendments A25, A26): `Flow.Unlinked` and
  `Link`, so an identity no user holds can sign up a new user;
  `Identities`, `IdentityInfo` and `Unlink`.
- `MethodResult.Address`: a proof that shows control of an address and a
  code sent there are one factor.
- `AddressOnly`, the optional interface of a method whose attempts count
  by address alone.
- The nested module `github.com/epistemer/auth/oidc`: signing in with an
  OpenID Connect provider (authorization code with PKCE) on go-oidc and
  x/oauth2, with `oidc.New` and `oidc.Callback` (amendments A25, A27).

### Changed

- The core no longer names passkeys for address-only throttling;
  `auth/passkey` implements `AddressOnly`.

## [v0.2.0] - 2026-11-17

Passkeys: the engine drives methods from modules, and `auth/passkey` is
the first, as locked by epistemer on 2026-11-17 (amendments A21–A24,
[docs/interface.md](docs/interface.md) §10). Released with
`authschema/v0.2.0` and `passkey/v0.2.0`.

### Added

- Methods from modules are driven (amendments A21, A22): `New` accepts
  `WithMethods`, `Challenge` calls a method's `Start`, `Prove` its
  `Verify`, and `Enroll` and `Finish` store its credentials.
- `SignInWithout`, a sign-in that names no login, for a method that finds
  the user from its proof.
- `MethodPasskey`: a passkey is an enrolled second factor.
- `FactorLabel`, the label of the factor an `Enroll` adds, for
  authenticator apps too.
- `Refuse`, for a module's `Verify` to refuse a proof with a reason.
- `MethodInput.Now`, the engine's clock.
- The nested module `github.com/epistemer/auth/passkey`: passkeys
  (WebAuthn Level 3) on go-webauthn, with `passkey.New`, `passkey.Response`
  and `passkey/passkeytest`, a software authenticator for an app's tests
  (amendments A21, A23).
- `authschema.Passkey()`, the group of passkey keys, nested with
  `authschema.Group(authschema.Passkey())`.
- `examples/shop` signs in and steps up with passkeys, and enrolls them.

### Changed

- `New` no longer refuses `WithMethods` (A19's refusal is withdrawn).
- `authschema.Group` takes nested groups (`members ...dsl.Member`); every
  existing call compiles unchanged.

## [v0.1.0] - 2026-11-16

The first release: the whole of the interface locked on 2026-11-14, with
amendments A1–A20 ([docs/interface.md](docs/interface.md) §10).

### Added

- `New` over the app's bbolt store, config, `Directory` and `Sender`, with
  options for claims, an event recorder, a per-user policy, the first
  methods, the client's address behind proxies, how refusals are answered,
  and a clock for tests. The module API (`Method`, `WithMethods`) is
  declared for `auth/passkey`; `New` refuses modules until v0.2.0 drives
  them.
- Flows: `SignIn`, `StepUp`, `Recover`, `Accept` and `Enroll`, driven by
  `Challenge`, `Prove`, `Follow` and `Finish`.
- Proofs: passwords (argon2id, with zxcvbn's strength estimate and
  `CheckPassword`), emailed and texted codes, emailed links, authenticator
  apps (RFC 6238) and recovery codes.
- Sessions on two carriers: a cookie, and a JWT access token with a rotating
  refresh token (`Refresh`, `Reissue`). `Load`, `Require`, `Check`, `From`,
  `Within`, and the levels `Verified` and `Unverified`.
- Management: `SignOut`, `Revoke`, `RevokeUser`, `Sessions`, `Devices`,
  `ForgetDevice`, `SetPassword`, `Invite`, `Factors`, `RemoveFactor`,
  `ResetFactors`, `DeleteUser`, `Sweep` and `Rekey`.
- Throttling by user, address and pair, with `RetryAfter`.
- Errors people can read, each an i18n key under `errors.auth.`.
- `auth/access`: permissions declared in code, groups, grants and
  memberships, the group `root`, `Can` for routes and `Check` for code.
- `auth/authtest`: a kit for tests, with a fake clock, a directory, an
  outbox and an event log.
- `authschema`: the cfgx group `auth`, with every key's range.
- `examples/shop`: a toy shop with web and API sign-in.

[v0.2.0]: https://github.com/epistemer/auth/releases/tag/v0.2.0
[v0.1.0]: https://github.com/epistemer/auth/releases/tag/v0.1.0
