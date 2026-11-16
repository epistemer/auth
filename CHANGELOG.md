# Changelog

All notable changes to this module and its nested modules (`authschema`).
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and versions follow [Semantic Versioning](https://semver.org/).

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

[v0.1.0]: https://github.com/epistemer/auth/releases/tag/v0.1.0
