# auth — Roadmap to the first release

> Status: **accepted plan**, written 2026-11-14 from [brief.md](brief.md)
> §13. Module: `github.com/epistemer/auth`.
>
> | Document | Answers |
> |----------|---------|
> | [ADR 0001](adr/0001-one-flow.md) | *What* the package does, and why that way |
> | [interface.md](interface.md) | *What* an app writes and gets back (locked 2026-11-14; passkeys 2026-11-17, A21) |
> | this file | *In what order*, and *when each piece counts as done* |

## How to use this document

- **Ownership.** Claude owns auth until `v1.0.0`
  ([ownership.md](ownership.md), delegated 2026-11-14).
- **IDs.** Every item has an ID (`M1.3`) and fits one PR or one focused
  session. Branch names, PR titles and commit subjects start with the ID.
- **Interface first.** M0 ends with the lock of `docs/interface.md`. After
  that a change to what an app writes or gets back is an amendment.
- **Versions.** The first usable release is `v0.1.0`. `v1.0.0` waits until
  zp's business code runs on it.
- **Agents.** Claude owns the flow engine, sessions, tokens and every rule of
  interface §5. Gemini, through agy, takes leaf items with a crisp done-when
  (the password list, TOTP against the RFC vectors, `authtest`, the schema
  fragment) and reviews Claude's work. Each delegated item runs in its own
  git worktree outside the repository.

## Overview

| Milestone | Goal | Needs |
|-----------|------|-------|
| [M0](#m0--foundations) | Module, CI, design records, spikes, interface locked | – |
| [M1](#m1--sign-in) | Flows, passwords, throttling, sessions, the cookie carrier | M0 |
| [M2](#m2--codes) | Codes and links, recovery, invitations, devices, verified sessions | M1 |
| [M3](#m3--bearer) | The access token, claims, rotating refresh tokens | M1 |
| [M4](#m4--authenticator-apps) | Enrolment, TOTP, recovery codes | M2 |
| [M5](#m5--access) | `auth/access` | M1 |
| [M6](#m6--release) | Example app, README, API review, the skill, `v0.1.0` | M2–M5 |
| [M7](#m7--passkeys-v020) | The engine drives modules; `auth/passkey`; `v0.2.0` | M6 |

## Definition of done (every work item)

1. `go test -race ./...` passes on the whole CI matrix (Go 1.26 and 1.27 on
   Linux, macOS and Windows), in every module.
2. It lands as a PR with green CI and a review by the other model family.
3. Every rule of interface §5 the item implements has a test that fails
   without it. The acceptance tests of interface §7 that the item makes
   possible are written in the same PR.
4. If the behaviour differs from interface.md, that document is amended in
   the same PR. A change to a rule of §5 also needs the other model family's review.
5. A new dependency needs an ADR.
6. No secret reaches a log line, an event or an error. A test greps for it.
7. Nothing of zp's names enters the repository: tests and examples use a toy
   shop.

---

## M0 — Foundations

| ✓ | ID | Item | Done when |
|---|----|------|-----------|
| ☑ | M0.1 | Module `github.com/epistemer/auth` (Go 1.26, MIT), `doc.go`, `CLAUDE.md`, and CI like errors' | CI runs green on a PR |
| ☑ | M0.2 | ADR 0001, this roadmap, `docs/status.md`, `docs/ownership.md`, and the brief as `docs/brief.md` | They are in the M0 PR |
| ☑ | M0.3 | Spikes S1 (bbolt writes under a flood), S2 (argon2 cost), S3 (passkeys and OIDC as nested modules) | Each has an ADR with its measurements: [0002](adr/0002-throttle-writes.md), [0003](adr/0003-argon2-cost.md), [0004](adr/0004-methods-as-modules.md) |
| ☑ | M0.4 | `docs/interface.md`, reviewed by the other model family ([review 0001](reviews/0001-design.md)) | epistemer locks the interface (2026-11-14) |

## M1 — Sign-in

| ✓ | ID | Item | Done when |
|---|----|------|-----------|
| ☑ | M1.1 | The store: buckets, protobuf records, key derivation from the master secret (interface §5.12, §8) | A record of each kind round-trips; a previous secret still verifies and decrypts ([ADR 0005](adr/0005-store-layout.md)) |
| ☑ | M1.2 | Passwords: argon2id, the bound, `CheckPassword`, zxcvbn's estimate and its lists (their source and licence in [ADR 0006](adr/0006-password-strength.md)) | Interface §7's password tests pass; a benchmark prints ADR 0003's table |
| ☑ | M1.3 | The flow engine: `SignIn`, `StepUp`, `Prove`, `Finish`, `Flow`, with the password method and the rules of §5.1 | §7's enumeration tests for passwords pass; those for codes come with M2.1 |
| ☑ | M1.4 | Throttling (§5.8), written with `Batch` | §7's throttling tests pass under the race detector |
| ☑ | M1.5 | Sessions and the cookie carrier: `Load`, `Require`, `Check`, `From`, `SignOut`, `Revoke`, `RevokeUser`, `Sessions`, CSRF (§5.6, §5.9) | §7's session tests pass against `httptest` |
| ☑ | M1.6 | Events, the errors of §4.6, `auth/authschema` as its own module, `auth/authtest` | A fake config and a generated one both satisfy `auth.Config` |

## M2 — Codes

| ✓ | ID | Item | Done when |
|---|----|------|-----------|
| ☑ | M2.1 | Codes (§5.3): `Challenge`, the code proofs, codes as the second proof (§5.7.2) | §7's code tests pass, and its enumeration test for `Challenge` |
| ☑ | M2.2 | Links and `Follow` (§5.3.6), `Recover`, `Invite` and `Accept`, with the notice messages | A recovery with a second factor enrolled doesn't finish on the emailed proof alone; §7's `Follow` tests and its enumeration test for `Recover` pass |
| ☑ | M2.3 | Devices and verified sessions (§5.7): `RememberDevice`, `Device`, `Devices`, `ForgetDevice`, policies | §7's device tests pass, and its throttling test for a registered device |

## M3 — Bearer

| ✓ | ID | Item | Done when |
|---|----|------|-----------|
| ☑ | M3.1 | The access token (§5.6) and the bearer carrier in `Load` | A token for a revoked session is refused; a token with any other header is refused; §7's `RevokeUser` test on the bearer carrier passes |
| ☑ | M3.2 | `Claimer`, `Refresh` with rotation and reuse detection, `Reissue` | §7's refresh tests pass |

## M4 — Authenticator apps

| ✓ | ID | Item | Done when |
|---|----|------|-----------|
| ☑ | M4.1 | `Enroll`, `Factors`, `RemoveFactor`, `ResetFactors`, changing a password through `Enroll` | A factor change without a fresh proof is refused |
| ☑ | M4.2 | TOTP (§5.4) | The RFC 6238 vectors pass; a code is refused the second time |
| ☑ | M4.3 | Recovery codes | Each works once; a new set cancels the old |

## M5 — Access

| ✓ | ID | Item | Done when |
|---|----|------|-----------|
| ☑ | M5.1 | `access.Permission`, groups, grants, memberships, `Check` (§5.10) | §7's permission tests pass |
| ☑ | M5.2 | `Can` as a requirement, the `root` group, `Stale` | A permission declared after `root` was made is held by `root` |

## M6 — Release

| ✓ | ID | Item | Done when |
|---|----|------|-----------|
| ☑ | M6.1 | An example app (a toy shop) with web and API sign-in, as its own module | Its end-to-end test signs in, steps up and is refused where it should be |
| ☑ | M6.2 | README, godoc examples, CHANGELOG, `docs/api-review.md` | Every exported identifier is checked against interface §4 |
| ☑ | M6.3 | A security review of the whole package by the other model family at its highest effort | Its findings are handled or recorded |
| ☑ | M6.4 | `v0.1.0`, the skill `~/.claude/skills/auth/`, and auth in epistemer's global CLAUDE.md | `go get github.com/epistemer/auth@v0.1.0` resolves and the example builds against it |

## M7 — Passkeys (v0.2.0)

Added 2026-11-17. The design is [ADR 0008](adr/0008-passkeys.md), the
contract [interface.md](interface.md) A21 (§4.11, §5.13), which epistemer
locked on 2026-11-17. It adds API to the core, to `authschema` and in a
new module.

| ✓ | ID | Item | Done when |
|---|----|------|-----------|
| ☑ | M7.0 | ADR 0008, the draft interface section with its amendments to §4.2, §4.3, §4.9, §5.1.3, §5.5 and §9, reviewed by the other model family ([review 0020](reviews/0020-passkey-draft.md)) | epistemer locks the draft; it is folded into interface.md as amendment A21 |
| ☑ | M7.1 | The engine drives modules: `New` accepts `WithMethods` (A19 withdrawn); `Challenge` calls `Start`, `Prove` calls `Verify`, under the new rules of §5.5; `SignInWithout`; passkeys as enrolled factors; `FactorLabel`, `Refuse`, `MethodPasskey`, `MethodInput.Now`. Tested with a fake method in the core's tests | Every new rule of §5.5 has a test that fails without it, with a fake method; the §7 tests that need no real passkey pass; the core's graph is unchanged |
| ☑ | M7.2 | `auth/passkey` as a nested module on go-webauthn (ADR 0008), with `passkey/passkeytest`; CI runs it in the matrix | §5.13 holds, each rule with a test that fails without it, through `passkeytest`; the §7 passkey tests pass; `go mod graph` of the core shows no WebAuthn module |
| ☑ | M7.3 | `authschema.Passkey()` and a variadic `Group`; the shop example signs in and enrolls with a passkey; README, CHANGELOG, `docs/api-review.md` for the new identifiers | The example's end-to-end test signs in by passkey alone and is verified; every new exported identifier is checked against the locked section |
| ☑ | M7.4 | A security review of M7.1–M7.3 by the other model family at its highest effort | Its findings are handled or recorded |
| ☑ | M7.5 | Tags `v0.2.0`, then `authschema/v0.2.0` and `passkey/v0.2.0` (ADR 0004); the skill and epistemer's global CLAUDE.md updated | A copy of the example with no `replace` builds against the tags and passes its end-to-end test |

## After v0.2.0

- `auth/oidc` (`v0.3.0`), with its own interface section.
- Then what interface §9 leaves out, as apps ask for it.
