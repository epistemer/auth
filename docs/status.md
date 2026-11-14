# Status log

Newest first. Every working session adds an entry: what landed, the decisions
taken for you, what's next, and what's waiting on you.

## 2026-11-14: passwords (M1.2)

- **Landed** (PR #3): `internal/password`.
  - argon2id at ADR 0003's defaults, the bound on hashes at once on every
    hashing path, rehash on new parameters, the dummy hash, NFKC with no
    trimming, the 1024-byte limit. A benchmark prints ADR 0003's table.
  - Password strength by zxcvbn's estimate, on your choice:
    [ADR 0006](adr/0006-password-strength.md) and amendment A3. zxcvbn's
    matchers and scoring are ported, with its lists and keyboard graphs
    from a pinned commit (MIT) and its own tests. `CheckPassword` checks the
    length, the hints' words, whole-password patterns, then the estimate
    against the new key `password.min_score`.
  - [Review 0003](reviews/0003-m1.2-passwords.md) by Gemini 4 Argon
    (High), about 115k tokens: twelve findings, nine accepted. The one
    that mattered: estimating only the first 100 characters could pass a
    long password made of a unit typed twice.
- **Decided for you:**
  - `password.min_score` defaults to 4, not the 3 I proposed: zxcvbn's
    length term gives any password of three pieces score 3, however cheap
    (`Summer2024!!`). The range is 3 to 4, so 3 is a config change away.
  - The old hint check and whole-password patterns stay in front of the
    estimate: dropping them would loosen §5.2.4.
  - Amendment A4: `password.memory` and `password.time` get upper bounds
    (4096 MiB, 64 passes), the bounds a stored hash is read with.
  - The port departs from zxcvbn only where it finds more (l33t subsets,
    every copy of a repeat, years past 2019, joined hint words).
- **Not done:** comparing every estimate against zxcvbn's JavaScript on a
  corpus. Running the downloaded script was blocked by the session's
  permissions; ported tests and zxcvbn's demo results stand in.
  §7's password tests pass at the package level; their
  `acceptance_test.go` versions come once `SignIn` exists (M1.3).
- **Next:** M1.3, the flow engine.
- **Waiting on you:** nothing.

## 2026-11-14: the store (M1.1)

- **Landed** (PR #2): PR #1 merged after CI passed on the lock commit. Then
  the first code:
  - `internal/storepb`: the protobuf records, generated as i18n's are, with
    a CI step that fails when they are stale.
  - `internal/secrets`: HKDF keys per purpose, MACs that verify under the
    current and previous secret, AES-256-GCM sealing that reports a value
    needing a reseal, tokens and IDs.
  - `internal/store`: the buckets, a layout version that refuses a newer
    store, and typed reads and writes.
  - [ADR 0005](adr/0005-store-layout.md) for the layout, and two
    clarifying amendments to the interface: A1 (no key is derived for
    recovery codes, which review 0001 already moved to SHA-256) and A2 (the
    bucket list lives in ADR 0005).
  - [Review 0002](reviews/0002-m1.1-store.md) by Gemini 3.8 Flash (High),
    about 170k tokens: ten findings, six accepted. The two that mattered:
    a passkey ID with a zero byte would have crashed the store, and
    `SignKey` could hand out any purpose's key.
- **Decided for you:** amendments A1 and A2; `go-cmp` as a test-only
  dependency.
- **Next:** M1.2, passwords.
- **Waiting on you:** nothing.

## 2026-11-14: the interface is locked (M0.4)

- **Landed:** you locked [interface.md](interface.md) as it stood in PR #1,
  with Claude's calls D4, D10 and D22–D26. M0 is complete.
- **Decided for you:** nothing.
- **Next:** M1.1, the store and key derivation.
- **Waiting on you:** nothing.

## 2026-11-14: the repository starts (M0.1–M0.3, M0.4 drafted)

- **Landed** (PR #1, open):
  - The module, CI like errors', `CLAUDE.md`, and
    [ownership.md](ownership.md), which you delegated today.
  - [brief.md](brief.md) from the design session, [ADR 0001](adr/0001-one-flow.md)
    and the [roadmap](roadmap.md).
  - Three spikes, each an ADR with its measurements:
    - [0002](adr/0002-throttle-writes.md): a counter written with `db.Update`
      tops out near 400 writes a second and stalls other writers for 640 ms
      under a flood; with `db.Batch` it reaches 12,800 and they don't notice.
    - [0003](adr/0003-argon2-cost.md): argon2id at 64 MiB and two passes costs
      about 130 ms here; sixteen at once passed 2 GiB, so hashing is bounded.
    - [0004](adr/0004-methods-as-modules.md): a real passkey and OIDC method
      compile against the core's plug-in interface as nested modules, and
      the core's module graph stays free of their 24 and 6 dependencies.
  - [interface.md](interface.md), drafted for the lock. Its whole API
    compiles as stubs.
  - [Review 0001](reviews/0001-design.md) by Gemini 4 Hydrogen (High), about
    72k tokens (Argon was cooling down): fifteen findings, eleven accepted
    and four in part, all folded into the interface.
- **Decided for you** (each can be overturned at the lock):
  - From the brief's open questions: `UserID` is a string (D22); the access
    token is HS256 under a derived key, encoded in the core (D23); five flow
    starters (D4). Whether a registered device verifies a session became a
    per-user policy field, `TrustDevices`, instead of one answer (D10).
  - After the review: `Recover` and `Accept` set a password and make no
    session (D25); once a user enrols a factor, a code sent to their address
    stops counting as a second proof (D26); `SignIn` takes the carrier and
    `Finish` doesn't; `Revoke` and `ForgetDevice` take the user.
  - One addition to the ownership terms: loosening a security rule comes
    back to you, however small.
  - The brief's section on zp was reworded for a public repository: it lists
    failure shapes without saying which zp has.
- **Next:** M1 (the store, passwords, the flow engine, throttling, sessions
  and the cookie carrier), once the interface is locked.
- **Waiting on you:** the lock of [interface.md](interface.md) (M0.4). The
  decisions most worth your eye are D4, D10 and D22–D26 in its §3.
