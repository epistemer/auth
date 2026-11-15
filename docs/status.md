# Status log

Newest first. Every working session adds an entry: what landed, the decisions
taken for you, what's next, and what's waiting on you.

## 2026-11-15: ownership terms

- PR #5 (M1.4) merged on green.
- epistemer dropped the extra term of [ownership.md](ownership.md):
  loosening a security rule no longer comes back to them. Only API design
  does, and merges on green are Claude's. A change to a rule of §5 still
  needs a test that fails without it, the other model family's review and
  an amendment, so it can be overturned.
- **Next:** M1.5, sessions and the cookie carrier.

## 2026-11-15: throttling (M1.4)

- **Landed** (PR #5): throttling (interface §5.8), with i18n bumped to
  v0.3.1, whose protobuf file no longer clashes with anyone's.
  - Every password proof, in `SignIn` and `StepUp`, is counted against the
    user, the client address and the pair in one `Batch` transaction
    before it is checked. A refused attempt does no hashing and returns
    `ErrTooManyAttempts`; `RetryAfter` says how long.
  - How the counters count is [ADR 0007](adr/0007-throttle-counters.md).
  - [Review 0005](reviews/0005-m1.4-throttle.md) by Gemini 4 Argon (High),
    about 83k tokens: ten findings, seven accepted and two in part. The one
    that mattered: the doubling overflowed after about 39 failures, and the
    negative wait let a few guesses through in a row.
- **Decided for you:** amendment A6.
  - The address's counter counts failures: a success takes back its own
    attempt's count, and never clears the counter. Read literally, §5.8
    counted successes too, so an office would wait after five sign-ins.
  - An IPv6 address is counted by its /64.
  - A counter in a wait doesn't decay before the wait ends.
  - Only an accepted proof clears counters: a disabled user's right
    password stays counted.
- **Not done:** §7's throttling test for a registered device waits for
  devices; the roadmap adds it to M2.3. `Sweep`, which removes old
  counters, comes with M1.5.
- **Your choice:** a refused attempt changes no counter (amendment A7,
  review 0005 finding 2). An address in a wait can no longer push other
  users' counters, and the wait doubles with each failure let through.
- **Waiting on you:** nothing.
- **Next:** M1.5, sessions and the cookie carrier.

## 2026-11-15: the flow engine (M1.3)

- **Landed** (PR #4): the root package.
  - The types of interface §4.1, `New` with the config's ranges checked,
    the options, and the errors of §4.6.
  - `SignIn`, `StepUp`, `Flow`, `Prove` and `Finish`. The password proof
    does one hash for every login: known, unknown, without a password,
    disabled. `Finish` makes a cookie session, ending any session the
    request carried; a step-up upgrades its own session in place with a
    new token and generation.
  - `CheckPassword` and `SetPassword`; replacing a password ends the
    user's sessions, makes older proofs in flows stale, and sends
    `MsgPasswordChanged`.
  - Events through a `Recorder`, or `log/slog`.
  - [Review 0004](reviews/0004-m1.3-flows.md) by Gemini 4 Argon (High),
    about 101k tokens: twelve findings, ten accepted. The two that
    mattered: a flow proved with an old password could finish after a
    change, and a rehash at sign-in could undo a change made meanwhile.
- **Fixed on the way:** `internal/storepb/records.proto` is now
  `auth_records.proto`. i18n registers a protobuf file of the same name,
  so any program with both panicked at start. i18n's own file has the same
  problem for anyone else who names theirs so.
- **Decided for you:**
  - Amendment A5: what `Ready` and `Offers` mean for a step-up, and its
    errors when finished from the wrong session.
  - What waits for its milestone: the bearer carrier (`SignIn` with
    `Bearer()` returns `ErrUnsupported` until M3), devices (`Device` and
    `RememberDevice` do nothing until M2.3, as §5.7.5 allows while no flow
    can prove a second method), throttling (M1.4), `Load` (M1.5).
  - A session cookie without `Remember` ends with the browser's session.
- **Not done:** §7's enumeration tests for `Recover` and `Challenge` need
  codes; the roadmap moves them to M2.1. The tests are in the package, not
  yet `acceptance_test.go` over `authtest` (M1.6).
- **Next:** M1.4, throttling.
- **Waiting on you:** nothing.

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
