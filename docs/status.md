# Status log

Newest first. Every working session adds an entry: what landed, the decisions
taken for you, what's next, and what's waiting on you.

## 2026-11-16: refresh tokens (M3.2)

- **Landed** (PR #12, on top of #11, #10 and #9): `Refresh` and `Reissue`
  (§5.6.8–11).
  - `Refresh` rotates the refresh token and issues an access token with the
    `Claimer`'s claims now. A token used again ends its session and records
    `refresh.reused`; within `refresh.grace` a client that lost the answer
    gets the same successor, while that successor is unused.
  - `Reissue` refreshes a session's claims: a new access token for a bearer
    session, new `Session.Claims` for a cookie one.
  - [Review 0012](reviews/0012-m3.2-refresh.md) by Gemini 4 Argon (High),
    about 72k tokens: nine findings, three critical, all fixed. The grace
    could hand out a successor already used, letting a thief walk the
    chain; a step-up's old refresh tokens were deleted rather than kept to
    catch their reuse; and reuse was judged after the `Claimer`, so its
    failing spared a session.
- **Decided:** amendment A14.
- **Still waiting on you:** the ruleset's required check, which holds #9
  and the four PRs stacked on it.
- **Next:** M4.1, `Enroll` and factors.

## 2026-11-16: the access token (M3.1)

- **Landed** (PR #11, on top of #10 and #9): the bearer carrier (§5.6.5–6).
  - `SignIn(Bearer())`; `Finish` returns an access token and a refresh
    token; a step-up issues both again at the new generation, so older
    access tokens stop working.
  - `Load(Bearer())` checks the token: the header's bytes, the signature in
    constant time, `exp`, `iat`, `iss`, `aud`, then the session `sid` names,
    which must be a live bearer session of `sub` at generation `gen`.
    Whether a request is verified comes from the session; its claims from
    the token.
  - [Review 0011](reviews/0011-m3.1-access.md) by Gemini 4 Argon (High),
    about 74k tokens: eight findings, seven accepted, one in part.
- **Decided:** amendment A13.
- **Still waiting on you:** the ruleset's required check (see 2026-11-15),
  which holds #9, and with it #10 and #11.
- **Next:** M3.2, `Refresh`, `Reissue` and the `Claimer`.

## 2026-11-15: devices (M2.3)

- PR #9 (M2.2) is green but blocked: the ruleset "CI check" requires
  `Go 1.26.x (ubuntu-latest)` from app 1236702, while CI runs on GitHub
  Actions (app 15368), so the required check never arrives. **Waiting on
  you:** set the required check's source to GitHub Actions (or any source).
  M2.3 is stacked on M2.2's branch meanwhile; I didn't use `--admin` to
  bypass your rule.
- **Landed** (PR #10, on top of #9): registered devices (§5.7).
  - `RememberDevice` registers the device in a sign-in or step-up that
    proved a second method, and sends `MsgNewDevice`. The cookie carrier
    keeps the token in `__Host-device`.
  - A registered device of the user stands for the second proof when the
    policy has `TrustDevices`; its token is replaced at the `Finish` of the
    sign-in that used it, not before.
  - `Devices` and `ForgetDevice`; a recovery or a password change forgets
    them all; `Sweep` removes expired ones.
  - A request with the user's device is throttled by the pair's counter
    alone (§5.8.6), the last of §7's throttling tests.
- **Decided:** amendment A12.
- **Next:** M3.1, the access token.

## 2026-11-15: links, recovery and invitations (M2.2)

- PR #8 (M2.1) merged on green. `main` now has a ruleset requiring
  `Go 1.26.x (ubuntu-latest)`, and every PR gets auto-merge when it opens.
- **Landed** (PR #9):
  - `Recover`, the same for every login: a link or a code to an address,
    then, for a user with an enrolled factor, that factor. `Finish` sets the
    password and makes no session; it ends every session and sends
    `MsgPasswordChanged`.
  - Links and `Follow`: holding the link is the proof, `Follow` is safe on a
    GET, and twice returns the same flow.
  - `Invite` and `Accept`, held to the same rules.
  - [Review 0009](reviews/0009-m2.2-recover.md) by Gemini 4 Argon (High),
    about 95k tokens: twelve findings, nine accepted. The one that mattered:
    `Follow` proved the flow `Recover` had started, so anyone who started a
    recovery for someone else could finish it once the link was followed,
    by its owner or by a mail scanner. The first use of a link now moves
    the flow to a token only the link's holder learns.
- **Decided:** amendment A11.
- **Not done:** forgetting the user's devices on recovery comes with
  devices (M2.3).
- **Next:** M2.3, devices and verified sessions.

## 2026-11-15: codes (M2.1)

- PR #7 (M1.6) merged on green. You're allowing auto-merge in the repo;
  from M2.1 on, PRs merge themselves once CI passes.
- **Landed** (PR #8): codes sent by email or SMS (§5.3).
  - `Challenge` sends a code, answering alike whatever happened (§5.1.5):
    an unknown login, no address, a directory error, a failed send, inside
    `code.resend`, past `code.hourly`. What happened is an event.
  - `EmailCode` and `SMSCode` proofs: a try is counted before the code is
    compared, in one transaction; a code is bound to its flow, its purpose
    and its method, and burnt by its last try or its first use. Wrong codes
    count toward throttling too.
  - With no factor enrolled, a code to each address the directory has is a
    second proof, and two proofs through one address count as one (§5.7.2).
    `WithFirst` may name the code methods, for sign-in by code.
  - [Review 0008](reviews/0008-m2.1-codes.md) by Gemini 4 Argon (High),
    about 90k tokens: twelve findings, six accepted and two in part. The one
    that mattered was mine: a code that was never sent had a real MAC, so it
    could be guessed with every new flow.
- **Decided:** amendment A10. Links and `Follow` move to M2.2 with
  `Recover`, the only flow that sends a link.
- **Next:** M2.2, links, `Recover`, `Invite` and `Accept`.

## 2026-11-15: authschema, authtest and the acceptance tests (M1.6)

- PR #6 (M1.5) merged on green.
- **Landed** (PR #7):
  - `auth/authschema`, a module of its own: the cfgx group `auth` with
    §4.8's keys, defaults and ranges. A toy shop's generated settings
    satisfy `auth.Config`, load §4.8's defaults, refuse every range on both
    sides, and pass `auth.New`.
  - `auth/authtest` as §4.10 has it, with cheap hashing through an internal
    hook only auth's module can reach.
  - `acceptance_test.go`: §7's lines so far, black-box through `authtest`,
    with a check that no event holds a secret the suite used.
  - Events: `session.ended` when a password change or a new sign-in ends a
    session. The errors of §4.6 are pinned, key and kind, by a test.
  - [Review 0007](reviews/0007-m1.6-authtest.md) by Gemini 4 Argon (High),
    about 79k tokens: eleven findings, six accepted, three in part. Most were
    acceptance tests that would have passed with their rule broken.
- **Decided:** amendment A9 (what the schema can and can't check, the zero
  `refresh.grace`, concurrency's default, `authtest` outside `go test`).
- **Recommendations for you (API, not blocking):**
  1. A validator the generated code can call, so cfgx refuses a short secret
     when it loads, not only `auth.New`: `authschema.ValidSecret(cfgx.Secret)
     error`, used with `.Validate` on both secrets. Default: leave it to
     `New`, as now.
  2. A way to give a kit a config. `authtest.New(tb, opts...)` takes only
     `auth.Option`s, so a test can't change `throttle.free` or
     `trusted_origins` on a kit. I'd add `authtest.NewWith(tb, cfg
     auth.Config, opts ...auth.Option) *Kit`, used with `authtest.Config`'s
     edits. Default: leave it out until an app needs it.
- **Next:** M2.1, codes and links.

## 2026-11-15: sessions and the cookie carrier (M1.5)

- **Landed** (PR #6): `Load` with the cookie carrier, `Require`, `Check`,
  the levels and `Within`, `SignOut`, `Revoke`, `RevokeUser`, `Sessions`
  and `Sweep`.
  - `Load` checks every request without a bearer token with
    `http.CrossOriginProtection` and `trusted_origins`, a sign-in without a
    session too; reads the client from `WithClientAddr` or the peer; and
    writes a session's `Seen` at most once a minute with `Batch`.
  - `Sweep` removes expired flows, dead sessions with their indexes, and
    counters past their window.
  - [Review 0006](reviews/0006-m1.5-sessions.md) by Gemini 4 Argon (High),
    about 77k tokens: twelve findings, nine accepted and two in part. The
    two that mattered: a session revoked while `Load` wrote its `Seen` was
    still admitted, and a request with a bearer header didn't end the
    cookie session it carried when signing in or out.
- **Decided:** amendment A8, the behaviour the contract left open (the
  refusal of a forged request, a bearer header beside a cookie, nested
  `Load`, unknown levels, `Require(nil)`, `SignOut` on error).
- **Not done:** `Load(Bearer())` attaches no session until M3.1, when bearer
  sessions exist; §7's `RevokeUser` test on the bearer carrier moves there.
  Codes, links, devices and refresh tokens join `Sweep` with their
  milestones.
- **Next:** M1.6, events, errors, `auth/authschema` and `auth/authtest`.

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
