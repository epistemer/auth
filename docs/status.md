# Status log

Newest first. Every working session adds an entry: what landed, the decisions
taken for you, what's next, and what's waiting on you.

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
