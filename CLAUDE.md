# auth

neozp's authentication package: sign-in flows, sessions, devices and
permissions (`auth/access`).

- Read [docs/roadmap.md](docs/roadmap.md), then the newest entry of
  [docs/status.md](docs/status.md). The design is
  [ADR 0001](docs/adr/0001-one-flow.md), the contract
  [docs/interface.md](docs/interface.md); [docs/brief.md](docs/brief.md) is
  the history before them.
- Claude owns this repository until v1.0.0, on the terms of
  [docs/ownership.md](docs/ownership.md) (delegated 2026-11-14). Only API
  design is epistemer's; the interface was locked by epistemer on
  2026-11-14. Security rules and merges are Claude's (told 2026-11-15).
- Load the `cfgx`, `i18n` and `errors` skills before touching config, keys
  or errors.
- This is security code. A change to a rule of interface §5 needs a test
  that fails without it, and a review by the other model family before it
  merges. Never log, record in an event or return a secret: a password, a
  code, a token, a key.
- Randomness comes from `crypto/rand` only. Secrets are compared in constant
  time.
- zp (`/home/epistemer/zp`) is private and read-only. Keep its names and the
  detail of its weaknesses out of this repository, which is public: examples
  and tests use a toy shop.
- Every working session adds an entry to docs/status.md.
