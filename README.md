# auth

neozp's authentication package: sign-in flows, sessions, devices and
permissions.

> **Being built.** No code is released yet. The contract is drafted and waits
> for its lock.

The app owns its users. This package owns how they prove who they are:

- **One flow for every way in.** Signing in, stepping up, recovering an
  account, accepting an invitation and adding a factor all collect proofs in
  one engine, so throttling, audit events and protection against account
  enumeration exist once.
- **Proofs:** passwords (argon2id), emailed or texted codes and links,
  authenticator apps (TOTP) and recovery codes. Passkeys and OpenID Connect
  come as modules after `v0.1.0`.
- **Sessions that record what was proven.** A session is verified or
  unverified. Routes need a verified one unless they say otherwise.
- **Two carriers.** An opaque cookie for browsers; for apps, a JWT access
  token that carries the app's claims and is refused the moment its session
  ends, with a rotating refresh token.
- **Permissions** declared in code, with groups and memberships
  (`auth/access`).

It stores its data in the app's bbolt file, takes its configuration through a
getter interface ([cfgx](https://github.com/epistemer/cfgx)), and returns
errors people can read in their language
([errors](https://github.com/epistemer/errors),
[i18n](https://github.com/epistemer/i18n)).

## Where to read

| | |
|---|---|
| [docs/interface.md](docs/interface.md) | The contract: what an app writes and gets back, and every rule |
| [docs/adr/0001-one-flow.md](docs/adr/0001-one-flow.md) | The design and the options it rejected |
| [docs/roadmap.md](docs/roadmap.md) | The order of work and what counts as done |
| [docs/status.md](docs/status.md) | What happened in each working session |

## License

MIT
