# ADR 0001: One flow engine, sessions that record what was proven

| | |
|---|---|
| Status | Accepted |
| Date | 2026-11-14 |
| Roadmap item | M0.2 |
| Deciders | epistemer decided D1, D3, D5–D7, D9 and D11–D14 in the design session of 2026-11-14. Claude decided the rest as owner; each can be overturned before the interface is locked |

The decision numbers are those of [interface.md](../interface.md) §3.

## Context

neozp needs authentication, sessions and permissions for every app built on
it. The package it replaces holds two full copies of every flow, one for
cookie sessions and one for bearer tokens, and the copies drifted: a fix made
in one doesn't reach the other. [brief.md](../brief.md) §1 lists the failure
shapes hand-written authentication code tends to have. The design has to make
each of them impossible to write, not merely absent today.

The package must also fit neozp: configuration through a getter interface
(cfgx), errors with two messages (errors), translated labels (i18n), bbolt as
the store for small, read-heavy data, and `net/http` with no web framework.

## Options

**Who owns users.**
- *Auth owns a user table.* Simple for auth, but every app has its own idea of
  a user, and neozp has no way yet for a library to own tables in the app's
  database.
- *The app owns users; auth sees them through an interface.* Auth keeps only
  what proves identity, keyed by the app's user ID. **Chosen (D2).**

**Where flows live.**
- *In each transport.* The shape that drifted.
- *In one engine, with transports that only carry the result.* A sign-in, a
  step-up, a recovery, an invitation and an enrolment are the same record
  collecting proofs. Throttling, events and protection against enumeration
  are written once. **Chosen (D4).**

**What a session is.**
- *A half-made session that handlers must remember to check.* Fails open when
  one forgets.
- *No session until every proof is in.* Safe, but it removes a distinction the
  app needs: routine actions from an unknown access point, guarded dangerous
  ones.
- *A session that records what was proven, with routes that fail closed.* A
  session is verified or unverified; `Require` needs a verified one unless a
  requirement says otherwise. **Chosen (D9).**

**Bearer tokens.**
- *Opaque only.* Immediate revocation, nothing for the client to read.
- *A stateless JWT.* Carries claims, but can't be revoked before it expires.
- *A JWT that names its session, checked on every request.* Carries the app's
  claims and is refused the moment its session ends. The check is one bbolt
  read. **Chosen (D6, D7).**

**The store.**
- *The app's database.* Joins and backups come free; a library owning tables
  is unsolved in neozp.
- *bbolt.* No migrations, no storage interface, a read costs microseconds, and
  cfgx and i18n already put a bbolt file in every app. Credentials then live
  outside the database's backups, and an app is one process. **Chosen (D3).**

**Authorization.**
- *casbin, with policies keyed by route.* A string DSL that is easy to get
  subtly wrong, a second store to keep in step, and a tie to a router neozp
  doesn't have yet.
- *Permissions declared in code, groups in bbolt.* A check is two reads.
  Routes map to permissions later. **Chosen (D11).**

**SAML.** Left out (D1). XML signature validation is where SAML libraries
keep failing, and OIDC covers the same need.

## Decision

One flow engine with the verbs `Challenge`, `Prove` and `Finish`. The app
owns users and sends messages; auth owns proofs, sessions, devices and, in
`auth/access`, permissions, all in bbolt. A session records what was proven,
and routes need a verified one unless they say otherwise.

## Consequences

- An app writes its own handlers and pages over the flow verbs. The package
  ships no UI.
- An app runs as one process, and backs up its bbolt file like its database.
- Creating a user and setting a credential are not one transaction
  (interface §8).
- Passkeys and OIDC plug into the engine as methods, in nested modules, so the
  core has no WebAuthn or OIDC dependency ([ADR 0004](0004-methods-as-modules.md)).
- Throttle counters are written with `Batch` ([ADR 0002](0002-throttle-writes.md)),
  and password hashing is bounded ([ADR 0003](0003-argon2-cost.md)).
