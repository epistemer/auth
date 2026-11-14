# ADR 0004: Passkeys and OIDC are methods in nested modules (spike S3)

| | |
|---|---|
| Status | Accepted |
| Date | 2026-11-14 |
| Roadmap item | M0.3 |
| Deciders | Claude, as owner. epistemer decided that they are nested modules (D14) |

## Context

Passkeys and OpenID Connect come after `v0.1.0`, but the core's interface is
locked before then. The spike had to show that both can be added without
changing the core, and that their dependencies stay out of the core's module
graph.

## Options

The spike wrote the core's exported API as stubs, and a real `passkey` and
`oidc` method against it, each in its own module inside the repository:
`github.com/go-webauthn/webauthn` `v0.18.2`, `github.com/coreos/go-oidc/v3`
`v3.21.0` and `golang.org/x/oauth2` `v0.38.0`. All three modules pass
`go vet`.

What it showed:

- **The module graph.** The core's graph is itself alone. `passkey` pulls in
  24 modules (CBOR, TPM attestation, a JWT library) and `oidc` six. A nested
  directory with its own `go.mod` is invisible to the core's `./...`.
- **One interface fits both.** A method has `Start`, which makes what the
  client needs (passkey options, a redirect URL) and some state the flow
  keeps, and `Verify`, which checks the proof against that state. Both
  libraries have entry points that take parsed data, not an `*http.Request`,
  and both ceremonies' state serializes to bytes.
- **What a method needs from the engine.** The user and their credentials for
  that method; a lookup by credential key (an OIDC issuer and subject); and a
  lookup by user ID (a discoverable passkey names the user by its handle).
- **What a method gives back.** Who the proof belongs to, when the flow didn't
  know; a credential to store or update (a new signature counter); whether the
  proof counts as two factors; and, for OIDC, a valid identity linked to no
  user.
- **Two requirements on the core's types.** `User` needs a `Name`, shown by
  passkey managers and authenticator apps. A `UserID` becomes the WebAuthn
  user handle, so it must be opaque, at most 64 bytes, and never a login or
  an address.
- **Co-development needs a `replace`.** A nested module that imports the core
  requires a published version of it. Between releases, its `go.mod` carries
  `replace github.com/epistemer/auth => ../`. A `replace` in a dependency is
  ignored by the apps that import it, so it harms nobody.

## Decision

- `auth/passkey` and `auth/oidc` are nested modules that implement
  `auth.Method` (interface §4.9) and are passed to `auth.New` with
  `WithMethods`.
- The core defines `Method`, `MethodInput`, `MethodResult`, `Credential`,
  `Identity` and `Proof` now, in `v0.1.0`, so the modules need no change to
  it later.
- `User` has a `Name`, and `UserID` carries the rule above.

## Consequences

- A release tags the core first, then each module (`passkey/v0.2.0`) after its
  `require` names the new core version.
- CI runs vet, staticcheck, the tidy check and the tests in every module, as
  i18n's does.
- The spike's code is scratch. The modules are written for real in their own
  milestones, each with its own interface section.
- `auth/authschema` imports cfgx's `dsl`, so it is a module of its own too, as
  i18n's schema is.
