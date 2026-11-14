// Package auth is neozp's authentication package: sign-in flows, sessions,
// devices and, in auth/access, permissions.
//
// The app owns its users. This package owns how they prove who they are:
// passwords, one-time codes, authenticator apps, recovery codes and, in
// nested modules, passkeys and OpenID Connect. Every way in is one flow that
// collects proofs until the user's policy is met, and a session records what
// was proven.
//
// The package is being built. The design is docs/adr/0001-one-flow.md, the
// contract is docs/interface.md, and docs/roadmap.md says what exists.
package auth
