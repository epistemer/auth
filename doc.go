// Package auth is neozp's authentication package: sign-in flows, sessions,
// devices and, in auth/access, permissions.
//
// The app owns its users. This package owns how they prove who they are:
// passwords, one-time codes and links, authenticator apps, recovery codes
// and, in nested modules, passkeys and OpenID Connect.
//
// # Flows
//
// Every way in is one flow that collects proofs until the user's policy is
// met: SignIn, StepUp, Recover, Accept (an invitation) and Enroll (a new
// factor). Challenge sends a code or a link, Prove takes a proof, and
// Finish ends the flow: it makes or upgrades a session, sets a password or
// stores a factor. A flow's token is a secret; Flow.Write keeps it in a
// cookie and FlowToken reads it back.
//
// # Sessions and requests
//
// Load attaches a request's session, read from a cookie (Cookie) or an
// access token (Bearer), and refuses forged cross-origin requests. Require
// rejects a request whose session doesn't meet every requirement: a Level,
// Within for a recent proof, or a permission from auth/access. Without a
// Level it needs a verified session.
//
// # What the app provides
//
// A Directory finds users by login and knows their addresses; a Sender
// delivers messages; a Config (from cfgx and authschema) holds the secret
// and the lifetimes. Optionally a Claimer adds claims to access tokens, a
// Recorder takes the audit events, and WithPolicy says, per user, whether an
// unverified session is allowed and whether a remembered device stands for
// the second proof.
//
// The contract is docs/interface.md; the design is docs/adr/0001-one-flow.md.
package auth
