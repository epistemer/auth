# neozp `auth`: design brief

> **History.** [ADR 0001](adr/0001-one-flow.md) and [interface.md](interface.md) replace this brief. Spikes and review 0001 changed several things after it was written, so where they differ, they are right. Kept as the record of what was known before the work began.

> Written on 2026-11-14 in a design session with epistemer, for the Claude Code session that starts this package. Decisions marked **epistemer** were made or accepted that day. Decisions marked **(Claude)** were settled while writing this brief and can be overturned before the interface is locked. zp appears only as shapes, without file names or the detail of its weaknesses, so this file can be committed as `docs/brief.md`.

## 0. How to use this brief

This is neozp's sixth package, after cfgx, i18n, genx, models and errors. The folder `/home/epistemer/auth` is empty and is not yet a git repository. The module path is assumed to be `github.com/epistemer/auth`; creating the GitHub repository is epistemer's to do.

1. Read the sibling repositories for their conventions: the README, `docs/interface.md` (a locked contract with a decisions table and amendments), `docs/roadmap.md`, `docs/status.md`, `docs/adr/`, `docs/ownership.md`, `CLAUDE.md` and CI. Load the `cfgx`, `i18n` and `errors` skills.
2. Set the module up like theirs: Go 1.26, MIT, the same CI jobs.
3. Write the design records from this brief: ADR 0001 from §§1–4, `docs/interface.md` from §§3–9 for epistemer to lock, and the roadmap from §13.
4. Run the spikes of M0 before the interface is locked. Two of them can change decisions (§13).
5. Ownership is epistemer's to grant when the work starts. Every working session adds an entry to `docs/status.md`.
6. zp is private and read-only. Keep its names out of this repository.

## 1. What zp's auth taught

zp's `auth` package holds two full copies of every flow, one for cookie sessions and one for JWT. They drifted: a fix made in one copy doesn't reach the other. That is the main lesson, and the reason for one flow engine.

The table lists the failure shapes this design has to make impossible. They are the common ones in hand-written authentication code. Reading zp prompted the list, but it is not a report on zp, and this public file doesn't say which of them zp has.

| Failure shape | What the new package does about it |
|---|---|
| Two transports, each with its own login, reset and verification code | One flow engine. Transports only carry the result (§5, §6.6) |
| A one-time code stored as it was sent, compared by a lookup, with no cap on guesses | Codes are stored as an HMAC, bound to one flow, and burn after a fixed number of tries (§6.3) |
| A lifetime setting described in seconds and applied in minutes | Every lifetime is a `time.Duration` from cfgx (§8) |
| A hashing error ignored, so some passwords stored an empty hash | Hashing has no input the user can make fail; errors are returned (§6.2) |
| A second factor skipped when the client names a known device, where the name is chosen by the client | A registered device is a token the server issued (§6.7) |
| A lookup of a salted hash by equality, so two flows could never succeed | One-time tokens use a keyed or plain SHA-256; salted hashes are for passwords only (§6.3) |
| Failed attempts recorded and never read | Throttling is part of every flow (§6.8) |
| Different answers for an unknown account and a wrong password | One answer and the same work for both (§6.1) |
| Permission checks defined and never called; a matcher that ignored part of the request | Routes fail closed; permissions are checked by the same middleware that loads the session (§6.10) |
| A session ID reused across logins and stored as it travels; the user row, password hash included, serialized into the session | Tokens are rotated at every change of privilege and stored hashed; a session holds an ID, not a user (§6.6) |
| An access token with no link to its session, valid after a block | The access token names its session, and the session is checked on every request (§6.6) |
| Secrets drawn from `math/rand` | `crypto/rand` only |
| Password strength as character-class scoring and a short word list | Length, a large list of common passwords and context words (§6.2) |
| One struct that sends mail, renders templates, holds groups and signs tokens | The app sends messages and owns users. The package owns proofs (§3) |

## 2. The idea

**The app owns users. Auth owns how they prove who they are.** Auth has no user table. It asks the app's `Directory` who a login belongs to and where to send a code, and it hands every message to the app's `Sender`. It keeps credentials, sessions, devices and permissions.

**Every way in is one flow.** Signing in, stepping up, recovering an account, accepting an invitation and adding a factor are all a *flow*: a short-lived server-side record that collects proofs until the policy is met. A proof is a password, a code, an authenticator code, a recovery code, a passkey assertion or an OIDC callback. Throttling, audit events and protection against account enumeration sit in the flow engine, so each exists once.

**A session records what was proven.** It is *verified* when it holds a second proof and *unverified* when it holds one from an access point the server doesn't know. Routes and permissions say which they need, and need a verified session unless they say otherwise.

## 3. Decisions

| # | Topic | Decision | Who |
|---|---|---|---|
| D1 | Scope | Authentication, sessions, devices and authorization. No SAML | epistemer |
| D2 | Users | The app owns the user table. Auth sees users through a `Directory` interface and never stores a profile | (Claude) |
| D3 | Store | bbolt, passed in as a `*bbolt.DB` (normally cfgx's `Store().DB()`). Records are protobuf. No storage interface | epistemer |
| D4 | Flows | One engine with the verbs `Challenge`, `Prove` and `Finish`, started by `SignIn`, `StepUp`, `Recover`, `Accept` or `Enroll` | (Claude) |
| D5 | Sessions | One session model with two carriers: an opaque cookie for the web, and a bearer pair for apps | epistemer |
| D6 | Bearer | The access token is a JWT that carries the app's claims. The refresh token is opaque and rotates | epistemer |
| D7 | Liveness | The access token names its session, and every request checks that session in bbolt | epistemer |
| D8 | Claims | The app implements a `Claimer`. Auth calls it when a session is issued, at every refresh and on `Reissue` | (Claude) |
| D9 | Assurance | Sessions are verified or unverified. `Require` needs a verified session unless a requirement says `auth.Unverified` | epistemer |
| D10 | Devices | A registered device is a server-issued token. Client fingerprints are not used | (Claude) |
| D11 | Authorization | Package `auth/access`: permissions are keys declared in code; groups and memberships live in bbolt. No casbin | epistemer |
| D12 | Scoping | Limiting a permission to a resource is out of v0.1. `Can` leaves room for it | epistemer |
| D13 | CSRF | `http.CrossOriginProtection` plus `SameSite` cookies. No per-form token | epistemer |
| D14 | Modules | The core module has no WebAuthn or OIDC dependency. `auth/passkey` and `auth/oidc` are nested modules | epistemer |
| D15 | Passwords | argon2id. No composition rules, no trimming | (Claude) |
| D16 | Authenticator apps | TOTP (RFC 6238) written in the core, with recovery codes | (Claude) |
| D17 | Messages | Auth sends nothing. The app's `Sender` renders and delivers, and builds every URL | (Claude) |
| D18 | Throttling | Growing delays keyed by account, client address and the pair. No permanent lockout | (Claude) |
| D19 | Audit | Every decision is an `Event` given to the app's `Recorder` | (Claude) |
| D20 | Secrets | One master secret from config. Keys for codes, token signing and encryption at rest are derived from it | (Claude) |
| D21 | HTTP | `net/http` middleware only. No web framework | sibling convention |
| D22 | zp | Moving zp's users over is not this package's concern | epistemer |

## 4. Packages

```
auth              flows, password, codes, TOTP, recovery codes, sessions, devices, carriers, middleware
auth/access       permissions, groups, memberships
auth/authschema   the cfgx schema fragment
auth/authtest     test helpers
auth/passkey      nested module: WebAuthn, on github.com/go-webauthn/webauthn
auth/oidc         nested module: OpenID Connect, on github.com/coreos/go-oidc/v3
```

The core depends on bbolt, protobuf, `golang.org/x/crypto` (argon2), `golang.org/x/text` (normalization), cfgx (for `cfgx.Secret`), i18n and errors. i18n's ADR 0002 is the precedent for nested modules.

## 5. API

A sketch. Names can change until the interface is locked; the shape is what was agreed.

### 5.1 What the app provides

```go
type UserID string

type User struct {
	ID       UserID
	Disabled bool // may not sign in
}

type Directory interface {
	Find(ctx context.Context, login string) (User, error) // auth.ErrNoUser when unknown
	Get(ctx context.Context, id UserID) (User, error)
	Address(ctx context.Context, id UserID, ch Channel) (string, error) // where a code goes
}

type Sender interface {
	Send(ctx context.Context, m Message) error
}

type Message struct {
	Kind    MessageKind // SignInCode, RecoveryCode, RecoveryLink, Invitation, PasswordChanged, NewDevice, FactorAdded
	Channel Channel     // Email, SMS
	To      string
	User    UserID
	Code    string    // for a code
	Token   string    // for a link; the app builds the URL
	Expires time.Time
}

// Optional.
type Claimer interface {
	Claims(ctx context.Context, u User) (map[string]any, error)
}
type Recorder interface {
	Record(ctx context.Context, e Event)
}
```

```go
a := auth.New(db, cfg, dir, sender,
	auth.WithClaims(claimer),
	auth.WithRecorder(rec),
	auth.WithPolicy(policy),              // func(ctx, User) Policy
	auth.WithMethods(passkey.Method(rp), oidc.Method(google)),
)
```

`Policy` says, per user, which first factors are allowed, whether a second proof is required before any session exists, and whether an unverified session may be issued. A staff policy would refuse unverified sessions; a customer policy would allow them.

### 5.2 Flows

```go
flow, err := a.SignIn(ctx, login, auth.Device(deviceToken)) // same answer for unknown accounts
flow, err := a.StepUp(ctx, sess)
flow, err := a.Recover(ctx, login)
flow, err := a.Accept(ctx, invitationToken)
flow, err := a.Enroll(ctx, sess, method)

ch, err   := a.Challenge(ctx, flow.Token, auth.EmailCode) // sends a code, or returns passkey options, an OIDC redirect, a TOTP setup
flow, err  = a.Prove(ctx, flow.Token, auth.Password(pw))  // or auth.Code, auth.TOTP, auth.RecoveryCode, passkey.Assertion, oidc.Callback
res, err  := a.Finish(ctx, flow.Token, auth.NewPassword(pw), auth.RememberDevice())
```

```go
type Flow struct {
	Token   string
	Purpose Purpose
	Offers  []Method // what the UI may show next; empty when Finish will succeed
	Expires time.Time
}

type Result struct {
	Session       *Session
	Cookie        *http.Cookie // cookie carrier
	Access        string       // bearer carrier
	Refresh       string
	Device        string   // set when a device was registered
	RecoveryCodes []string // shown once, after the first second factor is enrolled
}
```

`a.Invite(ctx, userID) (token string, err error)` makes the invitation that `Accept` consumes.

### 5.3 Sessions and requests

```go
mux.Handle("/app/", a.Load(auth.Cookie())(app))    // attaches the session when there is one; rejects nothing
mux.Handle("/api/", a.Load(auth.Bearer())(api))

a.Require()                             // a verified session
a.Require(auth.Unverified)              // any session
a.Require(auth.Within(5 * time.Minute)) // a proof made in the last five minutes
a.Require(ac.Can(PayoutApprove))        // a permission, at the assurance it declares

sess, ok := auth.From(ctx)
sess.User, sess.Verified(), sess.Factors(), sess.Claims()

res, err    := a.Refresh(ctx, refreshToken) // new access and refresh tokens, claims recomputed
access, err := a.Reissue(ctx, sess)         // new access token now, when the app knows the claims changed
err = a.Revoke(ctx, sess.ID)
err = a.RevokeUser(ctx, userID)             // the app calls this when it disables a user
list, err := a.Sessions(ctx, userID)
list, err := a.Devices(ctx, userID); err = a.ForgetDevice(ctx, deviceID)
```

`Load` also records the client's address and user agent in the context, for throttling and events. Code that isn't serving a request sets them with `auth.WithClient(ctx, client)`.

### 5.4 Permissions

```go
var (
	PayoutApprove = access.Permission("payout.approve", "Approve payouts")
	ReportView    = access.Permission("report.view", "View reports", auth.Unverified)
)

ac := access.New(db)

ac.Can(p) auth.Requirement
ac.Check(ctx, userID, p) error // for code that isn't a route

ac.CreateGroup, ac.RenameGroup, ac.DeleteGroup
ac.Grant(ctx, groupID, p); ac.Withdraw(ctx, groupID, p)
ac.Join(ctx, userID, groupID); ac.Leave(ctx, userID, groupID)
ac.Groups(ctx); ac.GroupsOf(ctx, userID); ac.Members(ctx, groupID); access.Permissions()
```

## 6. Rules

### 6.1 Flows

- A flow is a record in bbolt, found by the SHA-256 of a 256-bit random token. It lives for a short, configured time and is deleted by `Finish`.
- `Finish` succeeds only when the user's policy is met. No other call creates a session.
- **Enumeration.** `SignIn` and `Recover` answer the same way for an unknown login. Before the first proof, `Offers` is the configured set of first factors, never the user's own. A wrong password and an unknown account do the same hashing work and return the same error. `Challenge` reports success whether or not a message was sent.
- A disabled user is refused only after a correct first proof, so the refusal doesn't reveal the account to anyone else.
- `Recover` never removes a second factor. A user who has one must prove it, or a recovery code, before the new password is set.
- `Enroll` and any change to a factor need a fresh proof (`Within`), then proof of the new factor, before anything is stored.
- Finishing `Recover`, or changing a password, ends the user's other sessions and forgets their devices. The app is sent a `PasswordChanged` message for the user.

### 6.2 Passwords

- argon2id, stored as a PHC string with its parameters. A hash made with older parameters is replaced at the next successful sign-in.
- Hashing uses a lot of memory by design, so concurrent hashes are bounded by a semaphore. Requests beyond the bound wait.
- The password is normalized to NFKC and is never trimmed. Input over 1024 bytes is refused with an error; nothing is truncated.
- `auth.CheckPassword(ctx, pw, hints...)` is the one judge of strength, and returns public errors that a form can show:
  - a minimum length from config, and no rules about character classes;
  - an embedded list of common passwords (its source and licence are for M1 to settle);
  - context words: the login, the parts of the user's addresses, the issuer name, and any hints the app passes;
  - a single repeated character, a plain sequence, a keyboard walk.
- A lookup against a breach corpus is an optional interface, out of v0.1.

### 6.3 Codes and links

- A code is decimal digits drawn uniformly from `crypto/rand`. Its length (at least 6), lifetime, number of tries and resend delay come from config.
- It is stored as HMAC-SHA256 under a derived key, over the flow, the purpose, the channel and the code. A leaked store can't be searched for six digits.
- It is valid for one flow only. A flow has one live code per channel; sending another cancels the first.
- After the configured number of wrong tries the code is burnt and the flow needs a new one.
- Sends are limited per account and per address, to bound cost and nuisance.
- A link carries a 256-bit token, stored as SHA-256, used once. The app's `Sender` builds the URL, so no URL is ever built from a request's `Host` header.

### 6.4 Authenticator apps and recovery codes

- TOTP as authenticator apps implement it: HMAC-SHA1, six digits, thirty-second steps, written in the core and tested against the RFC 6238 vectors.
- A code from the step before or after is accepted. The last accepted step is stored, so a code works once.
- The secret is 160 random bits, encrypted at rest with AES-256-GCM under a derived key, with the user's ID as additional data.
- `Challenge` in an `Enroll` flow returns the secret and its `otpauth://` URI. Drawing the QR code is the app's job. The factor is stored only after one valid code.
- Wrong codes are throttled like passwords.
- Ten recovery codes are made when the first second factor is enrolled, stored as HMACs, each used once. Making a new set cancels the old one.

### 6.5 Passkeys and OIDC

Both are nested modules that plug in as methods. Their own interface sections are written when their milestones start.

- **Passkeys.** Registration happens in an `Enroll` flow and assertion in `SignIn` or `StepUp`. The challenge lives in the flow. A passkey used with user verification makes a verified session on its own. A signature counter that goes backwards is refused and recorded.
- **OIDC.** Authorization code with PKCE, `state` and `nonce`, all kept in the flow. An identity is the pair of issuer and subject. It signs in only the user it is linked to. It is never linked by matching an email address: linking happens in an `Enroll` flow, or through an optional hook that lets the app decide at first sign-in. Each provider is marked as giving a verified session or not.

### 6.6 Sessions and tokens

- A session holds its ID, the user's ID, the factors proven and when, whether it is verified, its device, its times, the client seen at creation, and the claims.
- It has an idle lifetime and an absolute one. "Last seen" is written at most once a minute.
- Tokens are 256 random bits, and only their SHA-256 is stored.
- A token is replaced whenever the session's privilege changes: at sign-in, at step-up and at refresh. A session presented at `SignIn` is never reused.
- **Cookie carrier.** One opaque token in a `__Host-` cookie: `Secure`, `HttpOnly`, `SameSite=Lax`, path `/`. Claims stay on the server. A development setting drops `Secure` and the prefix for plain-HTTP localhost.
- **Bearer carrier.**
  - The access token is a JWT with a fixed header. It carries the issuer, audience, subject, session ID, expiry, whether the session is verified, and the app's claims under one name. Its lifetime is minutes.
  - Verification compares the header byte for byte, checks the signature, then the expiry, then reads the session. A token for an ended session is refused at once.
  - The refresh token is opaque. Each use replaces it. Presenting a replaced one ends the session and records `refresh.reused`, except within a short grace period for a client that retried on a bad network.
- **Claims** are JSON values. A sum of money should be a string, because a JSON number comes back as a float. Claims are a display cache: a debit must read the ledger, never the token.
- A disabled user is refused at `Finish` and at `Refresh`. The app ends live sessions with `RevokeUser`.

### 6.7 Verified sessions and devices

- A session is verified when its flow proved two factors, or one factor that counts as two (a passkey with user verification), or one factor from a registered device.
- `Finish` with `RememberDevice` registers the device when the flow proved a second factor. The token is 256 random bits, stored as SHA-256, with a label, its times and an expiry.
- The web keeps it in its own `__Host-` cookie. An app keeps it in the platform's secure storage and passes it to `SignIn`.
- A `StepUp` flow turns an unverified session into a verified one in place, and replaces its token.
- A new device sends the user a `NewDevice` message.
- `Within` asks for a recent proof whatever the device, for the actions that matter most.

### 6.8 Throttling

- Three counters: per account, per client address, and per pair. The account counter is kept for unknown logins too.
- After a few free failures, each further failure doubles a wait, up to a configured ceiling. A success clears the pair's counter and the account's.
- There is no permanent lockout, because anyone could use one to lock a user out.
- During a wait the flow returns `ErrTooManyAttempts` (kind `RateLimited`) and says how long.
- The client address comes from the app, which knows its proxies: `auth.WithClientAddr` is the option that tells `Load` how to read it from a request.
- General HTTP rate limiting is another library's job.

### 6.9 CSRF

`a.Load(auth.Cookie())` wraps the handler in `http.CrossOriginProtection`, which refuses unsafe cross-origin requests using `Sec-Fetch-Site` and `Origin`. Trusted origins come from config. The bearer carrier needs none. State-changing routes must not answer to `GET`.

### 6.10 Authorization

- A permission is a package-level declaration with a permanent key. It declares an i18n key `permission.<key>` with its text, the way `errors.Key` does, so an admin page shows it translated.
- A permission needs a verified session unless it is declared `auth.Unverified`.
- A user holds a permission when a group they belong to was granted it. A check is two bbolt reads.
- The built-in group `root` holds every permission, including ones declared later. It can't be deleted, and its last member can't leave.
- A grant whose key is no longer declared is ignored and listed, never deleted silently.
- `Require` with no session answers 401. With a session that lacks the permission or the assurance it answers 403, with a code a client can act on (`not_verified` starts a step-up).

### 6.11 Events

Every decision is an event: `signin.succeeded`, `signin.failed`, `code.sent`, `factor.enrolled`, `session.revoked`, `refresh.reused`, `device.registered`, `permission.granted` and so on. An event has a time, a kind, the user, the session, the client, the method and a reason. It never holds a secret. Without a `Recorder`, events go to `log/slog`.

### 6.12 Keys

One master secret of at least 32 bytes comes from config as a `cfgx.Secret`. HKDF derives a separate key for code HMACs, for token signing and for encryption at rest. A second, optional "previous" secret is accepted for verifying and decrypting, so the secret can be rotated.

## 7. Storage

- One top-level bucket, `auth`, in the app's bbolt file. Under it: sessions, an index of sessions by user, refresh tokens, flows, credentials by user, indexes for OIDC identities and passkey IDs, devices, throttle counters, and `access` (groups, members, grants).
- Records are protobuf.
- Reads use their own read transaction and no cache.
- Expired flows, codes, sessions and counters are removed by `a.Sweep(ctx)`, which the app schedules.
- Two consequences to state in the README: an app runs as one process, as it already does with cfgx's store; and the bbolt file now holds credentials, so it is backed up like the database.
- A user created in the app's database and a credential set in bbolt are not one transaction. The order is: create the user, commit, then run the `Accept` or `Enroll` flow. A user left without a credential signs in through an invitation or recovery.

## 8. Config, errors and labels

- **Config.** `auth.Config` is an interface of getters. `authschema.Group()` returns the cfgx group, pinned with `GoName("Auth")`, so every app declares the keys the same way. Lifetimes are `dsl.Duration`. The keys cover: the issuer name; the master secret and the previous one; session idle and absolute lifetimes; access token lifetime and refresh grace; flow, code, link, invitation and device lifetimes; code length, tries and resend delay; password minimum length and argon2 cost; throttle thresholds; cookie names; trusted origins. Policy values such as the minimum length can be `Mutable`. Secrets can't.
- **Errors.** Every error a person can see is an `errors.Key` under `errors.auth.<name>` with a kind: `ErrBadCredentials` and `ErrNoSession` (Unauthenticated), `ErrNotVerified`, `ErrStale`, `ErrForbidden` and `ErrUserDisabled` (Forbidden), `ErrTooManyAttempts` (RateLimited), `ErrBadCode`, `ErrFlowExpired` and the password errors (Invalid).
- **Labels.** Methods, message kinds and event kinds that an admin page shows get i18n keys declared in code. This package generates no code, so it writes no `labels/v1` file.

## 9. Tests

`authtest.New(tb)` gives an `*auth.Auth` on a temporary bbolt file with a fake clock, an in-memory `Directory`, cheap argon2 parameters and a `Sender` that keeps what it was given (`authtest.LastCode(login)`).

Each row of §1 becomes an acceptance test. Among them:

- a code is refused after the configured tries, in another flow, and after its lifetime;
- a password of 1024 bytes in any script signs in after being set;
- an unknown login and a wrong password give the same error and call the hash once each;
- a device token for one user doesn't verify a session for another, and a made-up one verifies nothing;
- an access token is refused as soon as its session is revoked;
- a replayed refresh token ends the session;
- a route without `auth.Unverified` refuses an unverified session;
- a TOTP code is refused the second time;
- `Recover` with a second factor enrolled doesn't finish on the emailed proof alone.

## 10. Open questions, each with a default

These are **(Claude)** decisions that deserve a look before the lock.

1. **`UserID` is a string.** An app with integer IDs formats them. Default: string.
2. **The access token is signed with HS256 under a derived key.** Only the app verifies it, so one secret is enough and there are no key files. If another service must verify tokens, the answer is Ed25519 with a key file. Default: HS256.
3. **The JWT encoder is written in the core.** The format is fixed (one algorithm, one header), so it is about sixty lines with no negotiation to get wrong. The alternative is `golang-jwt/jwt/v5`. Default: written in the core.
4. **A registered device makes a session verified.** That is how zp treats it. The stricter reading is that only a second factor in this session does. Default: a device verifies; `Within` covers the worst actions.
5. **An OIDC identity can create a user at first sign-in** only through an optional hook the app implements. Default: the hook exists; without it, unlinked identities are refused.
6. **Flow starters are five functions**, not one `Begin` with a purpose. Default: five.

## 11. Out of v0.1

SAML; resource-scoped permissions; API keys for machine clients; a breach-corpus lookup; drawing QR codes; SMS or email delivery; an HTTP handler set or UI (the app writes its handlers over the flow verbs); moving zp's users over.

## 12. Risks to check early

- **bbolt has one writer.** A flood of failed sign-ins writes a counter each time, at about 2.4 ms a write with fsync, and holds up other writers of the same file (settings, translations). The address counter may need an in-memory check in front of it. Spike S1 measures this.
- **argon2 memory.** The cost that is safe on the target host, and the right bound on concurrent hashes, come from spike S2, not from a table.
- **Nested modules** with a `replace`-free release flow were worked out for i18n. Spike S3 confirms the same layout holds for `auth/passkey` before any core API depends on it.

## 13. Roadmap to v0.1.0

- **M0. Foundations.** Repository, CI, ADR 0001, `docs/interface.md` for epistemer to lock, spikes S1–S3.
- **M1. Sign-in.** `Directory`, the flow engine with `SignIn` and `StepUp`, passwords and `CheckPassword`, throttling, sessions, the cookie carrier, `Load` and `Require`, events, `authschema`, errors, `authtest`.
- **M2. Codes.** Codes and links, `Recover`, `Invite` and `Accept`, devices, verified and unverified sessions, the notice messages.
- **M3. Bearer.** The access token, `Claimer`, rotating refresh tokens, `Reissue`.
- **M4. Authenticator apps.** `Enroll`, TOTP, recovery codes.
- **M5. Access.** `auth/access` and `Can`.
- **M6. Release.** README, a skill at `~/.claude/skills/auth/`, `v0.1.0`.

After v0.1.0: `auth/passkey`, then `auth/oidc`, each with its own interface section and milestone.
