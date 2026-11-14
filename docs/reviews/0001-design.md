# Review 0001: the design, before the lock

| | |
|---|---|
| Date | 2026-11-14 |
| Under review | [interface.md](../interface.md) (draft) and ADRs [0001](../adr/0001-one-flow.md)–[0004](../adr/0004-methods-as-modules.md). No code exists yet |
| Reviewer | Gemini 4 Hydrogen (High) through agy, about 72k tokens. Argon was cooling down for seven hours |
| Triage | Claude |

Fifteen findings: eleven accepted, four accepted in part. Every change is in
the interface, and its API was compiled again as stubs with the spike's
passkey and OIDC methods.

Five of the changes alter what an app writes, so they are marked for
epistemer in the interface's decisions (D25, D26) or listed here: `SignIn`
takes the carrier and `Finish` doesn't; `Recover` and `Accept` make no
session; the first methods moved from `Policy` to `WithFirst`; `Revoke` and
`ForgetDevice` take the user; `Flow` gained `Verified`, `Write` and
`FlowToken`.

| # | Finding | Severity | Triage |
|---|---------|----------|--------|
| 1 | `Enroll` and `RemoveFactor` needed only a fresh proof of any method. With a password alone, from an unverified session or one a device verified, an attacker could remove or replace the second factor | Critical | **Accepted.** They need a verified session, and for a user with a second factor the fresh proof must be of a second method (§5.1.9) |
| 2 | The rules had auth keeping the flow token and rotating the device token in cookies, but no flow verb could write one, and a session didn't know its carrier | Critical | **Accepted.** `Flow.Write` and `FlowToken` carry the flow token; the device token is replaced only by `Finish` and returned in `Result`; a session remembers its carrier (§4.3, §5.1.11–12, §5.7.5) |
| 3 | An access token issued before a step-up kept working after it and gained the session's new status | Critical | **Accepted in part.** A session has a generation that a step-up raises, and the token carries it (§5.6.3, §5.6.6). Tokens from before a `Refresh` or `Reissue` keep working until they expire: their claims are a display cache, and requests in flight shouldn't fail (§5.6.7) |
| 4 | Throttling read the counters, then verified, then wrote. Concurrent guesses all read zero, which defeated `code.tries`, the TOTP replay rule and the bound on hashing | Critical | **Accepted.** An attempt is counted before it is checked, in one write transaction (§5.8.3, §5.3.4, §5.4.2). No in-memory state is needed |
| 5 | The per-login wait let anyone keep a user out; a login spelled differently got its own counter; decay was undefined | Critical | **Accepted in part.** Counters key on the user's ID or the normalized login; `throttle.window` defines decay; a registered device is held to the pair's counter only (§5.8.1, §5.8.5–6). What remains is stated in §5.8.7: a user with no registered device can be slowed up to the ceiling |
| 6 | A code sent to an address counted as the second proof for everyone, so a compromised mailbox could recover an account past TOTP | Major | **Accepted.** Once a factor is enrolled, a code to an address is no longer a second proof, and two proofs through one address count as one (§5.7.2, D26) |
| 7 | `refresh.grace` couldn't be implemented: the successor is stored only as a hash, so a retry couldn't be given it | Major | **Accepted.** The successor is kept for the grace period encrypted under a key derived from the replaced token (§5.6.8) |
| 8 | `Accept` and `Recover` could never be ready under the default policy | Major | **Accepted,** by a simpler rule than the one proposed: they set the password and make no session (§5.1.7–8, D25). Recovery is then never a way to sign in |
| 9 | `Ready` hid whether the session would be verified, so an app following the example never offered a second factor under `AllowUnverified` | Major | **Accepted.** `Flow.Verified`, and the example asks while it is false and something is on offer (§4.3, §6.2) |
| 10 | Enumeration through the per-user first methods, `SentTo`, the hourly limit, and a user with no password | Major | **Accepted.** `WithFirst` is global; `SentTo` is empty before the first proof; limits are silent; a missing password costs one hash (§4.2, §5.1.3–5) |
| 11 | A second rotation of the secret lost authenticator secrets and recovery codes | Major | **Accepted.** `Rekey`, and re-encryption on use; recovery codes are 80 bits stored as SHA-256 and don't use the secret (§5.12, §5.4.6) |
| 12 | Token verification didn't check `iss`, `aud` or that `sub` is the session's user; `Reissue` didn't refuse a disabled user | Major | **Accepted** (§5.6.6, §5.6.10) |
| 13 | An unlinked identity had no way to reach the app; a credential key could be stored over another user's | Major | **Accepted in part.** The key rule is §5.5.4. How an app learns of an unlinked identity is left to the OIDC amendment: adding a field to `Flow` is compatible (§5.5.5) |
| 14 | A route loaded with both carriers refused bearer calls; sign-in routes weren't shown behind the check; `Follow` on a `GET` spent the link | Major | **Accepted.** The check skips requests with a bearer header and covers requests with no session; `Follow` and `Accept` spend nothing (§5.9, §5.3.6, §6) |
| 15 | `Revoke` and `ForgetDevice` by ID alone; `DeleteUser` against `root`'s rule; a failed `Finish` deleting the flow; missing tests | Major | **Accepted in part.** The first three are §4.4, `RemoveUser` in §4.7 and §5.1.1. Of the tests listed, all were added except one for the carrier binding, which the type of `Finish` no longer allows to go wrong |
