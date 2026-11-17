# Review 0020: M7.0, the passkey draft

| | |
|---|---|
| Date | 2026-11-17 |
| Under review | [interface-passkey.md](../interface-passkey.md) and [ADR 0008](../adr/0008-passkeys.md) as first drafted, with excerpts of the locked interface (§4.1, §4.9, §5.1, §5.5, §5.7, §5.8, A17, A19, A20). Nothing is implemented |
| Reviewer | Gemini 4 Hydrogen (XHigh) through agy, about 94k tokens; the fixes checked by Gemini 4 Hydrogen (High), about 59k. Gemini 4 Argon (High) was planned, but its quota, and Argon (Medium)'s, was exhausted for about 113 hours; under the ownership terms nothing waits for a quota, so the strongest Gemini available ran. The review ran in a scratch folder holding only the draft, the ADR and the excerpts |
| Triage | Claude |

Fourteen findings: twelve accepted, two accepted in part. The check of
the fixes raised nine points: eight accepted, one declined again.

## The review

| # | Finding | Severity | Triage |
|---|---------|----------|--------|
| 1 | With attestation `none` a client can enroll any credential ID; the draft checked §5.5.4 only at `Finish` and not against the same user, so a re-enrollment could overwrite a passkey's key, counter and backup flag, and two users racing for one ID left a wedged flow | Critical | **Accepted.** §5.5.10: an ID anyone holds, the same user included, is refused at `Prove` and again at `Finish`; a refused `Finish` drops the pending credential and leaves the flow offering the method again |
| 2 | Making every passkey proof a second method lets one synced passkey remove the user's app, enroll a factor and register a device; and the generic rule made every module credential, OIDC's included, a factor | Critical | **Accepted in part.** Generic modules no longer become factors: §5.5.11 leaves it to each module's section. Declined for passkeys: locked §5.7.2 already names a passkey among the second methods; a UV passkey is two factors (NIST SP 800-63B counts synced passkeys at AAL2); gating on device-bound passkeys would refuse most passkeys users have; and every factor change already sends `MsgFactorAdded` or `MsgFactorRemoved` (§5.1.10) |
| 3 | A nil user before the first proof broke `Enroll` and `StepUp`, which have no proof of their own when `Challenge` runs | Critical | **Accepted.** Only flows started without a session get no user before their first proof (§4.9) |
| 4 | The counter rule let a presented zero pass against a stored ten, and stored the zero | High | **Accepted.** §5.13.6 follows WebAuthn §7.2: either above zero means the presented one must be greater |
| 5 | Address-only throttling was hard-coded for every module, broke §5.8.6, left `Challenge` and one flow free to hammer, and didn't take back a count on a failure of the method's own | High | **Accepted in part.** Modules get every counter of a kind of their own by default (§5.5.9); a passkey counts on the address, or a registered device's pair (§5.13.11); a flow takes ten `Challenge`s and five refused proofs per method; failures of the method's own take the count back (§5.5.6). The shared-address lockout as such was declined: it is the address counter passwords have (A20), and §5.8.6 now applies |
| 6 | Keeping go-webauthn's allowed credential list in the flow's 4 KiB state fails for a user with many or long IDs; rule 8 checked only `Credentials`, which is empty in a discoverable sign-in | High | **Accepted.** The state keeps no credential list (§5.13.9); a user holds at most 20 passkeys; the engine checks the credential the proof used, wherever `Verify` got it (§5.5.8); `Lookup` of a gone user is defined |
| 7 | "Every refusal is `ErrBadCredentials`" contradicted `ErrUserDisabled`, `ErrFlowExpired` and `ErrCannotVerify` | High | **Accepted.** §5.5.6 gives the order and the answer of each step |
| 8 | `SignIn(ctx, "", c)` meaning "no login" makes a blank form field switch modes, and changes what v0.1.0 answers for an empty login | High | **Accepted.** P6 now recommends a starter of its own, `SignInWithout`; `SignIn` with an empty login is unchanged |
| 9 | P3's "unset domain: no passkeys" contradicted `passkey.New` refusing an empty domain; `New`'s checks of origins and the domain had gaps; `crossOrigin` relied on the library | High | **Accepted.** P3 now recommends the opt-in fragment `authschema.Passkey()`; §4.11 spells out `New`'s checks; §5.13.1 refuses `crossOrigin: true` itself |
| 10 | `Refuse`'s reason, or go-webauthn's error text (which can hold the challenge or credential bytes), could reach an error or a log | Medium | **Accepted.** `Refuse`'s `Error()` is fixed, the reason matches a pattern, `Prove` answers plain `ErrBadCredentials`, and no library text reaches an error, a log line or an event; the reasons list is complete |
| 11 | go-webauthn wraps options in `publicKey`, which `parse…FromJSON` rejects; an empty `User.Name`; the record's encoding | Medium | **Accepted.** P4 says unwrapped; an empty name is the method's failure; `Credential.Data` is a versioned protobuf record of the module's own |
| 12 | The five-minute expiry can't be tested without a clock | Medium | **Accepted** as `MethodInput.Now`, the engine's clock (P10), rather than a module option |
| 13 | Edge cases: a discoverable response without a user handle, attestation the library can't check, backup state without eligibility, an empty credential ID, transports, the label | Medium | **Accepted.** Each is a rule of §5.13 with a test in §7 |
| 14 | `WithFirst` naming an absent method; options on `passkey.New`; `passkeytest` choosing among passkeys | Low | **Accepted in part.** `WithFirst`'s check is stated; one passkey per test authenticator. Options on `New` declined: P10 covers the clock |

On the API choices the reviewer agreed with P2, P4, P5, P7, P8 and P9, and
preferred the alternatives of P1 (`passkey.Name`, so the core names no
module), P3 and P6. P3 and P6 changed. P1 didn't: §5.7.2 already names
passkeys in the core, and apps then compare `Offers` with `auth.Method…`
constants only; both sides are in the draft for epistemer.

## The check of the fixes

| # | Point | Triage |
|---|-------|--------|
| 1 | `SignInWithout` read the device token only after the proof, so §5.8.6 couldn't hold and a user behind an address in a wait couldn't sign in from their own device | **Accepted.** The token is read at the start for throttling; it stands for nothing if the proof names another user |
| 2 | The order in §5.5.6 left out the duplicate check, and said a proof in an `Enroll` stores the credential, against §5.1.9 | **Accepted.** Rule 10 is checked in the transaction; the new credential waits in the flow for `Finish`; a refused `Finish` is specified |
| 3 | An attempt was counted before the flow, its state and the caps were checked, and the state wasn't spent on a failure of the method's own | **Accepted.** Those checks come first and count nothing; the state is spent whatever happens |
| 4 | "The credential the proof used" couldn't be known from `MethodResult` | **Accepted.** An accepted proof names it in `MethodResult.Credential`, updated or not (§4.9) |
| 5 | Concurrent enrollments passed the limit of 20 | **Accepted.** `Finish` checks it again |
| 6 | Finding 2's decline relied on a strawman: a fresh proof of another method for factor changes would be less drastic than gating on device-bound passkeys | **Declined again.** It would make §5.1.9 stricter for passkeys than the lock asks, and a user who signs in by passkey alone would need a password to add an app. The notices of §5.1.10 stay the mitigation. It can be revisited without API change |
| 7 | The label's default and length unit weren't in §5.13; backup state without eligibility at registration was ambiguous | **Accepted** |
| 8 | A failure of the module's own could still carry library text | **Accepted.** No library text in any error the module returns |
| 9 | `https://localhost` as the default origin never matches local development; a second `Create` in `passkeytest` | **Accepted.** Origins are required with the domain `localhost`; a second `Create` fails the test |
