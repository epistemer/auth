# Review 0024: M8.0, the OIDC draft

| | |
|---|---|
| Date | 2026-11-17 |
| Under review | [interface-oidc.md](../interface-oidc.md) and [ADR 0009](../adr/0009-oidc.md) as first drafted, with excerpts of the locked interface (§4.9, §5.5, §5.7, §5.8, §5.13.11, A22, A24). Nothing is implemented |
| Reviewer | Gemini 4 Hydrogen (XHigh) through agy, about 93k tokens. Argon is out of quota; nothing waits for one. The review ran in a scratch folder holding only the draft, the ADR and the excerpts |
| Triage | Claude |

Twelve findings, all accepted, three of them in part. The draft was
rewritten; the version under review is in git history.

| # | Finding | Severity | Triage |
|---|---------|----------|--------|
| 1 | `Callback(query)` can't name its method when an app has several providers, and a callback could be proved as another provider's | Critical | **Accepted.** O5 is now `Callback(provider, query)`; each provider has its own route |
| 2 | Discovery's endpoints unchecked (SSRF, a `javascript:` authorization URL), and only the exchange bounded | Critical | **Accepted.** §5.14.2: the document's issuer must match, its endpoints must be https with no user; one client with a timeout, no redirects and a 1 MiB cap serves discovery, keys and the exchange |
| 3 | The sign-up hook inside `Prove` contradicts §5.5.8 and the one-transaction rule, and leaves orphan users when a later check refuses | Critical | **Accepted.** O6 is now `Flow.Unlinked` and `Link`; §5.5.8 is amended for an unlinked identity's credential; the hook is the alternative |
| 4 | "New to auth" missed recovery codes, devices, ended sessions, invitations under way; the example used an unverified email; `ResetFactors` would unlink a passwordless user's only way in | High | **Accepted in part.** §5.14.7 checks all of those, and says what the engine can't see (a pre-provisioned account); the example checks `EmailVerified`; O8 is now `Identities` and `Unlink`, which refuses the last way in, and `ResetFactors` leaves identities |
| 5 | Discovery only in `Challenge` fails a callback on another instance or after a restart; concurrent first calls; cached failures | High | **Accepted.** Lazily in `Start` or `Verify`, coalesced, only successes cached |
| 6 | Callback and token checks: `azp` only with several audiences, no `iat`, go-oidc's own clock, `error` read before `state`, `iss` optional where the provider promises it, duplicate parameters | High | **Accepted.** §5.14.3's order, duplicates refused, `iss` required when discovery says so, `azp` whenever present, `iat`, `MethodInput.Now` |
| 7 | Races: two callbacks signing up one identity, `Enroll` finding another's identity | High | **Accepted.** A collision at `Link` is `duplicate`; `Enroll` leaves `User` empty so rule 10 answers alike |
| 8 | "§5.5.9, replaced" dropped the per-flow caps; NAT lockout through the shared address counter | High | **Accepted in part.** Only the first sentence is replaced and the caps stay. The shared counter is kept and documented, as for passwords |
| 9 | A provider outage or a wrong client secret answered as `ErrBadCredentials`, burning counts | Medium | **Accepted.** 5xx, 429, unreachable and `invalid_client` are the method's own failures; public clients send no basic auth |
| 10 | `issuer \0 subject` past 1023 bytes; control characters in `sub` | Medium | **Accepted.** The issuer is at most 767 bytes; `sub` without control characters; each method's identities its own |
| 11 | A stale session at a two-factor provider meets `Within`; an identity's mailbox and a code to it make two factors | Medium | **Accepted.** `max_age=300` and `auth_time` with `two_factors`; new O9, `MethodResult.Address`, makes such a pair one factor |
| 12 | Gaps the implementation would guess: RSA sizes, config read once, scope tokens, query size, PKCE encoding, the proof printing, labels, error checks in the example | Low | **Accepted in part.** All written into §4.12 and §5.14. O3 stays getters (the reviewer preferred a struct); both are in the table for epistemer |
