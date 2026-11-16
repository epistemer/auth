# Review 0016: M5, auth/access

| | |
|---|---|
| Date | 2026-11-16 |
| Under review | The M5 diff, with interface §4.7, §5.10, §4.4's `Require` and §7's permission lines |
| Reviewer | Gemini 4 Argon (High) through agy, about 112k tokens |
| Triage | Claude |

Six findings, all accepted.

| # | Finding | Severity | Triage |
|---|---------|----------|--------|
| 1 | In `auth.Check`, one requirement naming its level suppressed the Verified default for every requirement on the route, and the named level was never enforced by `Check` | Critical | **Accepted.** A `Level` given outright decides; otherwise Verified holds unless every requirement names its own, and each named level is enforced by `Check` too. Tests: a permission declared `Unverified` beside a requirement with no level, and a requirement claiming Verified it doesn't check |
| 2 | `Grant` took any handle, so a zero `Perm` wrote an empty key and an undeclared one could grant a real key | Major | **Accepted.** Only the handle `Permission` returned grants or withdraws |
| 3 | `Can` of an undeclared handle reported `Unverified`; its `T` panicked | Major | **Accepted.** Held to Verified; `T` is nil-safe; `Can` panics at once on a nil `Access` |
| 4 | Tests that would pass with their rule broken: a deleted group's grants and memberships, `RemoveUser`'s atomicity whatever the IDs drawn, `Stale` beside a declared grant, 403s through `WithReject`, `root` after refused changes | Major | **Accepted** |
| 5 | A test declared a permission and failed under `-count=2` | Minor | **Accepted.** It forgets it after itself |
| 6 | `Leave` and `Withdraw` took a group that doesn't exist; `leave` left a reverse entry without its member | Minor | **Accepted** |

Mutation checks: each of 9 rules of the first pass and 8 of the fixes,
removed in turn, fails a test, but two equivalent: deleting a group's
reverse index entries (IDs are never reused, and every reader skips a group
that's gone), and holding an undeclared handle to Verified (`Verified` is
`Level`'s zero value).
