# ADR 0007: How the throttle counters count

| | |
|---|---|
| Status | Accepted |
| Date | 2026-11-15 |
| Roadmap item | M1.4 |
| Deciders | Claude, as owner |

## Context

Interface §5.8 sets the rules: three counters (the user's, the client
address's, the pair's), an attempt counted before it is checked in one
transaction, waits that double after `throttle.free` failures, a success
that clears the user's and the pair's counters, and decay after
`throttle.window`. [ADR 0002](0002-throttle-writes.md) chose `db.Batch`.
Writing the code raised questions that the rules didn't settle.

## Decisions

1. **One transaction decides and counts.** `count` reads each counter and
   decays it, all in one `Batch`. If any is in a wait, the attempt is
   refused and nothing is written; `RetryAfter` gives the longest wait.
   Otherwise each counter gains one, `last` and the wait for the new count
   are set, and the counters are written before the proof is checked
   (amendment A7, on epistemer's choice; the first draft counted refused
   attempts too, as §5.8.3 then said).
2. **The wait.** After `n` failures it is none while `n < throttle.free`,
   then `1s << (n - free)`, capped at `throttle.ceiling`; past 30 doublings
   it is the ceiling, before the shift could overflow (review 0005). With the default
   five, the fifth failure starts a one-second wait, so the sixth attempt
   is refused; the next failure let through, once the wait is over, doubles
   it. A wait is never shortened by a later failure.
3. **What success does to the address.** The address's counter counts
   failures (§5.8.2), but an attempt is counted before anyone knows it will
   fail. So a success takes back its own count. If no other attempt touched
   the counter since (the counter's `seq` is the one this attempt wrote), it
   goes back to how the attempt found it, wait included, and a counter left
   empty is deleted. Otherwise the count drops by one and the wait shrinks
   to what the remaining count would set from now, so a wait a failure set
   stays and one this attempt's count set ends. A success older than
   `throttle.window` takes nothing off, since its counter may have started
   again without it. A success never clears the address's counter, so a
   stranger can't reset it by signing in to an account of their own
   (amendment A6). Only an accepted proof is a success: a disabled user's
   right password stays counted.
4. **Decay.** A counter with no attempt for `throttle.window` starts again
   from zero, but not while its wait is in force. Without that, a window
   shorter than the ceiling would end a wait early.
5. **Keys.** A counter's key is its kind and the hex SHA-256 of what it
   counts, each part prefixed with its length and labelled: `user` and the
   user's ID, or `login` and the normalized login's hash; `addr` and the
   address; `pair` and both. So an ID and a login never share a counter, the
   store holds neither logins nor addresses, and keys hold no zero byte.
6. **Addresses.** An IPv4 address mapped into IPv6 is the IPv4 address. An
   IPv6 address is counted by its /64, the block one subscriber is usually
   given; counting single IPv6 addresses would give one attacker billions
   of counters (amendment A6). A request with no address is counted against
   the user alone (§5.8.9).
7. **Devices.** A request that presents a registered device is counted
   against the pair alone (§5.8.6). Without an address there is no pair, and
   it is counted against the user. A success clears the user's and the
   pair's counters whether or not the attempt was counted against them
   (§5.8.5). Devices arrive with M2.3, which tests this end to end.
8. **What is throttled.** Every password proof, in `SignIn` and `StepUp`
   alike. Codes, TOTP and modules' methods join with their milestones.

## Consequences

- `Counter` gains `seq`, bumped on every write. Adding a field to a protobuf
  message keeps the layout compatible.
- A known oracle remains. Two logins that resolve to one user share that
  user's counter, so someone who fails five times on one of them, then tries
  the other from a fresh address, learns whether they are the same account.
  This follows from keying on the user's ID (§5.8.1), which stops anyone from
  getting extra tries by using another login. Doing both would need one key
  for logins that resolve and one for those that don't, and that brings back
  the extra tries.
- A refused attempt changes nothing, so an address in a wait can't push
  any other counter, and hammering during a wait doesn't lengthen it. A
  guesser gains nothing from that: every guess is counted before it is
  checked, and a patient one waits each wait out either way. An address
  that many people share (an office, a mobile carrier's NAT) is still
  slowed by everyone's failures: under the default settings, fifteen
  failures within the hour make everyone there wait up to the ceiling.
- A crash between `count` and the check leaves the attempt counted as a
  failure. That is the strict side.
