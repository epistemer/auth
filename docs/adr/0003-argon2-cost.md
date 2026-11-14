# ADR 0003: argon2id at 64 MiB, two passes, bounded (spike S2)

| | |
|---|---|
| Status | Accepted |
| Date | 2026-11-14 |
| Roadmap item | M0.3 |
| Deciders | Claude, as owner |

## Context

Passwords are hashed with argon2id (interface D15). Its cost is memory and
passes. The defaults had to be picked from a measurement, and the spike had to
say what happens when many sign-ins hash at once.

## Options

Measured on the development machine (4 cores), `golang.org/x/crypto`
`v0.59.0`, best of three for a single hash.

| Parameters | One hash | 4 at once | 16 at once |
|---|---|---|---|
| 19 MiB, 2 passes, 1 thread (OWASP's minimum) | 39 ms | 99 ms | 447 ms |
| 46 MiB, 1 pass, 1 thread (OWASP's alternative) | 87 ms | 250 ms | 470 ms |
| 64 MiB, 3 passes, 4 threads (RFC 9106's second choice) | 96 ms | 573 ms | 1,972 ms |
| 64 MiB, 3 passes, 1 thread | 248 ms | 689 ms | 1,779 ms |
| **64 MiB, 2 passes, 1 thread** | **132 ms** | **242 ms** | **921 ms** |
| 128 MiB, 2 passes, 1 thread | 264 ms | 500 ms | 2,401 ms |

Sixteen hashes at once at 64 MiB took the process past 2 GiB of memory from
the operating system. Unbounded, a burst of sign-ins is a way to exhaust
memory.

## Decision

- Defaults: 64 MiB, 2 passes, 1 thread. That is well above OWASP's minimum and
  costs about 130 ms here.
- Concurrent hashes are bounded by a semaphore. The default bound is the
  number of CPUs; requests beyond it wait. Peak memory for hashing is then
  the bound times the memory setting (256 MiB on this machine).
- Memory, passes and the bound are config keys (interface §4.8). The
  parameters are stored with each hash, and a hash made with other parameters
  is replaced at the next successful sign-in.

## Consequences

- An operator on a smaller host lowers the memory or the bound, not the code.
- The wait behind the semaphore is a second, natural throttle on sign-in
  floods. It also means a flood slows honest sign-ins, so throttling
  (interface §5.8) refuses a waiting account before it reaches the hash.
- The numbers are from one machine. The README says to measure on the target
  host, and M1 ships a benchmark that prints this table.
