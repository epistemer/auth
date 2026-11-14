# ADR 0002: Throttle counters are written with `Batch` (spike S1)

| | |
|---|---|
| Status | Accepted |
| Date | 2026-11-14 |
| Roadmap item | M0.3 |
| Deciders | Claude, as owner |

## Context

Every failed sign-in writes a counter (interface §5.8). bbolt has one writer
at a time, and a commit with fsync takes milliseconds. The file is shared
with cfgx's settings and i18n's translations. The question was whether a
flood of failed sign-ins would starve those other writers.

## Options

Measured on the development machine (4 cores, ext4 on a SATA SSD, bbolt
`v1.5.0`), four seconds a row. Each flood worker bumps one counter per
"failure". Alongside, one other writer does an `Update` every 100 ms, as a
settings edit would, and one reader does a lookup every millisecond.

| How the counter is written | Workers | Flood, writes/s | Other writer, p50 | Other writer, p99 | Read, p50 |
|---|---|---|---|---|---|
| no flood | 0 | – | 3.2 ms | 6.0 ms | 8 µs |
| `db.Update` each | 1 | 411 | 5.9 ms | 13 ms | 7 µs |
| `db.Update` each | 16 | 400 | 41 ms | 50 ms | 8 µs |
| `db.Update` each | 256 | 466 | 640 ms | 643 ms | 8 µs |
| `db.Batch` each | 16 | 1,032 | 2.2 ms | 9.5 ms | 10 µs |
| `db.Batch` each | 256 | 12,800 | 2.6 ms | 15 ms | 11 µs |
| `db.Batch` each | 2,000 | 41,500 | 38 ms | 57 ms | 10 µs |

- **`db.Update` per failure** tops out near 400 writes a second, and the other
  writer queues behind every one of them.
- **`db.Batch` per failure** lets concurrent callers share a commit. Throughput
  grows with the number of callers, and the other writer barely notices until
  thousands write at once.
- **An in-memory counter in front of bbolt** would also work, but it adds a
  second source of truth and isn't needed at these numbers.

Reads are unaffected in every row.

## Decision

Counters, and a session's "last seen", are written with `db.Batch`. Writes
that must be alone in their transaction (issuing a session, storing a
credential) use `db.Update`.

## Consequences

- A `Batch` function may run more than once, so it must depend only on what
  it reads in its own transaction.
- An attempt is counted before it is checked: the function adds one to the
  counters and decides, in the same transaction, whether the attempt may go
  on (interface §5.8.3). Reading the counters first and writing them after
  the check would let concurrent attempts all read zero
  ([review 0001](../reviews/0001-design.md), finding 4).
- A failed sign-in waits up to bbolt's batch delay (10 ms by default) before
  it answers. That is small beside the password hash.
- No in-memory limiter is built. If an app sees thousands of concurrent
  failures, general rate limiting in front of the app is the answer
  (interface §5.8).
