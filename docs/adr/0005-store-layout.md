# ADR 0005: The store's layout, records and derived keys

| | |
|---|---|
| Status | Accepted |
| Date | 2026-11-14 |
| Roadmap item | M1.1 |
| Deciders | Claude, as owner |

## Context

Interface §8 fixes bbolt and protobuf and says the layout is private. M1.1
had to settle the buckets and their keys, the records, how they are
generated, and how keys come from the master secret (§5.12).

## Decision

**Buckets**, under the top-level bucket `auth`:

| Bucket | Key | Value |
|---|---|---|
| `sessions` | session ID | `Session` |
| `session_tokens` | SHA-256 of the session token | session ID |
| `sessions_by_user` | user `\0` session ID | empty |
| `refresh` | SHA-256 of the refresh token | `Refresh` |
| `flows` | SHA-256 of the flow token | `Flow` |
| `credentials` | user `\0` method `\0` credential key | `Credential` |
| `credential_keys` | method `\0` credential key | user |
| `devices` | device ID | `Device` |
| `device_tokens` | SHA-256 of the device token | device ID |
| `devices_by_user` | user `\0` device ID | empty |
| `links` | SHA-256 of the link or invitation token | `Link` |
| `throttle` | kind `\0` key | `Counter` |
| `meta` | `version` | the layout version, one byte |

- **IDs and tokens are separate.** A session or device has a 128-bit random
  ID that an app may show and pass to `Revoke` or `ForgetDevice`, and a
  256-bit token that only the carrier holds. Records are found by ID; the
  token's SHA-256 indexes the ID. So an ID in a URL or a log reveals nothing
  that signs anyone in, and replacing a token doesn't change the ID.
- **Keys join parts with a zero byte**, and a part containing one panics, so
  no key can pose as another. User IDs, method names and hashes never hold
  one; a `UserID` that did would be refused at the API (D22 already limits
  it).
- `auth/access` gets its own top-level bucket, `auth_access`, written in M5.
- `Init` creates the buckets and writes the layout version. A store whose
  version is newer than the code's is refused, so an old binary never writes
  records it doesn't understand.

**Records** are in `internal/storepb/records.proto`. Times are Unix
nanoseconds. No field holds a password, a code, a token or a key as it
travelled. Encoding is deterministic.

**Generation** follows i18n's ADR 0001: `protoc` 3.21.x with
`protoc-gen-go` pinned by a `tool` directive, the output committed, and a CI
step that regenerates and fails on a difference other than protoc's version
line.

**Derived keys.** HKDF-SHA256 over the master secret, with the salt
`github.com/epistemer/auth` and the info `auth/v1/<purpose>`, gives one
32-byte key for each of `codes`, `sign` and `seal`. The strings are
permanent.

- A MAC frames each part with its length, so `("ab","c")` and `("a","bc")`
  differ. `Verify` computes the MAC under both the current and the previous
  key whatever the first gives, so its timing doesn't tell which matched.
- Sealing is AES-256-GCM with a random nonce, bound to additional data (the
  user's ID for an authenticator secret). A sealed value starts with a format
  byte. `Open` tries the current key, then the previous one, and says when
  only the previous one worked, so the caller seals it again.
- The refresh token's successor (§5.6.8) is sealed under a key derived from
  the replaced token itself, with its own HKDF info, so the store alone can't
  produce it.

**Test dependency.** `github.com/google/go-cmp` compares records in tests. It
is test-only, as in cfgx.

## Consequences

- Rotating the secret twice without `Rekey` in between loses sealed
  authenticator secrets. A test shows it, and §5.12.3 is why `Rekey` exists.
- Interface §8 named a draft list of buckets; amendment A2 points it here.
- A maintainer needs `protoc` 3.21.x to change the records.
