# ADR 0006: Password strength by zxcvbn's estimate, its lists embedded

| | |
|---|---|
| Status | Accepted |
| Date | 2026-11-14 |
| Roadmap item | M1.2 |
| Deciders | epistemer chose zxcvbn over a plain list; Claude, as owner, the rest |

## Context

Interface §5.2.4 judged a new password by its length, an embedded list of
common passwords, the user's own words and a few trivial patterns. All but
the hint check judged the password as a whole. `P@ssword2024`,
`jennifer1987` and `qwertyuiop2024` pass that kind of check unless the list
holds them exactly, and a list can't hold every way of combining weak pieces.

zxcvbn (Dan Wheeler, Dropbox; USENIX Security 2016) estimates the guesses an
attacker needs. It finds every guessable piece of a password: ranked
dictionary words, also reversed and in l33t, the user's own data, keyboard
walks, repeats, sequences, years and dates. Then it finds the cheapest way to
cover the whole password with those pieces and brute force. Its score is 0 to
4, at 10³, 10⁶, 10⁸ and 10¹⁰ guesses.

## Options

1. **A list only** (SecLists' top 100,000). Catches listed passwords
   exactly and nothing else.
2. **Entropy from the character set** (length × log₂ of the alphabet). NIST
   dropped it in SP 800-63B: it rates `P@ssw0rd1!` as strong.
3. **Depend on a Go port of zxcvbn.** A third party's re-implementation in
   the code that decides what a password must be, which we would have to
   review line by line anyway, and follow for fixes.
4. **Port zxcvbn into `internal/password`** with its lists and graphs,
   reviewed and tested here. About 1,000 lines with the matchers.

## Decision

Option 4, on epistemer's choice (2026-11-14). `CheckPassword` checks, in
order:

1. The length (`password.min_length`).
2. The hints' words of four characters or more, any of which refuses the
   password (`ErrPasswordPersonal`), as before.
3. A password that is, as a whole, one repeated unit, one run or one walk
   along a keyboard row (`ErrPasswordSimple`), as before.
4. zxcvbn's estimate of its first 100 characters, whose score must reach
   `password.min_score` (default 4). The piece that covers the most
   characters names the error: a hint's word is `Personal`, a listed word
   is `Common`, a pattern is `Simple`.

Steps 2 and 3 stay although the estimate catches most of what they catch.
They are rules of the locked interface, and dropping them would loosen it.

### The data

From [github.com/dropbox/zxcvbn](https://github.com/dropbox/zxcvbn) at
commit `67c4ece9efc40c9d0a1d7d995b2b22a91be500c2` (2017-10-13, the last on
master), MIT licence, copied to `internal/password/data/LICENSE.zxcvbn`.
`data/extract.go` wrote the lists and `graphs.json` from
`src/frequency_lists.coffee` (SHA-256
`664d32190713e42b7726072a5cf7533bd4a469e5588c7c1bd2ff9485cdf83276`) and
`src/adjacency_graphs.coffee`, unchanged in content and order:

| List | Words | zxcvbn's source for it |
|---|---|---|
| passwords | 30,000 | Mark Burnett's corpus of 10 million passwords |
| english_wikipedia | 30,000 | Word counts over English Wikipedia |
| us_tv_and_film | 19,160 | Wiktionary's frequency list of English in television and films |
| surnames | 10,000 | The 1990 US census |
| female_names | 3,712 | The 1990 US census |
| male_names | 983 | The 1990 US census |

zxcvbn keeps each word once, in the list where its rank is lowest, and drops
a rare short word that brute force would guess sooner. The rank is the
position in the list as published. The files take 808 KB, embedded.

zxcvbn publishes the lists under its MIT licence. The Wiktionary list's
source is CC BY-SA; a list of word counts carries little of it, and zxcvbn
has shipped the list under MIT since 2016. We take zxcvbn's terms.

### Where the port departs

- A substitute in l33t stands for one of its letters throughout the
  password, and every such choice is tried. zxcvbn lets each letter take one
  of its substitutes at a time, so it misses `p4@ssword` for `paassword`.
  The port only ever finds more.
- Years match 1900 to 2099. zxcvbn's pattern stopped at 2019, so a 2024
  counted as four random digits.
- Capitals are judged by Unicode, where zxcvbn knows only A to Z.
- The reference year is passed in, where zxcvbn reads the clock: auth
  passes its own clock's year (`WithClock`), so tests are stable.
- Only the first 100 characters are judged. A password is at least as
  strong as its first 100 characters, so this can refuse a strong password
  and never pass a weak one. It bounds the cost of a long input: 4.4 ms on
  this machine for 100 characters, against 0.6 ms for a four-word
  passphrase and about 150 ms for the hash that follows.
- zxcvbn's feedback sentences aren't ported. The three errors carry the
  message, through i18n.

zxcvbn's own matcher and scoring tests are ported to `strength_test.go`, with
its demo's results for `password`, `correcthorsebatterystaple` and
`Tr0ub4dour&3`. Running zxcvbn's JavaScript on a corpus to compare every
estimate was tried and not done: the session's permissions didn't allow
running the downloaded code.

### The default score

The default is 4, not the 3 first proposed. zxcvbn adds 10,000ⁿ⁻¹ guesses to a
covering of n pieces, to model an attacker who tries fewer pieces first. A
password of three pieces therefore gets at least 10⁸ guesses and scores 3,
however cheap the pieces: `Summer2024!!`, `abcdef123456!` and
`baseball!football` all score 3. At 4 they fail, while `orange tiger 47`,
`purple-monkey-dishwasher` and any 12 random characters pass. The range is 3
to 4; going below 3 is a looser rule and is epistemer's to decide.

## Consequences

- `ErrPasswordCommon` now also covers common words and names, and
  `ErrPasswordSimple` dates and years. Interface amendment A3 records it,
  with the new key and the new order of §5.2.4.
- The lists are English and American. A password in Arabic, or Arabic
  written in Latin letters (`habibi2020`), is judged by its patterns and
  length only. A list for another audience is a later addition, as a list
  in `data/` with its source recorded here.
- A breach-corpus lookup stays out of v0.1 (§9).
- 808 KB of data in the binary, and about 6 MiB of heap once the first
  password is checked: the lists load on first use.
