package password

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// Reason says why a new password was refused. auth maps each to its public
// error (interface §4.6).
type Reason int

const (
	OK Reason = iota
	TooShort
	TooLong
	Common
	Personal
	Simple
)

// Rules are what Check holds a new password to.
type Rules struct {
	MinLength int // characters after normalization
	MinScore  int // zxcvbn's score, 0 to 4
	Year      int // the current year: dates near it are guessed first
}

// minPart is the shortest hint word that a password may not contain:
// shorter words ("a", "co", "ali") would refuse too many good passwords.
const minPart = 4

// Check judges a new password, in the order of §5.2.4 as amendment A3
// left it: the length; the hints' words, any of which refuses it; a
// password that is one trivial pattern as a whole; then the estimate of its
// guesses, which must reach r.MinScore. hints are the login, the user's
// name and addresses, the issuer and anything the caller adds.
func Check(pw string, r Rules, hints ...string) Reason {
	n, err := Normalize(pw)
	if err != nil {
		return TooLong
	}
	runes := []rune(n)
	if len(runes) < r.MinLength {
		return TooShort
	}
	lower := strings.ToLower(n)
	for _, h := range hints {
		for _, part := range words(h, minPart) {
			if strings.Contains(lower, part) {
				return Personal
			}
		}
	}
	if simple(lower) {
		return Simple
	}
	e := estimateLong(newJudge(r.Year, hints), runes)
	if e.score() >= r.MinScore {
		return OK
	}
	return blame(e)
}

// estimateLong estimates a password of any length from its first
// maxJudged characters. Cutting can raise an estimate, when a pattern
// crosses the cut: the second copy of a repeated unit, chopped, prices as
// random characters. A password that is a unit repeated as a whole is
// therefore also priced as zxcvbn prices a repeat, and the lower estimate
// stands. A pattern crossing the cut inside a longer password is the gap
// left (ADR 0006): estimating every character costs seconds at 1024.
func estimateLong(jd *judge, pw []rune) estimate {
	if len(pw) <= maxJudged {
		return jd.analyze(pw)
	}
	e := jd.analyze(pw[:maxJudged])
	if unit := period(pw); unit < len(pw) {
		g := finite(jd.analyze(pw[:min(unit, maxJudged)]).guesses * float64(len(pw)/unit))
		if g < e.guesses {
			e = estimate{guesses: g, seq: []*match{{pattern: repeat, i: 0, j: len(pw) - 1, token: pw, count: len(pw) / unit}}}
		}
	}
	return e
}

// blame names what made a password weak: the reason whose matches cover
// the most characters, and between equals the hints before the lists before
// the patterns. A password left to brute force alone is Simple: only one
// under nine characters can be, below the shortest minimum length.
func blame(e estimate) Reason {
	covered := map[Reason]int{}
	for _, m := range e.seq {
		switch {
		case m.pattern == bruteforce:
		case m.pattern == dictionary && m.list == userList:
			covered[Personal] += len(m.token)
		case m.pattern == dictionary:
			covered[Common] += len(m.token)
		default:
			covered[Simple] += len(m.token)
		}
	}
	best := Simple
	for _, r := range []Reason{Common, Personal} { // later wins a tie
		if covered[r] > covered[best] || covered[r] == covered[best] && covered[r] > 0 {
			best = r
		}
	}
	return best
}

// words splits a hint into lower-case words of at least least characters:
// "sara.ali@example.com" gives sara, example with least 4.
func words(hint string, least int) []string {
	hint, _ = Normalize(hint)
	var out []string
	for _, f := range strings.FieldsFunc(strings.ToLower(hint), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	}) {
		if utf8.RuneCountInString(f) >= least {
			out = append(out, f)
		}
	}
	return out
}

var rows = []string{
	"`1234567890-=", "qwertyuiop[]", "asdfghjkl;'", "zxcvbnm,./",
	"1qaz2wsx3edc4rfv5tgb6yhn7ujm8ik,9ol.0p;/", "qazwsxedcrfvtgbyhnujmikolp",
}

// simple reports a password that is, as a whole, a short unit repeated
// ("aaaaaaaaaaaa", "abcabcabcabc"), a run of consecutive characters
// ("abcdefghijkl", "987654321098"), or a walk along a keyboard row. The
// estimate catches most of these too; this check keeps the rule exact.
func simple(s string) bool {
	r := []rune(s)
	for unit := 1; unit <= 4 && unit < len(r); unit++ {
		if repeats(r, unit) {
			return true
		}
	}
	if consecutive(r, 1) || consecutive(r, -1) {
		return true
	}
	for _, row := range rows {
		if walk(s, row) || walk(s, reverse(row)) {
			return true
		}
	}
	return false
}

func repeats(r []rune, unit int) bool {
	for i := unit; i < len(r); i++ {
		if r[i] != r[i-unit] {
			return false
		}
	}
	return true
}

// consecutive allows wrapping between 9 and 0, as in 7890123.
func consecutive(r []rune, step int) bool {
	if len(r) < 2 {
		return false
	}
	for i := 1; i < len(r); i++ {
		d := int(r[i] - r[i-1])
		if d != step && !(unicode.IsDigit(r[i]) && unicode.IsDigit(r[i-1]) && d == -9*step) {
			return false
		}
	}
	return true
}

// walk reports whether s is made of pieces of row, repeated: qwertyqwerty.
func walk(s, row string) bool {
	if len(s) < 4 {
		return false
	}
	for len(s) > 0 {
		n := 0
		for i := len(row); i >= 4 && n == 0; i-- {
			for j := 0; j+i <= len(row); j++ {
				if strings.HasPrefix(s, row[j:j+i]) {
					n = i
					break
				}
			}
		}
		if n == 0 {
			return false
		}
		s = s[n:]
	}
	return true
}

func reverse(s string) string {
	b := []byte(s)
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	return string(b)
}
