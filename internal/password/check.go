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

// minPart is the shortest hint part that counts: shorter parts ("a", "co")
// would refuse too many good passwords.
const minPart = 4

// Check judges a new password, in the order of §5.2.4: length, the list of
// common passwords, personal words, trivial patterns. minLen counts
// characters after normalization. hints are the login, the user's name and
// addresses, the issuer and anything the caller adds; each is split into
// words.
func Check(pw string, minLen int, common func(string) bool, hints ...string) Reason {
	n, err := Normalize(pw)
	if err != nil {
		return TooLong
	}
	if utf8.RuneCountInString(n) < minLen {
		return TooShort
	}
	lower := strings.ToLower(n)
	if common != nil && (common(lower) || common(strings.TrimSpace(lower))) {
		return Common
	}
	for _, h := range hints {
		for _, part := range words(h) {
			if strings.Contains(lower, part) {
				return Personal
			}
		}
	}
	if simple(lower) {
		return Simple
	}
	return OK
}

// words splits a hint into lower-case words of at least minPart
// characters: "sara.ali@example.com" gives sara, example; "Sara Ali" gives
// sara.
func words(hint string) []string {
	hint, _ = Normalize(hint)
	var out []string
	for _, f := range strings.FieldsFunc(strings.ToLower(hint), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	}) {
		if utf8.RuneCountInString(f) >= minPart {
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
// ("abcdefghijkl", "987654321098"), or a walk along a keyboard row. Only the
// whole password is judged: a pattern inside a longer one is the list's job.
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
