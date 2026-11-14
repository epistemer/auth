package password

import (
	"slices"
	"strings"
	"unicode"
)

// omnimatch finds every guessable piece of pw, sorted by position.
func (jd *judge) omnimatch(pw []rune) []*match {
	lower := lowerRunes(pw)
	var ms []*match
	ms = append(ms, jd.dictionaryMatch(pw, lower)...)
	ms = append(ms, jd.reverseMatch(pw, lower)...)
	ms = append(ms, jd.l33tMatch(pw, lower)...)
	ms = append(ms, jd.spatialMatch(pw)...)
	ms = append(ms, jd.repeatMatch(pw)...)
	ms = append(ms, sequenceMatch(pw)...)
	ms = append(ms, yearMatch(pw)...)
	ms = append(ms, jd.dateMatch(pw)...)
	slices.SortStableFunc(ms, func(a, b *match) int {
		if a.i != b.i {
			return a.i - b.i
		}
		return a.j - b.j
	})
	return ms
}

// dictionaryMatch finds the words of the lists and the hints in lookup, a
// lower-case form of pw.
func (jd *judge) dictionaryMatch(pw, lookup []rune) []*match {
	longest := max(jd.c.maxLen, jd.userMax)
	var ms []*match
	for i := range lookup {
		for j := i; j < len(lookup) && j-i < longest; j++ {
			w := string(lookup[i : j+1])
			if e, ok := jd.c.words[w]; ok {
				ms = append(ms, &match{pattern: dictionary, i: i, j: j, token: pw[i : j+1], word: w, list: e.list, rank: e.rank})
			}
			if r, ok := jd.user[w]; ok {
				ms = append(ms, &match{pattern: dictionary, i: i, j: j, token: pw[i : j+1], word: w, list: userList, rank: r})
			}
		}
	}
	return ms
}

func (jd *judge) reverseMatch(pw, lower []rune) []*match {
	n := len(pw)
	rpw, rlower := slices.Clone(pw), slices.Clone(lower)
	slices.Reverse(rpw)
	slices.Reverse(rlower)
	ms := jd.dictionaryMatch(rpw, rlower)
	for _, m := range ms {
		m.i, m.j = n-1-m.j, n-1-m.i
		m.token = pw[m.i : m.j+1]
		m.reversed = true
	}
	return ms
}

// l33t maps each substitute to the letters it stands for.
var l33t = map[rune][]rune{
	'4': {'a'}, '@': {'a'}, '8': {'b'}, '(': {'c'}, '{': {'c'}, '[': {'c'}, '<': {'c'},
	'3': {'e'}, '6': {'g'}, '9': {'g'}, '1': {'i', 'l'}, '!': {'i'}, '|': {'i', 'l'},
	'7': {'l', 't'}, '0': {'o'}, '$': {'s'}, '5': {'s'}, '+': {'t'}, '%': {'x'}, '2': {'z'},
}

// l33tMatch finds words written with substitutes, as p@ssw0rd. Each
// substitute in pw stands for one of its letters throughout; the port tries
// every such choice. At most three substitutes stand for two letters, so
// there are at most eight. zxcvbn instead lets each letter take one of its
// substitutes at a time, so it misses p4@ssword for paassword, which the
// port finds: a difference that only ever lowers the estimate.
func (jd *judge) l33tMatch(pw, lower []rune) []*match {
	var present []rune
	for _, r := range lower {
		if l33t[r] != nil && !slices.Contains(present, r) {
			present = append(present, r)
		}
	}
	if len(present) == 0 {
		return nil
	}
	slices.Sort(present)
	subs := []map[rune]rune{{}}
	for _, c := range present {
		var next []map[rune]rune
		for _, s := range subs {
			for _, letter := range l33t[c] {
				t := make(map[rune]rune, len(s)+1)
				for k, v := range s {
					t[k] = v
				}
				t[c] = letter
				next = append(next, t)
			}
		}
		subs = next
	}
	seen := map[string]bool{}
	var ms []*match
	for _, s := range subs {
		subbed := make([]rune, len(lower))
		for i, r := range lower {
			if l, ok := s[r]; ok {
				subbed[i] = l
			} else {
				subbed[i] = r
			}
		}
		for _, m := range jd.dictionaryMatch(pw, subbed) {
			if len(m.token) < 2 || string(lower[m.i:m.j+1]) == m.word {
				continue // single characters are noise; and a match must substitute
			}
			used := map[rune]rune{}
			var key strings.Builder
			for _, c := range present {
				if slices.Contains(m.token, c) {
					used[c] = s[c]
					key.WriteRune(c)
					key.WriteRune(s[c])
				}
			}
			k := string(rune(m.i)) + string(rune(m.j)) + string(rune(m.list+2)) + m.word + "\x00" + key.String()
			if seen[k] {
				continue
			}
			seen[k] = true
			m.sub = used
			ms = append(ms, m)
		}
	}
	return ms
}

// shiftedKeys are the characters typed with shift on a qwerty or dvorak
// keyboard.
const shiftedKeys = "~!@#$%^&*()_+QWERTYUIOP{}|ASDFGHJKL:\"ZXCVBNM<>?"

// spatialMatch finds walks along a keyboard or a keypad of three keys or
// more.
func (jd *judge) spatialMatch(pw []rune) []*match {
	var ms []*match
	for _, g := range jd.c.graphs {
		i := 0
		for i < len(pw)-1 {
			k := i + 1
			last, turns, shifted := -1, 0, 0
			if g.keyboard && strings.ContainsRune(shiftedKeys, pw[i]) {
				shifted = 1
			}
			for {
				found := false
				if k < len(pw) {
					for dir, keys := range g.adj[pw[k-1]] {
						at := slices.Index(keys, pw[k])
						if at < 0 {
							continue
						}
						found = true
						if at == 1 {
							shifted++ // the second character of a key is its shifted one
						}
						if dir != last {
							turns++
							last = dir
						}
						break
					}
				}
				if found {
					k++
					continue
				}
				if k-i > 2 {
					ms = append(ms, &match{pattern: spatial, i: i, j: k - 1, token: pw[i:k], graph: g, turns: turns, shifted: shifted})
				}
				i = k
				break
			}
		}
	}
	return ms
}

// repeatMatch finds a unit repeated, as aaaa or abcabc, and prices it as
// the unit's own estimate times the count. It does by hand what zxcvbn does
// with back-references, which Go's regexp lacks: at the leftmost position
// that starts a repeat, the greedy reading takes the longest unit and the
// lazy one the shortest, each repeated as often as it goes; the longer of
// the two wins, reduced to its shortest unit.
func (jd *judge) repeatMatch(pw []rune) []*match {
	n := len(pw)
	repeats := func(p, unit int) int {
		c := 1
		for p+(c+1)*unit <= n && slices.Equal(pw[p:p+unit], pw[p+c*unit:p+(c+1)*unit]) {
			c++
		}
		return c
	}
	var ms []*match
	from := 0
	for from < n {
		p, greedy, lazy := -1, 0, 0
		for q := from; q < n && p < 0; q++ {
			for unit := (n - q) / 2; unit >= 1; unit-- {
				if repeats(q, unit) >= 2 {
					if greedy == 0 {
						greedy = unit
					}
					lazy = unit
				}
			}
			if greedy > 0 {
				p = q
			}
		}
		if p < 0 {
			break
		}
		unit, count := lazy, repeats(p, lazy)
		if gl := greedy * repeats(p, greedy); gl > unit*count {
			unit = period(pw[p : p+gl])
			count = gl / unit
		}
		tok := pw[p : p+unit*count]
		base := jd.analyze(pw[p : p+unit])
		ms = append(ms, &match{pattern: repeat, i: p, j: p + len(tok) - 1, token: tok, base: base.guesses, count: count})
		from = p + len(tok)
	}
	return ms
}

// period is the shortest unit s is made of, repeated.
func period(s []rune) int {
	for unit := 1; unit < len(s); unit++ {
		if len(s)%unit != 0 {
			continue
		}
		ok := true
		for i := unit; i < len(s) && ok; i++ {
			ok = s[i] == s[i-unit]
		}
		if ok {
			return unit
		}
	}
	return len(s)
}

const maxDelta = 5

// sequenceMatch finds runs of characters a fixed step apart, as abcd, 9753
// or zyx.
func sequenceMatch(pw []rune) []*match {
	if len(pw) < 2 {
		return nil
	}
	var ms []*match
	add := func(i, j, delta int) {
		d := max(delta, -delta)
		if (j-i > 1 || d == 1) && d > 0 && d <= maxDelta {
			ms = append(ms, &match{pattern: sequence, i: i, j: j, token: pw[i : j+1], ascending: delta > 0})
		}
	}
	i, last := 0, int(pw[1]-pw[0])
	for k := 1; k < len(pw); k++ {
		delta := int(pw[k] - pw[k-1])
		if delta == last {
			continue
		}
		add(i, k-1, last)
		i, last = k-1, delta
	}
	add(i, len(pw)-1, last)
	return ms
}

func isDigit(r rune) bool { return '0' <= r && r <= '9' }

func atoi(rs []rune) int {
	n := 0
	for _, r := range rs {
		n = n*10 + int(r-'0')
	}
	return n
}

// yearMatch finds years from 1900 to 2099. zxcvbn's pattern stopped at
// 2019.
func yearMatch(pw []rune) []*match {
	var ms []*match
	for i := 0; i+4 <= len(pw); {
		t := pw[i : i+4]
		if (t[0] == '1' && t[1] == '9' || t[0] == '2' && t[1] == '0') && isDigit(t[2]) && isDigit(t[3]) {
			ms = append(ms, &match{pattern: recentYear, i: i, j: i + 3, token: t, year: atoi(t)})
			i += 4
			continue
		}
		i++
	}
	return ms
}

const (
	dateMinYear = 1000
	dateMaxYear = 2050
)

// dateSplits are where a run of 4 to 8 digits may divide into day, month
// and year.
var dateSplits = map[int][][2]int{
	4: {{1, 2}, {2, 3}},
	5: {{1, 3}, {2, 3}},
	6: {{1, 2}, {2, 4}, {4, 5}},
	7: {{1, 3}, {2, 3}, {4, 5}, {4, 6}},
	8: {{2, 4}, {4, 6}},
}

func isDateSeparator(r rune) bool { return unicode.IsSpace(r) || strings.ContainsRune(`/\_.-`, r) }

// dateMatch finds dates: three numbers, a 2- or 4-digit year first or last,
// a month and a day, with no separator or the same one twice.
func (jd *judge) dateMatch(pw []rune) []*match {
	var ms []*match
	n := len(pw)
	for i := 0; i+4 <= n; i++ {
		for j := i + 3; j <= i+7 && j < n; j++ {
			tok := pw[i : j+1]
			if !allDigits(tok) {
				continue
			}
			var best *dmy
			for _, s := range dateSplits[len(tok)] {
				d := toDMY(atoi(tok[:s[0]]), atoi(tok[s[0]:s[1]]), atoi(tok[s[1]:]))
				if d != nil && (best == nil || abs(d.year-jd.year) < abs(best.year-jd.year)) {
					best = d
				}
			}
			if best != nil {
				ms = append(ms, &match{pattern: date, i: i, j: j, token: tok, year: best.year})
			}
		}
	}
	for i := 0; i+6 <= n; i++ {
		for j := i + 5; j <= i+9 && j < n; j++ {
			tok := pw[i : j+1]
			a, b, c, ok := splitDate(tok)
			if !ok {
				continue
			}
			if d := toDMY(a, b, c); d != nil {
				ms = append(ms, &match{pattern: date, i: i, j: j, token: tok, year: d.year, separator: true})
			}
		}
	}
	// A date inside another, as 15_06_04 inside 2015_06_04, is noise.
	var out []*match
	for _, m := range ms {
		inside := false
		for _, o := range ms {
			if o != m && o.i <= m.i && o.j >= m.j {
				inside = true
				break
			}
		}
		if !inside {
			out = append(out, m)
		}
	}
	return out
}

func allDigits(rs []rune) bool {
	for _, r := range rs {
		if !isDigit(r) {
			return false
		}
	}
	return true
}

func abs(n int) int { return max(n, -n) }

// splitDate reads 1 to 4 digits, a separator, 1 or 2 digits, the same
// separator and 1 to 4 digits, the whole token.
func splitDate(tok []rune) (a, b, c int, ok bool) {
	digits := func(from int) int {
		k := from
		for k < len(tok) && isDigit(tok[k]) {
			k++
		}
		return k
	}
	e1 := digits(0)
	if e1 < 1 || e1 > 4 || e1 >= len(tok) || !isDateSeparator(tok[e1]) {
		return 0, 0, 0, false
	}
	sep := tok[e1]
	e2 := digits(e1 + 1)
	if e2-e1-1 < 1 || e2-e1-1 > 2 || e2 >= len(tok) || tok[e2] != sep {
		return 0, 0, 0, false
	}
	e3 := digits(e2 + 1)
	if e3 != len(tok) || e3-e2-1 < 1 || e3-e2-1 > 4 {
		return 0, 0, 0, false
	}
	return atoi(tok[:e1]), atoi(tok[e1+1 : e2]), atoi(tok[e2+1:]), true
}

type dmy struct{ day, month, year int }

// toDMY reads three numbers as a date, or returns nil. It is zxcvbn's
// map_ints_to_dmy.
func toDMY(a, b, c int) *dmy {
	ints := [3]int{a, b, c}
	if b > 31 || b <= 0 {
		return nil
	}
	over12, over31, under1 := 0, 0, 0
	for _, v := range ints {
		if 99 < v && v < dateMinYear || v > dateMaxYear {
			return nil
		}
		if v > 31 {
			over31++
		}
		if v > 12 {
			over12++
		}
		if v <= 0 {
			under1++
		}
	}
	if over31 >= 2 || over12 == 3 || under1 >= 2 {
		return nil
	}
	splits := [2]struct {
		y    int
		rest [2]int
	}{{c, [2]int{a, b}}, {a, [2]int{b, c}}}
	for _, s := range splits {
		if dateMinYear <= s.y && s.y <= dateMaxYear {
			if d, m, ok := toDM(s.rest); ok {
				return &dmy{d, m, s.y}
			}
			return nil // a four-digit year with no day and month: not a date
		}
	}
	for _, s := range splits {
		if d, m, ok := toDM(s.rest); ok {
			y := s.y
			switch {
			case y > 99:
			case y > 50:
				y += 1900
			default:
				y += 2000
			}
			return &dmy{d, m, y}
		}
	}
	return nil
}

func toDM(p [2]int) (day, month int, ok bool) {
	for _, dm := range [2][2]int{p, {p[1], p[0]}} {
		if 1 <= dm[0] && dm[0] <= 31 && 1 <= dm[1] && dm[1] <= 12 {
			return dm[0], dm[1], true
		}
	}
	return 0, 0, false
}
