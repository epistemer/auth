package password

import (
	"math"
	"math/rand/v2"
	"strings"
	"testing"
	"time"
)

// Most cases here are zxcvbn's own (test/test-scoring.coffee and
// test/test-matching.coffee at the commit ADR 0006 names).

func TestEmbeddedData(t *testing.T) {
	c := load()
	count := map[int]int{}
	for _, e := range c.words {
		count[e.list]++
	}
	// zxcvbn's lists, each word kept once, where its rank is lowest.
	for i, want := range []int{30000, 30000, 3712, 10000, 19160, 983} {
		if count[i] != want {
			t.Errorf("%s: %d words, want %d", lists[i], count[i], want)
		}
	}
	if e := c.words["wow"]; lists[e.list] != "us_tv_and_film" || e.rank != 322 {
		t.Errorf("wow: %s %d", lists[e.list], e.rank)
	}
	if c.keyboardStarts != 94 || math.Abs(c.keyboardDegree-4.595744680851064) > 1e-12 {
		t.Errorf("qwerty: %v keys, degree %v", c.keyboardStarts, c.keyboardDegree)
	}
	if c.keypadStarts != 15 || math.Abs(c.keypadDegree-5.066666666666666) > 1e-12 {
		t.Errorf("keypad: %v keys, degree %v", c.keypadStarts, c.keypadDegree)
	}
}

func TestNCk(t *testing.T) {
	for _, c := range [][3]int{{0, 0, 1}, {1, 0, 1}, {5, 0, 1}, {0, 1, 0}, {0, 5, 0}, {2, 1, 2}, {4, 2, 6}, {33, 7, 4272048}} {
		if got := nCk(c[0], c[1]); got != float64(c[2]) {
			t.Errorf("nCk(%d, %d) = %v", c[0], c[1], got)
		}
	}
}

func TestUpperVariations(t *testing.T) {
	for _, c := range []struct {
		word string
		want float64
	}{
		{"", 1}, {"a", 1}, {"A", 2}, {"abcdef", 1}, {"Abcdef", 2}, {"abcdeF", 2}, {"ABCDEF", 2},
		{"aBcdef", nCk(6, 1)}, {"aBcDef", nCk(6, 1) + nCk(6, 2)}, {"ABCDEf", nCk(6, 1)},
		{"aBCDEf", nCk(6, 1) + nCk(6, 2)}, {"ABCdef", nCk(6, 1) + nCk(6, 2) + nCk(6, 3)},
	} {
		if got := upperVariations([]rune(c.word)); got != c.want {
			t.Errorf("%q: %v, want %v", c.word, got, c.want)
		}
	}
}

func TestL33tVariations(t *testing.T) {
	for _, c := range []struct {
		word string
		want float64
		sub  map[rune]rune
	}{
		{"", 1, nil}, {"a", 1, nil}, {"4", 2, map[rune]rune{'4': 'a'}}, {"4pple", 2, map[rune]rune{'4': 'a'}},
		{"abcet", 1, nil}, {"4bcet", 2, map[rune]rune{'4': 'a'}}, {"a8cet", 2, map[rune]rune{'8': 'b'}},
		{"abce+", 2, map[rune]rune{'+': 't'}}, {"48cet", 4, map[rune]rune{'4': 'a', '8': 'b'}},
		{"a4a4aa", nCk(6, 2) + nCk(6, 1), map[rune]rune{'4': 'a'}},
		{"4a4a44", nCk(6, 2) + nCk(6, 1), map[rune]rune{'4': 'a'}},
		{"a44att+", (nCk(4, 2) + nCk(4, 1)) * nCk(3, 1), map[rune]rune{'4': 'a', '+': 't'}},
		{"Aa44aA", nCk(6, 2) + nCk(6, 1), map[rune]rune{'4': 'a'}}, // capitals don't count
	} {
		if got := l33tVariations(&match{token: []rune(c.word), sub: c.sub}); got != c.want {
			t.Errorf("%q: %v, want %v", c.word, got, c.want)
		}
	}
}

func TestGuesses(t *testing.T) {
	jd := newJudge(2026, nil)
	c := jd.c
	one := func(m *match) float64 { return jd.guesses(m, len(m.token)) }
	for _, s := range []struct {
		tok  string
		asc  bool
		want float64
	}{
		{"ab", true, 4 * 2}, {"XYZ", true, 26 * 3}, {"4567", true, 10 * 4}, {"7654", false, 10 * 4 * 2}, {"ZYX", false, 4 * 3 * 2},
	} {
		if got := one(&match{pattern: sequence, token: []rune(s.tok), ascending: s.asc}); got != s.want {
			t.Errorf("sequence %q: %v, want %v", s.tok, got, s.want)
		}
	}
	if got := one(&match{pattern: recentYear, token: []rune("1972"), year: 1972}); got != 2026-1972 {
		t.Errorf("1972: %v", got)
	}
	if got := one(&match{pattern: recentYear, token: []rune("2025"), year: 2025}); got != minYearSpace {
		t.Errorf("2025: %v", got)
	}
	if got := one(&match{pattern: date, token: []rune("1123"), year: 1923}); got != 365*(2026-1923) {
		t.Errorf("1923: %v", got)
	}
	if got := one(&match{pattern: date, token: []rune("1/1/2020"), year: 2020, separator: true}); got != 365*minYearSpace*4 {
		t.Errorf("2020: %v", got)
	}
	base := c.keyboardStarts * c.keyboardDegree * 5
	qwerty := c.graphs[0]
	for _, s := range []struct {
		tok     string
		shifted int
		want    float64
	}{
		{"zxcvbn", 0, base}, {"ZxCvbn", 2, base * (nCk(6, 2) + nCk(6, 1))}, {"ZXCVBN", 6, base * 2},
	} {
		got := one(&match{pattern: spatial, token: []rune(s.tok), graph: qwerty, turns: 1, shifted: s.shifted})
		if math.Abs(got-s.want) > 1e-9*s.want {
			t.Errorf("spatial %q: %v, want %v", s.tok, got, s.want)
		}
	}
	for _, s := range []struct {
		word string
		rank int
		rev  bool
		sub  map[rune]rune
		want float64
	}{
		{"aaaaa", 32, false, nil, 32}, {"AAAaaa", 32, false, nil, 32 * upperVariations([]rune("AAAaaa"))},
		{"aaa", 32, true, nil, 64}, {"aaa@@@", 32, false, map[rune]rune{'@': 'a'}, 32 * (nCk(6, 3) + nCk(6, 2) + nCk(6, 1))},
	} {
		got := one(&match{pattern: dictionary, token: []rune(s.word), rank: s.rank, reversed: s.rev, sub: s.sub})
		if got != s.want {
			t.Errorf("dictionary %q: %v, want %v", s.word, got, s.want)
		}
	}
}

// The covering: cheapest, with brute force filling the gaps.
func TestCheapest(t *testing.T) {
	jd := newJudge(2026, nil)
	pw := []rune("0123456789")
	m := func(i, j int, g float64) *match {
		return &match{pattern: dictionary, i: i, j: j, token: pw[i : j+1], guesses: g}
	}
	shape := func(e estimate) (out [][2]int) {
		for _, x := range e.seq {
			out = append(out, [2]int{x.i, x.j})
		}
		return out
	}
	eq := func(a, b [][2]int) bool {
		if len(a) != len(b) {
			return false
		}
		for i := range a {
			if a[i] != b[i] {
				return false
			}
		}
		return true
	}
	for _, c := range []struct {
		ms   []*match
		want [][2]int
	}{
		{nil, [][2]int{{0, 9}}},
		{[]*match{m(0, 5, 1)}, [][2]int{{0, 5}, {6, 9}}},
		{[]*match{m(3, 9, 1)}, [][2]int{{0, 2}, {3, 9}}},
		{[]*match{m(1, 8, 1)}, [][2]int{{0, 0}, {1, 8}, {9, 9}}},
		{[]*match{m(0, 9, 1), m(0, 9, 2)}, [][2]int{{0, 9}}},
		{[]*match{m(0, 9, 3), m(0, 3, 2), m(4, 9, 1)}, [][2]int{{0, 9}}},
	} {
		if got := shape(jd.cheapest(pw, c.ms)); !eq(got, c.want) {
			t.Errorf("%v, want %v", got, c.want)
		}
	}
	// One match: 1! times its guesses, plus 10000^0.
	if e := jd.cheapest(pw, []*match{m(0, 9, 1), m(0, 9, 2)}); e.guesses != 2 || e.seq[0].guesses != 1 {
		t.Errorf("chose %v", e.guesses)
	}
	if e := jd.cheapest(nil, nil); e.guesses != 1 {
		t.Errorf("empty: %v", e.guesses)
	}
}

func spans(ms []*match, p pattern) (out []string) {
	for _, m := range ms {
		if m.pattern == p {
			out = append(out, string(m.token))
		}
	}
	return out
}

func TestDictionaryMatch(t *testing.T) {
	jd := newJudge(2026, []string{"foo", "bar"})
	var users []string
	for _, m := range jd.omnimatch([]rune("foobar")) {
		if m.pattern == dictionary && m.list == userList && !m.reversed && m.sub == nil {
			users = append(users, string(m.token))
			if want := map[string]int{"foo": 1, "bar": 2}[m.word]; m.rank != want {
				t.Errorf("%s: rank %d", m.word, m.rank)
			}
		}
	}
	if strings.Join(users, ",") != "foo,bar" {
		t.Errorf("hints: %v", users)
	}
	// A hint whole and its words: the login's name part matches alone.
	jd = newJudge(2026, []string{"sara.ali@example.com"})
	for _, w := range []string{"sara.ali@example.com", "sara", "ali", "example", "com"} {
		if _, ok := jd.user[w]; !ok {
			t.Errorf("hint word %q missing", w)
		}
	}
}

func testJudge(words map[string]int) *judge {
	c := &corpus{words: map[string]entry{}}
	for w, r := range words {
		c.words[w] = entry{0, r}
		c.maxLen = max(c.maxLen, len(w))
	}
	return &judge{c: c, user: map[string]int{}, year: 2026}
}

func TestReverseMatch(t *testing.T) {
	jd := testJudge(map[string]int{"123": 1, "321": 2, "456": 3, "654": 4})
	pw := []rune("0123456789")
	var got []string
	for _, m := range jd.reverseMatch(pw, pw) {
		got = append(got, string(m.token)+":"+m.word)
	}
	if strings.Join(got, ",") != "456:654,123:321" && strings.Join(got, ",") != "123:321,456:654" {
		t.Errorf("%v", got)
	}
}

func TestL33tMatch(t *testing.T) {
	jd := testJudge(map[string]int{"aac": 1, "password": 3, "paassword": 4, "asdf0": 5, "cgo": 1})
	lm := func(pw string) []*match {
		r := []rune(pw)
		return jd.l33tMatch(r, lowerRunes(r))
	}
	if len(lm("")) != 0 || len(lm("password")) != 0 {
		t.Error("matched without a substitute")
	}
	for _, c := range []struct{ pw, token, word string }{
		{"p4ssword", "p4ssword", "password"},
		{"p@ssw0rd", "p@ssw0rd", "password"},
		{"aSdfO{G0asDfO", "{G0", "cgo"},
		{"p4@ssword", "p4@ssword", "paassword"}, // zxcvbn misses this one
	} {
		ms := lm(c.pw)
		found := false
		for _, m := range ms {
			found = found || string(m.token) == c.token && m.word == c.word
		}
		if !found {
			t.Errorf("%q: no %q for %q", c.pw, c.token, c.word)
		}
	}
	if ms := lm("@a(go{G0"); len(ms) != 3 {
		t.Errorf("overlapping: %v", spans(ms, dictionary))
	}
	if ms := newJudge(2026, nil).l33tMatch([]rune("4 1 @"), []rune("4 1 @")); len(ms) != 0 {
		t.Errorf("single characters: %v", spans(ms, dictionary))
	}
}

func TestSpatialMatch(t *testing.T) {
	jd := newJudge(2026, nil)
	for _, pw := range []string{"", "/", "qw", "*/"} {
		if ms := jd.spatialMatch([]rune(pw)); len(ms) != 0 {
			t.Errorf("%q matched", pw)
		}
	}
	for _, c := range []struct {
		pw, graph      string
		turns, shifted int
	}{
		{"12345", "qwerty", 1, 0}, {"@WSX", "qwerty", 1, 4}, {"6tfGHJ", "qwerty", 2, 3}, {"hGFd", "qwerty", 1, 2},
		{"/;p09876yhn", "qwerty", 3, 0}, {"Xdr%", "qwerty", 1, 2}, {"159-", "keypad", 1, 0}, {"*84", "keypad", 1, 0},
		{"/8520", "keypad", 1, 0}, {"369", "keypad", 1, 0}, {"/963.", "mac_keypad", 1, 0},
		{"*-632.0214", "mac_keypad", 9, 0}, {"aoEP%yIxkjq:", "dvorak", 4, 5}, {";qoaOQ:Aoq;a", "dvorak", 11, 4},
	} {
		found := false
		for _, m := range jd.spatialMatch([]rune(c.pw)) {
			if m.graph.name == c.graph && string(m.token) == c.pw {
				found = true
				if m.turns != c.turns || m.shifted != c.shifted {
					t.Errorf("%q: turns %d shifted %d", c.pw, m.turns, m.shifted)
				}
			}
		}
		if !found {
			t.Errorf("%q isn't a %s walk", c.pw, c.graph)
		}
	}
	found := false
	for _, m := range jd.spatialMatch([]rune("rz!6tfGHJ%z")) {
		found = found || m.graph.name == "qwerty" && m.i == 3 && m.j == 8 && m.turns == 2 && m.shifted == 3
	}
	if !found {
		t.Error("an embedded walk")
	}
}

func TestSequenceMatch(t *testing.T) {
	for _, pw := range []string{"", "a", "1"} {
		if len(sequenceMatch([]rune(pw))) != 0 {
			t.Errorf("%q matched", pw)
		}
	}
	if got := strings.Join(spans(sequenceMatch([]rune("abcbabc")), sequence), ","); got != "abc,cba,abc" {
		t.Errorf("overlapping: %s", got)
	}
	for _, pw := range []string{"!jihg22", "22jihg!", "jihg"} {
		if got := spans(sequenceMatch([]rune(pw)), sequence); !containsStr(got, "jihg") {
			t.Errorf("%q: %v", pw, got)
		}
	}
	for _, c := range []struct {
		pw  string
		asc bool
	}{
		{"ABC", true}, {"CBA", false}, {"PQR", true}, {"RQP", false}, {"XYZ", true}, {"ZYX", false},
		{"abcd", true}, {"dcba", false}, {"jihg", false}, {"wxyz", true}, {"zxvt", false}, {"0369", true}, {"97531", false},
	} {
		ms := sequenceMatch([]rune(c.pw))
		if len(ms) != 1 || string(ms[0].token) != c.pw || ms[0].ascending != c.asc {
			t.Errorf("%q: %v", c.pw, spans(ms, sequence))
		}
	}
}

func containsStr(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

func TestRepeatMatch(t *testing.T) {
	jd := newJudge(2026, nil)
	base := func(ms []*match) (out []string) {
		for _, m := range ms {
			out = append(out, string(m.token)+"/"+string(m.token[:len(m.token)/m.count]))
		}
		return out
	}
	for _, c := range []struct{ pw, want string }{
		{"", ""}, {"#", ""},
		{"@&&&&&u", "&&&&&/&"}, {"y4@&&&&&u%7", "&&&&&/&"},
		{"aaa", "aaa/a"}, {"ZZZZZZZZZZZZ", "ZZZZZZZZZZZZ/Z"},
		{"BBB1111aaaaa@@@@@@", "BBB/B,1111/1,aaaaa/a,@@@@@@/@"},
		{"2818BBBbzsdf1111@*&@!aaaaaEUDA@@@@@@1729", "BBB/B,1111/1,aaaaa/a,@@@@@@/@"},
		{"abab", "abab/ab"}, {"aabaab", "aabaab/aab"}, {"abababab", "abababab/ab"},
	} {
		if got := strings.Join(base(jd.repeatMatch([]rune(c.pw))), ","); got != c.want {
			t.Errorf("%q: %s, want %s", c.pw, got, c.want)
		}
	}
	// The repeat costs its unit's estimate times the count.
	ms := jd.repeatMatch([]rune("batterystaplebatterystaplebatterystaple"))
	unit := jd.analyze([]rune("batterystaple"))
	if len(ms) != 1 || ms[0].count != 3 || jd.guesses(ms[0], 39) != unit.guesses*3 {
		t.Errorf("batterystaple: %v", base(ms))
	}
}

func TestYearAndDateMatch(t *testing.T) {
	for _, pw := range []string{"1922", "2017", "2026"} {
		if ms := yearMatch([]rune(pw)); len(ms) != 1 || string(ms[0].token) != pw {
			t.Errorf("%q", pw)
		}
	}
	jd := newJudge(2026, nil)
	for _, sep := range []string{"", " ", "-", "/", "\\", "_", "."} {
		pw := "13" + sep + "2" + sep + "1921"
		ms := jd.dateMatch([]rune(pw))
		if len(ms) != 1 || string(ms[0].token) != pw || ms[0].year != 1921 || ms[0].separator != (sep != "") {
			t.Errorf("%q: %v", pw, spans(ms, date))
		}
	}
	for _, c := range []struct {
		pw   string
		year int
	}{
		{"8.8.88", 1988}, {"88.8.8", 1988}, {"111504", 2004}, {"1/1/91", 1991}, {"02/02/02", 2002}, {"2015_06_04", 2015},
	} {
		ms := jd.dateMatch([]rune(c.pw))
		if len(ms) != 1 || string(ms[0].token) != c.pw || ms[0].year != c.year {
			t.Errorf("%q: %v", c.pw, spans(ms, date))
		}
	}
	for _, pw := range []string{"0/0/0000", "32/32/32"} {
		if ms := jd.dateMatch([]rune(pw)); len(ms) != 0 {
			t.Errorf("%q matched %v", pw, spans(ms, date))
		}
	}
}

// Results zxcvbn's demo gives, which the port reproduces.
func TestKnownEstimates(t *testing.T) {
	for _, c := range []struct {
		pw    string
		log10 float64
		score int
	}{
		{"password", 0.477, 0},
		{"correcthorsebatterystaple", 14.437, 4},
		{"Tr0ub4dour&3", 7.280, 2},
	} {
		e := newJudge(2026, nil).analyze([]rune(c.pw))
		if math.Abs(math.Log10(e.guesses)-c.log10) > 0.001 || e.score() != c.score {
			t.Errorf("%q: log10 %.3f score %d", c.pw, math.Log10(e.guesses), e.score())
		}
	}
}

// Check reads at most maxJudged characters, so the slowest input of the
// longest allowed size stays cheap, and none panics.
func TestWorstCases(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	inputs := []string{
		strings.Repeat("a", MaxInput), strings.Repeat("1|7", 341), strings.Repeat("ab", 512),
		strings.Repeat("password", 128), strings.Repeat("12/12/1990", 102), strings.Repeat("qwerty", 170),
		strings.Repeat("ش", 512), strings.Repeat("4@1!|70$5+%2", 85),
	}
	for range 50 {
		b := make([]byte, 100+r.IntN(900))
		for i := range b {
			b[i] = byte(32 + r.IntN(95))
		}
		inputs = append(inputs, string(b))
	}
	start := time.Now()
	for _, in := range inputs {
		Check(in, rules, "sara.ali@example.com", "Sara Ali")
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("%d inputs took %v", len(inputs), d)
	}
}

func FuzzCheck(f *testing.F) {
	for _, s := range []string{"", "password", "p4@ssw0rd1990", "abab", "13/2/1921", "\xff\xfe", "aaaa1111bbbb"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, pw string) {
		Check(pw, rules, "hint")
	})
}

func BenchmarkCheck(b *testing.B) {
	for _, pw := range []string{"correct horse battery staple", strings.Repeat("Tr0ub4dour&3", 9)} {
		b.Run(pw[:12], func(b *testing.B) {
			for b.Loop() {
				Check(pw, rules, "sara.ali@example.com", "Sara Ali", "Toy Shop")
			}
		})
	}
}
