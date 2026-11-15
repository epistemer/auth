package password

// This file and match.go port zxcvbn's estimator (Dan Wheeler and Dropbox,
// MIT; data/LICENSE.zxcvbn), at the commit ADR 0006 names. The model is
// zxcvbn's: find every guessable piece of a password, then the cheapest way
// to cover it with pieces and brute force. Where the port departs from it,
// a comment says so.

import (
	"bufio"
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"math"
	"slices"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// maxJudged is how many characters of a password the estimator reads, as
// zxcvbn advises: past it, the cost grows to seconds. See estimateLong.
const maxJudged = 100

//go:embed data/*.txt data/graphs.json
var dataFS embed.FS

// lists are zxcvbn's ranked lists, by file name. A word is in one list
// only, the one where its rank is lowest.
var lists = []string{"passwords", "english_wikipedia", "female_names", "surnames", "us_tv_and_film", "male_names"}

// userList stands for the hints in a match's list field.
const userList = -1

type entry struct {
	list int
	rank int
}

type graph struct {
	name     string
	keyboard bool              // qwerty and dvorak, as against the keypads
	adj      map[rune][][]rune // neighbours by direction; nil where there is none
}

type corpus struct {
	words  map[string]entry
	maxLen int // the longest word, in characters
	graphs []*graph

	keyboardStarts, keypadStarts float64
	keyboardDegree, keypadDegree float64
}

var load = sync.OnceValue(func() *corpus {
	c, err := parse()
	if err != nil {
		panic("password: embedded data: " + err.Error())
	}
	return c
})

func parse() (*corpus, error) {
	c := &corpus{words: map[string]entry{}}
	for li, name := range lists {
		b, err := dataFS.ReadFile("data/" + name + ".txt")
		if err != nil {
			return nil, err
		}
		s := bufio.NewScanner(bytes.NewReader(b))
		for rank := 1; s.Scan(); rank++ {
			w := s.Text()
			if e, ok := c.words[w]; !ok || rank < e.rank {
				c.words[w] = entry{li, rank}
			}
			c.maxLen = max(c.maxLen, utf8.RuneCountInString(w))
		}
	}
	b, err := dataFS.ReadFile("data/graphs.json")
	if err != nil {
		return nil, err
	}
	var raw map[string]map[string][]*string
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, err
	}
	for _, name := range []string{"qwerty", "dvorak", "keypad", "mac_keypad"} {
		g := &graph{name: name, keyboard: name == "qwerty" || name == "dvorak", adj: map[rune][][]rune{}}
		if raw[name] == nil {
			return nil, fmt.Errorf("no graph %s", name)
		}
		for k, ns := range raw[name] {
			r, size := utf8.DecodeRuneInString(k)
			if size != len(k) {
				return nil, fmt.Errorf("graph %s: key %q", name, k)
			}
			dirs := make([][]rune, len(ns))
			for i, n := range ns {
				if n != nil {
					dirs[i] = []rune(*n)
				}
			}
			g.adj[r] = dirs
		}
		c.graphs = append(c.graphs, g)
	}
	c.keyboardStarts, c.keyboardDegree = shape(c.graphs[0])
	c.keypadStarts, c.keypadDegree = shape(c.graphs[2])
	return c, nil
}

// shape returns a graph's number of keys and their average number of
// neighbours.
func shape(g *graph) (keys, degree float64) {
	n := 0
	for _, dirs := range g.adj {
		for _, d := range dirs {
			if d != nil {
				n++
			}
		}
	}
	return float64(len(g.adj)), float64(n) / float64(len(g.adj))
}

type pattern uint8

const (
	bruteforce pattern = iota
	dictionary
	spatial
	repeat
	sequence
	recentYear // zxcvbn's regex matcher, whose one regex finds years
	date
)

type match struct {
	pattern pattern
	i, j    int    // the characters covered, inclusive
	token   []rune // as typed

	// dictionary
	word     string // as listed: lower case, substitutions undone
	list     int    // an index into lists, or userList
	rank     int
	reversed bool
	sub      map[rune]rune // l33t: the substitutions the token uses

	// spatial
	graph          *graph
	turns, shifted int

	// repeat
	base  float64 // the guesses of the repeated unit
	count int

	// sequence
	ascending bool

	// recentYear, date
	year      int
	separator bool

	guesses float64 // 0 until estimated
}

// judge holds what one estimate needs besides the password.
type judge struct {
	c       *corpus
	user    map[string]int // the hints, ranked in the order given
	userMax int
	year    int // the reference year: dates near it are guessed first
}

func newJudge(year int, hints []string) *judge {
	j := &judge{c: load(), user: map[string]int{}, year: year}
	add := func(w string) {
		if w == "" {
			return
		}
		if _, ok := j.user[w]; !ok {
			j.user[w] = len(j.user) + 1
			j.userMax = max(j.userMax, utf8.RuneCountInString(w))
		}
	}
	// zxcvbn ranks each hint whole. A login or an address whole rarely
	// appears in a password, so its words are ranked too, and joined: "Red
	// Hat" gives red hat, red, hat and redhat.
	for _, h := range hints {
		if len(h) > MaxInput {
			h = strings.ToValidUTF8(h[:MaxInput], "")
		}
		n := norm.NFKC.String(h)
		add(string(lowerRunes([]rune(n))))
		ws := words(n, 1)
		for _, w := range ws {
			if utf8.RuneCountInString(w) >= 3 {
				add(w)
			}
		}
		if len(ws) > 1 {
			add(strings.Join(ws, ""))
		}
	}
	return j
}

// estimate is a password's guesses and the matches that cover it.
type estimate struct {
	guesses float64
	seq     []*match
}

// score maps guesses to zxcvbn's 0 to 4, with its small allowance at each
// boundary.
func (e estimate) score() int {
	const delta = 5
	switch g := e.guesses; {
	case g < 1e3+delta:
		return 0
	case g < 1e6+delta:
		return 1
	case g < 1e8+delta:
		return 2
	case g < 1e10+delta:
		return 3
	}
	return 4
}

func (jd *judge) analyze(pw []rune) estimate {
	return jd.cheapest(pw, jd.omnimatch(pw))
}

const (
	bruteforceCardinality  = 10
	minGuessesBeforeGrowth = 10000
	minSubmatchSingle      = 10
	minSubmatchMulti       = 50
)

// cheapest finds the covering of pw with the fewest guesses, where a
// covering of l matches costs l! times the product of their guesses, plus
// minGuessesBeforeGrowth^(l-1): the attacker tries every order of the
// pieces, and shorter coverings first. It is zxcvbn's dynamic programme.
func (jd *judge) cheapest(pw []rune, ms []*match) estimate {
	n := len(pw)
	if n == 0 {
		return estimate{guesses: 1}
	}
	byEnd := make([][]*match, n)
	for _, m := range ms {
		byEnd[m.j] = append(byEnd[m.j], m)
	}
	for _, l := range byEnd {
		slices.SortStableFunc(l, func(a, b *match) int { return a.i - b.i })
	}
	// best[k][l] is the cheapest covering of pw[:k+1] by l matches, kept
	// only while no covering by l or fewer is cheaper.
	type cell struct {
		m     *match
		pi, g float64
	}
	best := make([]map[int]cell, n)
	for k := range best {
		best[k] = map[int]cell{}
	}
	lengths := func(k int) []int {
		ls := make([]int, 0, len(best[k]))
		for l := range best[k] {
			ls = append(ls, l)
		}
		slices.Sort(ls)
		return ls
	}
	update := func(m *match, l int) {
		k := m.j
		pi := jd.guesses(m, n)
		if l > 1 {
			pi = finite(pi * best[m.i-1][l-1].pi)
		}
		g := finite(factorial(l)*pi + math.Pow(minGuessesBeforeGrowth, float64(l-1)))
		for cl, c := range best[k] {
			if cl <= l && c.g <= g {
				return
			}
		}
		best[k][l] = cell{m, pi, g}
	}
	brute := func(i, j int) *match {
		return &match{pattern: bruteforce, i: i, j: j, token: pw[i : j+1]}
	}
	for k := range n {
		for _, m := range byEnd[k] {
			if m.i > 0 {
				for _, l := range lengths(m.i - 1) {
					update(m, l+1)
				}
			} else {
				update(m, 1)
			}
		}
		update(brute(0, k), 1)
		for i := 1; i <= k; i++ {
			m := brute(i, k)
			for _, l := range lengths(i - 1) {
				// Two bruteforce matches side by side are never cheaper
				// than one over both.
				if best[i-1][l].m.pattern == bruteforce {
					continue
				}
				update(m, l+1)
			}
		}
	}
	bestL, bestG := 0, math.Inf(1)
	for _, l := range lengths(n - 1) {
		if g := best[n-1][l].g; g < bestG {
			bestL, bestG = l, g
		}
	}
	var seq []*match
	for k, l := n-1, bestL; k >= 0; l-- {
		m := best[k][l].m
		seq = append(seq, m)
		k = m.i - 1
	}
	slices.Reverse(seq)
	return estimate{guesses: bestG, seq: seq}
}

func factorial(n int) float64 {
	f := 1.0
	for i := 2; i <= n; i++ {
		f *= float64(i)
	}
	return f
}

func nCk(n, k int) float64 {
	if k > n {
		return 0
	}
	r := 1.0
	for d := 1; d <= k; d++ {
		r *= float64(n)
		r /= float64(d)
		n--
	}
	return r
}

// guesses estimates one match, within a password of n characters, once.
func (jd *judge) guesses(m *match, n int) float64 {
	if m.guesses != 0 {
		return m.guesses
	}
	least := 1.0
	if len(m.token) < n {
		least = minSubmatchMulti
		if len(m.token) == 1 {
			least = minSubmatchSingle
		}
	}
	var g float64
	switch m.pattern {
	case bruteforce:
		g = math.Pow(bruteforceCardinality, float64(len(m.token)))
		// One more than a submatch's least, so that any other match over
		// the same characters wins.
		floor := float64(minSubmatchMulti + 1)
		if len(m.token) == 1 {
			floor = minSubmatchSingle + 1
		}
		g = max(g, floor)
	case dictionary:
		g = float64(m.rank) * upperVariations(m.token) * l33tVariations(m)
		if m.reversed {
			g *= 2
		}
	case spatial:
		g = jd.spatialGuesses(m)
	case repeat:
		g = m.base * float64(m.count)
	case sequence:
		g = sequenceGuesses(m)
	case recentYear:
		g = math.Max(math.Abs(float64(m.year-jd.year)), minYearSpace)
	case date:
		g = math.Max(math.Abs(float64(m.year-jd.year)), minYearSpace) * 365
		if m.separator {
			g *= 4
		}
	}
	m.guesses = finite(max(g, least))
	return m.guesses
}

// finite keeps a product of guesses from overflowing to +Inf, where every
// covering would look alike: past 10^308 all are as strong as can be.
func finite(g float64) float64 {
	return min(g, math.MaxFloat64)
}

const minYearSpace = 20

func sequenceGuesses(m *match) float64 {
	var base float64
	switch first := m.token[0]; {
	case first == 'a' || first == 'A' || first == 'z' || first == 'Z' ||
		first == '0' || first == '1' || first == '9':
		base = 4 // the obvious starting points
	case '0' <= first && first <= '9':
		base = 10
	default:
		base = 26
	}
	if !m.ascending {
		base *= 2
	}
	return base * float64(len(m.token))
}

func (jd *judge) spatialGuesses(m *match) float64 {
	s, d := jd.c.keypadStarts, jd.c.keypadDegree
	if m.graph.keyboard {
		s, d = jd.c.keyboardStarts, jd.c.keyboardDegree
	}
	var g float64
	L, t := len(m.token), m.turns
	// The patterns of length L or less with t turns or less.
	for i := 2; i <= L; i++ {
		for j := 1; j <= min(t, i-1); j++ {
			g += nCk(i-1, j-1) * s * math.Pow(d, float64(j))
		}
	}
	if m.shifted > 0 {
		S, U := m.shifted, L-m.shifted
		if U == 0 {
			g *= 2
		} else {
			var v float64
			for i := 1; i <= min(S, U); i++ {
				v += nCk(S+U, i)
			}
			g *= v
		}
	}
	return g
}

// upperVariations counts the ways the attacker capitalizes the word. The
// port judges upper and lower case by Unicode, where zxcvbn knows only A–Z.
func upperVariations(token []rune) float64 {
	var upper, lower int
	for _, r := range token {
		switch {
		case unicode.IsUpper(r):
			upper++
		case unicode.IsLower(r):
			lower++
		}
	}
	if upper == 0 {
		return 1
	}
	if lower == 0 {
		return 2 // all capitals
	}
	// The first or the last letter alone in capitals: one common scheme.
	if upper == 1 && (unicode.IsUpper(token[0]) || unicode.IsUpper(token[len(token)-1])) {
		return 2
	}
	var v float64
	for i := 1; i <= min(upper, lower); i++ {
		v += nCk(upper+lower, i)
	}
	return v
}

func l33tVariations(m *match) float64 {
	if m.sub == nil {
		return 1
	}
	v := 1.0
	lower := lowerRunes(m.token)
	for subbed, letter := range m.sub {
		var S, U int
		for _, r := range lower {
			switch r {
			case subbed:
				S++
			case letter:
				U++
			}
		}
		if S == 0 || U == 0 {
			v *= 2
			continue
		}
		var p float64
		for i := 1; i <= min(U, S); i++ {
			p += nCk(U+S, i)
		}
		v *= p
	}
	return v
}

func lowerRunes(r []rune) []rune {
	out := make([]rune, len(r))
	for i, c := range r {
		out[i] = unicode.ToLower(c)
	}
	return out
}
