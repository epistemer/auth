//go:build ignore

// extract writes this directory's lists and graphs from zxcvbn's sources
// (ADR 0006). Run it from this directory with the path of a zxcvbn checkout
// at the commit ADR 0006 names:
//
//	go run extract.go /path/to/zxcvbn
//
// It reads src/frequency_lists.coffee and src/adjacency_graphs.coffee,
// which are generated files of one known shape, and fails on anything else.
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	listLine  = regexp.MustCompile(`^  ([a-z_]+): "(.*)"\.split\(","\)$`)
	graphLine = regexp.MustCompile(`^  ([a-z_]+): (\{.*\})$`)
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: go run extract.go <zxcvbn checkout>")
		os.Exit(2)
	}
	src := filepath.Join(os.Args[1], "src")
	if err := lists(filepath.Join(src, "frequency_lists.coffee")); err != nil {
		fail(err)
	}
	if err := graphs(filepath.Join(src, "adjacency_graphs.coffee")); err != nil {
		fail(err)
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

func lines(path string, f func(string) error) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	s := bufio.NewScanner(bytes.NewReader(b))
	s.Buffer(nil, 4<<20)
	for s.Scan() {
		if err := f(s.Text()); err != nil {
			return err
		}
	}
	return s.Err()
}

func lists(path string) error {
	n := 0
	err := lines(path, func(l string) error {
		m := listLine.FindStringSubmatch(l)
		if m == nil {
			return nil
		}
		body := m[2]
		if strings.Contains(body, "#{") {
			return fmt.Errorf("%s: interpolation in a list", m[1])
		}
		// The only escape the file uses is \' (one password); undo any.
		body = regexp.MustCompile(`\\(.)`).ReplaceAllString(body, "$1")
		words := strings.Split(body, ",")
		for _, w := range words {
			if w == "" || strings.ContainsAny(w, "\n\r") {
				return fmt.Errorf("%s: bad word %q", m[1], w)
			}
		}
		n++
		return os.WriteFile(m[1]+".txt", []byte(strings.Join(words, "\n")+"\n"), 0o644)
	})
	if err == nil && n != 6 {
		err = fmt.Errorf("found %d lists, want 6", n)
	}
	return err
}

func graphs(path string) error {
	out := map[string]map[string][]*string{}
	err := lines(path, func(l string) error {
		m := graphLine.FindStringSubmatch(l)
		if m == nil {
			return nil
		}
		var g map[string][]*string
		if err := json.Unmarshal([]byte(m[2]), &g); err != nil {
			return fmt.Errorf("%s: %w", m[1], err)
		}
		out[m[1]] = g
		return nil
	})
	if err != nil {
		return err
	}
	if len(out) != 4 {
		return fmt.Errorf("found %d graphs, want 4", len(out))
	}
	b, err := json.MarshalIndent(out, "", "\t")
	if err != nil {
		return err
	}
	return os.WriteFile("graphs.json", append(b, '\n'), 0o644)
}
