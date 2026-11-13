// Ranks versions with golang.org/x/mod/semver (gen.sh copies the copy
// vendored in GOROOT next to this file as package main) and marks
// pseudo-versions with module.IsPseudoVersion's expression.
// Usage: go run . versions.lines outdir
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

var pseudoVersionRE = regexp.MustCompile(`^v[0-9]+\.(0\.0-|\d+\.\d+-([^+]*\.)?0\.)\d{14}-[A-Za-z0-9]+(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$`)

func isPseudo(v string) bool {
	return strings.Count(v, "-") >= 2 && IsValid(v) && pseudoVersionRE.MatchString(v)
}

func main() {
	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		panic(err)
	}
	var in []string
	for _, line := range strings.Split(string(data), "\n") {
		if line == "" {
			continue
		}
		var s string
		if err := json.Unmarshal([]byte(line), &s); err != nil {
			panic(err)
		}
		in = append(in, s)
	}
	seen := map[string]bool{}
	var vs []string
	for _, v := range in {
		if !seen[v] {
			seen[v] = true
			vs = append(vs, v)
		}
	}
	var valid []string
	for _, v := range vs {
		if IsValid(v) {
			valid = append(valid, v)
		}
	}
	sort.SliceStable(valid, func(i, j int) bool { return Compare(valid[i], valid[j]) < 0 })
	rank := map[string]int{}
	r := -1
	for i, v := range valid {
		if i == 0 || Compare(valid[i-1], v) != 0 {
			r++
		}
		rank[v] = r
	}
	out, err := os.Create(filepath.Join(os.Args[2], "go-versions.tsv"))
	if err != nil {
		panic(err)
	}
	defer out.Close()
	for _, v := range vs {
		q, _ := json.Marshal(v)
		rk := -1
		if IsValid(v) {
			rk = rank[v]
		}
		p := 0
		if isPseudo(v) {
			p = 1
		}
		fmt.Fprintf(out, "%s\t%d\t%d\n", q, rk, p)
	}
}
