package nameguard

import "testing"

func TestDamerauLevenshtein(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"requests", "requests", 0},
		{"reqeusts", "requests", 1}, // adjacent transposition
		{"request", "requests", 1},  // single insertion
		{"expres", "express", 1},    // single deletion
		{"lodahs", "lodash", 1},     // transposition
		{"numpy", "numpy", 0},
		{"", "abc", 3},
		{"abc", "", 3},
		{"kitten", "sitting", 3}, // classic
		{"flask", "flake", 2},    // two substitutions, not a transposition
	}
	for _, tt := range tests {
		if got := damerauLevenshtein(tt.a, tt.b, -1); got != tt.want {
			t.Errorf("damerauLevenshtein(%q,%q) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestDamerauLevenshteinBounded(t *testing.T) {
	// When the true distance exceeds the bound, the function returns max+1 rather
	// than the exact value (an early-exit optimization).
	if got := damerauLevenshtein("abcdefgh", "stuvwxyz", 2); got <= 2 {
		t.Errorf("expected bounded result > 2 for distant strings, got %d", got)
	}
	// A length difference greater than the bound short-circuits immediately.
	if got := damerauLevenshtein("a", "abcdef", 2); got != 3 {
		t.Errorf("expected 3 (max+1) for length-diff short-circuit, got %d", got)
	}
	// Within the bound, the exact distance is returned.
	if got := damerauLevenshtein("reqeusts", "requests", 2); got != 1 {
		t.Errorf("expected exact distance 1 within bound, got %d", got)
	}
}

func TestConfusableCanonical(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"lodash", "lodash"},
		{"1odash", "lodash"},  // digit one -> l
		{"l0dash", "lodash"},  // zero -> o
		{"rnoment", "moment"}, // rn -> m
		{"reque5ts", "requests"},
		{"expre$$", "express"},
		{"vviki", "wiki"}, // vv -> w
	}
	for _, tt := range tests {
		if got := confusableCanonical(tt.in); got != tt.want {
			t.Errorf("confusableCanonical(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestHomoglyphSkeleton(t *testing.T) {
	// "reаct" with a Cyrillic 'а' (U+0430) folds to ASCII "react" via a known map.
	skeleton, mapped, nonASCII := homoglyphSkeleton("reаct")
	if skeleton != "react" {
		t.Errorf("skeleton = %q, want %q", skeleton, "react")
	}
	if !mapped || !nonASCII {
		t.Errorf("expected mapped=true nonASCII=true, got mapped=%v nonASCII=%v", mapped, nonASCII)
	}

	// A pure-ASCII name yields no skeletonization.
	if _, mapped, nonASCII := homoglyphSkeleton("react"); mapped || nonASCII {
		t.Errorf("pure ASCII should not be flagged, got mapped=%v nonASCII=%v", mapped, nonASCII)
	}

	// An accented but unmapped non-ASCII letter is flagged nonASCII but not mapped.
	if _, mapped, nonASCII := homoglyphSkeleton("café"); mapped || !nonASCII {
		t.Errorf("accented name: want mapped=false nonASCII=true, got mapped=%v nonASCII=%v", mapped, nonASCII)
	}
}
