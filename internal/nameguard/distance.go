package nameguard

import "strings"

// damerauLevenshtein computes the optimal string alignment (OSA) edit distance
// between a and b over runes — insertions, deletions, substitutions, and
// transpositions of adjacent characters. OSA is sufficient for catching the
// single-keystroke errors typosquats exploit (a transposition like "reqeusts" vs
// "requests" is distance 1).
//
// When max >= 0 the computation short-circuits: if every cell of a row exceeds
// max the function returns max+1, so a scan over a large popular-name list does
// not pay full DP cost for obviously-distant candidates.
func damerauLevenshtein(a, b string, max int) int {
	ra, rb := []rune(a), []rune(b)
	la, lb := len(ra), len(rb)
	if la == 0 {
		return lb
	}
	if lb == 0 {
		return la
	}
	// Length difference is a lower bound on the distance; bail early.
	if max >= 0 {
		diff := la - lb
		if diff < 0 {
			diff = -diff
		}
		if diff > max {
			return max + 1
		}
	}

	prev2 := make([]int, lb+1) // row i-2
	prev := make([]int, lb+1)  // row i-1
	curr := make([]int, lb+1)  // row i
	for j := 0; j <= lb; j++ {
		prev[j] = j
	}

	for i := 1; i <= la; i++ {
		curr[0] = i
		rowMin := curr[0]
		for j := 1; j <= lb; j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			del := prev[j] + 1
			ins := curr[j-1] + 1
			sub := prev[j-1] + cost
			best := min3(del, ins, sub)
			if i > 1 && j > 1 && ra[i-1] == rb[j-2] && ra[i-2] == rb[j-1] {
				if t := prev2[j-2] + 1; t < best {
					best = t
				}
			}
			curr[j] = best
			if best < rowMin {
				rowMin = best
			}
		}
		if max >= 0 && rowMin > max {
			return max + 1
		}
		prev2, prev, curr = prev, curr, prev2
	}
	return prev[lb]
}

func min3(a, b, c int) int {
	if b < a {
		a = b
	}
	if c < a {
		a = c
	}
	return a
}

// confusableCanonical collapses visually-confusable ASCII substitutions so a name
// that looks identical to a popular one — but uses look-alike characters — folds
// to the same string. It maps digit/punctuation homoglyphs to their letter form
// (0→o, 1→l, 3→e, 5→s, |→l) and the classic multi-character "rn"→"m" and "vv"→"w"
// ligature squats. Applied symmetrically to both the candidate and the popular
// name, an exact post-canonicalization match with differing raw forms is a
// high-confidence typosquat.
func confusableCanonical(s string) string {
	s = strings.ToLower(s)
	s = strings.ReplaceAll(s, "rn", "m")
	s = strings.ReplaceAll(s, "vv", "w")
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch r {
		case '0':
			b.WriteByte('o')
		case '1', '|', '!':
			b.WriteByte('l')
		case '3':
			b.WriteByte('e')
		case '4':
			b.WriteByte('a')
		case '5', '$':
			b.WriteByte('s')
		case '7':
			b.WriteByte('t')
		case '8':
			b.WriteByte('b')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// homoglyphMap maps non-ASCII characters that visually resemble an ASCII letter
// to that letter. It covers the Cyrillic and Greek confusables most commonly
// abused in package-name spoofing; the list is intentionally conservative (only
// genuine look-alikes) to avoid mis-skeletonizing legitimately non-ASCII names.
var homoglyphMap = map[rune]rune{
	// Cyrillic lowercase look-alikes.
	'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x',
	'к': 'k', 'м': 'm', 'т': 't', 'н': 'h', 'в': 'b', 'і': 'i', 'ѕ': 's',
	'ј': 'j', 'ԁ': 'd', 'џ': 'u', 'ё': 'e',
	// Greek lowercase look-alikes.
	'α': 'a', 'β': 'b', 'ο': 'o', 'ρ': 'p', 'ν': 'v', 'τ': 't', 'υ': 'u',
	'χ': 'x', 'ι': 'i', 'κ': 'k', 'μ': 'm', 'ε': 'e',
	// Fullwidth / other Latin look-alikes.
	'ⅼ': 'l', 'ⅰ': 'i', 'ｏ': 'o', 'ａ': 'a',
}

// homoglyphSkeleton returns the name with confusable non-ASCII characters mapped
// to their ASCII look-alike. It separately reports whether a known look-alike
// mapping was applied (mapped — a deliberate spoofing character) and whether any
// non-ASCII letter at all was present (nonASCII). The two are distinguished so a
// known confusable (a Cyrillic 'а' for Latin 'a') is treated as more suspicious
// than a merely-accented but unmapped non-ASCII letter.
func homoglyphSkeleton(name string) (skeleton string, mapped, nonASCII bool) {
	var b strings.Builder
	b.Grow(len(name))
	for _, r := range name {
		if m, ok := homoglyphMap[r]; ok {
			b.WriteRune(m)
			mapped = true
			nonASCII = true
			continue
		}
		if r > 127 && isLetterish(r) {
			nonASCII = true
		}
		b.WriteRune(r)
	}
	return b.String(), mapped, nonASCII
}

// isLetterish reports whether r is a letter-category rune (used to decide whether
// a non-ASCII rune is a suspicious letter substitution rather than, say, a digit
// or punctuation that some registries legitimately allow). It avoids importing
// unicode tables for the full property set by checking the common letter ranges.
func isLetterish(r rune) bool {
	switch {
	case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z':
		return true
	case r >= 0x00C0 && r <= 0x024F: // Latin-1 supplement + extended
		return true
	case r >= 0x0370 && r <= 0x03FF: // Greek
		return true
	case r >= 0x0400 && r <= 0x04FF: // Cyrillic
		return true
	case r >= 0x2C60 && r <= 0x2C7F, r >= 0x1E00 && r <= 0x1EFF: // Latin extended additional
		return true
	case r >= 0xFF00 && r <= 0xFFEF: // Halfwidth/Fullwidth forms
		return true
	default:
		return false
	}
}

// hasNonASCII reports whether s contains any rune above the ASCII range.
func hasNonASCII(s string) bool {
	for _, r := range s {
		if r > 127 {
			return true
		}
	}
	return false
}
