package vulnscan

import (
	"math"
	"strings"
)

// ParseCVSSBaseScore computes the CVSS base score from a v3.0/v3.1 or v4.0 vector
// string and reports whether the vector was understood. For v3.x it implements
// the official base-score formula (CVSS v3.1 specification §7.1); for v4.0, whose
// scoring is a non-closed-form lookup table, it falls back to a conservative
// qualitative approximation from the exploitability/impact metrics. The boolean
// is false for an unrecognized or unparseable vector so the caller can fall back
// to a database-supplied qualitative rating.
func ParseCVSSBaseScore(vector string) (float64, bool) {
	v := strings.ToUpper(strings.TrimSpace(vector))
	switch {
	case strings.HasPrefix(v, "CVSS:3.0/"), strings.HasPrefix(v, "CVSS:3.1/"):
		return cvss3BaseScore(v[len("CVSS:3.0/"):])
	case strings.HasPrefix(v, "CVSS:4.0/"):
		return cvss4ApproxScore(v[len("CVSS:4.0/"):])
	default:
		return 0, false
	}
}

// metricMap parses the "KEY:VALUE/KEY:VALUE" body of a CVSS vector into a map.
func metricMap(body string) map[string]string {
	m := make(map[string]string)
	for _, part := range strings.Split(body, "/") {
		k, val, ok := strings.Cut(part, ":")
		if ok {
			m[strings.TrimSpace(k)] = strings.TrimSpace(val)
		}
	}
	return m
}

// cvss3BaseScore implements the CVSS v3.1 base-score formula. It returns false
// when a required base metric is missing or has an unknown value.
func cvss3BaseScore(body string) (float64, bool) {
	m := metricMap(body)

	av, ok := lookup(map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}, m["AV"])
	if !ok {
		return 0, false
	}
	ac, ok := lookup(map[string]float64{"L": 0.77, "H": 0.44}, m["AC"])
	if !ok {
		return 0, false
	}
	ui, ok := lookup(map[string]float64{"N": 0.85, "R": 0.62}, m["UI"])
	if !ok {
		return 0, false
	}
	scopeChanged, ok := scope(m["S"])
	if !ok {
		return 0, false
	}
	// Privileges Required is scope-dependent: an unchanged scope discounts L/H less
	// than a changed scope does.
	var prTable map[string]float64
	if scopeChanged {
		prTable = map[string]float64{"N": 0.85, "L": 0.68, "H": 0.50}
	} else {
		prTable = map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}
	}
	pr, ok := lookup(prTable, m["PR"])
	if !ok {
		return 0, false
	}

	impactTable := map[string]float64{"H": 0.56, "L": 0.22, "N": 0.00}
	c, ok := lookup(impactTable, m["C"])
	if !ok {
		return 0, false
	}
	i, ok := lookup(impactTable, m["I"])
	if !ok {
		return 0, false
	}
	a, ok := lookup(impactTable, m["A"])
	if !ok {
		return 0, false
	}

	iscBase := 1 - (1-c)*(1-i)*(1-a)
	var impact float64
	if scopeChanged {
		impact = 7.52*(iscBase-0.029) - 3.25*math.Pow(iscBase-0.02, 15)
	} else {
		impact = 6.42 * iscBase
	}
	if impact <= 0 {
		return 0, true
	}

	exploitability := 8.22 * av * ac * pr * ui
	var base float64
	if scopeChanged {
		base = roundUp1(math.Min(1.08*(impact+exploitability), 10))
	} else {
		base = roundUp1(math.Min(impact+exploitability, 10))
	}
	return base, true
}

// cvss4ApproxScore approximates a CVSS v4.0 base score. The official v4.0 scoring
// is a discrete lookup over a large equivalence-class table that does not reduce
// to a formula; rather than vendor that table we derive a conservative qualitative
// score from the attack and impact metrics, which is sufficient for severity-
// threshold gating. It returns false when no base impact metric is present.
func cvss4ApproxScore(body string) (float64, bool) {
	m := metricMap(body)
	impactTable := map[string]float64{"H": 0.56, "L": 0.22, "N": 0.00}
	// v4.0 splits impact into Vulnerable-System (VC/VI/VA) and Subsequent-System
	// (SC/SI/SA); take the strongest of each dimension.
	vc := maxImpact(impactTable, m["VC"], m["SC"])
	vi := maxImpact(impactTable, m["VI"], m["SI"])
	va := maxImpact(impactTable, m["VA"], m["SA"])
	if _, ok := m["VC"]; !ok {
		if _, ok2 := m["VI"]; !ok2 {
			if _, ok3 := m["VA"]; !ok3 {
				return 0, false
			}
		}
	}
	iscBase := 1 - (1-vc)*(1-vi)*(1-va)
	impact := 6.42 * iscBase

	av, _ := lookup(map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}, m["AV"])
	ac, _ := lookup(map[string]float64{"L": 0.77, "H": 0.44}, m["AC"])
	ui, _ := lookup(map[string]float64{"N": 0.85, "P": 0.62, "A": 0.62, "R": 0.62}, m["UI"])
	pr, _ := lookup(map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}, m["PR"])
	exploitability := 8.22 * av * ac * pr * ui

	if impact <= 0 {
		return 0, true
	}
	return roundUp1(math.Min(impact+exploitability, 10)), true
}

func maxImpact(table map[string]float64, a, b string) float64 {
	va, _ := lookup(table, a)
	vb, _ := lookup(table, b)
	return math.Max(va, vb)
}

func lookup(table map[string]float64, key string) (float64, bool) {
	v, ok := table[strings.TrimSpace(key)]
	return v, ok
}

func scope(s string) (changed, ok bool) {
	switch strings.TrimSpace(s) {
	case "U":
		return false, true
	case "C":
		return true, true
	default:
		return false, false
	}
}

// roundUp1 implements the CVSS v3.1 "Roundup" function (specification §Appendix
// A): round up to one decimal place, accounting for floating-point
// representation error.
func roundUp1(x float64) float64 {
	intInput := int(math.Round(x * 100000))
	if intInput%10000 == 0 {
		return float64(intInput) / 100000
	}
	return (math.Floor(float64(intInput)/10000) + 1) / 10
}
