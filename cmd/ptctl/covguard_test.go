package main

import (
	"reflect"
	"testing"
)

func TestParseCriticalFloors(t *testing.T) {
	got, err := parseCriticalFloors("internal/cache=80, internal/proxy=75.5", 0)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	want := map[string]float64{"internal/cache": 80, "internal/proxy": 75.5}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("floors = %+v, want %+v", got, want)
	}

	// Default floor applies to entries without an explicit =floor.
	got2, err := parseCriticalFloors("internal/cache, internal/proxy=90", 70)
	if err != nil {
		t.Fatalf("parse with default: %v", err)
	}
	if got2["internal/cache"] != 70 || got2["internal/proxy"] != 90 {
		t.Errorf("default floor not applied: %+v", got2)
	}

	// Empty spec is a nil map, not an error.
	if m, err := parseCriticalFloors("   ", 0); err != nil || m != nil {
		t.Errorf("empty spec = (%v, %v), want (nil, nil)", m, err)
	}
}

func TestParseCriticalFloorsErrors(t *testing.T) {
	cases := []struct {
		name, spec string
		def        float64
	}{
		{"no floor and no default", "internal/cache", 0},
		{"bad number", "internal/cache=abc", 0},
		{"over 100", "internal/cache=150", 0},
		{"empty pkg", "=80", 0},
	}
	for _, c := range cases {
		if _, err := parseCriticalFloors(c.spec, c.def); err == nil {
			t.Errorf("%s: expected error for %q", c.name, c.spec)
		}
	}
}

func TestSplitTestArgs(t *testing.T) {
	if got := splitTestArgs("  -count=1  -tags=integration "); !reflect.DeepEqual(got, []string{"-count=1", "-tags=integration"}) {
		t.Errorf("splitTestArgs = %+v", got)
	}
	if got := splitTestArgs(""); got != nil {
		t.Errorf("empty splitTestArgs = %+v, want nil", got)
	}
}
