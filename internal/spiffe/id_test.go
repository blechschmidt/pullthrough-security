package spiffe

import "testing"

func TestParseID(t *testing.T) {
	tests := []struct {
		name       string
		in         string
		wantDomain string
		wantPath   string
		wantErr    bool
	}{
		{name: "workload", in: "spiffe://example.org/ns/prod/sa/web", wantDomain: "example.org", wantPath: "/ns/prod/sa/web"},
		{name: "bare domain", in: "spiffe://example.org", wantDomain: "example.org", wantPath: ""},
		{name: "trailing slash", in: "spiffe://example.org/", wantDomain: "example.org", wantPath: ""},
		{name: "uppercase scheme+host", in: "SPIFFE://Example.ORG/ns/a", wantDomain: "example.org", wantPath: "/ns/a"},
		{name: "wrong scheme", in: "https://example.org/x", wantErr: true},
		{name: "empty", in: "", wantErr: true},
		{name: "no host", in: "spiffe:///ns/a", wantErr: true},
		{name: "with port", in: "spiffe://example.org:8443/ns/a", wantErr: true},
		{name: "with query", in: "spiffe://example.org/ns/a?x=1", wantErr: true},
		{name: "with fragment", in: "spiffe://example.org/ns/a#f", wantErr: true},
		{name: "with userinfo", in: "spiffe://user@example.org/ns/a", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			id, err := ParseID(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ParseID(%q) = %+v, want error", tc.in, id)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseID(%q) error: %v", tc.in, err)
			}
			if id.TrustDomain != tc.wantDomain || id.Path != tc.wantPath {
				t.Fatalf("ParseID(%q) = {%q,%q}, want {%q,%q}", tc.in, id.TrustDomain, id.Path, tc.wantDomain, tc.wantPath)
			}
		})
	}
}

func TestIDStringRoundTrip(t *testing.T) {
	id, err := ParseID("spiffe://example.org/ns/prod/sa/web")
	if err != nil {
		t.Fatal(err)
	}
	if got := id.String(); got != "spiffe://example.org/ns/prod/sa/web" {
		t.Fatalf("String() = %q", got)
	}
}

func TestIDSelectors(t *testing.T) {
	id, _ := ParseID("spiffe://example.org/ns/prod/sa/web")
	sel := id.Selectors()
	if sel["ns"] != "prod" || sel["sa"] != "web" {
		t.Fatalf("selectors = %v", sel)
	}
	if got := mustParse(t, "spiffe://example.org").Selectors(); got != nil {
		t.Fatalf("bare-domain selectors = %v, want nil", got)
	}
}

func mustParse(t *testing.T, s string) ID {
	t.Helper()
	id, err := ParseID(s)
	if err != nil {
		t.Fatalf("ParseID(%q): %v", s, err)
	}
	return id
}
