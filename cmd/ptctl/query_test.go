package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/findings"
	"github.com/blechschmidt/pullthrough-security/internal/queryapi"
)

func TestParseLeaf(t *testing.T) {
	cases := []struct {
		spec  string
		field string
		op    string
		value any
	}{
		{"riskScore:gt:80", "riskScore", "gt", float64(80)},
		{"signatureVerified:eq:false", "signatureVerified", "eq", false},
		{"riskBand:in:high,critical", "riskBand", "in", []any{"high", "critical"}},
		{"coordinate:contains:lodash", "coordinate", "contains", "lodash"},
		{"served:exists", "served", "exists", true},
	}
	for _, c := range cases {
		leaf, err := parseLeaf(c.spec)
		if err != nil {
			t.Fatalf("parseLeaf(%q): %v", c.spec, err)
		}
		if leaf.Field != c.field || leaf.Op != c.op {
			t.Errorf("parseLeaf(%q) = field %q op %q", c.spec, leaf.Field, leaf.Op)
		}
		if !jsonEqual(leaf.Value, c.value) {
			t.Errorf("parseLeaf(%q) value = %#v, want %#v", c.spec, leaf.Value, c.value)
		}
	}
	if _, err := parseLeaf("bad"); err == nil {
		t.Error("expected error for malformed spec")
	}
}

func TestParseOrder(t *testing.T) {
	got, err := parseOrder("riskScore,-downstreamPaths")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Field != "riskScore" || got[0].Desc || got[1].Field != "downstreamPaths" || !got[1].Desc {
		t.Errorf("parseOrder = %+v", got)
	}
}

func TestBuildQueryBuilderMode(t *testing.T) {
	fs := flag.NewFlagSet("query", flag.ContinueOnError)
	_ = fs.Parse(nil)
	q, err := buildQuery(fs, "", "coordinate,riskBand", "-riskScore", 25, 5, "acme",
		multiFlag{"blockAdjacent:eq:true", "downstreamPaths:gt:5"})
	if err != nil {
		t.Fatal(err)
	}
	if q.Tenant != "acme" || q.Limit != 25 || q.Offset != 5 {
		t.Errorf("scalars wrong: %+v", q)
	}
	if len(q.Select) != 2 || q.Where == nil || len(q.Where.And) != 2 {
		t.Errorf("composition wrong: %+v", q)
	}
}

func TestBuildQueryRawMode(t *testing.T) {
	fs := flag.NewFlagSet("query", flag.ContinueOnError)
	_ = fs.Parse([]string{`{"select":["coordinate"],"limit":3}`})
	q, err := buildQuery(fs, "", "", "", 0, 0, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(q.Select) != 1 || q.Limit != 3 {
		t.Errorf("raw parse wrong: %+v", q)
	}
}

// TestQueryEndToEnd drives the real admin handler + query engine through the
// ptctl client, confirming the wire shape the builder emits is accepted and the
// joined result decodes.
func TestQueryEndToEnd(t *testing.T) {
	now := time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)
	fp := &e2eFindings{docs: []findings.Document{{
		Tenant:      "acme",
		Artifact:    findings.Artifact{Ecosystem: "npm", Name: "evil", Version: "1.0.0", Coordinate: "npm/evil@1.0.0"},
		Findings:    []findings.Finding{{Gate: findings.GateSigverify, Severity: findings.SeverityHigh, Level: findings.LevelError}},
		GeneratedAt: now.Add(-time.Hour),
	}}}
	eng := queryapi.New(queryapi.Config{Now: func() time.Time { return now }}, queryapi.Providers{Findings: fp})

	mux := http.NewServeMux()
	mux.HandleFunc("/admin/api/query", func(w http.ResponseWriter, r *http.Request) {
		var q queryapi.Query
		if err := json.NewDecoder(r.Body).Decode(&q); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		res, err := eng.Query(q)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(res)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c, _ := newClient(globalFlags{url: srv.URL, tenant: "acme"})
	q := queryapi.Query{
		Tenant: "acme",
		Select: []string{"coordinate", "signatureVerified"},
		Where:  &queryapi.Filter{Field: "signatureVerified", Op: "eq", Value: false},
	}
	var res queryapi.Result
	if err := c.postJSON(c.adminURL("api/query", nil), q, &res); err != nil {
		t.Fatalf("postJSON: %v", err)
	}
	if res.Total != 1 || res.Rows[0]["coordinate"] != "evil@1.0.0" {
		t.Fatalf("unexpected result: %+v", res)
	}

	// Render to confirm the table writer handles real rows.
	var buf bytes.Buffer
	renderTable(&buf, res)
	if !strings.Contains(buf.String(), "evil@1.0.0") || !strings.Contains(buf.String(), "cost=") {
		t.Errorf("table render missing content:\n%s", buf.String())
	}
}

type e2eFindings struct{ docs []findings.Document }

func (e *e2eFindings) Documents(tenant, q string) []findings.Document { return e.docs }

func jsonEqual(a, b any) bool {
	ba, _ := json.Marshal(a)
	bb, _ := json.Marshal(b)
	return bytes.Equal(ba, bb)
}
