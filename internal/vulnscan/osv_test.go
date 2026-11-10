package vulnscan

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

// fakeTransport routes OSV requests to in-memory handlers keyed by path prefix.
type fakeTransport struct {
	batch   func(req osvBatchRequest) osvBatchResponse
	vulns   map[string]osvRecord
	calls   int
	failNow bool
}

func (f *fakeTransport) Do(req *http.Request) (*http.Response, error) {
	f.calls++
	if f.failNow {
		return nil, io.ErrUnexpectedEOF
	}
	switch {
	case strings.HasSuffix(req.URL.Path, "/querybatch"):
		var in osvBatchRequest
		_ = json.NewDecoder(req.Body).Decode(&in)
		return jsonResp(f.batch(in)), nil
	case strings.Contains(req.URL.Path, "/v1/vulns/"):
		id := req.URL.Path[strings.LastIndex(req.URL.Path, "/")+1:]
		rec, ok := f.vulns[id]
		if !ok {
			return &http.Response{StatusCode: 404, Body: io.NopCloser(strings.NewReader("not found")), Header: http.Header{}}, nil
		}
		return jsonResp(rec), nil
	}
	return &http.Response{StatusCode: 404, Body: io.NopCloser(strings.NewReader("")), Header: http.Header{}}, nil
}

func jsonResp(v any) *http.Response {
	b, _ := json.Marshal(v)
	return &http.Response{
		StatusCode: 200,
		Body:       io.NopCloser(strings.NewReader(string(b))),
		Header:     http.Header{"Content-Type": []string{"application/json"}},
	}
}

func TestOSVScannerFindsVulnerability(t *testing.T) {
	ft := &fakeTransport{
		batch: func(req osvBatchRequest) osvBatchResponse {
			resp := osvBatchResponse{Results: make([]osvBatchResult, len(req.Queries))}
			for i, q := range req.Queries {
				if q.Package.Name == "lodash" && q.Package.Ecosystem == "npm" {
					resp.Results[i].Vulns = []struct {
						ID       string `json:"id"`
						Modified string `json:"modified"`
					}{{ID: "GHSA-test-0001"}}
				}
			}
			return resp
		},
		vulns: map[string]osvRecord{
			"GHSA-test-0001": {
				ID:      "GHSA-test-0001",
				Summary: "Prototype pollution in lodash",
				Aliases: []string{"CVE-2020-8203"},
				Severity: []osvSeverity{
					{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
				},
				Affected: []osvAffected{
					{
						Package: osvPackage{Name: "lodash", Ecosystem: "npm"},
						Ranges: []struct {
							Events []map[string]string `json:"events"`
						}{{Events: []map[string]string{{"introduced": "0"}, {"fixed": "4.17.19"}}}},
					},
				},
			},
		},
	}
	scanner := NewOSVScanner("", WithOSVHTTPClient(ft))

	sbom := newSBOM()
	primary := Component{Name: "lodash", Version: "4.17.0", PURL: "pkg:npm/lodash@4.17.0", ecosystem: "npm"}
	sbom.Metadata.Component = &primary

	vulns, err := scanner.Scan(context.Background(), sbom)
	if err != nil {
		t.Fatal(err)
	}
	if len(vulns) != 1 {
		t.Fatalf("expected 1 vuln, got %d", len(vulns))
	}
	v := vulns[0]
	if v.ID != "GHSA-test-0001" {
		t.Errorf("id = %s", v.ID)
	}
	if v.Severity != SeverityCritical {
		t.Errorf("severity = %s want critical (cvss %.1f)", v.Severity, v.CVSS)
	}
	if v.CVSS != 9.8 {
		t.Errorf("cvss = %.1f want 9.8", v.CVSS)
	}
	if len(v.FixedVersions) != 1 || v.FixedVersions[0] != "4.17.19" {
		t.Errorf("fixed = %v", v.FixedVersions)
	}
}

func TestOSVScannerNoVulns(t *testing.T) {
	ft := &fakeTransport{
		batch: func(req osvBatchRequest) osvBatchResponse {
			return osvBatchResponse{Results: make([]osvBatchResult, len(req.Queries))}
		},
	}
	scanner := NewOSVScanner("", WithOSVHTTPClient(ft))
	sbom := newSBOM()
	primary := Component{Name: "safe", Version: "1.0.0", PURL: "pkg:pypi/safe@1.0.0", ecosystem: "pip"}
	sbom.Metadata.Component = &primary
	vulns, err := scanner.Scan(context.Background(), sbom)
	if err != nil {
		t.Fatal(err)
	}
	if len(vulns) != 0 {
		t.Errorf("expected no vulns, got %d", len(vulns))
	}
}

func TestOSVScannerSkipsUnsupportedEcosystem(t *testing.T) {
	ft := &fakeTransport{batch: func(req osvBatchRequest) osvBatchResponse {
		t.Errorf("docker component should not be queried")
		return osvBatchResponse{}
	}}
	scanner := NewOSVScanner("", WithOSVHTTPClient(ft))
	sbom := newSBOM()
	primary := Component{Name: "nginx", Version: "1.0", ecosystem: "docker"}
	sbom.Metadata.Component = &primary
	vulns, err := scanner.Scan(context.Background(), sbom)
	if err != nil {
		t.Fatal(err)
	}
	if len(vulns) != 0 || ft.calls != 0 {
		t.Errorf("expected no calls/vulns for docker, calls=%d vulns=%d", ft.calls, len(vulns))
	}
}

func TestOSVScannerPropagatesError(t *testing.T) {
	ft := &fakeTransport{failNow: true}
	scanner := NewOSVScanner("", WithOSVHTTPClient(ft))
	sbom := newSBOM()
	primary := Component{Name: "lodash", Version: "4.17.0", ecosystem: "npm"}
	sbom.Metadata.Component = &primary
	if _, err := scanner.Scan(context.Background(), sbom); err == nil {
		t.Fatal("expected error from failing transport")
	}
}
