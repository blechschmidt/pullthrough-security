//go:build integration
// +build integration

package pkgscan

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
)

// This file is the suite's kit for other end-to-end suites. The repository
// lock-file suite (internal/e2e/repolock, Task 183) pins, scans and updates
// the dependencies a repository's lock files name — in every ecosystem — and
// needs what this suite already has: a stub registry per upstream type that
// speaks the ecosystem's protocol and serves packages in its own format, and a
// mock LLM that speaks the providers' wire formats. Exporting them keeps one
// copy of each: a protocol fix made for one suite holds for both.

// MaliciousMarker is the text the mock LLM judges malicious, in a package's
// content.
const MaliciousMarker = maliciousMarker

// MockLLM is the mock provider endpoint: Anthropic Messages at
// "<base>/v1/messages", OpenAI Chat Completions at "<base>/v1/chat/completions".
// It judges package material malicious when it contains MaliciousMarker, and
// benign otherwise; it answers the commit scanner's prompts by the same rule.
type MockLLM struct{ m *mockLLM }

// StartMockLLM starts the mock on a free loopback port.
func StartMockLLM() *MockLLM { return &MockLLM{m: startMockLLM()} }

// BaseURL is the value of llmPackageScan.baseUrl for provider ("claude" or
// "openai").
func (m *MockLLM) BaseURL(provider string) string { return m.m.BaseURL(provider) }

// APIKey is the key the mock expects (it records whether a request carried it).
func (m *MockLLM) APIKey() string { return mockAPIKey }

// Close stops the mock.
func (m *MockLLM) Close() { m.m.Close() }

// PackageScans counts the package-scan completions answered so far.
func (m *MockLLM) PackageScans() int {
	n := 0
	for _, c := range m.m.Calls() {
		if c.Kind == "package" {
			n++
		}
	}
	return n
}

// Saw reports whether a package-scan completion was shown token, and what the
// mock answered the last one that was ("benign", "malicious", …).
func (m *MockLLM) Saw(token string) (bool, string) {
	calls := m.m.PackageScans(token)
	if len(calls) == 0 {
		return false, ""
	}
	return true, calls[len(calls)-1].Outcome
}

// Unauthorized counts the completions that did not carry the API key.
func (m *MockLLM) Unauthorized() int {
	n := 0
	for _, c := range m.m.Calls() {
		if !c.Authorized {
			n++
		}
	}
	return n
}

// StubPackage is one package a stub registry serves.
type StubPackage struct {
	// Name and Version are the coordinate in the ecosystem's own spelling, as
	// the proxy's backend reports it for the payload.
	Name, Version string
	// Path is the payload's request path below the upstream's mount ("/…"),
	// and Header the request headers a client sends with it (an Accept).
	Path   string
	Header http.Header
	// Body is the payload's bytes as the stub serves them.
	Body []byte
	// Followers are the paths a client requests after the payload (an OCI
	// image's config and layer blobs).
	Followers []string
	// Token is the package's content token: a package scan that read this
	// package's content showed it to the model.
	Token string
	// Marker is the path of the file that carries the token, as the scanner
	// lists it.
	Marker string
}

// Stub is a started stub registry of one ecosystem.
type Stub struct {
	s *stub
	e eco
}

// StubIDs returns the IDs of the ecosystems with a stub registry, sorted.
func StubIDs() []string {
	var out []string
	for _, e := range ecosystems() {
		if e.Registry != nil {
			out = append(out, e.ID)
		}
	}
	sort.Strings(out)
	return out
}

// StartStub starts the stub registry of the ecosystem id: it serves the
// suite's packages ("benign", "malicious", …) in that ecosystem's format.
func StartStub(id string) (*Stub, error) {
	for _, e := range ecosystems() {
		if e.ID != id {
			continue
		}
		if e.Registry == nil {
			return nil, fmt.Errorf("pkgscan: ecosystem %s has no stub registry", id)
		}
		s, err := startStub(e)
		if err != nil {
			return nil, err
		}
		return &Stub{s: s, e: e}, nil
	}
	return nil, fmt.Errorf("pkgscan: no ecosystem %q (have %s)", id, strings.Join(StubIDs(), " "))
}

// URL is the stub's base URL ("http://127.0.0.1:<port>").
func (s *Stub) URL() string { return s.s.URL() }

// Close stops the stub.
func (s *Stub) Close() { s.s.Close() }

// Type is the upstream type the stub plays.
func (s *Stub) Type() string { return s.e.Type }

// UpstreamURL is the `url:` of an upstream fronting the stub.
func (s *Stub) UpstreamURL() string { return s.s.URL() + s.e.UpstreamPath }

// Settings is the `settings:` block of an upstream fronting the stub (nil for
// none).
func (s *Stub) Settings() map[string]string {
	if s.e.Settings == nil {
		return nil
	}
	return s.e.Settings(s.s.URL())
}

// Generic is the `generic:` block of a declarative upstream (nil for none).
func (s *Stub) Generic() map[string]any { return s.e.Generic }

// Package returns the package of a variant ("benign", "malicious").
func (s *Stub) Package(v string) (StubPackage, bool) {
	p := s.s.reg.pulls[variant(v)]
	if p == nil {
		return StubPackage{}, false
	}
	out := StubPackage{
		Name: p.Name, Version: p.Version, Path: p.Payload.Path, Header: p.Payload.Header.Clone(),
		Body: append([]byte(nil), p.Body...), Token: newSpec(s.e.ID, variant(v)).Token, Marker: p.Marker,
	}
	for _, f := range p.Followers {
		out.Followers = append(out.Followers, f.Path)
	}
	return out, true
}

// Requests returns every request the stub received, "<method> <uri> -> <status>".
func (s *Stub) Requests() []string { return s.s.reg.mux.Requests() }

// Hits counts the 2xx answers to requests for path (query string ignored).
func (s *Stub) Hits(path string) int { return s.s.reg.mux.Hits(path) }
