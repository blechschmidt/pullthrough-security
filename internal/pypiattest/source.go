package pypiattest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// ErrNotApplicable signals that the gate does not apply to an artifact (not a
// PyPI distribution, or missing the coordinate needed to locate attestations).
// The caller treats it as "skip" rather than a verification failure.
var ErrNotApplicable = errors.New("pypiattest: gate not applicable to artifact")

// HTTPDoer is the minimal HTTP surface the source needs. The standard
// *http.Client and the proxy's outbound client satisfy it.
type HTTPDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// Source discovers inbound PEP 740 attestation material for a distribution. It is
// the only registry/HTTP-aware part of the gate, kept behind an interface so the
// verification core stays exhaustively unit-testable with fixtures.
type Source interface {
	// Fetch returns the discovered attestation material for a distribution, nil when
	// the distribution simply has no published attestation, or ErrNotApplicable when
	// the source cannot locate the distribution.
	Fetch(ctx context.Context, art Artifact) (*Material, error)
}

// PyPISource discovers PEP 740 attestations from a PyPI-compatible index. It
// resolves the distribution's filename and "provenance" presence from the JSON
// Simple-index release record, then fetches the provenance object from the
// Integrity API.
//
// Two bases are configurable so a private mirror can expose the two surfaces on
// different hosts; both default to https://pypi.org. The Integrity URL is
// constructed from the resolved filename rather than following the index's
// "provenance" field verbatim, so a malicious upstream cannot point the proxy's
// egress at an arbitrary host (the field is used only as a presence flag).
type PyPISource struct {
	doer          HTTPDoer
	indexBase     string
	integrityBase string
}

// NewPyPISource constructs a PyPISource. indexBase is the index root
// (default "https://pypi.org"); integrityBase is the Integrity-API root
// (defaults to indexBase).
func NewPyPISource(doer HTTPDoer, indexBase, integrityBase string) *PyPISource {
	ib := strings.TrimRight(strings.TrimSpace(indexBase), "/")
	if ib == "" {
		ib = "https://pypi.org"
	}
	gb := strings.TrimRight(strings.TrimSpace(integrityBase), "/")
	if gb == "" {
		gb = ib
	}
	return &PyPISource{doer: doer, indexBase: ib, integrityBase: gb}
}

// releaseRecord is the subset of the PyPI JSON release record this source reads.
type releaseRecord struct {
	URLs []struct {
		Filename   string            `json:"filename"`
		Digests    map[string]string `json:"digests"`
		Provenance *string           `json:"provenance"`
	} `json:"urls"`
}

// Fetch implements Source. It returns ErrNotApplicable when the artifact carries
// no name/version to resolve, (nil, nil) when the distribution has no published
// provenance, and an error for an infrastructure failure the gate treats with its
// fail-open/closed posture.
func (s *PyPISource) Fetch(ctx context.Context, art Artifact) (*Material, error) {
	if s == nil || s.doer == nil {
		return nil, ErrNotApplicable
	}
	if art.Name == "" || art.Version == "" {
		return nil, ErrNotApplicable
	}

	idxURL := s.indexBase + "/pypi/" + url.PathEscape(art.Name) + "/" + url.PathEscape(art.Version) + "/json"
	body, err := s.fetchJSON(ctx, idxURL)
	if err != nil {
		return nil, fmt.Errorf("pypiattest: fetching release index: %w", err)
	}
	if body == nil {
		return nil, nil // no such release
	}

	var rec releaseRecord
	if err := json.Unmarshal(body, &rec); err != nil {
		return nil, fmt.Errorf("pypiattest: decoding release index: %w", err)
	}

	filename, hasProvenance, ok := matchDistribution(rec, art.Digest)
	if !ok || !hasProvenance {
		return nil, nil // the served file is not in the index, or has no provenance
	}

	provURL := s.integrityBase + "/integrity/" +
		url.PathEscape(art.Name) + "/" +
		url.PathEscape(art.Version) + "/" +
		url.PathEscape(filename) + "/provenance"
	pbody, err := s.fetchJSON(ctx, provURL)
	if err != nil {
		return nil, fmt.Errorf("pypiattest: fetching provenance: %w", err)
	}
	if pbody == nil {
		return nil, nil
	}

	atts, err := parseProvenance(pbody)
	if err != nil {
		return nil, fmt.Errorf("pypiattest: %w", err)
	}
	if len(atts) == 0 {
		return nil, nil
	}
	return &Material{Source: "pypi-attestations", Attestations: atts}, nil
}

// matchDistribution finds the release-record URL entry for the served file and
// reports its filename and whether it carries a provenance pointer. When the
// artifact digest is known the entry is matched by sha256 (so the attestation we
// fetch is for the exact file served); absent a digest, the first entry that
// carries provenance is used.
func matchDistribution(rec releaseRecord, artDigest string) (filename string, hasProvenance, ok bool) {
	wantHex := digestHex(artDigest)
	for _, u := range rec.URLs {
		if u.Filename == "" {
			continue
		}
		prov := u.Provenance != nil && strings.TrimSpace(*u.Provenance) != ""
		if wantHex != "" {
			if strings.EqualFold(strings.TrimSpace(u.Digests["sha256"]), wantHex) {
				return u.Filename, prov, true
			}
			continue
		}
		if prov {
			return u.Filename, true, true
		}
	}
	return "", false, false
}

// digestHex extracts the lower-hex sha256 value from a "sha256:<hex>" artifact
// digest, returning "" for any other algorithm or a malformed value.
func digestHex(digest string) string {
	algo, hex, ok := strings.Cut(strings.ToLower(strings.TrimSpace(digest)), ":")
	if !ok || algo != "sha256" || hex == "" {
		return ""
	}
	return hex
}

// fetchJSON GETs rawURL and returns its (bounded) body. A 404 yields (nil, nil):
// the resource simply does not exist.
func (s *PyPISource) fetchJSON(ctx context.Context, rawURL string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := s.doer.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
		_ = resp.Body.Close()
	}()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("request returned status %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxProvenanceBytes))
}
