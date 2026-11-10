package admin

import (
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/cache"
	"github.com/blechschmidt/pullthrough-security/internal/provenance"
	"github.com/blechschmidt/pullthrough-security/internal/scan/commit"
	"github.com/blechschmidt/pullthrough-security/internal/vulnscan"
)

// overviewResponse is the payload for GET {prefix}/api/overview: a single,
// dashboard-friendly snapshot of the proxy's state.
type overviewResponse struct {
	Info            Info             `json:"info"`
	Backends        []string         `json:"backends"`
	Cache           *cacheMetricsDTO `json:"cache,omitempty"`
	CacheEntryCount int              `json:"cacheEntryCount"`
	CacheTotalBytes int64            `json:"cacheTotalBytes"`
	Scan            *scanSummaryDTO  `json:"scan,omitempty"`
}

type cacheMetricsDTO struct {
	Hits         int64   `json:"hits"`
	Misses       int64   `json:"misses"`
	HitRatio     float64 `json:"hitRatio"`
	Loads        int64   `json:"loads"`
	Puts         int64   `json:"puts"`
	Evictions    int64   `json:"evictions"`
	Expired      int64   `json:"expired"`
	Errors       int64   `json:"errors"`
	BytesWritten int64   `json:"bytesWritten"`
	BytesServed  int64   `json:"bytesServed"`
}

type scanSummaryDTO struct {
	QueueDepth int `json:"queueDepth"`
	Pending    int `json:"pending"`
	Total      int `json:"total"`
	Malicious  int `json:"malicious"`
}

// cacheEntryDTO is the inspectable view of one cached artifact.
type cacheEntryDTO struct {
	Key         string            `json:"key"`
	Size        int64             `json:"size"`
	Origin      string            `json:"origin,omitempty"`
	ContentType string            `json:"contentType,omitempty"`
	ETag        string            `json:"etag,omitempty"`
	ModTime     time.Time         `json:"modTime"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

func cacheEntryToDTO(s cache.Stat) cacheEntryDTO {
	return cacheEntryDTO{
		Key:         s.Key,
		Size:        s.Size,
		Origin:      s.Metadata[cache.MetaOrigin],
		ContentType: s.Metadata[cache.MetaContentType],
		ETag:        s.Metadata[cache.MetaETag],
		ModTime:     s.ModTime,
		Metadata:    s.Metadata,
	}
}

type cacheListResponse struct {
	Total    int             `json:"total"`
	Returned int             `json:"returned"`
	Items    []cacheEntryDTO `json:"items"`
}

// scanSummaryItemDTO is a compact verdict row for the scans listing.
type scanSummaryItemDTO struct {
	SHA             string    `json:"sha"`
	RiskScore       int       `json:"riskScore"`
	Malicious       bool      `json:"malicious"`
	HighestSeverity string    `json:"highestSeverity"`
	Findings        int       `json:"findings"`
	Escalated       bool      `json:"escalated"`
	Provider        string    `json:"provider,omitempty"`
	Error           string    `json:"error,omitempty"`
	ScannedAt       time.Time `json:"scannedAt"`
}

func scanVerdictToSummary(v *commit.Verdict) scanSummaryItemDTO {
	return scanSummaryItemDTO{
		SHA:             v.SHA,
		RiskScore:       v.RiskScore,
		Malicious:       v.Malicious,
		HighestSeverity: v.HighestSeverity(),
		Findings:        len(v.Findings),
		Escalated:       v.Escalated,
		Provider:        v.Provider,
		Error:           v.Error,
		ScannedAt:       v.ScannedAt,
	}
}

type scanListResponse struct {
	Enabled    bool                 `json:"enabled"`
	Total      int                  `json:"total"`
	Returned   int                  `json:"returned"`
	QueueDepth int                  `json:"queueDepth"`
	Items      []scanSummaryItemDTO `json:"items"`
}

// provenanceLinkDTO is the inspectable view of a provenance association. The raw
// attestation bytes are not inlined; only their presence and size are reported.
type provenanceLinkDTO struct {
	Ecosystem         string `json:"ecosystem,omitempty"`
	Name              string `json:"name,omitempty"`
	Version           string `json:"version,omitempty"`
	Digest            string `json:"digest,omitempty"`
	RepositoryURL     string `json:"repositoryUrl,omitempty"`
	CommitSHA         string `json:"commitSha,omitempty"`
	BuilderID         string `json:"builderId,omitempty"`
	Confidence        string `json:"confidence,omitempty"`
	Resolver          string `json:"resolver,omitempty"`
	PredicateType     string `json:"predicateType,omitempty"`
	SignerIdentity    string `json:"signerIdentity,omitempty"`
	SignatureVerified bool   `json:"signatureVerified"`
	ChainTrusted      bool   `json:"chainTrusted"`
	Attested          bool   `json:"attested"`
	AttestationSize   int    `json:"attestationSize,omitempty"`
}

func provenanceLinkToDTO(l *provenance.Link) provenanceLinkDTO {
	return provenanceLinkDTO{
		Ecosystem:         l.Artifact.Ecosystem,
		Name:              l.Artifact.Name,
		Version:           l.Artifact.Version,
		Digest:            l.Artifact.Digest,
		RepositoryURL:     l.RepositoryURL,
		CommitSHA:         l.CommitSHA,
		BuilderID:         l.BuilderID,
		Confidence:        string(l.Confidence),
		Resolver:          l.ResolverName,
		PredicateType:     l.PredicateType,
		SignerIdentity:    l.SignerIdentity,
		SignatureVerified: l.SignatureVerified,
		ChainTrusted:      l.ChainTrusted,
		Attested:          len(l.Attestation) > 0,
		AttestationSize:   len(l.Attestation),
	}
}

// provenanceVerdictDTO is the compact scan verdict surfaced alongside a link.
type provenanceVerdictDTO struct {
	SHA             string `json:"sha"`
	RiskScore       int    `json:"riskScore"`
	Malicious       bool   `json:"malicious"`
	HighestSeverity string `json:"highestSeverity"`
	Findings        int    `json:"findings"`
}

// enrichedLinkDTO is a provenance link joined with its source commit's verdict.
type enrichedLinkDTO struct {
	provenanceLinkDTO
	Verdict *provenanceVerdictDTO `json:"verdict,omitempty"`
}

func enrichedLinkToDTO(l *provenance.EnrichedLink) enrichedLinkDTO {
	dto := enrichedLinkDTO{provenanceLinkDTO: provenanceLinkToDTO(l.Link)}
	if l.Verdict != nil {
		dto.Verdict = &provenanceVerdictDTO{
			SHA:             l.Verdict.SHA,
			RiskScore:       l.Verdict.RiskScore,
			Malicious:       l.Verdict.Malicious,
			HighestSeverity: l.Verdict.HighestSeverity,
			Findings:        l.Verdict.Findings,
		}
	}
	return dto
}

type provenanceLinksResponse struct {
	Enabled  bool              `json:"enabled"`
	Total    int               `json:"total"`
	Returned int               `json:"returned"`
	Items    []enrichedLinkDTO `json:"items"`
}

// vulnListResponse is the payload for GET {prefix}/api/vulns.
type vulnListResponse struct {
	Enabled  bool               `json:"enabled"`
	Total    int                `json:"total"`
	Returned int                `json:"returned"`
	Metrics  *vulnscan.Snapshot `json:"metrics,omitempty"`
	Items    []vulnSummaryDTO   `json:"items"`
}

// vulnSummaryDTO is the per-artifact row in the scan list: the headline figures
// without the full finding detail (which the entry endpoint serves).
type vulnSummaryDTO struct {
	Digest        string                  `json:"digest"`
	Ecosystem     string                  `json:"ecosystem,omitempty"`
	Package       string                  `json:"package"`
	Version       string                  `json:"version,omitempty"`
	Scanner       string                  `json:"scanner,omitempty"`
	MaxSeverity   string                  `json:"maxSeverity"`
	MaxCVSS       float64                 `json:"maxCvss"`
	Counts        vulnscan.SeverityCounts `json:"counts"`
	VEXSuppressed int                     `json:"vexSuppressed,omitempty"`
	VEXEscalated  int                     `json:"vexEscalated,omitempty"`
	Offline       bool                    `json:"offline,omitempty"`
	Error         string                  `json:"error,omitempty"`
	ScannedAt     time.Time               `json:"scannedAt"`
}

func vulnReportToSummary(r *vulnscan.Report) vulnSummaryDTO {
	return vulnSummaryDTO{
		Digest:        r.Digest,
		Ecosystem:     r.Artifact.Ecosystem,
		Package:       r.Artifact.Name,
		Version:       r.Artifact.Version,
		Scanner:       r.Scanner,
		MaxSeverity:   string(r.MaxSeverity),
		MaxCVSS:       r.MaxCVSS,
		Counts:        r.Counts,
		VEXSuppressed: r.VEXSuppressed,
		VEXEscalated:  r.VEXEscalated,
		Offline:       r.Offline,
		Error:         r.Error,
		ScannedAt:     r.ScannedAt,
	}
}
