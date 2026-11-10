package admin

import (
	"net/http"

	"github.com/blechschmidt/pullthrough-security/internal/cache"
)

// integrityStatusResponse is the GET /api/integrity payload: the cumulative
// verification counters plus the most recent background-scan report.
type integrityStatusResponse struct {
	Enabled       bool                           `json:"enabled"`
	VerifyOnServe bool                           `json:"verifyOnServe"`
	Metrics       cache.IntegrityMetricsSnapshot `json:"metrics"`
	LastScan      *cache.IntegrityReport         `json:"lastScan,omitempty"`
}

// handleIntegrityStatus reports read-time integrity verification counters and the
// most recent background-scan report, so an operator can see how many blobs have
// been verified and whether any corruption has been detected (Task 107).
func (s *Server) handleIntegrityStatus(w http.ResponseWriter, r *http.Request) {
	if s.opts.Integrity == nil {
		s.writeJSON(w, http.StatusOK, integrityStatusResponse{Enabled: false})
		return
	}
	resp := integrityStatusResponse{
		Enabled:       true,
		VerifyOnServe: s.opts.CacheIntegrityVerifyOnServe,
		Metrics:       s.opts.Integrity.IntegrityMetrics(),
	}
	if rep, ok := s.opts.Integrity.LastScan(); ok {
		resp.LastScan = &rep
	}
	s.writeJSON(w, http.StatusOK, resp)
}

// handleCacheCompaction reports the transparent storage-efficiency layer's
// cumulative compression + deduplication statistics (Task 125), so an operator
// (or `ptctl compaction`) can see how much on-disk / S3 space the cache is
// saving. When the layer is disabled it returns an Enabled=false snapshot.
func (s *Server) handleCacheCompaction(w http.ResponseWriter, r *http.Request) {
	if s.opts.Compaction == nil {
		s.writeJSON(w, http.StatusOK, cache.CompactionStats{Enabled: false, Codec: "none"})
		return
	}
	s.writeJSON(w, http.StatusOK, s.opts.Compaction.CompactionStats())
}

// handleCacheEncryption reports the at-rest encryption envelope's status and
// cumulative statistics (Task 141), so an operator (or `ptctl cache-encryption
// status`) can confirm encryption is active, which KEK is primary, and how many
// objects have been encrypted/decrypted. When the layer is disabled it returns
// an Enabled=false snapshot.
func (s *Server) handleCacheEncryption(w http.ResponseWriter, r *http.Request) {
	if s.opts.Encryption == nil {
		s.writeJSON(w, http.StatusOK, cache.EncryptionStats{Enabled: false, Algorithm: "none"})
		return
	}
	s.writeJSON(w, http.StatusOK, s.opts.Encryption.EncryptionStats())
}

// handleCacheEncryptionRotate triggers a key-encryption-key rotation: every
// object wrapped under a non-primary KEK has its data key unwrapped and re-wrapped
// to the active (primary) KEK, updating only the metadata sidecar — the encrypted
// payload is never rewritten (Task 141). It returns a rotation report (scanned /
// re-wrapped / already-current / skipped / error counts). At most one rotation
// runs at a time.
func (s *Server) handleCacheEncryptionRotate(w http.ResponseWriter, r *http.Request) {
	if s.opts.Encryption == nil {
		s.writeError(w, http.StatusNotFound, "at-rest cache encryption is not enabled")
		return
	}
	rep, err := s.opts.Encryption.RotateKEK(r.Context())
	if err != nil {
		s.writeError(w, http.StatusServiceUnavailable, "key rotation failed: "+err.Error())
		return
	}
	s.logger.Info("admin: cache KEK rotation triggered",
		"primaryKeyId", rep.PrimaryKeyID, "scanned", rep.Scanned, "rewrapped", rep.Rewrapped,
		"alreadyCurrent", rep.AlreadyCurrent, "skipped", rep.Skipped, "errors", rep.Errors,
		"unsupported", rep.Unsupported)
	s.writeJSON(w, http.StatusOK, rep)
}

// integrityScanResponse wraps the report produced by an on-demand scan.
type integrityScanResponse struct {
	Report cache.IntegrityReport `json:"report"`
}

// handleIntegrityScan triggers an on-demand background integrity scan: it
// re-reads every cached blob, re-verifies its stored content digest, and
// quarantines any corruption found (emitting an audit event + notification for
// each). It returns the scan report (counts of scanned/verified/corrupted/
// skipped entries and a sample of corrupt keys). At most one scan runs at a
// time; a concurrent trigger blocks until the running scan completes. For a very
// large cache this can take a while, as every blob is re-hashed.
func (s *Server) handleIntegrityScan(w http.ResponseWriter, r *http.Request) {
	if s.opts.Integrity == nil {
		s.writeError(w, http.StatusNotFound, "cache integrity verification is not enabled")
		return
	}
	rep, err := s.opts.Integrity.ScanIntegrity(r.Context())
	if err != nil {
		s.writeError(w, http.StatusServiceUnavailable, "integrity scan failed: "+err.Error())
		return
	}
	s.logger.Info("admin: cache integrity scan triggered",
		"scanned", rep.Scanned, "verified", rep.Verified, "corrupted", rep.Corrupted,
		"skipped", rep.Skipped, "errors", rep.Errors, "bytesScanned", rep.BytesScanned)
	s.writeJSON(w, http.StatusOK, integrityScanResponse{Report: rep})
}
