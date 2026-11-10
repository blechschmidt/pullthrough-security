package pypiattest

import (
	"os"
	"path/filepath"
	"testing"
)

// TestParseProvenance_Golden parses the committed PEP 740 golden fixture and
// asserts the wire-format reconstruction: the compact {statement, signature}
// envelope is rebuilt into a standard DSSE envelope, the publisher wrapper is
// captured, and the base64 Sigstore transparency entry is re-encoded onto the
// shared rekor.LogEntry shape (hex Merkle hashes / log id).
func TestParseProvenance_Golden(t *testing.T) {
	body, err := os.ReadFile(filepath.Join("testdata", "pypi-provenance.json"))
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	atts, err := parseProvenance(body)
	if err != nil {
		t.Fatalf("parseProvenance: %v", err)
	}
	if len(atts) != 1 {
		t.Fatalf("want 1 attestation, got %d", len(atts))
	}
	a := atts[0]

	// Envelope reconstruction.
	if a.DSSE.Envelope == nil {
		t.Fatal("nil envelope")
	}
	if a.DSSE.Envelope.PayloadType != inTotoPayloadType {
		t.Fatalf("payloadType = %q", a.DSSE.Envelope.PayloadType)
	}
	if a.DSSE.Envelope.Payload == "" || len(a.DSSE.Envelope.Signatures) != 1 || a.DSSE.Envelope.Signatures[0].Sig == "" {
		t.Fatalf("envelope payload/signature not reconstructed: %+v", a.DSSE.Envelope)
	}

	// Publisher wrapper.
	if a.Publisher.Kind != "GitHub" || a.Publisher.Repository != "acme/widgets" || a.Publisher.Environment != "pypi" {
		t.Fatalf("publisher = %+v", a.Publisher)
	}

	// Transparency entry re-encoding (base64 -> hex, string -> int64).
	if len(a.LogEntries) != 1 {
		t.Fatalf("want 1 log entry, got %d", len(a.LogEntries))
	}
	e := a.LogEntries[0]
	if e.LogIndex != 7 || e.IntegratedTime != 1700000000 {
		t.Fatalf("logIndex/integratedTime = %d/%d", e.LogIndex, e.IntegratedTime)
	}
	if e.LogID != "ff" {
		t.Fatalf("logID hex = %q (want ff)", e.LogID)
	}
	if e.Body != "Ym9keQ==" || e.SET != "c2V0" {
		t.Fatalf("body/SET = %q/%q", e.Body, e.SET)
	}
	if e.InclusionProof == nil {
		t.Fatal("nil inclusion proof")
	}
	if e.InclusionProof.RootHash != "0001020304" || e.InclusionProof.TreeSize != 8 {
		t.Fatalf("rootHash/treeSize = %q/%d", e.InclusionProof.RootHash, e.InclusionProof.TreeSize)
	}
	if len(e.InclusionProof.Hashes) != 2 || e.InclusionProof.Hashes[0] != "01" || e.InclusionProof.Hashes[1] != "02" {
		t.Fatalf("hashes = %v (want [01 02])", e.InclusionProof.Hashes)
	}
	if e.InclusionProof.Checkpoint != "checkpoint-note" {
		t.Fatalf("checkpoint = %q", e.InclusionProof.Checkpoint)
	}
}
