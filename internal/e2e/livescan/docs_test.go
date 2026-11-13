package livescan

import (
	"flag"
	"os"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite the generated corpus section of docs/llm-live-scan.md")

const docPath = "../../../docs/llm-live-scan.md"

// The research notes of docs/llm-live-scan.md are generated from the corpus:
// the page and the fixtures cannot disagree. Regenerate with
//
//	go test ./internal/e2e/livescan -run TestDocsCorpusSectionIsCurrent -update
func TestDocsCorpusSectionIsCurrent(t *testing.T) {
	samples, err := Corpus()
	if err != nil {
		t.Fatal(err)
	}
	want := ReferenceMarkdown(samples)
	raw, err := os.ReadFile(docPath)
	if err != nil {
		t.Fatalf("reading the docs page: %v", err)
	}
	doc := string(raw)
	begin, end := strings.Index(doc, docBegin), strings.Index(doc, docEnd)
	if begin < 0 || end < begin {
		t.Fatalf("docs/llm-live-scan.md has no generated section: it must contain\n%s\n...\n%s", docBegin, docEnd)
	}
	have := doc[begin+len(docBegin) : end]
	if strings.TrimSpace(have) == strings.TrimSpace(want) {
		return
	}
	if *update {
		out := doc[:begin+len(docBegin)] + "\n\n" + want + "\n" + doc[end:]
		if err := os.WriteFile(docPath, []byte(out), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("rewrote the generated section of %s", docPath)
		return
	}
	t.Errorf("the generated corpus section of docs/llm-live-scan.md is stale; run:\n  go test ./internal/e2e/livescan -run TestDocsCorpusSectionIsCurrent -update")
}
