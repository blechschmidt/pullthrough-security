package provenance

import (
	"encoding/json"
	"testing"
)

func TestStatementBindsDigest(t *testing.T) {
	stmt, err := parseStatement(statementFor("sha256:ABCDEF", "https://github.com/o/r", "aa"))
	if err != nil {
		t.Fatal(err)
	}
	// Case-insensitive on hex.
	if !stmt.BindsDigest("sha256:abcdef") {
		t.Error("BindsDigest should match case-insensitively")
	}
	if stmt.BindsDigest("sha256:0000") {
		t.Error("BindsDigest matched a different digest")
	}
	if stmt.BindsDigest("sha512:abcdef") {
		t.Error("BindsDigest matched across algorithms")
	}
	if stmt.BindsDigest("not-a-digest") {
		t.Error("BindsDigest accepted a malformed digest")
	}
}

func TestSourceRef_SLSAv1ResolvedDependency(t *testing.T) {
	commit := "1111111111111111111111111111111111111111"
	stmt, _ := parseStatement(statementFor("sha256:aa", "https://github.com/acme/widget", commit))
	src, ok := stmt.sourceRef()
	if !ok {
		t.Fatal("sourceRef returned ok=false")
	}
	if src.RepositoryURL != "https://github.com/acme/widget" {
		t.Errorf("repo = %q", src.RepositoryURL)
	}
	if src.CommitSHA != commit {
		t.Errorf("commit = %q, want %q", src.CommitSHA, commit)
	}
	if src.BuilderID != "https://github.com/actions/runner" {
		t.Errorf("builder = %q", src.BuilderID)
	}
}

func TestSourceRef_SLSAv02Materials(t *testing.T) {
	commit := "2222222222222222222222222222222222222222"
	stmt := map[string]any{
		"_type":         inTotoStatementV1,
		"predicateType": predicateSLSAv02,
		"subject":       []map[string]any{{"name": "x", "digest": map[string]string{"sha256": "aa"}}},
		"predicate": map[string]any{
			"builder": map[string]any{"id": "https://builder.example/v1"},
			"materials": []map[string]any{
				{"uri": "git+https://github.com/acme/lib.git", "digest": map[string]string{"sha1": commit}},
			},
		},
	}
	b, _ := json.Marshal(stmt)
	parsed, _ := parseStatement(b)
	src, ok := parsed.sourceRef()
	if !ok {
		t.Fatal("sourceRef ok=false")
	}
	if src.RepositoryURL != "https://github.com/acme/lib" {
		t.Errorf("repo = %q, want normalized github URL", src.RepositoryURL)
	}
	if src.CommitSHA != commit {
		t.Errorf("commit = %q", src.CommitSHA)
	}
}

func TestSourceRef_NonSLSAPredicate(t *testing.T) {
	stmt := map[string]any{
		"_type":         inTotoStatementV1,
		"predicateType": "https://spdx.dev/Document",
		"subject":       []map[string]any{{"name": "x", "digest": map[string]string{"sha256": "aa"}}},
		"predicate":     map[string]any{},
	}
	b, _ := json.Marshal(stmt)
	parsed, _ := parseStatement(b)
	if _, ok := parsed.sourceRef(); ok {
		t.Error("sourceRef should be false for a non-SLSA predicate")
	}
}

func TestNormalizeRepoURL(t *testing.T) {
	cases := map[string]string{
		"git+https://github.com/o/r.git":  "https://github.com/o/r",
		"git://github.com/o/r":            "https://github.com/o/r",
		"ssh://git@github.com/o/r.git":    "https://github.com/o/r",
		"git@github.com:o/r.git":          "https://github.com/o/r",
		"github.com/o/r":                  "https://github.com/o/r",
		"https://github.com/o/r#readme":   "https://github.com/o/r",
		"https://github.com/o/r/":         "https://github.com/o/r",
		"https://gitlab.com/group/sub/pr": "https://gitlab.com/group/sub/pr",
	}
	for in, want := range cases {
		if got := normalizeRepoURL(in); got != want {
			t.Errorf("normalizeRepoURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestLooksLikeRepoURL(t *testing.T) {
	if looksLikeRepoURL("https://example.com") {
		t.Error("a host-only URL is not a repo URL")
	}
	if !looksLikeRepoURL("https://github.com/o/r") {
		t.Error("github.com/o/r should look like a repo URL")
	}
	if looksLikeRepoURL("pkg:oci/image@sha256:aa") {
		t.Error("an OCI purl is not a repo URL")
	}
}

func TestParseStatement_RejectsNoSubject(t *testing.T) {
	b, _ := json.Marshal(map[string]any{"_type": inTotoStatementV1, "predicateType": predicateSLSAv1})
	if _, err := parseStatement(b); err == nil {
		t.Error("expected error for a statement with no subjects")
	}
}
