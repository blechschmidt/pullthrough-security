package terraform

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"

	//lint:ignore SA1019 test-only key generation/signing with the frozen openpgp pkg.
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
)

func sha256Hex(b []byte) string { return fmt.Sprintf("%x", sha256.Sum256(b)) }

// --- pure-parser unit tests -------------------------------------------------

func TestClassify(t *testing.T) {
	cases := []struct {
		path string
		want resourceKind
	}{
		{"/.well-known/terraform.json", kindDiscovery},
		{"/v1/modules/hashicorp/consul/aws/versions", kindModuleVersions},
		{"/v1/modules/hashicorp/consul/aws/1.0.0/download", kindModuleDownload},
		{"/v1/modules/hashicorp/consul/aws/download", kindModuleDownload},
		{"/v1/modules/hashicorp/consul/aws/1.0.0/archive", kindModuleArchive},
		{"/v1/providers/hashicorp/aws/versions", kindProviderVersions},
		{"/v1/providers/hashicorp/aws/5.0.0/download/linux/amd64", kindProviderDownload},
		{"/v1/providers/hashicorp/aws/5.0.0/download/linux/amd64/zip", kindProviderZip},
		{"/v1/providers/hashicorp/aws/5.0.0/download/linux/amd64/shasums", kindProviderShasums},
		{"/v1/providers/hashicorp/aws/5.0.0/download/linux/amd64/shasums.sig", kindProviderShasumsSig},
		{"/v1/modules/hashicorp/consul/aws", kindModuleMeta},
		{"/v1/providers/hashicorp/aws", kindProviderMeta},
	}
	for _, c := range cases {
		res, ok := classify(c.path)
		if !ok {
			t.Errorf("classify(%q) returned ok=false", c.path)
			continue
		}
		if res.kind != c.want {
			t.Errorf("classify(%q).kind = %v, want %v", c.path, res.kind, c.want)
		}
	}

	for _, bad := range []string{"", "/", "/../etc/passwd", "/v2/providers/x/y", "/v1/foo/bar"} {
		if _, ok := classify(bad); ok && bad != "/v1/foo/bar" {
			// "/v1/foo/bar" is not modules/providers → ok=false expected too.
			t.Errorf("classify(%q) unexpectedly ok", bad)
		}
	}
	if _, ok := classify("/v1/foo/bar"); ok {
		t.Errorf("classify of unknown v1 namespace should be unsupported")
	}
}

func TestClassifyCoordinate(t *testing.T) {
	res, _ := classify("/v1/providers/hashicorp/aws/5.0.0/download/linux/amd64/zip")
	if got := res.coordinateName(); got != "hashicorp/aws" {
		t.Errorf("provider coordinate = %q", got)
	}
	if res.version != "5.0.0" || res.os != "linux" || res.arch != "amd64" {
		t.Errorf("provider fields = %+v", res)
	}
	mod, _ := classify("/v1/modules/hashicorp/consul/aws/1.0.0/archive")
	if got := mod.coordinateName(); got != "hashicorp/consul/aws" {
		t.Errorf("module coordinate = %q", got)
	}
}

func TestParseTerraformGet(t *testing.T) {
	g, ok := parseTerraformGet("https://api.github.com/repos/o/r/tarball/v5.0.0//*?archive=tar.gz")
	if !ok {
		t.Fatal("parse failed")
	}
	if g.url != "https://api.github.com/repos/o/r/tarball/v5.0.0" {
		t.Errorf("url = %q", g.url)
	}
	if g.subdir != "*" {
		t.Errorf("subdir = %q", g.subdir)
	}
	if g.query != "archive=tar.gz" {
		t.Errorf("query = %q", g.query)
	}
	if !g.cacheable() {
		t.Error("https tarball should be cacheable")
	}
	out := g.rewrite("https://proxy/archive")
	if out != "https://proxy/archive//*?archive=tar.gz" {
		t.Errorf("rewrite = %q", out)
	}

	git, _ := parseTerraformGet("git::https://github.com/o/r.git//mod?ref=v1")
	if git.cacheable() {
		t.Error("git getter must not be cacheable")
	}
	if git.force != "git" {
		t.Errorf("force = %q", git.force)
	}
}

func TestTerraformGetArchiveTypeHint(t *testing.T) {
	g, _ := parseTerraformGet("https://example.com/src.zip")
	out := g.rewrite("https://proxy/a")
	if out != "https://proxy/a?archive=zip" {
		t.Errorf("rewrite with archive hint = %q", out)
	}
}

func TestParseSHASUMS(t *testing.T) {
	good := sha256Hex([]byte("zip"))
	data := good + "  terraform-provider-null_3.2.1_linux_amd64.zip\n" +
		"deadbeef shortsum.zip\n" + // too short → skipped
		good + " *binmode.zip\n" +
		"\n"
	sums := parseSHASUMS([]byte(data))
	if sums["terraform-provider-null_3.2.1_linux_amd64.zip"] != good {
		t.Errorf("missing/incorrect entry: %v", sums)
	}
	if sums["binmode.zip"] != good {
		t.Errorf("binary-mode entry not parsed: %v", sums)
	}
	if _, ok := sums["shortsum.zip"]; ok {
		t.Error("malformed short digest should be skipped")
	}
}

func TestRewriteProviderPackagePreservesFields(t *testing.T) {
	src := []byte(`{"os":"linux","arch":"amd64","filename":"f.zip","download_url":"https://u/f.zip",` +
		`"shasums_url":"https://u/SHA256SUMS","shasums_signature_url":"https://u/SHA256SUMS.sig",` +
		`"shasum":"abc","protocols":["5.0"],"signing_keys":{"gpg_public_keys":[{"key_id":"K"}]}}`)
	out, err := rewriteProviderPackage(src, "https://p/zip", "https://p/shasums", "https://p/shasums.sig")
	if err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatalf("rewritten not valid JSON: %v", err)
	}
	if m["download_url"] != "https://p/zip" {
		t.Errorf("download_url not rewritten: %v", m["download_url"])
	}
	if m["shasums_url"] != "https://p/shasums" {
		t.Errorf("shasums_url not rewritten: %v", m["shasums_url"])
	}
	if m["shasum"] != "abc" {
		t.Errorf("shasum field not preserved: %v", m["shasum"])
	}
	if _, ok := m["signing_keys"]; !ok {
		t.Error("signing_keys dropped")
	}
}

// --- GPG signature verification --------------------------------------------

// genKeyAndSign creates a throwaway OpenPGP key, returns its armored public key
// and a detached binary signature over message.
func genKeyAndSign(t *testing.T, message []byte) (armoredPub string, sig []byte) {
	t.Helper()
	ent, err := openpgp.NewEntity("Test Provider", "tf", "tf@example.com", nil)
	if err != nil {
		t.Fatalf("NewEntity: %v", err)
	}
	var pub bytes.Buffer
	aw, err := armor.Encode(&pub, openpgp.PublicKeyType, nil)
	if err != nil {
		t.Fatalf("armor.Encode: %v", err)
	}
	if err := ent.Serialize(aw); err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	_ = aw.Close()

	var sigBuf bytes.Buffer
	if err := openpgp.DetachSign(&sigBuf, ent, bytes.NewReader(message), nil); err != nil {
		t.Fatalf("DetachSign: %v", err)
	}
	return pub.String(), sigBuf.Bytes()
}

func TestVerifySHASUMSSignature(t *testing.T) {
	manifest := []byte(sha256Hex([]byte("zip")) + "  f.zip\n")
	pub, sig := genKeyAndSign(t, manifest)

	status, err := verifySHASUMSSignature(manifest, sig, []string{pub}, "u")
	if err != nil || status != sigVerified {
		t.Fatalf("good signature: status=%v err=%v", status, err)
	}

	// Tampered manifest → invalid (hard failure).
	status, err = verifySHASUMSSignature([]byte("tampered\n"), sig, []string{pub}, "u")
	if err == nil || status != sigInvalid {
		t.Fatalf("tampered: status=%v err=%v (want invalid+error)", status, err)
	}

	// No signature → unsigned (no error).
	status, err = verifySHASUMSSignature(manifest, nil, []string{pub}, "u")
	if err != nil || status != sigUnsigned {
		t.Fatalf("missing sig: status=%v err=%v", status, err)
	}

	// No keys → unsigned.
	status, err = verifySHASUMSSignature(manifest, sig, nil, "u")
	if err != nil || status != sigUnsigned {
		t.Fatalf("no keys: status=%v err=%v", status, err)
	}
}

// --- integration: fake registry + backend ----------------------------------

type fakeRegistry struct {
	srv      *httptest.Server
	files    map[string][]byte
	headers  map[string]http.Header
	statuses map[string]int
}

func newFakeRegistry(t *testing.T) *fakeRegistry {
	t.Helper()
	fr := &fakeRegistry{
		files:    map[string][]byte{},
		headers:  map[string]http.Header{},
		statuses: map[string]int{},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if h, ok := fr.headers[r.URL.Path]; ok {
			for k, vs := range h {
				for _, v := range vs {
					w.Header().Add(k, v)
				}
			}
		}
		if st, ok := fr.statuses[r.URL.Path]; ok {
			w.WriteHeader(st)
			if st == http.StatusNoContent {
				return
			}
		}
		body, ok := fr.files[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(body)
	})
	fr.srv = httptest.NewServer(mux)
	t.Cleanup(fr.srv.Close)
	return fr
}

func newTestBackend(t *testing.T, fr *fakeRegistry, m *Metrics) *Backend {
	t.Helper()
	b, err := New(Options{
		Name:          "tf",
		UpstreamURL:   fr.srv.URL,
		PublicBaseURL: "https://proxy/v1/tf",
		Client:        upstream.NewWithHTTPClient(fr.srv.Client(), "test/1"),
		Metrics:       m,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return b
}

func resolveFetch(t *testing.T, b *Backend, path string) (*backends.FetchResult, []byte, error) {
	t.Helper()
	res, err := b.Resolve(context.Background(), &backends.Request{Method: http.MethodGet, Path: path, Query: url.Values{}})
	if err != nil {
		return nil, nil, err
	}
	fres, err := b.Fetch(context.Background(), res)
	if err != nil {
		return nil, nil, err
	}
	var body []byte
	var rerr error
	if fres.Content != nil {
		body, rerr = io.ReadAll(fres.Content)
		_ = fres.Content.Close()
	}
	fres.Resolved = res
	// A streaming verifier (provider ZIP) surfaces a checksum mismatch as a read
	// error at end-of-stream, mirroring how the cache-fill path detects it.
	return fres, body, rerr
}

// seedProvider registers a signed provider release in the fake registry and
// returns the zip bytes.
func seedProvider(t *testing.T, fr *fakeRegistry, tamperSum bool) []byte {
	t.Helper()
	zip := []byte("PK\x03\x04 fake provider zip payload")
	filename := "terraform-provider-null_3.2.1_linux_amd64.zip"
	sum := sha256Hex(zip)
	if tamperSum {
		sum = sha256Hex([]byte("a different artifact"))
	}
	manifest := []byte(sum + "  " + filename + "\n")
	pub, sig := genKeyAndSign(t, manifest)

	fr.files["/dl/"+filename] = zip
	fr.files["/dl/SHA256SUMS"] = manifest
	fr.files["/dl/SHA256SUMS.sig"] = sig

	desc := map[string]any{
		"protocols":             []string{"5.0"},
		"os":                    "linux",
		"arch":                  "amd64",
		"filename":              filename,
		"download_url":          fr.srv.URL + "/dl/" + filename,
		"shasums_url":           fr.srv.URL + "/dl/SHA256SUMS",
		"shasums_signature_url": fr.srv.URL + "/dl/SHA256SUMS.sig",
		"shasum":                sum,
		"signing_keys": map[string]any{
			"gpg_public_keys": []map[string]any{{"key_id": "TESTKEY", "ascii_armor": pub}},
		},
	}
	enc, _ := json.Marshal(desc)
	fr.files["/v1/providers/hashicorp/null/3.2.1/download/linux/amd64"] = enc
	return zip
}

func TestProviderZipVerifies(t *testing.T) {
	fr := newFakeRegistry(t)
	zip := seedProvider(t, fr, false)
	m := &Metrics{}
	b := newTestBackend(t, fr, m)

	fres, body, err := resolveFetch(t, b, "/v1/providers/hashicorp/null/3.2.1/download/linux/amd64/zip")
	if err != nil {
		t.Fatalf("fetch zip: %v", err)
	}
	if !bytes.Equal(body, zip) {
		t.Fatalf("zip body mismatch")
	}
	if fres.Resolved.Metadata[MetaChecksumVerified] != "sha256" {
		t.Errorf("checksum metadata = %q", fres.Resolved.Metadata[MetaChecksumVerified])
	}
	if fres.Resolved.Metadata[MetaSignatureVerified] != "verified" {
		t.Errorf("signature metadata = %q", fres.Resolved.Metadata[MetaSignatureVerified])
	}
	if got := m.Stats(); got.ProvidersVerified != 1 || got.SignatureVerified != 1 {
		t.Errorf("metrics = %+v", got)
	}
}

func TestProviderZipChecksumMismatchRefused(t *testing.T) {
	fr := newFakeRegistry(t)
	seedProvider(t, fr, true) // SHASUMS declares a digest that doesn't match the zip
	m := &Metrics{}
	b := newTestBackend(t, fr, m)

	// The descriptor's shasum disagrees with the manifest? No — both are the tampered
	// value, but neither matches the actual zip. The streaming verifier must fail at
	// EOF, surfacing a ChecksumMismatchError through the read.
	_, _, err := resolveFetch(t, b, "/v1/providers/hashicorp/null/3.2.1/download/linux/amd64/zip")
	if err == nil {
		t.Fatal("expected checksum mismatch error")
	}
	var cm *ChecksumMismatchError
	if !errors.As(err, &cm) {
		t.Fatalf("error = %v, want ChecksumMismatchError", err)
	}
	if m.Stats().ChecksumMismatch != 1 {
		t.Errorf("mismatch metric = %v", m.Stats().ChecksumMismatch)
	}
}

func TestProviderZipForgedSignatureRefused(t *testing.T) {
	fr := newFakeRegistry(t)
	seedProvider(t, fr, false)
	// Replace the signature with garbage so verification fails against the key.
	fr.files["/dl/SHA256SUMS.sig"] = []byte("not a real signature")
	m := &Metrics{}
	b := newTestBackend(t, fr, m)

	_, _, err := resolveFetch(t, b, "/v1/providers/hashicorp/null/3.2.1/download/linux/amd64/zip")
	if err == nil {
		t.Fatal("expected signature verification error")
	}
	var se *SignatureError
	if !errors.As(err, &se) {
		t.Fatalf("error = %v, want SignatureError", err)
	}
	if m.Stats().SignatureFailed != 1 {
		t.Errorf("signature-failed metric = %v", m.Stats().SignatureFailed)
	}
}

func TestProviderDownloadRewritesURLs(t *testing.T) {
	fr := newFakeRegistry(t)
	seedProvider(t, fr, false)
	b := newTestBackend(t, fr, &Metrics{})

	_, body, err := resolveFetch(t, b, "/v1/providers/hashicorp/null/3.2.1/download/linux/amd64")
	if err != nil {
		t.Fatalf("fetch descriptor: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatalf("descriptor not JSON: %v", err)
	}
	want := "https://proxy/v1/tf/v1/providers/hashicorp/null/3.2.1/download/linux/amd64/zip"
	if m["download_url"] != want {
		t.Errorf("download_url = %v, want %v", m["download_url"], want)
	}
	if !strings.HasSuffix(m["shasums_url"].(string), "/shasums") {
		t.Errorf("shasums_url not rewritten: %v", m["shasums_url"])
	}
	// signing_keys and shasum must survive for the client's own verification.
	if _, ok := m["signing_keys"]; !ok {
		t.Error("signing_keys dropped from rewritten descriptor")
	}
}

func TestModuleDownloadRewriteAndArchive(t *testing.T) {
	fr := newFakeRegistry(t)
	archive := []byte("module source archive tarball")
	fr.files["/src/consul.tar.gz"] = archive
	dlPath := "/v1/modules/hashicorp/consul/aws/1.2.0/download"
	fr.statuses[dlPath] = http.StatusNoContent
	fr.headers[dlPath] = http.Header{"X-Terraform-Get": {fr.srv.URL + "/src/consul.tar.gz"}}

	m := &Metrics{}
	b := newTestBackend(t, fr, m)

	// Download endpoint: header rewritten to the proxy archive endpoint.
	fres, _, err := resolveFetch(t, b, dlPath)
	if err != nil {
		t.Fatalf("fetch download: %v", err)
	}
	got := fres.Header.Get("X-Terraform-Get")
	want := "https://proxy/v1/tf/v1/modules/hashicorp/consul/aws/1.2.0/archive?archive=tar.gz"
	if got != want {
		t.Errorf("X-Terraform-Get = %q, want %q", got, want)
	}

	// Archive endpoint: fetches and serves the actual archive bytes.
	_, body, err := resolveFetch(t, b, "/v1/modules/hashicorp/consul/aws/1.2.0/archive")
	if err != nil {
		t.Fatalf("fetch archive: %v", err)
	}
	if !bytes.Equal(body, archive) {
		t.Errorf("archive body mismatch")
	}
	if m.Stats().ModuleArchives != 1 {
		t.Errorf("module-archive metric = %v", m.Stats().ModuleArchives)
	}
}

func TestModuleDownloadPassthroughGitGetter(t *testing.T) {
	fr := newFakeRegistry(t)
	dlPath := "/v1/modules/hashicorp/consul/aws/1.2.0/download"
	fr.statuses[dlPath] = http.StatusNoContent
	gitURL := "git::https://github.com/o/r.git//mod?ref=v1"
	fr.headers[dlPath] = http.Header{"X-Terraform-Get": {gitURL}}
	m := &Metrics{}
	b := newTestBackend(t, fr, m)

	fres, _, err := resolveFetch(t, b, dlPath)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if got := fres.Header.Get("X-Terraform-Get"); got != gitURL {
		t.Errorf("git getter should pass through unchanged, got %q", got)
	}
	if m.Stats().ModuleArchivePassed != 1 {
		t.Errorf("passthrough metric = %v", m.Stats().ModuleArchivePassed)
	}
}

func TestDiscoveryDocument(t *testing.T) {
	b := newTestBackend(t, newFakeRegistry(t), nil)
	_, body, err := resolveFetch(t, b, "/.well-known/terraform.json")
	if err != nil {
		t.Fatalf("fetch discovery: %v", err)
	}
	var m map[string]string
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatalf("discovery not JSON: %v", err)
	}
	if m["modules.v1"] != "/v1/tf/v1/modules/" || m["providers.v1"] != "/v1/tf/v1/providers/" {
		t.Errorf("discovery doc = %v", m)
	}
}

func TestProviderShasumsProxied(t *testing.T) {
	fr := newFakeRegistry(t)
	seedProvider(t, fr, false)
	b := newTestBackend(t, fr, &Metrics{})

	_, body, err := resolveFetch(t, b, "/v1/providers/hashicorp/null/3.2.1/download/linux/amd64/shasums")
	if err != nil {
		t.Fatalf("fetch shasums: %v", err)
	}
	if !bytes.Contains(body, []byte("terraform-provider-null_3.2.1_linux_amd64.zip")) {
		t.Errorf("shasums body unexpected: %q", body)
	}
}

func TestPassthroughWithoutPublicBase(t *testing.T) {
	fr := newFakeRegistry(t)
	seedProvider(t, fr, false)
	b, err := New(Options{
		Name:        "tf",
		UpstreamURL: fr.srv.URL,
		Client:      upstream.NewWithHTTPClient(fr.srv.Client(), "test/1"),
		Metrics:     &Metrics{},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if b.canRewrite {
		t.Fatal("backend without scheme'd public base must not rewrite")
	}
	res, _ := b.Resolve(context.Background(), &backends.Request{Method: http.MethodGet,
		Path: "/v1/providers/hashicorp/null/3.2.1/download/linux/amd64", Query: url.Values{}})
	fres, err := b.Fetch(context.Background(), res)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	body, _ := io.ReadAll(fres.Content)
	_ = fres.Content.Close()
	var m map[string]any
	_ = json.Unmarshal(body, &m)
	if !strings.HasPrefix(m["download_url"].(string), fr.srv.URL) {
		t.Errorf("without public base, download_url should be the upstream URL, got %v", m["download_url"])
	}
}
