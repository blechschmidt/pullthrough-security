package yum

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

// countedRepo is a repository in current Fedora's form (a zstd primary,
// repomd.xml declaring its checksum) whose requests are counted.
type countedRepo struct {
	t     *testing.T
	srv   *httptest.Server
	mu    sync.Mutex
	files map[string][]byte
	hits  map[string]int
	// primaryPath is where the primary repomd.xml names is served.
	primaryPath string
}

// countedRPMs are the repository's packages, path to payload.
var countedRPMs = map[string][]byte{
	"Packages/h/hello-1.0-1.fc44.x86_64.rpm": []byte("the genuine hello rpm"),
	"Packages/w/world-2.0-1.fc44.x86_64.rpm": []byte("the genuine world rpm"),
}

func newCountedRepo(t *testing.T) *countedRepo {
	t.Helper()
	r := &countedRepo{t: t, files: map[string][]byte{}, hits: map[string]int{}}
	r.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.mu.Lock()
		r.hits[req.URL.Path]++
		body, ok := r.files[req.URL.Path]
		r.mu.Unlock()
		if !ok {
			http.NotFound(w, req)
			return
		}
		_, _ = w.Write(body)
	}))
	t.Cleanup(r.srv.Close)
	for p, b := range countedRPMs {
		r.set("/"+p, b)
	}
	r.publish(countedPrimary(countedRPMs))
	return r
}

// countedPrimary is a primary declaring the digests of rpms (path to payload).
func countedPrimary(rpms map[string][]byte) []byte {
	var entries []string
	for p, b := range rpms {
		name := p[strings.LastIndexByte(p, '/')+1 : strings.Index(p, "-")]
		entries = append(entries, fmt.Sprintf(`<package type="rpm"><name>%s</name><arch>x86_64</arch><version epoch="0" ver="1" rel="1"/>
<checksum type="sha256" pkgid="YES">%s</checksum><location href="%s"/><format><rpm:license>MIT</rpm:license></format></package>
`, name, sha256Hex(b), p))
	}
	return []byte(primaryDoc(entries...))
}

// publish serves primary (zstd) and a repomd.xml declaring it.
func (r *countedRepo) publish(primary []byte) {
	body := zstdBytes(r.t, primary)
	loc := "repodata/" + sha256Hex(body) + "-primary.xml.zst"
	r.set("/"+loc, body)
	r.set("/repodata/repomd.xml", []byte(fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<repomd xmlns="http://linux.duke.edu/metadata/repo"><revision>1</revision>
<data type="primary"><checksum type="sha256">%s</checksum><location href="%s"/><size>%d</size></data>
</repomd>`, sha256Hex(body), loc, len(body))))
	r.mu.Lock()
	r.primaryPath = "/" + loc
	r.mu.Unlock()
}

func (r *countedRepo) set(path string, body []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.files[path] = body
}

func (r *countedRepo) count(path string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.hits[path]
}

func (r *countedRepo) backend(opts Options) *Backend {
	r.t.Helper()
	opts.Name, opts.UpstreamURL = "fedora", r.srv.URL
	opts.Client = upstream.NewWithHTTPClient(r.srv.Client(), "test/1")
	if opts.Metrics == nil {
		opts.Metrics = &Metrics{}
	}
	b, err := New(opts)
	if err != nil {
		r.t.Fatal(err)
	}
	return b
}

// fetchRPMAs fetches an .rpm through the backend and returns how it was
// verified.
func fetchRPMAs(t *testing.T, b *Backend, path string) (string, error) {
	t.Helper()
	fres, _, err := fetchAll(t, b, resolve(t, b, "/"+path))
	if fres == nil {
		return "", err
	}
	return fres.Resolved.Metadata[MetaChecksumVerified], err
}

// The backend's own population (an .rpm fetched while the store holds no
// digest for it — every .rpm the full mirror fetches, as the feed reads the
// primary itself) records only a primary whose bytes match the checksum
// repomd.xml declares: a forged one makes no tampered package "verified".
func TestPopulationVerifiesThePrimaryAgainstRepomd(t *testing.T) {
	r := newCountedRepo(t)
	genuine := r.files[r.primaryPath]
	tampered := []byte("a tampered hello rpm")
	r.set("/Packages/h/hello-1.0-1.fc44.x86_64.rpm", tampered)
	forged := zstdBytes(t, countedPrimary(map[string][]byte{"Packages/h/hello-1.0-1.fc44.x86_64.rpm": tampered}))
	r.set(r.primaryPath, forged)

	// A client fetching the forged primary is refused it.
	client := r.backend(Options{})
	_, _, err := fetchAll(t, client, resolve(t, client, r.primaryPath))
	var mismatch *ChecksumMismatchError
	if !errors.As(err, &mismatch) {
		t.Fatalf("a client's fetch of the forged primary: %v, want a checksum mismatch", err)
	}
	// The backend's own population records nothing from it either.
	m := &Metrics{}
	cold := r.backend(Options{Metrics: m})
	verified, err := fetchRPMAs(t, cold, "Packages/h/hello-1.0-1.fc44.x86_64.rpm")
	if err != nil || verified != "none" || cold.digests.len() != 0 {
		t.Errorf("the tampered package against a forged primary: verified %q, %v, %d digests", verified, err, cold.digests.len())
	}
	if m.Stats().RepodataMismatch != 1 {
		t.Errorf("RepodataMismatch = %v, want 1", m.Stats().RepodataMismatch)
	}
	// The genuine primary back: the tampered package is refused, the genuine
	// one verified.
	r.set(r.primaryPath, genuine)
	if _, err := fetchRPMAs(t, cold, "Packages/h/hello-1.0-1.fc44.x86_64.rpm"); !errors.As(err, &mismatch) {
		t.Errorf("the tampered package against the genuine primary: %v, want a checksum mismatch", err)
	}
	r.set("/Packages/h/hello-1.0-1.fc44.x86_64.rpm", countedRPMs["Packages/h/hello-1.0-1.fc44.x86_64.rpm"])
	if verified, err := fetchRPMAs(t, cold, "Packages/h/hello-1.0-1.fc44.x86_64.rpm"); err != nil || verified != "sha256" {
		t.Errorf("the genuine package: verified %q, %v", verified, err)
	}
}

// A primary fetched by a client records digests only when it verified against
// repomd.xml: one repomd.xml does not declare (or that is not there) records
// nothing.
func TestUnverifiedRepodataRecordsNothing(t *testing.T) {
	r := newCountedRepo(t)
	primary := r.files[r.primaryPath]
	r.set("/repodata/other-primary.xml.zst", primary)
	b := r.backend(Options{})
	if _, _, err := fetchAll(t, b, resolve(t, b, "/repodata/other-primary.xml.zst")); err != nil {
		t.Fatal(err)
	}
	if b.digests.len() != 0 {
		t.Errorf("a primary repomd.xml does not declare recorded %d digests", b.digests.len())
	}
	if _, _, err := fetchAll(t, b, resolve(t, b, r.primaryPath)); err != nil {
		t.Fatal(err)
	}
	if b.digests.len() != len(countedRPMs) {
		t.Errorf("the primary repomd.xml declares recorded %d digests", b.digests.len())
	}
}

// With a keyring, the repomd.xml the population trusts must be signed, as
// one a client is served must be.
func TestPopulationRequiresTheSignature(t *testing.T) {
	ent, pub := testKeypair(t)
	r := newCountedRepo(t)
	b := r.backend(Options{GPGKey: pub})
	// No repomd.xml.asc: nothing is recorded, the package is served as
	// unverified.
	if verified, err := fetchRPMAs(t, b, "Packages/h/hello-1.0-1.fc44.x86_64.rpm"); err != nil || verified != "none" || b.digests.len() != 0 {
		t.Errorf("without a signature: verified %q, %v, %d digests", verified, err, b.digests.len())
	}
	// A signature over another document: still nothing.
	r.set("/repodata/repomd.xml.asc", detachSign(t, ent, []byte("<repomd/>")))
	if verified, _ := fetchRPMAs(t, b, "Packages/h/hello-1.0-1.fc44.x86_64.rpm"); verified != "none" {
		t.Errorf("with a signature over another document: verified %q", verified)
	}
	// The repository's signature: the package verifies.
	r.set("/repodata/repomd.xml.asc", detachSign(t, ent, r.files["/repodata/repomd.xml"]))
	if verified, err := fetchRPMAs(t, b, "Packages/h/hello-1.0-1.fc44.x86_64.rpm"); err != nil || verified != "sha256" {
		t.Errorf("with the repository's signature: verified %q, %v", verified, err)
	}
}

// A primary that fails — it breaks off, its decompressor's check fails at the
// end — records nothing: digests read before the failure could be the wrong
// ones (a damaged byte), and would refuse the genuine package.
func TestBrokenPrimaryRecordsNothing(t *testing.T) {
	r := newCountedRepo(t)
	good := countedRPMs["Packages/h/hello-1.0-1.fc44.x86_64.rpm"]
	doc := countedPrimary(map[string][]byte{"Packages/h/hello-1.0-1.fc44.x86_64.rpm": good})
	var buf bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&buf, gzip.NoCompression)
	_, _ = zw.Write(doc)
	_ = zw.Close()
	body := buf.Bytes()
	i := bytes.Index(body, []byte(sha256Hex(good)))
	// A damaged digest, still hex: gzip's CRC fails at the end.
	if body[i] == '0' {
		body[i] = '1'
	} else {
		body[i] = '0'
	}
	b := r.backend(Options{})
	if b.populateFromPrimaryBytes("repodata/x-primary.xml.gz", body) || b.digests.len() != 0 {
		t.Errorf("a primary failing its CRC recorded %d digests", b.digests.len())
	}
	if verified, err := fetchRPMAs(t, b, "Packages/h/hello-1.0-1.fc44.x86_64.rpm"); err != nil || verified != "sha256" {
		t.Errorf("the genuine package after a damaged primary: verified %q, %v", verified, err)
	}
}

// One population at a time, and none again for the primary already loaded:
// concurrent misses read the primary once; a package the primary does not
// list costs repomd.xml, not the primary; a package that is not there costs
// no population; a store cleared since is populated again.
func TestPopulationIsSingleFlightAndRemembersThePrimary(t *testing.T) {
	r := newCountedRepo(t)
	b := r.backend(Options{})
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			p := "Packages/h/hello-1.0-1.fc44.x86_64.rpm"
			if i%2 == 1 {
				p = "Packages/w/world-2.0-1.fc44.x86_64.rpm"
			}
			res := resolve(t, b, "/"+p)
			fres, err := b.Fetch(context.Background(), res)
			if err != nil {
				t.Error(err)
				return
			}
			fres.Content.Close()
			if fres.Resolved.Metadata[MetaChecksumVerified] != "sha256" {
				t.Errorf("%s: verified %q", p, fres.Resolved.Metadata[MetaChecksumVerified])
			}
		}(i)
	}
	wg.Wait()
	if n := r.count(r.primaryPath); n != 1 {
		t.Errorf("8 concurrent misses read the primary %d times", n)
	}
	repomdReads := r.count("/repodata/repomd.xml")

	// Not in the primary: repomd.xml is read again, the primary is not.
	r.set("/Packages/g/ghost-1.0-1.fc44.x86_64.rpm", []byte("a package the primary does not list"))
	if verified, err := fetchRPMAs(t, b, "Packages/g/ghost-1.0-1.fc44.x86_64.rpm"); err != nil || verified != "none" {
		t.Errorf("an unlisted package: verified %q, %v", verified, err)
	}
	if r.count(r.primaryPath) != 1 || r.count("/repodata/repomd.xml") != repomdReads+1 {
		t.Errorf("an unlisted package read the primary %d times, repomd.xml %d more", r.count(r.primaryPath), r.count("/repodata/repomd.xml")-repomdReads)
	}
	// Not there at all: no population.
	if _, err := fetchRPMAs(t, b, "Packages/n/none-1.0-1.fc44.x86_64.rpm"); err == nil {
		t.Errorf("a missing package was served")
	}
	if r.count("/repodata/repomd.xml") != repomdReads+1 {
		t.Errorf("a missing package populated the store")
	}
	// A new primary (the package published): read once.
	newer := map[string][]byte{"Packages/g/ghost-1.0-1.fc44.x86_64.rpm": r.files["/Packages/g/ghost-1.0-1.fc44.x86_64.rpm"]}
	for p, c := range countedRPMs {
		newer[p] = c
	}
	r.publish(countedPrimary(newer))
	if verified, err := fetchRPMAs(t, b, "Packages/g/ghost-1.0-1.fc44.x86_64.rpm"); err != nil || verified != "sha256" {
		t.Errorf("the package once published: verified %q, %v", verified, err)
	}
	// The store cleared since (it fills up): the primary is read again.
	b.digests.mu.Lock()
	b.digests.entries = map[string]expectedChecksum{}
	b.digests.mu.Unlock()
	if verified, err := fetchRPMAs(t, b, "Packages/w/world-2.0-1.fc44.x86_64.rpm"); err != nil || verified != "sha256" {
		t.Errorf("after the store was cleared: verified %q, %v", verified, err)
	}
	if n := r.count(r.primaryPath); n != 2 {
		t.Errorf("the new primary was read %d times, want 2 (once published, once after the store was cleared)", n)
	}
	// A waiting miss gives up with its context.
	b.populating <- struct{}{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	b.populateFromRepo(ctx)
	<-b.populating
}

// A primary declaring more packages than the store holds records none (a
// store holding part of a primary would verify some packages and not others,
// at random).
func TestPopulationRefusesAPrimaryLargerThanTheStore(t *testing.T) {
	r := newCountedRepo(t)
	m := &Metrics{}
	b := r.backend(Options{DigestStoreMax: 1, Metrics: m})
	if verified, err := fetchRPMAs(t, b, "Packages/h/hello-1.0-1.fc44.x86_64.rpm"); err != nil || verified != "none" || b.digests.len() != 0 {
		t.Errorf("a primary larger than the store: verified %q, %v, %d digests", verified, err, b.digests.len())
	}
	if m.Stats().PrimaryErrors != 1 {
		t.Errorf("PrimaryErrors = %v, want 1", m.Stats().PrimaryErrors)
	}
}
