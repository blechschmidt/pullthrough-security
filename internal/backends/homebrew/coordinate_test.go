package homebrew

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

// --- registry-native path validation ----------------------------------------

func TestClassifyRegistryPaths(t *testing.T) {
	digest := strings.Repeat("a", 64)
	good := []struct {
		path string
		want resourceKind
	}{
		{"/v2/homebrew/core/hello/manifests/2.12.3-1", kindManifest},
		{"/v2/homebrew/core/hello/manifests/sha256:" + digest, kindManifest},
		{"/v2/homebrew/core/openssl/3/manifests/3.5.9", kindManifest},
		{"/v2/homebrew/core/python/3.12/manifests/3.12.16", kindManifest},
		{"/v2/homebrew/core/boost/manifests/1.92.0_1", kindManifest},
		{"/v2/homebrew/core/hello/blobs/sha256:" + digest, kindBottle},
		{"/v2/homebrew/core/openssl/3/blobs/sha256:" + digest, kindBottle},
		{"/v2/homebrew/core/sdl2_image/blobs/sha256:" + digest, kindBottle},
		{"/v2/homebrew/core/c-ares/blobs/sha256:" + digest, kindBottle},
		{"/v2/acme/tap/widget/blobs/sha256:" + digest, kindBottle},
		// The repository may itself end in a marker word; only the penultimate
		// segment is the marker.
		{"/v2/homebrew/core/blobs/manifests/1.0", kindManifest},
	}
	for _, c := range good {
		res, ok := classify(c.path)
		if !ok {
			t.Errorf("classify(%q) returned ok=false", c.path)
			continue
		}
		if res.kind != c.want {
			t.Errorf("classify(%q).kind = %v, want %v", c.path, res.kind, c.want)
		}
		if !res.registryNative {
			t.Errorf("classify(%q) not marked registry-native", c.path)
		}
	}

	long := strings.Repeat("a", maxRepoSegmentLen+1)
	bad := []string{
		"/v2", "/v2/", // the API-version probe is not served
		"/v2/homebrew/core/hello",                                   // no marker
		"/v2/homebrew/core/hello/tags/list",                         // tag listing
		"/v2/homebrew/core/hello/referrers/sha256:" + digest,        // referrers API
		"/v2/homebrew/core/hello/blobs/uploads",                     // upload session
		"/v2/_catalog",                                              // catalog
		"/v2/hello/blobs/sha256:" + digest,                          // one-segment repository
		"/v2/library/alpine/blobs/sha256:" + digest,                 // two-segment repository: a plain container image
		"/v2/library/alpine/manifests/latest",                       //
		"/v2/homebrew/core/a/b/c/blobs/sha256:" + digest,            // too deep to be {org}/{tap}/{name}[/{version}]
		"/v2/homebrew/core/hello/blobs/sha256:short",                // malformed digest
		"/v2/homebrew/core/hello/blobs/sha256:" + digest + "0",      // over-long digest
		"/v2/homebrew/core/hello/blobs/sha512:" + digest,            // unsupported algorithm
		"/v2/homebrew/core/hello/blobs/" + digest,                   // bare hex
		"/v2/homebrew/core/hello/blobs/latest",                      // a blob is never tag-addressed
		"/v2/homebrew/core/hello/manifests/sha256:short",            // malformed digest reference
		"/v2/homebrew/core/hello/manifests/md5:" + digest,           // ":" is not a tag character
		"/v2/homebrew/core/hello/manifests/-leading-dash",           // tags start with [A-Za-z0-9_]
		"/v2/homebrew/core/hello/manifests/.hidden",                 //
		"/v2/homebrew/core/hello/manifests/has space",               //
		"/v2/homebrew/core/hello/manifests/semi;colon",              //
		"/v2/homebrew/core/hello/manifests/" + long,                 // over-long tag
		"/v2/homebrew/core/hello/manifests/2.12.3-1/extra",          // trailing segment
		"/v2/homebrew/core/Hello/manifests/1.0",                     // uppercase repository
		"/v2/Homebrew/core/hello/manifests/1.0",                     //
		"/v2/homebrew/core/hel%6co/manifests/1.0",                   // percent sign
		"/v2/homebrew/core/hello@1/manifests/1.0",                   // "@" is encoded as "/" in a repository
		"/v2/homebrew/core/gtk+3/manifests/1.0",                     // "+" is encoded as "x"
		"/v2/homebrew/core/he:llo/manifests/1.0",                    //
		"/v2/homebrew/core/he?llo/manifests/1.0",                    //
		"/v2/homebrew/core/he#llo/manifests/1.0",                    //
		"/v2/homebrew/core/he\\llo/manifests/1.0",                   //
		"/v2/homebrew/core/-hello/manifests/1.0",                    // components start and end alphanumeric
		"/v2/homebrew/core/hello./manifests/1.0",                    //
		"/v2/homebrew/core/_/manifests/1.0",                         //
		"/v2/homebrew/core/" + long + "/manifests/1.0",              // over-long component
		"/v2/homebrew/core/../../etc/manifests/1.0",                 // traversal
		"/v2/homebrew/./hello/manifests/1.0",                        //
		"/v2/homebrew//hello/manifests/1.0",                         // empty segment
		"/v2/homebrew/core/hello/manifests/",                        // empty reference
		"/v2/homebrew/core/hello/manifests",                         //
		"/v1/homebrew/core/hello/manifests/1.0",                     // not the OCI prefix
		"/V2/homebrew/core/hello/manifests/1.0",                     //
		"/api/../v2/homebrew/core/hello/manifests/1.0",              //
		"/bottle/hello/1.0/v2/homebrew/core/hello/manifests/latest", // the synthetic endpoint serves blobs only
	}
	for _, path := range bad {
		if res, ok := classify(path); ok && (res.kind == kindManifest || res.kind == kindBottle) {
			t.Errorf("classify(%q) unexpectedly accepted as %s", path, res.kindLabel())
		}
	}
}

func TestClassifyRegistryFields(t *testing.T) {
	digest := strings.Repeat("b", 64)

	// An uppercase digest is canonicalised: the upstream path and cache key are
	// built from the lowercase form, never echoed from the request.
	res, ok := classify("/v2/homebrew/core/openssl/3/blobs/sha256:" + strings.ToUpper(digest))
	if !ok {
		t.Fatal("classify failed")
	}
	want := resource{
		kind:           kindBottle,
		name:           "openssl@3",
		blobPath:       "v2/homebrew/core/openssl/3/blobs/sha256:" + digest,
		repo:           "homebrew/core/openssl/3",
		digest:         digest,
		registryNative: true,
	}
	if res != want {
		t.Errorf("blob resource = %+v\nwant %+v", res, want)
	}
	if !res.cacheable() || !res.isBottle() || res.rewrites() || res.kindLabel() != "bottle" {
		t.Errorf("blob resource predicates wrong: %+v", res)
	}

	res, ok = classify("/v2/acme/tap/widget/manifests/1.0.0-2")
	if !ok {
		t.Fatal("classify failed")
	}
	want = resource{
		kind:           kindManifest,
		name:           "acme/tap/widget",
		repo:           "acme/tap/widget",
		reference:      "1.0.0-2",
		registryNative: true,
	}
	if res != want {
		t.Errorf("manifest resource = %+v\nwant %+v", res, want)
	}
	if res.cacheable() || res.isBottle() || res.rewrites() || res.kindLabel() != "manifest" {
		t.Errorf("manifest resource predicates wrong: %+v", res)
	}

	// The synthetic endpoint is unchanged and not registry-native.
	res, ok = classify("/bottle/wget/1.21.4/v2/homebrew/core/wget/blobs/sha256:" + digest)
	if !ok || res.registryNative || res.name != "wget" || res.version != "1.21.4" {
		t.Errorf("synthetic bottle resource = %+v", res)
	}
}

func TestValidOCITag(t *testing.T) {
	for _, tag := range []string{"2.12.3", "2.12.3-1", "1.92.0_1", "7.1.2-35", "_x", "A", "r3108", strings.Repeat("a", 128)} {
		if !validOCITag(tag) {
			t.Errorf("validOCITag(%q) = false", tag)
		}
	}
	for _, tag := range []string{"", ".x", "-x", "a b", "a/b", "a:b", "a+b", "a@b", "é", strings.Repeat("a", 129)} {
		if validOCITag(tag) {
			t.Errorf("validOCITag(%q) = true", tag)
		}
	}
}

// --- formula names ----------------------------------------------------------

func TestImageFormulaName(t *testing.T) {
	// brew: formula_name.tr("@", "/").tr("+", "x")
	for name, want := range map[string]string{
		"hello":        "hello",
		"openssl@3":    "openssl/3",
		"python@3.12":  "python/3.12",
		"gtk+3":        "gtkx3",
		"libsigc++@2":  "libsigcxx/2",
		"libxml++":     "libxmlxx",
		"dvd+rw-tools": "dvdxrw-tools",
	} {
		if got := imageFormulaName(name); got != want {
			t.Errorf("imageFormulaName(%q) = %q, want %q", name, got, want)
		}
	}
}

func TestPathFormulaName(t *testing.T) {
	cases := []struct{ repo, tap, image, name string }{
		{"homebrew/core/hello", "homebrew/core", "hello", "hello"},
		{"homebrew/core/openssl/3", "homebrew/core", "openssl/3", "openssl@3"},
		{"homebrew/core/python/3.12", "homebrew/core", "python/3.12", "python@3.12"},
		// "+" cannot be recovered from the path: the image spelling stands.
		{"homebrew/core/gtkx3", "homebrew/core", "gtkx3", "gtkx3"},
		// A formula outside the core tap is tap-qualified, so it can never pass
		// for the core formula of the same name.
		{"acme/tap/wget", "acme/tap", "wget", "acme/tap/wget"},
		{"acme/tap/widget/2", "acme/tap", "widget/2", "acme/tap/widget@2"},
	}
	for _, c := range cases {
		tap, image := splitRepo(c.repo)
		if tap != c.tap || image != c.image {
			t.Errorf("splitRepo(%q) = %q, %q; want %q, %q", c.repo, tap, image, c.tap, c.image)
		}
		if got := pathFormulaName(tap, image); got != c.name {
			t.Errorf("pathFormulaName(%q) = %q, want %q", c.repo, got, c.name)
		}
	}
	if tap, image := splitRepo("too/short"); tap != "too/short" || image != "" {
		t.Errorf("splitRepo of a two-segment repository = %q, %q", tap, image)
	}
}

func TestFormulaNameFromTitle(t *testing.T) {
	cases := []struct {
		tap, image, title string
		want              string
		ok                bool
	}{
		{"homebrew/core", "hello", "hello", "hello", true},
		{"homebrew/core", "openssl/3", "openssl@3", "openssl@3", true},
		{"homebrew/core", "gtkx3", "gtk+3", "gtk+3", true},
		{"homebrew/core", "libsigcxx/2", "libsigc++@2", "libsigc++@2", true},
		{"homebrew/core", "hello", "  hello  ", "hello", true},
		// A per-platform manifest titles itself "<formula> <reference name>".
		{"homebrew/core", "hello", "hello 2.12.3.x86_64_linux.1", "hello", true},
		// A tap formula's full name; brew lowercases the organisation in the path.
		{"acme/tap", "widget", "acme/tap/widget", "acme/tap/widget", true},
		{"acme/tap", "widget", "Acme/tap/widget", "acme/tap/widget", true},
		{"acme/tap", "widget", "widget", "acme/tap/widget", true},
		// Titles that do not map back to the repository are rejected.
		{"homebrew/core", "hello", "curl", "", false},
		{"homebrew/core", "hello", "", "", false},
		{"homebrew/core", "gtkx3", "gtk+4", "", false},
		{"homebrew/core", "openssl/3", "openssl/3", "", false},
		{"acme/tap", "widget", "homebrew/core/widget", "", false},
		{"homebrew/core", "widget", "acme/tap/widget", "", false},
		{"homebrew/core", "hello", "hello/", "", false},
	}
	for _, c := range cases {
		got, ok := formulaNameFromTitle(c.tap, c.image, c.title)
		if got != c.want || ok != c.ok {
			t.Errorf("formulaNameFromTitle(%q, %q, %q) = %q, %v; want %q, %v",
				c.tap, c.image, c.title, got, ok, c.want, c.ok)
		}
	}
}

func TestFormulaNameCandidates(t *testing.T) {
	for image, want := range map[string][]string{
		"hello":               {"hello"},
		"openssl/3":           {"openssl@3"},
		"gtkx3":               {"gtkx3", "gtk+3"},
		"dvdxrw-tools":        {"dvdxrw-tools", "dvd+rw-tools"},
		"libsigcxx/2":         {"libsigcxx@2", "libsigcx+@2", "libsigc++@2"},
		"libxmlxx":            {"libxmlxx", "libxmlx+", "libxml++", "lib+ml++"},
		"mysql-connector-cxx": {"mysql-connector-cxx", "mysql-connector-cx+", "mysql-connector-c++"},
		// Bounded: at most maxPlusCandidates trailing "x" are tried.
		"xxxxx": {"xxxxx", "xxxx+", "xxx++", "xx+++"},
	} {
		if got := formulaNameCandidates(image); !reflect.DeepEqual(got, want) {
			t.Errorf("formulaNameCandidates(%q) = %v, want %v", image, got, want)
		}
	}
}

// --- manifest parsing -------------------------------------------------------

func TestParseBottleManifestIndex(t *testing.T) {
	linux, mac := strings.Repeat("1", 64), strings.Repeat("2", 64)
	facts, ok := parseBottleManifest(ociIndex("hello", "2.12.3", 1,
		platformBottle{"x86_64_linux", linux}, platformBottle{"arm64_sequoia", mac}))
	if !ok {
		t.Fatal("a bottle index must parse")
	}
	if facts.title != "hello" {
		t.Errorf("title = %q", facts.title)
	}
	want := []manifestBottle{{digest: linux, version: "2.12.3"}, {digest: mac, version: "2.12.3"}}
	if !reflect.DeepEqual(facts.bottles, want) {
		t.Errorf("bottles = %+v, want %+v", facts.bottles, want)
	}
}

func TestParseBottleManifestTolerance(t *testing.T) {
	digest := strings.Repeat("3", 64)
	entry := func(ann string) string { return `{"annotations":{` + ann + `}}` }
	good := `"org.opencontainers.image.ref.name":"1.0.sonoma","sh.brew.bottle.digest":"` + digest + `"`

	cases := []struct {
		name string
		doc  string
		want []manifestBottle
	}{
		{"uppercase digest is normalised",
			`{"manifests":[` + entry(`"org.opencontainers.image.ref.name":"1.0.sonoma","sh.brew.bottle.digest":"`+strings.ToUpper(digest)+`"`) + `]}`,
			[]manifestBottle{{digest, "1.0"}}},
		{"a non-string annotation does not spoil the document",
			`{"annotations":{"org.opencontainers.image.title":42},"manifests":[` + entry(good+`,"sh.brew.tab":{"nested":true}`) + `]}`,
			[]manifestBottle{{digest, "1.0"}}},
		{"entries without a bottle digest are skipped",
			`{"manifests":[{"annotations":{"org.opencontainers.image.ref.name":"1.0.sonoma"}},{},` + entry(good) + `]}`,
			[]manifestBottle{{digest, "1.0"}}},
		{"an entry with a malformed digest is skipped",
			`{"manifests":[` + entry(`"org.opencontainers.image.ref.name":"1.0.sonoma","sh.brew.bottle.digest":"abc"`) + `,` + entry(good) + `]}`,
			[]manifestBottle{{digest, "1.0"}}},
		{"an entry with no derivable version is skipped",
			`{"manifests":[` + entry(`"sh.brew.bottle.digest":"`+digest+`"`) + `]}`,
			nil},
		{"an entry whose version is not a valid tag is skipped",
			`{"manifests":[` + entry(`"org.opencontainers.image.ref.name":"1/0.sonoma","sh.brew.bottle.digest":"`+digest+`"`) + `]}`,
			nil},
		{"the document version stands in for a missing reference name",
			`{"annotations":{"org.opencontainers.image.version":"4.5_2"},"manifests":[` + entry(`"sh.brew.bottle.digest":"`+digest+`"`) + `]}`,
			[]manifestBottle{{digest, "4.5"}}},
		{"a per-platform image manifest carries the annotations at its top level",
			`{"layers":[{"digest":"sha256:` + digest + `"}],"annotations":{` + good + `}}`,
			[]manifestBottle{{digest, "1.0"}}},
		{"not a bottle image", `{"schemaVersion":2,"manifests":[{"digest":"sha256:` + digest + `"}]}`, nil},
		{"empty object", `{}`, nil},
		{"JSON of the wrong shape", `[1,2,3]`, nil},
		{"annotations of the wrong shape", `{"annotations":"nope"}`, nil},
		{"not JSON", `not json`, nil},
		{"empty", ``, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			facts, ok := parseBottleManifest([]byte(c.doc))
			if ok != (len(c.want) > 0) {
				t.Errorf("ok = %v, want %v", ok, len(c.want) > 0)
			}
			if !reflect.DeepEqual(facts.bottles, c.want) {
				t.Errorf("bottles = %+v, want %+v", facts.bottles, c.want)
			}
		})
	}
}

func TestParseBottleManifestIsBounded(t *testing.T) {
	var sb strings.Builder
	sb.WriteString(`{"manifests":[`)
	for i := 0; i < maxBottlesPerManifest+50; i++ {
		if i > 0 {
			sb.WriteByte(',')
		}
		fmt.Fprintf(&sb, `{"annotations":{"org.opencontainers.image.ref.name":"1.0.sonoma","sh.brew.bottle.digest":"%064x"}}`, i)
	}
	sb.WriteString(`]}`)
	facts, ok := parseBottleManifest([]byte(sb.String()))
	if !ok || len(facts.bottles) != maxBottlesPerManifest {
		t.Errorf("learned %d bottles from one manifest, want the cap %d", len(facts.bottles), maxBottlesPerManifest)
	}
}

func TestFormulaVersion(t *testing.T) {
	cases := []struct {
		refName, pkgVersion string
		want                string
		ok                  bool
	}{
		// Real shapes: "<pkg_version>.<bottle tag>[.<rebuild>]".
		{"2.12.3.x86_64_linux.1", "2.12.3", "2.12.3", true},
		{"2.12.3.arm64_sequoia", "2.12.3", "2.12.3", true},
		{"1.92.0_1.x86_64_linux", "1.92.0_1", "1.92.0", true},
		{"1.25.0_2.all.3", "1.25.0_2", "1.25.0", true},
		{"7.1.2-35.arm64_golden_gate", "7.1.2-35", "7.1.2-35", true},
		{"r3108.sonoma.2", "r3108", "r3108", true},
		// Without a document version the reference name is split on its own.
		{"2.12.3.x86_64_linux.1", "", "2.12.3", true},
		{"1.92.0_1.arm64_sonoma", "", "1.92.0", true},
		{"7.1.2-35.x86_64_linux", "", "7.1.2-35", true},
		{"1.0.rc1.sonoma", "", "1.0.rc1", true},
		{"1.0.beta.big_sur.4", "", "1.0.beta", true},
		// A document version the reference name does not extend is overruled by
		// the reference name (the annotation brew itself checks).
		{"2.12.3.x86_64_linux", "9.9.9", "2.12.3", true},
		{"1.2.3.sonoma", "1.2", "1.2.3", true},
		// An unparseable reference name falls back to the document version.
		{"", "3.5.9", "3.5.9", true},
		{"garbage", "3.5.9_1", "3.5.9", true},
		// Nothing usable.
		{"", "", "", false},
		{"2.12.3", "", "", false},          // no bottle tag
		{"2.12.3.1", "", "", false},        // a rebuild but no tag
		{"1/2.sonoma", "", "", false},      // not a valid version
		{"1.0.sonoma", "a b", "1.0", true}, // an unusable document version is ignored
		{".sonoma", "", "", false},
	}
	for _, c := range cases {
		got, ok := formulaVersion(c.refName, c.pkgVersion)
		if got != c.want || ok != c.ok {
			t.Errorf("formulaVersion(%q, %q) = %q, %v; want %q, %v", c.refName, c.pkgVersion, got, ok, c.want, c.ok)
		}
	}
}

func TestStripRevision(t *testing.T) {
	// Mirrors brew's PkgVersion.parse: /\A(.+?)(?:_(\d+))?\z/
	for in, want := range map[string]string{
		"1.92.0_1":  "1.92.0",
		"1.25.0_12": "1.25.0",
		"2.12.3":    "2.12.3",
		"7.1.2-35":  "7.1.2-35",
		"1_2_3":     "1_2",
		"1.0_beta":  "1.0_beta",
		"1.0_":      "1.0_",
		"_1":        "_1",
		"":          "",
	} {
		if got := stripRevision(in); got != want {
			t.Errorf("stripRevision(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestIsBottleTag(t *testing.T) {
	for _, tag := range []string{"all", "sonoma", "arm64_sequoia", "x86_64_linux", "arm64_linux", "big_sur", "el_capitan", "arm64_golden_gate"} {
		if !isBottleTag(tag) {
			t.Errorf("isBottleTag(%q) = false", tag)
		}
	}
	for _, tag := range []string{"", "1", "12", "3x", "_x", "Sonoma", "a-b", "a.b"} {
		if isBottleTag(tag) {
			t.Errorf("isBottleTag(%q) = true", tag)
		}
	}
}

// --- the bounded index ------------------------------------------------------

func TestBottleIndexIsBoundedLRU(t *testing.T) {
	now := time.Unix(1000, 0)
	idx := newBottleIndex(3, func() time.Time { return now })
	key := func(i int) bottleKey { return bottleKey{repo: "homebrew/core/f", digest: fmt.Sprintf("%064d", i)} }
	fact := func(v string) bottleFact { return bottleFact{version: v, source: versionSourceManifest} }

	for i := 1; i <= 3; i++ {
		idx.put(key(i), fact(fmt.Sprint(i)))
	}
	// Touch 1 so that 2 becomes the least recently used, then overflow.
	if _, ok := idx.get(key(1)); !ok {
		t.Fatal("entry 1 missing")
	}
	idx.put(key(4), fact("4"))
	if idx.len() != 3 {
		t.Fatalf("len = %d, want the bound 3", idx.len())
	}
	if _, ok := idx.get(key(2)); ok {
		t.Error("the least recently used entry (2) must have been evicted")
	}
	for _, i := range []int{1, 3, 4} {
		if got, ok := idx.get(key(i)); !ok || got.version != fmt.Sprint(i) {
			t.Errorf("entry %d = %+v, %v", i, got, ok)
		}
	}

	// Updating an entry replaces it in place and refreshes its recency.
	idx.put(key(1), fact("1b"))
	idx.put(key(5), fact("5"))
	if got, ok := idx.get(key(1)); !ok || got.version != "1b" {
		t.Errorf("updated entry = %+v, %v", got, ok)
	}
	if _, ok := idx.get(key(3)); ok {
		t.Error("entry 3 was least recently used and must have been evicted")
	}
	if idx.len() != 3 {
		t.Errorf("len = %d, want 3", idx.len())
	}
}

func TestBottleIndexUnresolvedFactsExpire(t *testing.T) {
	now := time.Unix(1000, 0)
	idx := newBottleIndex(8, func() time.Time { return now })
	k := bottleKey{repo: "homebrew/core/hello", digest: strings.Repeat("a", 64)}

	idx.put(k, bottleFact{name: "hello", expires: now.Add(time.Minute)})
	if got, ok := idx.get(k); !ok || got.known() || got.name != "hello" {
		t.Fatalf("unresolved fact = %+v, %v", got, ok)
	}
	now = now.Add(time.Minute)
	if _, ok := idx.get(k); ok {
		t.Error("an expired fact must be reported absent")
	}
	if idx.len() != 0 {
		t.Errorf("len = %d: the expired fact must be dropped", idx.len())
	}
}

func TestBottleIndexPutIfUnknown(t *testing.T) {
	now := time.Unix(1000, 0)
	idx := newBottleIndex(8, func() time.Time { return now })
	k := bottleKey{repo: "homebrew/core/hello", digest: strings.Repeat("a", 64)}
	learned := bottleFact{name: "hello", version: "2.12.3", source: versionSourceManifest}
	recovered := bottleFact{name: "hello", version: "2.12.3", source: versionSourceFormulaAPI}
	unresolved := bottleFact{expires: now.Add(time.Minute)}

	// Absent: recorded.
	if got := idx.putIfUnknown(k, unresolved); got != unresolved {
		t.Errorf("putIfUnknown on an absent key returned %+v", got)
	}
	// An unresolved marker gives way to a version.
	if got := idx.putIfUnknown(k, recovered); got != recovered {
		t.Errorf("putIfUnknown over an unresolved marker returned %+v", got)
	}
	// A known version is never displaced — not by a marker, not by another source.
	idx.put(k, learned)
	for _, f := range []bottleFact{unresolved, recovered} {
		if got := idx.putIfUnknown(k, f); got != learned {
			t.Errorf("putIfUnknown displaced a known version: %+v", got)
		}
	}
	if got, _ := idx.get(k); got != learned {
		t.Errorf("index holds %+v, want %+v", got, learned)
	}
}

func TestNewBottleIndexDefaults(t *testing.T) {
	idx := newBottleIndex(0, nil)
	if idx.max != defaultBottleIndexSize || idx.now == nil {
		t.Errorf("defaults not applied: max=%d", idx.max)
	}
}

// --- manifest fetches in flight ---------------------------------------------

// waitAsync runs flights.wait on its own goroutine and delivers its result.
func waitAsync(ctx context.Context, f *manifestFlights, repo string, timeout time.Duration) <-chan bool {
	out := make(chan bool, 1)
	go func() { out <- f.wait(ctx, repo, timeout) }()
	return out
}

func TestManifestFlightsWaitForEveryFetchOfTheRepository(t *testing.T) {
	f := newManifestFlights()
	ctx := context.Background()

	// Nothing in flight: no wait.
	if f.wait(ctx, "homebrew/core/hello", time.Minute) {
		t.Fatal("wait reported a fetch in flight on an idle tracker")
	}

	endFirst := f.begin("homebrew/core/hello")
	endSecond := f.begin("homebrew/core/hello")
	endOther := f.begin("homebrew/core/wget")

	waiter := waitAsync(ctx, f, "homebrew/core/hello", time.Minute)
	assertBlocked := func(when string) {
		t.Helper()
		select {
		case <-waiter:
			t.Fatalf("wait returned %s", when)
		case <-time.After(50 * time.Millisecond):
		}
	}
	assertBlocked("while two fetches were in flight")

	// Another repository's fetch ending is irrelevant, and ending one fetch
	// twice does not stand in for the other.
	endOther()
	endFirst()
	endFirst()
	assertBlocked("while one fetch was still in flight")

	endSecond()
	if !<-waiter {
		t.Error("wait must report that there was a fetch to wait for")
	}

	// Nothing is retained once the fetches are over.
	f.mu.Lock()
	remaining := len(f.flights)
	f.mu.Unlock()
	if remaining != 0 {
		t.Errorf("%d repositories still tracked after every fetch ended", remaining)
	}
	if f.wait(ctx, "homebrew/core/hello", time.Minute) {
		t.Error("wait reported a fetch in flight after it ended")
	}
}

func TestManifestFlightsWaitIsBounded(t *testing.T) {
	f := newManifestFlights()
	defer f.begin("homebrew/core/hello")() // never ends during the test

	// By the timeout...
	start := time.Now()
	if !f.wait(context.Background(), "homebrew/core/hello", 30*time.Millisecond) {
		t.Error("wait must report the fetch it gave up on")
	}
	if elapsed := time.Since(start); elapsed < 30*time.Millisecond || elapsed > 5*time.Second {
		t.Errorf("wait took %v, want roughly the 30ms bound", elapsed)
	}

	// ...and by the request's context.
	ctx, cancel := context.WithCancel(context.Background())
	waiter := waitAsync(ctx, f, "homebrew/core/hello", time.Minute)
	cancel()
	select {
	case <-waiter:
	case <-time.After(5 * time.Second):
		t.Fatal("wait ignored the cancelled context")
	}
}

func TestManifestFlightsConcurrentUse(t *testing.T) {
	f := newManifestFlights()
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			repo := fmt.Sprintf("homebrew/core/f%d", i%4)
			end := f.begin(repo)
			f.wait(context.Background(), repo, time.Millisecond)
			end()
		}(i)
	}
	wg.Wait()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.flights) != 0 {
		t.Errorf("%d repositories still tracked", len(f.flights))
	}
}

func TestMetricsVersionSources(t *testing.T) {
	m := &Metrics{}
	for _, source := range []string{
		versionSourceManifest, versionSourceFormulaAPI, versionSourceFormulaAPI,
		versionSourceDigest, versionSourceDigest, versionSourceDigest,
		versionSourceURL, // the synthetic endpoint is not counted
	} {
		m.incVersionSource(source)
	}
	s := m.Stats()
	if s.VersionFromManifest != 1 || s.VersionFromFormulaAPI != 2 || s.VersionFromDigest != 3 {
		t.Errorf("version-source metrics = %+v", s)
	}
}
