package helm

import (
	"fmt"
	"net/url"
	"sort"
	"strings"
	"testing"
)

// testLinks mints links under an absolute public base, as the backend does when
// the proxy's public URL is configured.
var testLinks = linker{base: "https://proxy.example.com/v1/charts/"}

// rewriteDoc scans and rewrites an index document.
func rewriteDoc(doc string, links linker) (string, error) {
	scanned, err := scanIndex([]byte(doc))
	if err != nil {
		return "", err
	}
	out, err := scanned.rewrite([]byte(doc), links)
	return string(out), err
}

// mustRewrite is rewriteDoc for documents that must be accepted.
func mustRewrite(t *testing.T, doc string, links linker) string {
	t.Helper()
	out, err := rewriteDoc(doc, links)
	if err != nil {
		t.Fatalf("rewrite: %v\n--- document ---\n%s", err, doc)
	}
	return out
}

// chartURLs returns every chart URL of a document, in document order.
func chartURLs(t *testing.T, doc string) []string {
	t.Helper()
	scanned, err := scanIndex([]byte(doc))
	if err != nil {
		t.Fatalf("scanning document: %v\n--- document ---\n%s", err, doc)
	}
	var urls []string
	for _, e := range scanned.entries {
		for _, u := range e.urls {
			urls = append(urls, u.value)
		}
	}
	return urls
}

// A realistic index, in the layout `helm repo index` writes, covering the three
// shapes a chart URL takes: absolute on the repository's own host, relative to
// the repository, and absolute on another host. Everything that merely looks
// like a chart URL (home, sources, an icon, prose mentioning "urls:") must
// survive untouched.
const realisticIndex = `apiVersion: v1
entries:
  podinfo:
  - apiVersion: v1
    appVersion: 6.7.1
    created: "2024-09-23T10:11:12.000000001Z"
    description: Podinfo Helm chart for Kubernetes
    digest: 1111111111111111111111111111111111111111111111111111111111111111
    home: https://charts.example.com/podinfo
    name: podinfo
    sources:
    - https://charts.example.com/podinfo/podinfo-6.7.1.tgz
    urls:
    - https://charts.example.com/podinfo/podinfo-6.7.1.tgz
    version: 6.7.1
  cert-manager:
  - annotations:
      artifacthub.io/changes: |
        - kind: fixed
          description: the chart lists its urls:
          - https://cdn.example.net/not-a-chart-url.tgz
    description: A chart whose long description is folded onto a second line the
      way yaml.v2 folds it, and which mentions https://cdn.example.net/x.tgz
    digest: 2222222222222222222222222222222222222222222222222222222222222222
    icon: https://cdn.example.net/icons/cert-manager.png
    name: cert-manager
    urls:
    - charts/cert-manager-v1.16.1.tgz # served next to the index
    version: v1.16.1
  ingress-nginx:
  - digest: 3333333333333333333333333333333333333333333333333333333333333333
    name: ingress-nginx
    urls:
    - https://github.example.org/kubernetes/ingress-nginx/releases/download/helm-chart-4.11.3/ingress-nginx-4.11.3.tgz
    version: 4.11.3
generated: "2024-10-08T19:04:35.000000002Z"
`

func TestRewriteReplacesExactlyTheChartURLs(t *testing.T) {
	got := mustRewrite(t, realisticIndex, testLinks)

	// Build the expectation textually: the three URL scalars (and nothing else)
	// are replaced. The same-host URL also appears under `sources`, so it is
	// replaced at its second occurrence only.
	want := realisticIndex
	replaceNth := func(s, old, new string, n int) string {
		idx := -1
		for i := 0; i < n; i++ {
			next := strings.Index(s[idx+1:], old)
			if next < 0 {
				t.Fatalf("occurrence %d of %q not found", n, old)
			}
			idx += 1 + next
		}
		return s[:idx] + new + s[idx+len(old):]
	}
	want = replaceNth(want, "https://charts.example.com/podinfo/podinfo-6.7.1.tgz",
		`"https://proxy.example.com/v1/charts/-/podinfo/6.7.1/podinfo-6.7.1.tgz"`, 2)
	want = replaceNth(want, "charts/cert-manager-v1.16.1.tgz",
		`"https://proxy.example.com/v1/charts/-/cert-manager/v1.16.1/cert-manager-v1.16.1.tgz"`, 1)
	want = replaceNth(want, "https://github.example.org/kubernetes/ingress-nginx/releases/download/helm-chart-4.11.3/ingress-nginx-4.11.3.tgz",
		`"https://proxy.example.com/v1/charts/-/ingress-nginx/4.11.3/ingress-nginx-4.11.3.tgz"`, 1)

	if got != want {
		t.Errorf("rewritten index differs from the expectation\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}

	// No chart URL of the served document points anywhere but the proxy.
	for _, u := range chartURLs(t, got) {
		if !strings.HasPrefix(u, testLinks.base+"-/") {
			t.Errorf("chart URL %q does not lead back through the proxy", u)
		}
	}
}

func TestRewriteWithoutPublicBaseUsesRelativeReferences(t *testing.T) {
	got := mustRewrite(t, realisticIndex, linker{})
	want := []string{
		"-/podinfo/6.7.1/podinfo-6.7.1.tgz",
		"-/cert-manager/v1.16.1/cert-manager-v1.16.1.tgz",
		"-/ingress-nginx/4.11.3/ingress-nginx-4.11.3.tgz",
	}
	urls := chartURLs(t, got)
	if strings.Join(urls, "\n") != strings.Join(want, "\n") {
		t.Errorf("chart URLs = %q, want %q", urls, want)
	}
	// A relative reference stays on whatever host and mount the client added the
	// repository under; nothing upstream-chosen is left for it to resolve.
	for _, u := range urls {
		ref, err := url.Parse(u)
		if err != nil || ref.IsAbs() || ref.Host != "" || strings.HasPrefix(u, "/") {
			t.Errorf("chart URL %q is not a repository-relative reference", u)
		}
	}
}

// Every notation a URL scalar can take must be located and replaced in place.
func TestRewriteHandlesEveryScalarNotation(t *testing.T) {
	const link = `"https://proxy.example.com/v1/charts/-/c/1.0.0/c-1.0.0.tgz"`
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "block plain",
			in:   "entries:\n  c:\n  - version: 1.0.0\n    urls:\n    - https://h.example/c-1.0.0.tgz\n",
			want: "entries:\n  c:\n  - version: 1.0.0\n    urls:\n    - " + link + "\n",
		},
		{
			name: "single quoted",
			in:   "entries:\n  c:\n  - version: 1.0.0\n    urls:\n    - 'https://h.example/c-1.0.0.tgz'\n",
			want: "entries:\n  c:\n  - version: 1.0.0\n    urls:\n    - " + link + "\n",
		},
		{
			name: "single quoted with an escaped quote",
			in:   "entries:\n  c:\n  - version: 1.0.0\n    urls:\n    - 'https://h.example/it''s/c-1.0.0.tgz'\n",
			want: "entries:\n  c:\n  - version: 1.0.0\n    urls:\n    - " + link + "\n",
		},
		{
			name: "double quoted",
			in:   "entries:\n  c:\n  - version: 1.0.0\n    urls:\n    - \"https://h.example/c-1.0.0.tgz\"\n",
			want: "entries:\n  c:\n  - version: 1.0.0\n    urls:\n    - " + link + "\n",
		},
		{
			name: "double quoted with escapes",
			in:   "entries:\n  c:\n  - version: 1.0.0\n    urls:\n    - \"https://h.example/a\\\"b/c-1.0.0.tgz?x=1\\u0026y=2\"\n",
			want: "entries:\n  c:\n  - version: 1.0.0\n    urls:\n    - " + link + "\n",
		},
		{
			name: "trailing comment and padding",
			in:   "entries:\n  c:\n  - version: 1.0.0\n    urls:\n    -   https://h.example/c-1.0.0.tgz   # mirror\n",
			want: "entries:\n  c:\n  - version: 1.0.0\n    urls:\n    -   " + link + "   # mirror\n",
		},
		{
			name: "value on the line after the dash",
			in:   "entries:\n  c:\n  - version: 1.0.0\n    urls:\n    -\n      https://h.example/c-1.0.0.tgz\n",
			want: "entries:\n  c:\n  - version: 1.0.0\n    urls:\n    -\n      " + link + "\n",
		},
		{
			name: "flow sequence with mirrors",
			in:   "entries:\n  c:\n  - {version: 1.0.0, urls: [https://h.example/c-1.0.0.tgz, 'https://m.example/c-1.0.0.tgz']}\n",
			want: "entries:\n  c:\n  - {version: 1.0.0, urls: [" + link + ", " + link + "]}\n",
		},
		{
			name: "minified JSON",
			in:   `{"apiVersion":"v1","entries":{"c":[{"version":"1.0.0","urls":["https://h.example/c-1.0.0.tgz"],"digest":"x"}]}}`,
			want: `{"apiVersion":"v1","entries":{"c":[{"version":"1.0.0","urls":[` + link + `],"digest":"x"}]}}`,
		},
		{
			name: "indented JSON",
			in:   "{\n  \"entries\": {\n    \"c\": [\n      {\n        \"urls\": [\n          \"https://h.example/c-1.0.0.tgz\"\n        ],\n        \"version\": \"1.0.0\"\n      }\n    ]\n  }\n}\n",
			want: "{\n  \"entries\": {\n    \"c\": [\n      {\n        \"urls\": [\n          " + link + "\n        ],\n        \"version\": \"1.0.0\"\n      }\n    ]\n  }\n}\n",
		},
		{
			name: "CRLF line endings",
			in:   "entries:\r\n  c:\r\n  - version: 1.0.0\r\n    urls:\r\n    - https://h.example/c-1.0.0.tgz\r\n",
			want: "entries:\r\n  c:\r\n  - version: 1.0.0\r\n    urls:\r\n    - " + link + "\r\n",
		},
		{
			name: "bare CR line endings",
			in:   "entries:\r  c:\r  - version: 1.0.0\r    urls:\r    - https://h.example/c-1.0.0.tgz\r",
			want: "entries:\r  c:\r  - version: 1.0.0\r    urls:\r    - " + link + "\r",
		},
		{
			name: "byte-order mark",
			in:   "\xef\xbb\xbfentries:\n  c:\n  - version: 1.0.0\n    urls:\n    - https://h.example/c-1.0.0.tgz\n",
			want: "\xef\xbb\xbfentries:\n  c:\n  - version: 1.0.0\n    urls:\n    - " + link + "\n",
		},
		{
			name: "multi-byte characters before the URL on its line",
			in:   `{"entries":{"c":[{"description":"çé 日本語 🚀","version":"1.0.0","urls":["https://h.example/c-1.0.0.tgz"]}]}}`,
			want: `{"entries":{"c":[{"description":"çé 日本語 🚀","version":"1.0.0","urls":[` + link + `]}]}}`,
		},
		{
			name: "Unicode line breaks inside an earlier string",
			in:   "{\"entries\":{\"c\":[{\"description\":\"a\u0085b\u2028c\u2029d\",\"version\":\"1.0.0\",\"urls\":[\"https://h.example/c-1.0.0.tgz\"]}]}}",
			want: "{\"entries\":{\"c\":[{\"description\":\"a\u0085b\u2028c\u2029d\",\"version\":\"1.0.0\",\"urls\":[" + link + "]}]}}",
		},
		{
			name: "leading document marker",
			in:   "---\nentries:\n  c:\n  - version: 1.0.0\n    urls:\n    - https://h.example/c-1.0.0.tgz\n",
			want: "---\nentries:\n  c:\n  - version: 1.0.0\n    urls:\n    - " + link + "\n",
		},
		{
			name: "explicit key indicator",
			in:   "entries:\n  c:\n  - version: 1.0.0\n    ? urls\n    : - https://h.example/c-1.0.0.tgz\n",
			want: "entries:\n  c:\n  - version: 1.0.0\n    ? urls\n    : - " + link + "\n",
		},
		{
			name: "document end marker and a stray trailing separator",
			in:   "entries:\n  c:\n  - version: 1.0.0\n    urls:\n    - https://h.example/c-1.0.0.tgz\n...\n---\n# nothing follows\n",
			want: "entries:\n  c:\n  - version: 1.0.0\n    urls:\n    - " + link + "\n...\n---\n# nothing follows\n",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := mustRewrite(t, tc.in, testLinks)
			if got != tc.want {
				t.Errorf("rewritten document:\n got %q\nwant %q", got, tc.want)
			}
		})
	}
}

// Helm decodes the index through encoding/json, which matches keys to fields
// case-insensitively (under Unicode simple folding) and, for a JSON index, lets
// a repeated key through. Each spelling below reaches a real Helm client as an
// entry's urls, so each must be rewritten.
func TestRewriteMatchesKeysTheWayHelmDoes(t *testing.T) {
	cases := map[string]string{
		"upper-case urls":    "entries:\n  c:\n  - version: 1.0.0\n    URLS:\n    - https://evil.example/c-1.0.0.tgz\n",
		"mixed-case urls":    "entries:\n  c:\n  - version: 1.0.0\n    uRlS:\n    - https://evil.example/c-1.0.0.tgz\n",
		"long-s urls":        "entries:\n  c:\n  - version: 1.0.0\n    url\u017f:\n    - https://evil.example/c-1.0.0.tgz\n",
		"upper-case entries": "ENTRIES:\n  c:\n  - version: 1.0.0\n    urls:\n    - https://evil.example/c-1.0.0.tgz\n",
		"quoted keys":        "\"entries\":\n  c:\n  - version: 1.0.0\n    'urls':\n    - https://evil.example/c-1.0.0.tgz\n",
		"escaped key":        "entries:\n  c:\n  - version: 1.0.0\n    \"ur\\u006cs\":\n    - https://evil.example/c-1.0.0.tgz\n",
		"both cases at once": "entries:\n  c:\n  - version: 1.0.0\n    urls:\n    - https://evil.example/c-1.0.0.tgz\n    URLS:\n    - https://evil.example/other/c-1.0.0.tgz\n",
		"repeated JSON urls": `{"entries":{"c":[{"version":"1.0.0","urls":["https://evil.example/a/c-1.0.0.tgz"],"urls":["https://evil.example/b/c-1.0.0.tgz"]}]}}`,
		"repeated JSON entries": `{"entries":{"c":[{"version":"1.0.0","urls":["https://evil.example/c-1.0.0.tgz"]}]},` +
			`"entries":{"d":[{"version":"2.0.0","urls":["https://evil.example/d-2.0.0.tgz"]}]}}`,
		"non-specific tag on the key": "entries:\n  c:\n  - version: 1.0.0\n    ! urls:\n    - https://evil.example/c-1.0.0.tgz\n",
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			got := mustRewrite(t, doc, testLinks)
			if strings.Contains(got, "evil.example") {
				t.Errorf("an upstream URL survived the rewrite:\n%s", got)
			}
			urls := chartURLs(t, got)
			if len(urls) == 0 {
				t.Fatalf("no chart URLs found in the rewritten document:\n%s", got)
			}
			for _, u := range urls {
				if !strings.HasPrefix(u, testLinks.base+"-/") {
					t.Errorf("chart URL %q does not lead back through the proxy", u)
				}
			}
		})
	}
}

// YAML can give an entry its urls without spelling "urls" where it applies, and
// a real Helm client honors every one of these forms. The rewrite does not try
// to emulate them: a document it cannot fully account for is refused, never
// served with a URL it did not rewrite.
func TestRewriteRefusesWhatItCannotAccountFor(t *testing.T) {
	const entry = "entries:\n  c:\n  - version: 1.0.0\n"
	cases := map[string]string{
		"urls is an alias":                "serverInfo:\n  x: &u [https://evil.example/c-1.0.0.tgz]\n" + entry + "    urls: *u\n",
		"a url is an alias":               "serverInfo:\n  x: &u https://evil.example/c-1.0.0.tgz\n" + entry + "    urls:\n    - *u\n",
		"the urls key is an alias":        "serverInfo:\n  x: &k urls\n" + entry + "    *k : [https://evil.example/c-1.0.0.tgz]\n",
		"an entry is an alias":            "serverInfo:\n  x: &e {version: 1.0.0, urls: [https://evil.example/c-1.0.0.tgz]}\nentries:\n  c:\n  - *e\n",
		"a chart's versions are an alias": "serverInfo:\n  x: &l [{version: 1.0.0, urls: [https://evil.example/c-1.0.0.tgz]}]\nentries:\n  c: *l\n",
		"entries is an alias":             "serverInfo:\n  x: &m {c: [{version: 1.0.0, urls: [https://evil.example/c-1.0.0.tgz]}]}\nentries: *m\n",
		"merge key in an entry":           entry + "    <<: {urls: [https://evil.example/c-1.0.0.tgz]}\n",
		"merge key in entries":            "entries:\n  <<: {c: [{version: 1.0.0, urls: [https://evil.example/c-1.0.0.tgz]}]}\n",
		"merge key at the top":            "<<: {entries: {c: [{version: 1.0.0, urls: [https://evil.example/c-1.0.0.tgz]}]}}\n",
		"binary-tagged urls key":          entry + "    !!binary dXJscw==:\n    - https://evil.example/c-1.0.0.tgz\n",
		"binary-tagged entries key":       "!!binary ZW50cmllcw==:\n  c:\n  - version: 1.0.0\n    urls: [https://evil.example/c-1.0.0.tgz]\n",
		"explicitly tagged urls key":      entry + "    !!str urls:\n    - https://evil.example/c-1.0.0.tgz\n",
		"collection as a key":             entry + "    ? [urls]\n    : [https://evil.example/c-1.0.0.tgz]\n",
		"binary-tagged url":               entry + "    urls:\n    - !!binary aHR0cHM6Ly9ldmlsLmV4YW1wbGUvYy0xLjAuMC50Z3o=\n",
		"explicitly tagged url":           entry + "    urls:\n    - !!str https://evil.example/c-1.0.0.tgz\n",
		"non-specific tag on a url":       entry + "    urls:\n    - ! https://evil.example/c-1.0.0.tgz\n",
		"anchored url":                    entry + "    urls:\n    - &u https://evil.example/c-1.0.0.tgz\n",
		"url folded over two lines":       entry + "    urls:\n    - https://evil.example/c-1.0.0\n      .tgz\n",
		"quoted url over two lines":       entry + "    urls:\n    - \"https://evil.example/\n      c-1.0.0.tgz\"\n",
		"url as a literal block":          entry + "    urls:\n    - |\n      https://evil.example/c-1.0.0.tgz\n",
		"url as a folded block":           entry + "    urls:\n    - >-\n      https://evil.example/c-1.0.0.tgz\n",
		"urls is a string":                entry + "    urls: https://evil.example/c-1.0.0.tgz\n",
		"urls is a mapping":               entry + "    urls: {a: https://evil.example/c-1.0.0.tgz}\n",
		"a url is a mapping":              entry + "    urls:\n    - a: https://evil.example/c-1.0.0.tgz\n",
		"a url is a list":                 entry + "    urls:\n    - [https://evil.example/c-1.0.0.tgz]\n",
		"entries is a list":               "entries:\n- c\n",
		"entries is a string":             "entries: c\n",
		"a chart's versions are a map":    "entries:\n  c:\n    version: 1.0.0\n",
		"a chart's versions are a string": "entries:\n  c: 1.0.0\n",
		"a version is a string":           "entries:\n  c:\n  - 1.0.0\n",
		"a second document":               entry + "    urls: [a-1.0.0.tgz]\n---\nentries: {}\n",
		"an empty first document":         "---\n---\n" + entry + "    urls: [https://evil.example/c-1.0.0.tgz]\n",
		"top level is a list":             "- entries\n",
		"top level is a string":           "just a string",
		"empty document":                  "",
		"only a comment":                  "# nothing here\n",
		"not YAML":                        "\x00\x01 not: [valid",
		"UTF-16 little endian":            "\xff\xfee\x00n\x00t\x00r\x00i\x00e\x00s\x00:\x00 \x00{\x00}\x00\n\x00",
		"UTF-16 big endian":               "\xfe\xff\x00e\x00n\x00t\x00r\x00i\x00e\x00s\x00:\x00 \x00{\x00}\x00\n",
	}
	// These are well-formed as far as the document's structure goes; what fails
	// is locating the URL scalar in the source text, which only the rewrite does.
	refusedByRewriteOnly := map[string]bool{
		"non-specific tag on a url": true,
		"url folded over two lines": true,
		"quoted url over two lines": true,
		"url as a literal block":    true,
		"url as a folded block":     true,
	}
	names := make([]string, 0, len(cases))
	for name := range cases {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		doc := cases[name]
		t.Run(name, func(t *testing.T) {
			if out, err := rewriteDoc(doc, testLinks); err == nil {
				t.Errorf("document was accepted; rewritten to:\n%s", out)
			}
			// ParseIndex reads a document's structure by the same rules.
			if _, err := ParseIndex([]byte(doc)); err == nil && !refusedByRewriteOnly[name] {
				t.Error("ParseIndex accepted the document")
			}
		})
	}
}

// Aliases, tags and merge keys are only refused where they could carry a chart
// URL. Elsewhere in an entry they are the repository's business.
func TestRewriteToleratesYAMLFeaturesOutsideTheURLPath(t *testing.T) {
	doc := "apiVersion: v1\n" +
		"serverInfo:\n  contact: &who {name: ops, email: ops@example.com}\n" +
		"entries:\n" +
		"  c:\n" +
		"  - version: 1.0.0\n" +
		"    maintainers:\n    - *who\n" +
		"    annotations:\n      <<: {team: platform}\n" +
		"    keywords: !!seq [a, b]\n" +
		"    description: !!str tagged text\n" +
		"    urls:\n    - https://h.example/c-1.0.0.tgz\n"
	got := mustRewrite(t, doc, testLinks)
	want := strings.Replace(doc, "https://h.example/c-1.0.0.tgz",
		`"https://proxy.example.com/v1/charts/-/c/1.0.0/c-1.0.0.tgz"`, 1)
	if got != want {
		t.Errorf("rewritten document:\n got %q\nwant %q", got, want)
	}
}

// An entry whose chart name or version cannot be carried in a URL path cannot
// be addressed through the proxy. Its URLs are still taken away from the
// client: they are replaced by a link that leads to the proxy and names nothing.
func TestRewriteNeutralizesUnaddressableEntries(t *testing.T) {
	cases := map[string]string{
		"no version":              "entries:\n  c:\n  - name: c\n    urls: [https://evil.example/c-1.0.0.tgz]\n",
		"null version":            "entries:\n  c:\n  - version: ~\n    urls: [https://evil.example/c-1.0.0.tgz]\n",
		"aliased version":         "serverInfo: {v: &v 1.0.0}\nentries:\n  c:\n  - version: *v\n    urls: [https://evil.example/c-1.0.0.tgz]\n",
		"slash in the chart name": "entries:\n  a/b:\n  - version: 1.0.0\n    urls: [https://evil.example/c-1.0.0.tgz]\n",
		"dot-dot chart name":      "entries:\n  ..:\n  - version: 1.0.0\n    urls: [https://evil.example/c-1.0.0.tgz]\n",
		"empty chart name":        "entries:\n  \"\":\n  - version: 1.0.0\n    urls: [https://evil.example/c-1.0.0.tgz]\n",
		"slash in the version":    "entries:\n  c:\n  - version: 1.0/0\n    urls: [https://evil.example/c-1.0.0.tgz]\n",
		"backslash in the name":   "entries:\n  'a\\b':\n  - version: 1.0.0\n    urls: [https://evil.example/c-1.0.0.tgz]\n",
		"control character":       "entries:\n  \"a\\tb\":\n  - version: 1.0.0\n    urls: [https://evil.example/c-1.0.0.tgz]\n",
		"oversized chart name":    "entries:\n  " + strings.Repeat("n", maxSegmentLen+1) + ":\n  - version: 1.0.0\n    urls: [https://evil.example/c-1.0.0.tgz]\n",
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			got := mustRewrite(t, doc, testLinks)
			if strings.Contains(got, "evil.example") {
				t.Errorf("the upstream URL survived the rewrite:\n%s", got)
			}
			urls := chartURLs(t, got)
			if len(urls) != 1 || urls[0] != "https://proxy.example.com/v1/charts/-/unaddressable-entry" {
				t.Errorf("chart URLs = %q, want the unaddressable-entry link", urls)
			}
		})
	}
	// The link names nothing the backend serves.
	if _, ok := classify("/-/unaddressable-entry"); ok {
		t.Error("the unaddressable-entry link must not classify as a resource")
	}
}

// An empty URL names no location (a client resolves it to the repository
// itself), so there is nothing to take away and the bytes are left as they are.
func TestRewriteLeavesEmptyURLsAlone(t *testing.T) {
	for _, doc := range []string{
		"entries:\n  c:\n  - version: 1.0.0\n    urls:\n    - \"\"\n    - ''\n    - \"  \"\n    -\n",
		"entries:\n  c:\n  - version: 1.0.0\n    urls: []\n",
		"entries:\n  c:\n  - version: 1.0.0\n    urls:\n",
		"entries:\n  c:\n  - version: 1.0.0\n",
		"entries: {}\n",
		"apiVersion: v1\n",
	} {
		if got := mustRewrite(t, doc, testLinks); got != doc {
			t.Errorf("document without chart URLs was modified:\n got %q\nwant %q", got, doc)
		}
	}
}

// Whatever a URL scalar holds, it is replaced: the rewrite does not try to
// judge which strings a client might treat as pointing elsewhere.
func TestRewriteReplacesEveryNonEmptyURL(t *testing.T) {
	for _, u := range []string{
		"//evil.example/c-1.0.0.tgz",       // scheme-relative: resolves to another host
		"/absolute/path/c-1.0.0.tgz",       // host-relative
		"../other/c-1.0.0.tgz",             // climbs out of the mount
		"HTTPS://EVIL.EXAMPLE/c-1.0.0.tgz", // odd case
		"https:/evil.example/c-1.0.0.tgz",  // malformed
		"oci://registry.example/charts/c:1.0.0",
		"ftp://evil.example/c-1.0.0.tgz",
		"file:///etc/passwd",
		"javascript:alert(1)",
		"c-1.0.0.tgz?token=abc#frag",
		"~",
		"null",
		"123",
	} {
		doc := "entries:\n  c:\n  - version: 1.0.0\n    urls:\n    - '" + u + "'\n"
		got := mustRewrite(t, doc, testLinks)
		urls := chartURLs(t, got)
		if len(urls) != 1 || !strings.HasPrefix(urls[0], testLinks.base+"-/c/1.0.0/") {
			t.Errorf("url %q: rewritten to %q, want a link under %s-/c/1.0.0/", u, urls, testLinks.base)
		}
	}
}

// Every link a rewritten index hands out must come back — after the URL
// decoding the gateway applies to a request path — as an index-resolved
// resource that the index maps to the location the link replaced.
func TestRewrittenLinksResolveBackToTheirLocations(t *testing.T) {
	doc := `apiVersion: v1
entries:
  plain:
  - version: 1.2.3
    urls: [https://a.example/plain-1.2.3.tgz]
  build-metadata:
  - version: 1.0.0+build.5
    urls: [https://a.example/build-metadata-1.0.0+build.5.tgz]
  "with space":
  - version: 1.0.0
    urls: ["https://a.example/with%20space-1.0.0.tgz"]
  "ünïcode":
  - version: 1.0.0-β
    urls: [https://a.example/dl/unicode.tgz]
  percent%41:
  - version: 1.0.0
    urls: [charts/percent%2541-1.0.0.tgz]
  name-2go:
  - version: 3.0.0
    urls: [https://a.example/name-2go-3.0.0.tgz]
  mirrored:
  - version: 2.0.0
    urls:
    - https://a.example/mirrored-2.0.0.tgz
    - https://b.example/mirror/mirrored-2.0.0.tgz
    - https://c.example/other-name.tgz
  query:
  - version: 1.0.0
    urls: ["https://a.example/download?id=42"]
  no-basename:
  - version: 1.0.0
    urls: [https://a.example/]
  oci-hosted:
  - version: 1.0.0
    urls: [oci://registry.example/charts/oci-hosted:1.0.0]
  listed-twice:
  - version: 1.0.0
    digest: 1111111111111111111111111111111111111111111111111111111111111111
    urls: [https://a.example/listed-twice-1.0.0.tgz]
  - version: 1.0.0
    digest: 2222222222222222222222222222222222222222222222222222222222222222
    urls: [https://b.example/listed-twice-1.0.0.tgz]
`
	scanned, err := scanIndex([]byte(doc))
	if err != nil {
		t.Fatalf("scanIndex: %v", err)
	}
	out, err := scanned.rewrite([]byte(doc), testLinks)
	if err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	idx := scanned.index()
	rewritten, err := scanIndex(out)
	if err != nil {
		t.Fatalf("scanning the rewritten document: %v\n%s", err, out)
	}
	if len(rewritten.entries) != len(scanned.entries) {
		t.Fatalf("entries: %d before, %d after", len(scanned.entries), len(rewritten.entries))
	}

	for i, e := range scanned.entries {
		for j, original := range e.urls {
			link := rewritten.entries[i].urls[j].value
			u, err := url.Parse(link)
			if err != nil {
				t.Errorf("%s %s: link %q does not parse: %v", e.chart, e.version, link, err)
				continue
			}
			// The gateway strips "/v1/<name>" from the decoded path.
			res, ok := classify(strings.TrimPrefix(u.Path, "/v1/charts"))
			if !ok || !res.indexed || res.kind != kindChart {
				t.Errorf("%s %s: link %q does not classify as an index-resolved chart", e.chart, e.version, link)
				continue
			}
			if res.name != e.chart || res.version != e.version {
				t.Errorf("%s %s: link %q carries coordinate %s %s", e.chart, e.version, link, res.name, res.version)
			}
			found := false
			for _, loc := range idx.locate(res.name, res.version, res.filename) {
				found = found || loc.URL == original.location()
			}
			if !found {
				t.Errorf("%s %s: link %q does not resolve back to %q", e.chart, e.version, link, original.location())
			}
		}
	}

	// Mirrors that share a basename share a link, in the index's order; a
	// location with another basename gets its own.
	locs := idx.locate("mirrored", "2.0.0", "mirrored-2.0.0.tgz")
	if len(locs) != 2 || locs[0].URL != "https://a.example/mirrored-2.0.0.tgz" || locs[1].URL != "https://b.example/mirror/mirrored-2.0.0.tgz" {
		t.Errorf("mirrored locations = %+v", locs)
	}
	if locs := idx.locate("mirrored", "2.0.0", "other-name.tgz"); len(locs) != 1 || locs[0].URL != "https://c.example/other-name.tgz" {
		t.Errorf("other-name locations = %+v", locs)
	}
	// Each location is verified against the digest of the entry that lists it.
	locs = idx.locate("listed-twice", "1.0.0", "listed-twice-1.0.0.tgz")
	if len(locs) != 2 || !strings.HasPrefix(locs[0].Digest, "1111") || !strings.HasPrefix(locs[1].Digest, "2222") {
		t.Errorf("listed-twice locations = %+v", locs)
	}
	// Nothing is returned for a chart, version, or file the index does not list.
	for _, miss := range [][3]string{
		{"plain", "9.9.9", "plain-9.9.9.tgz"},
		{"absent", "1.2.3", "plain-1.2.3.tgz"},
		{"plain", "1.2.3", "other.tgz"},
		{"mirrored", "2.0.0", "plain-1.2.3.tgz"},
	} {
		if locs := idx.locate(miss[0], miss[1], miss[2]); len(locs) != 0 {
			t.Errorf("locate(%q, %q, %q) = %+v, want nothing", miss[0], miss[1], miss[2], locs)
		}
	}
}

func TestArchiveFile(t *testing.T) {
	cases := []struct {
		location string
		want     string
	}{
		{"https://h.example/charts/nginx-1.2.3.tgz", "nginx-1.2.3.tgz"},
		{"http://h.example/nginx-1.2.3.tgz", "nginx-1.2.3.tgz"},
		{"nginx-1.2.3.tgz", "nginx-1.2.3.tgz"},
		{"charts/nginx-1.2.3.tgz", "nginx-1.2.3.tgz"},
		{"/abs/nginx-1.2.3.tgz", "nginx-1.2.3.tgz"},
		{"//h.example/x/nginx-1.2.3.tgz", "nginx-1.2.3.tgz"},
		// The basename the client would have saved is kept even when it is not
		// the conventional one.
		{"https://h.example/dl/odd_name.tar.gz", "odd_name.tar.gz"},
		{"https://h.example/nginx-1.2.3.tgz?sig=abc#frag", "nginx-1.2.3.tgz"},
		{"https://h.example/my%20chart-1.2.3.tgz", "my chart-1.2.3.tgz"},
		// No usable basename: the conventional name.
		{"https://h.example", "c-1.0.0.tgz"},
		{"https://h.example/", "c-1.0.0.tgz"},
		{"https://h.example/dir/", "c-1.0.0.tgz"},
		{"//h.example", "c-1.0.0.tgz"},
		{"https://h.example/a%2Fb.tgz", "c-1.0.0.tgz"},
		{"https://h.example/bad%zzescape.tgz", "c-1.0.0.tgz"},
		{"https://h.example/..", "c-1.0.0.tgz"},
		{"https://h.example/" + strings.Repeat("x", maxSegmentLen+1), "c-1.0.0.tgz"},
		// A basename ending in ".prov" would read as a provenance request.
		{"https://h.example/nginx-1.2.3.tgz.prov", "c-1.0.0.tgz"},
		// Not an HTTP(S) or relative URL: the conventional name (which is also
		// what Helm saves an OCI chart as).
		{"oci://registry.example/charts/c:1.0.0", "c-1.0.0.tgz"},
		{"ftp://h.example/nginx-1.2.3.tgz", "c-1.0.0.tgz"},
		{"file:///srv/charts/nginx-1.2.3.tgz", "c-1.0.0.tgz"},
	}
	for _, tc := range cases {
		got := archiveFile(tc.location, "c", "1.0.0")
		if got != tc.want {
			t.Errorf("archiveFile(%q) = %q, want %q", tc.location, got, tc.want)
		}
		if !addressable(got) || strings.HasSuffix(got, provExt) {
			t.Errorf("archiveFile(%q) = %q is not a usable path segment", tc.location, got)
		}
	}
	// Even an oversized chart/version pair yields something addressable.
	long := strings.Repeat("n", 200)
	if got := archiveFile("https://h.example/", long, long); !addressable(got) {
		t.Errorf("archiveFile with an oversized coordinate = %q, not addressable", got)
	}
}

func TestLinker(t *testing.T) {
	abs := linker{base: "https://proxy.example.com/v1/charts/"}
	if got := abs.archive("nginx", "1.2.3", "nginx-1.2.3.tgz"); got != "https://proxy.example.com/v1/charts/-/nginx/1.2.3/nginx-1.2.3.tgz" {
		t.Errorf("absolute link = %q", got)
	}
	rel := linker{}
	if got := rel.archive("nginx", "1.2.3", "nginx-1.2.3.tgz"); got != "-/nginx/1.2.3/nginx-1.2.3.tgz" {
		t.Errorf("relative link = %q", got)
	}
	// Anything outside the unreserved set is percent-encoded, so a link is always
	// safe to place between quotes and decodes back to what went in.
	got := abs.archive(`we"ird\na me`, "1.0.0+b", "f#?%.tgz")
	if !quotable(got) {
		t.Errorf("link %q is not quotable", got)
	}
	u, err := url.Parse(got)
	if err != nil {
		t.Fatalf("link %q does not parse: %v", got, err)
	}
	if want := `/v1/charts/-/we"ird\na me/1.0.0+b/f#?%.tgz`; u.Path != want {
		t.Errorf("decoded link path = %q, want %q", u.Path, want)
	}
}

func TestLinkBase(t *testing.T) {
	cases := map[string]string{
		"https://proxy.example.com/v1/charts":   "https://proxy.example.com/v1/charts/",
		"https://proxy.example.com/v1/charts/":  "https://proxy.example.com/v1/charts/",
		" http://127.0.0.1:8080/v1/charts ":     "http://127.0.0.1:8080/v1/charts/",
		"http://[::1]:8080/v1/charts":           "http://[::1]:8080/v1/charts/",
		"https://proxy.example.com/pre fix/v1/": "https://proxy.example.com/pre%20fix/v1/",
		// Not an absolute http(s) URL: relative references are used instead.
		"":                                    "",
		"/v1/charts":                          "",
		"proxy.example.com/v1/charts":         "",
		"ftp://proxy.example.com/v1/charts":   "",
		"https:///v1/charts":                  "",
		"https://proxy.example.com/v1?x=1":    "",
		"https://proxy.example.com/v1#frag":   "",
		"https://proxy.example.com/\x7f/v1":   "",
		"https://pro\"xy.example.com/v1":      "",
		"http://proxy.example.com:port/v1":    "",
		"https://proxy.example.com/%zz/v1":    "",
		"https://proxy.example.com/v1\\chart": "https://proxy.example.com/v1%5Cchart/",
	}
	for in, want := range cases {
		if got := linkBase(in); got != want {
			t.Errorf("linkBase(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSourceCursor(t *testing.T) {
	// One line per YAML line-break form, with multi-byte characters before the
	// target so byte offsets and character columns diverge.
	src := "\xef\xbb\xbf" + "ab\n" + "çé X\r\n" + "日本 Y\r" + "🚀 Z\u0085" + "q W\u2028" + "V\u2029" + "U"
	targets := []struct {
		line, col int
		want      string
	}{
		{1, 1, "a"}, {1, 2, "b"},
		{2, 4, "X"},
		{3, 4, "Y"},
		{4, 3, "Z"},
		{5, 3, "W"},
		{6, 1, "V"},
		{7, 1, "U"},
	}
	c := newSourceCursor([]byte(src))
	for _, tg := range targets {
		off, ok := c.seek(tg.line, tg.col)
		if !ok {
			t.Fatalf("seek(%d,%d) failed", tg.line, tg.col)
		}
		if got := src[off : off+len(tg.want)]; got != tg.want {
			t.Errorf("seek(%d,%d) -> offset %d = %q, want %q", tg.line, tg.col, off, got, tg.want)
		}
	}
	// Seeking to where the cursor already is succeeds; anywhere behind it, past
	// the end of a line, or past the end of the source does not.
	if _, ok := c.seek(7, 1); !ok {
		t.Error("seeking to the current position should succeed")
	}
	for _, bad := range [][2]int{{6, 1}, {7, 0}, {7, 3}, {8, 1}} {
		c := newSourceCursor([]byte(src))
		if _, ok := c.seek(7, 1); !ok {
			t.Fatal("seek(7,1) failed")
		}
		if _, ok := c.seek(bad[0], bad[1]); ok {
			t.Errorf("seek(%d,%d) after (7,1) should fail", bad[0], bad[1])
		}
	}
	if _, ok := newSourceCursor([]byte("ab\ncd")).seek(1, 4); ok {
		t.Error("seeking past the end of a line should fail")
	}
}

func TestParseIndexReadsKeysCaseInsensitively(t *testing.T) {
	idx, err := ParseIndex([]byte("APIVERSION: v1\nEntries:\n  c:\n  - Version: 1.0.0\n    NAME: c\n    DIGEST: " +
		strings.Repeat("a", 64) + "\n    AppVersion: \"2\"\n    Deprecated: true\n    URLS: [c-1.0.0.tgz]\n"))
	if err != nil {
		t.Fatalf("ParseIndex: %v", err)
	}
	cv, ok := idx.FindVersion("c", "1.0.0")
	if !ok {
		t.Fatal("entry not found")
	}
	if idx.APIVersion != "v1" || cv.Name != "c" || cv.Digest != strings.Repeat("a", 64) || cv.AppVersion != "2" ||
		!cv.Deprecated || len(cv.URLs) != 1 || cv.URLs[0] != "c-1.0.0.tgz" {
		t.Errorf("index = %+v, entry = %+v", idx, cv)
	}
}

// syntheticIndex renders an index in the layout `helm repo index` writes, with
// entries about the size real repositories publish (roughly 1 KiB each), half
// of them hosted on another host.
func syntheticIndex(charts, versionsPerChart int) []byte {
	var sb strings.Builder
	sb.WriteString("apiVersion: v1\nentries:\n")
	for c := 0; c < charts; c++ {
		name := fmt.Sprintf("chart-%03d", c)
		fmt.Fprintf(&sb, "  %s:\n", name)
		for v := versionsPerChart; v > 0; v-- {
			version := fmt.Sprintf("%d.%d.%d", 1+v/100, v%100/10, v%10)
			host := "https://charts.example.com/repo"
			if v%2 == 0 {
				host = "https://github.example.org/org/" + name + "/releases/download/" + name + "-" + version
			}
			fmt.Fprintf(&sb, `  - annotations:
      artifacthub.io/changes: |
        - kind: changed
          description: Update the application to the latest upstream release
      artifacthub.io/license: Apache-2.0
      category: Infrastructure
      images: |
        - name: %[1]s
          image: registry.example.com/library/%[1]s:%[2]s-debian-12-r0
    apiVersion: v2
    appVersion: %[2]s
    created: "2024-01-02T03:04:05.123456789Z"
    dependencies:
    - name: common
      repository: oci://registry.example.com/charts
      tags:
      - common
      version: 2.x.x
    description: A chart that installs %[1]s, an application whose description
      is long enough to be folded onto a second line by the YAML emitter.
    digest: %064[3]x
    home: https://example.com/%[1]s
    icon: https://example.com/assets/%[1]s/img/%[1]s-stack-220x234.png
    keywords:
    - %[1]s
    - infrastructure
    - example
    maintainers:
    - name: Example, Inc.
      url: https://github.example.org/org/charts
    name: %[1]s
    sources:
    - https://github.example.org/org/charts/tree/main/%[1]s
    urls:
    - %[4]s/%[1]s-%[2]s.tgz
    version: %[2]s
`, name, version, c*1000+v, host)
		}
	}
	sb.WriteString("generated: \"2024-01-02T03:04:05.123456789Z\"\n")
	return []byte(sb.String())
}

// BenchmarkRewriteIndex measures what a changed upstream index costs: the full
// parse and the rewrite, once. (An unchanged index costs neither; see
// indexcache.go.)
func BenchmarkRewriteIndex(b *testing.B) {
	data := syntheticIndex(50, 100) // 5,000 chart versions
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		doc, err := scanIndex(data)
		if err != nil {
			b.Fatal(err)
		}
		out, err := doc.rewrite(data, testLinks)
		if err != nil {
			b.Fatal(err)
		}
		if len(out) == len(data) || len(doc.index().Entries) != 50 {
			b.Fatal("the index was not rewritten")
		}
	}
}

// The synthetic index is itself a regression fixture: every one of its chart
// URLs must come out rewritten and resolve back to where it pointed.
func TestRewriteSyntheticIndex(t *testing.T) {
	data := syntheticIndex(7, 13)
	doc, err := scanIndex(data)
	if err != nil {
		t.Fatalf("scanIndex: %v", err)
	}
	out, err := doc.rewrite(data, testLinks)
	if err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	urls := chartURLs(t, string(out))
	if len(urls) != 7*13 {
		t.Fatalf("rewritten index lists %d chart URLs, want %d", len(urls), 7*13)
	}
	idx := doc.index()
	for _, link := range urls {
		u, err := url.Parse(link)
		if err != nil || !strings.HasPrefix(link, testLinks.base+"-/") {
			t.Fatalf("chart URL %q is not a proxied link (%v)", link, err)
		}
		res, ok := classify(strings.TrimPrefix(u.Path, "/v1/charts"))
		if !ok || len(idx.locate(res.name, res.version, res.filename)) != 1 {
			t.Errorf("link %q does not resolve back to exactly one location", link)
		}
	}
	// Exactly the chart URLs changed: the other list items holding URLs (each
	// entry's `sources`) are still there, unquoted, as published.
	if replaced := strings.Count(string(data), "- https://") - strings.Count(string(out), "- https://"); replaced != 7*13 {
		t.Errorf("%d plain https list items were replaced, want %d", replaced, 7*13)
	}
	if kept := strings.Count(string(out), "    - https://github.example.org/org/charts/tree/main/"); kept != 7*13 {
		t.Errorf("%d `sources` URLs survive, want %d", kept, 7*13)
	}
}
