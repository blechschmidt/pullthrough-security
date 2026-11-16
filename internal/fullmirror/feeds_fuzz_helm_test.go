//go:build fuzz
// +build fuzz

// Fuzz targets for the helm feed's parsers (Task 191): the streaming reader
// of a repository's index.yaml, held to yaml.v3 and the backend's own parser
// (whenever the streaming reader reads a document, they must read the same
// chart versions from it), and the version order. Run e.g.:
//
//	go test -tags fuzz -run='^$' -fuzz='^FuzzHelmIndex$' -fuzztime=20s ./internal/fullmirror/
package fullmirror

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func helmFuzzSeed(f *testing.F, name string) []byte {
	f.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "feeds", "helm", name))
	if err != nil {
		f.Fatal(err)
	}
	return data
}

func FuzzHelmIndex(f *testing.F) {
	for _, fx := range []string{"index-prometheus-community.yaml", "index-bitnami.yaml", "index-artifactory.yaml"} {
		f.Add(helmFuzzSeed(f, fx))
	}
	head := "apiVersion: v1\nentries:\n  c:\n  - name: c\n"
	tail := "    urls:\n    - https://x.example/c-1.tgz\n"
	for _, doc := range []string{
		head + "    version: '1.0.0'\n    digest: \"a\\x62c\"\n" + tail,
		"apiVersion: v1\nentries:\n  c:\n    - name: c\n      version: 1.0.0\n      urls:\n        - https://x.example/c-1.tgz\n",
		"apiVersion: v1\nentries:\n  c:\n  -\n    version: 1.0.0\n    urls:\n    - https://x.example/c-1.tgz\n",
		head + "    description: |-\n      line one\n\n      line two\n    notes: >2\n       indented\n    version: 1.0.0\n" + tail,
		head + "    description: a long\n      description - with a dash\n    version: 1.0.0\n" + tail,
		head + "    description: \"a long\n      quoted one\"\n    version: 1.0.0\n" + tail,
		head + "    keywords: []\n    annotations: {}\n    version: 1.0.0 # v\n" + tail + "---\n...\n",
		"--- # index\n" + head + "    version: ~\n" + tail + "generated: 2026-01-01T00:00:00Z\n",
		head + "    version: 1.0.0\n    urls:\n    - ~\n    - https://x.example/c-1.tgz\n",
		head + "    version: 1.0.0\n    urls:\n    -\n    - ''\n    - null # n\n    - NULL\n",
		"apiVersion: v1\nentries: {}\n",
	} {
		f.Add([]byte(doc))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			return
		}
		var streamed []helmEntry
		_, err := helmScanIndex(bytes.NewReader(data), func(e helmEntry) error {
			streamed = append(streamed, e)
			return nil
		})
		if err != nil {
			var unsupported *helmUnsupportedError
			if !errors.As(err, &unsupported) && !IsPermanent(err) {
				t.Fatalf("an error that is neither unsupported nor permanent: %v", err)
			}
			return
		}
		whole, _, werr := helmReadIndexWhole(data)
		if werr != nil {
			t.Fatalf("the streaming reader read %q as %+v; yaml.v3 and the backend refuse it: %v", data, streamed, werr)
		}
		if !reflect.DeepEqual(streamed, whole) {
			t.Fatalf("%q: streamed %+v, yaml.v3 read %+v", data, streamed, whole)
		}
	})
}

func FuzzHelmVersionOrder(f *testing.F) {
	f.Add("1.0.0", "1.0.0-rc.1", "v1.0")
	f.Add("1.2.3+build", "1.2.3", "1.10.0-alpha.beta")
	f.Add("x", "01.2.3", "1.0.0-0")
	f.Fuzz(func(t *testing.T, a, b, c string) {
		ab, ba := helmCompareVersions(a, b), helmCompareVersions(b, a)
		if ab != -ba || (ab == 0) != (a == b) || helmCompareVersions(a, a) != 0 {
			t.Fatalf("compare(%q, %q) = %d, compare(%q, %q) = %d", a, b, ab, b, a, ba)
		}
		if ab <= 0 && helmCompareVersions(b, c) <= 0 && helmCompareVersions(a, c) > 0 {
			t.Fatalf("%q <= %q <= %q but %q > %q", a, b, c, a, c)
		}
	})
}
