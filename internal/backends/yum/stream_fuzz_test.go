//go:build fuzz
// +build fuzz

// Fuzz targets for the streaming primary.xml reader (Task 191). A hostile
// repository controls the primary.xml the backend (and the full mirror's feed)
// reads on the pull path: the reader must never panic, must hold no more than
// its token and nesting bounds allow, and must pass on only entries within its
// field bounds.
//
//	go test -tags fuzz -run=^$ -fuzz=FuzzStreamPrimary ./internal/backends/yum/
package yum

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

func FuzzStreamPrimary(f *testing.F) {
	f.Add([]byte(primaryDoc(fedoraEntries)))
	f.Add([]byte(primaryDoc(`<package><name>a</name><name>b</name><location href="a.rpm"/></package>`)))
	f.Add([]byte(`<metadata><package><name>x</name><location xml:base="http://e/" href="x.rpm"/></package></metadata>`))
	f.Add([]byte(`<metadata/><metadata/>`))
	f.Add([]byte(`<metadata><package><format>` + strings.Repeat("<x>", 70) + `</format></package></metadata>`))
	f.Add([]byte("not xml"))
	f.Add([]byte(""))
	f.Fuzz(func(t *testing.T, data []byte) {
		err := StreamPrimary(bytes.NewReader(data), func(e PrimaryEntry) error {
			if e.Name == "" || e.Location == "" {
				t.Fatalf("an entry without a name or a location: %+v", e)
			}
			for _, s := range []string{e.Name, e.Arch, e.Epoch, e.Version, e.Release, e.ChecksumType, e.Checksum, e.Location, e.LocationBase} {
				if len(s) > maxPrimaryField {
					t.Fatalf("a field past the bound: %d bytes", len(s))
				}
			}
			if e.Size < 0 || e.Time < 0 {
				t.Fatalf("a negative number: %+v", e)
			}
			return nil
		})
		if err != nil && !errors.Is(err, ErrMalformedPrimary) {
			t.Fatalf("a document's fault not marked malformed: %v", err)
		}
	})
}

func FuzzOpenPrimary(f *testing.F) {
	doc := []byte(primaryDoc(fedoraEntries))
	f.Add(gzipBytes(doc), "x-primary.xml.gz")
	f.Add(doc, "x-primary.xml")
	f.Add([]byte(bz2Empty), "x-primary.xml.bz2")
	f.Add([]byte("\xfd7zXZ\x00\x00\x04"), "x-primary.xml.xz")
	f.Add([]byte("\x28\xb5\x2f\xfd\x00\x60"), "x-primary.xml.zst")
	f.Add([]byte("\x00ZCK1"), "x-primary.xml.zck")
	f.Fuzz(func(t *testing.T, data []byte, name string) {
		const limit = 1 << 20
		r, release, err := OpenPrimary(bytes.NewReader(data), name, limit)
		if err != nil {
			return
		}
		defer release()
		n, _ := io.Copy(io.Discard, r)
		if n > limit {
			t.Fatalf("read %d bytes past the %d-byte limit", n, limit)
		}
	})
}
