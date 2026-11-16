//go:build fuzz
// +build fuzz

package fullmirror

import (
	"bytes"
	"strings"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/backends/yum"
)

// FuzzYumRepomd feeds repomd.xml documents to the yum feed's parser: it must
// not panic, and the primary it accepts must be a verifiable file below the
// repository root.
func FuzzYumRepomd(f *testing.F) {
	for _, name := range []string{"repomd-fedora.xml", "repomd-rocky.xml", "repomd-epel.xml"} {
		f.Add(fixture(f, "yum", name))
	}
	f.Add([]byte(`<repomd><data type="primary"><checksum type="sha">` + strings.Repeat("a", 40) + `</checksum><location href="repodata/p.xml.gz"/></data></repomd>`))
	f.Add([]byte(`<repomd><data type="primary"><location xml:base="http://x/" href="../p"/></data></repomd>`))
	f.Add([]byte(`<repomd>` + strings.Repeat("<x>", 40) + `</repomd>`))
	f.Add([]byte("not xml"))
	f.Fuzz(func(t *testing.T, data []byte) {
		md, err := yumParseRepomd(data)
		if err != nil {
			return
		}
		if len(md.Data) > yumMaxData {
			t.Fatalf("%d data entries kept", len(md.Data))
		}
		p, err := md.primary()
		if err != nil {
			return
		}
		if p.Base != "" || p.Checksum.Hex == "" || strings.HasPrefix(p.Href, "/") || strings.Contains(p.Href, "..") {
			t.Fatalf("an unusable primary accepted: %+v", p)
		}
		if _, _, n, ok := yumNewHash(p.Checksum.Alg); !ok || len(p.Checksum.Hex) != n {
			t.Fatalf("a checksum of the wrong length: %+v", p.Checksum)
		}
		head, _ := md.head(p)
		if !cleanName(head) {
			t.Fatalf("a head the engine cannot show: %q", head)
		}
	})
}

// FuzzYumPrimary feeds primary.xml documents through the backend's streaming
// reader to the feed's records: no panic, and every record one the copy keeps,
// naming an .rpm below the repository root.
func FuzzYumPrimary(f *testing.F) {
	for _, name := range []string{"primary-fedora.xml", "primary-rocky.xml", "primary-epel.xml"} {
		f.Add(fixture(f, "yum", name))
	}
	f.Add([]byte(`<metadata><package><name>a</name><version epoch="1" ver="1.0" rel="1"/><location href="/a/../b.rpm"/></package></metadata>`))
	f.Add([]byte(`<metadata><package><name>a</name><version ver="1^2~3" rel="1"/><location href="P/a%20b.rpm"/></package></metadata>`))
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = yum.StreamPrimary(bytes.NewReader(data), func(e yum.PrimaryEntry) error {
			rec, ok := yumRecord(e)
			if !ok {
				return nil
			}
			if !rec.valid() || !validArtifactPath(rec.Path) || !strings.HasSuffix(rec.Path, ".rpm") {
				t.Fatalf("a record the copy cannot keep: %+v", rec)
			}
			if !yumValidName(rec.Name) || rec.Version == "" {
				t.Fatalf("a record without a name or version: %+v", rec)
			}
			return nil
		})
	})
}

// FuzzYumVersionOrder holds rpmvercmp to what sorting needs: no panic, and an
// order (each comparison the reverse of its mirror, every version equal to
// itself).
func FuzzYumVersionOrder(f *testing.F) {
	f.Add("1.0~rc1^git1", "1.0")
	f.Add("1:30.2-29.fc44", "30.2-30.fc44")
	f.Add("1.8.12-1.el9", "1.8.12-1.el9_8.1")
	f.Add("", "~")
	f.Fuzz(func(t *testing.T, a, b string) {
		if yumVercmp(a, a) != 0 || yumCompareEVR(a, a) != 0 {
			t.Fatalf("%q differs from itself", a)
		}
		if x, y := yumVercmp(a, b), yumVercmp(b, a); x != -y {
			t.Fatalf("rpmvercmp(%q, %q) = %d but rpmvercmp(%q, %q) = %d", a, b, x, b, a, y)
		}
		if x, y := yumCompareEVR(a, b), yumCompareEVR(b, a); x != -y {
			t.Fatalf("EVR(%q, %q) = %d but EVR(%q, %q) = %d", a, b, x, b, a, y)
		}
	})
}
