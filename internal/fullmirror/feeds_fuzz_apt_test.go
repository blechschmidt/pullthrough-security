//go:build fuzz
// +build fuzz

package fullmirror

import (
	"bytes"
	"strings"
	"testing"
)

// FuzzAptRelease feeds Release and InRelease files to the apt feed's parser:
// it must not panic, and every index entry it keeps must be a Packages file
// below the suite with a SHA-256 and a size.
func FuzzAptRelease(f *testing.F) {
	f.Add(fixture(f, "apt", "InRelease-trixie"))
	f.Add(fixture(f, "apt", "InRelease-noble-updates"))
	f.Add(aptStripClearsign(fixture(f, "apt", "InRelease-trixie")))
	f.Add([]byte("-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n- Origin: x\nSHA256:\n " + strings.Repeat("a", 64) + " 1 main/binary-amd64/Packages\n-----BEGIN PGP SIGNATURE-----\n"))
	f.Add([]byte("Date: Mon, 2 Jan 2006 15:04:05 -0700\nSHA256:\n x 1 2\n"))
	f.Add([]byte("-----BEGIN PGP SIGNED MESSAGE-----"))
	f.Fuzz(func(t *testing.T, data []byte) {
		rel, err := aptParseRelease(data)
		if err != nil {
			return
		}
		if len(rel.Files) == 0 || len(rel.Files) > aptMaxEntries {
			t.Fatalf("%d index entries kept", len(rel.Files))
		}
		for p, e := range rel.Files {
			if strings.HasPrefix(p, "/") || strings.Contains(p, "..") || len(e.SHA256) != 64 || e.Size < 0 {
				t.Fatalf("an entry the feed cannot use: %q %+v", p, e)
			}
		}
		if !rel.Date.IsZero() && (rel.Date.Unix() <= aptMinTime || rel.Date.Unix() >= aptMaxTime) {
			t.Fatalf("an implausible date kept: %s", rel.Date)
		}
	})
}

// FuzzAptPackages feeds Packages indexes through the stanza parser to the
// feed's records: no panic, and every record one the copy keeps, naming a .deb
// below the archive root.
func FuzzAptPackages(f *testing.F) {
	f.Add(fixture(f, "apt", "Packages-trixie-main-amd64"))
	f.Add(fixture(f, "apt", "Packages-noble-updates-main-amd64"))
	f.Add([]byte("Package: a\nVersion: 1\nVersion: 2\nFilename: pool/a_1_all.deb\n\nPackage: b\nVersion: 1:2~3\nFilename: /pool/../b.deb\n"))
	f.Add([]byte("package: x\r\nversion: 1.0\r\nfilename: pool/x_1.0_amd64.deb\r\n \r\n#comment\n\tcontinued\n"))
	f.Add([]byte("\r\r\r\n\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = aptParsePackages(bytes.NewReader(data), func(st *aptStanza) {
			if st.Package == "" || st.bad {
				t.Fatalf("a stanza passed on that names no package or is bad: %+v", st)
			}
			rec, ok := aptRecord(st, "trixie/main/binary-amd64")
			if !ok {
				return
			}
			if !rec.valid() || !validArtifactPath(rec.Path) || !aptValidPackage(rec.Name) || !aptValidVersion(rec.Version) {
				t.Fatalf("a record the copy cannot keep: %+v", rec)
			}
			if !strings.HasSuffix(rec.Path, ".deb") && !strings.HasSuffix(rec.Path, ".udeb") && !strings.HasSuffix(rec.Path, ".ddeb") {
				t.Fatalf("a record that is no package: %+v", rec)
			}
		})
	})
}

// FuzzAptVersionOrder holds dpkg's comparison to what sorting needs: no panic,
// and an order (each comparison the reverse of its mirror, every version
// equal to itself).
func FuzzAptVersionOrder(f *testing.F) {
	f.Add("1:9.20.26-1~deb13u1", "9.20.26-1")
	f.Add("1.0~~a", "1.0~")
	f.Add("2026c-0+deb13u1", "2026e-0ubuntu0.24.04.1")
	f.Add("", "-")
	f.Fuzz(func(t *testing.T, a, b string) {
		if aptCompareVersions(a, a) != 0 {
			t.Fatalf("%q differs from itself", a)
		}
		if x, y := aptCompareVersions(a, b), aptCompareVersions(b, a); x != -y {
			t.Fatalf("compare(%q, %q) = %d but compare(%q, %q) = %d", a, b, x, b, a, y)
		}
	})
}
