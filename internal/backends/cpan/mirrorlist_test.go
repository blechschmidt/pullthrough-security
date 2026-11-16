package cpan

import (
	"strings"
	"testing"
	"time"
)

// checksumsSample is the head of ETHER's CHECKSUMS (recorded from
// cpan.metacpan.org on 2026-11-16), with a subdirectory entry, a repeated
// entry, a quoted size and malformed fields added.
const checksumsSample = `0&&<<''; # this PGP-signed message is also valid perl
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA512

# CHECKSUMS file written on Sun Nov 15 22:13:47 2026 GMT by CPAN::Checksums (v2.14)
$cksum = {
  'Acme-CPANAuthors-Canadian-0.0108.meta' => {
    'cpan_path' => 'E/ET/ETHER',
    'md5' => '4afb76c1b070bddc14ea54a8c8cb79ed',
    'mtime' => '2022-01-04',
    'sha256' => 'f3516dd7f38c3ffa9e54fbe4bca222475f34820181d2ad19260515fd593e2e8d',
    'size' => 44299
  },
  'Acme-CPANAuthors-Canadian-0.0108.tar.gz' => {
    'cpan_path' => 'E/ET/ETHER',
    'md5' => 'ab4b1f23abf8dc9cdd26fca1dc09be9c',
    'md5-ungz' => '99f8df76555fe8e7d2fe2d8b3ee47458',
    'mtime' => '2022-01-04',
    'sha256' => '7ad62d525bf89a1541cbfc50b85c18b70bdb3c4c3593cb51fb722e4f6817e1f5',
    'sha256-ungz' => 'bf7a517c6a1577242f36d9a7a6580e0bbb3a0cb79043cf3184ba6b33741e867e',
    'size' => 26874
  },
  'Acme-CPANAuthors-Canadian-0.0108.tar.gz' => {
    'size' => 1
  },
  'Old' => {
    'isdir' => 1
  },
  'Try-Tiny-0.31.zip' => {
    'mtime' => 'yesterday',
    'sha256' => 'not-a-digest',
    'size' => '1234'
  },
  'Try-Tiny-0.32.tar.gz' => {
    'size' => -5
  }
};
__END__
-----BEGIN PGP SIGNATURE-----
=HTOJ
-----END PGP SIGNATURE-----
`

func TestListChecksumsKeepsSizesAndMtimes(t *testing.T) {
	got, err := ListChecksums([]byte(checksumsSample))
	if err != nil {
		t.Fatal(err)
	}
	day := time.Date(2022, 1, 4, 0, 0, 0, 0, time.UTC)
	want := []ChecksumsEntry{
		{File: "Acme-CPANAuthors-Canadian-0.0108.meta", Size: 44299, Mtime: day, SHA256: "f3516dd7f38c3ffa9e54fbe4bca222475f34820181d2ad19260515fd593e2e8d"},
		{File: "Acme-CPANAuthors-Canadian-0.0108.tar.gz", Size: 26874, Mtime: day, SHA256: "7ad62d525bf89a1541cbfc50b85c18b70bdb3c4c3593cb51fb722e4f6817e1f5"},
		{File: "Old", IsDir: true},
		{File: "Try-Tiny-0.31.zip", Size: 1234},
		{File: "Try-Tiny-0.32.tar.gz"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d entries %+v, want %d", len(got), got, len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("entry %d: %+v, want %+v", i, got[i], want[i])
		}
	}
	// The digests agree with ParseChecksums, the parser the backend verifies
	// downloads against.
	cs, err := ParseChecksums([]byte(checksumsSample))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range got {
		d, ok := cs.sha256For(e.File)
		if (e.SHA256 != "") != ok || d != e.SHA256 {
			t.Errorf("%s: ListChecksums %q, ParseChecksums %q %v", e.File, e.SHA256, d, ok)
		}
	}
	if _, err := ListChecksums([]byte(strings.Repeat("x", maxChecksumsBytes+1))); err == nil {
		t.Errorf("an oversized document was read")
	}
	if got, err := ListChecksums([]byte("not perl at all\n}\n")); err != nil || len(got) != 0 {
		t.Errorf("garbage: %v, %v", got, err)
	}
}

func TestParseDistFilenameMatchesClassify(t *testing.T) {
	for _, file := range []string{
		"Acme-CPANAuthors-Canadian-0.0108.tar.gz", "Ekorn-Pipeline-v0.3.3.tar.gz", "SPVM-UV-0.008.tar.gz",
		"Thing-2.0.zip", "libwww-perl-6.72.tgz", "Foo-1.0-TRIAL.tar.bz2", "Foo-Bar.tar.gz", "Foo-1.0.meta", "CHECKSUMS",
	} {
		dist, version, ok := ParseDistFilename(file)
		r, cok := classify("/authors/id/E/ET/ETHER/" + file)
		if !cok {
			t.Fatalf("classify refused %s", file)
		}
		isDist := r.kind == kindDistribution
		if ok != isDist || dist != r.name || version != r.version {
			t.Errorf("%s: ParseDistFilename = %q %q %v; classify kind %v name %q version %q", file, dist, version, ok, r.kind, r.name, r.version)
		}
	}
	if d, v, ok := ParseDistFilename("Ekorn-Pipeline-v0.3.3.tar.gz"); !ok || d != "Ekorn-Pipeline" || v != "v0.3.3" {
		t.Errorf("Ekorn-Pipeline: %q %q %v", d, v, ok)
	}
}
