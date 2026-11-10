package apt

import "testing"

func TestClassifyTable(t *testing.T) {
	cases := []struct {
		path string
		ok   bool
		kind resourceKind
	}{
		{"/pool/main/h/hello/hello_1.0_amd64.deb", true, kindDeb},
		{"/pool/main/h/hello/hello_1.0_amd64.udeb", true, kindDeb},
		{"/dists/bookworm/InRelease", true, kindInRelease},
		{"/dists/bookworm/Release", true, kindRelease},
		{"/dists/bookworm/Release.gpg", true, kindReleaseSig},
		{"/dists/bookworm/main/binary-amd64/Packages.gz", true, kindPackages},
		{"/dists/bookworm/main/binary-amd64/Packages", true, kindPackages},
		{"/dists/bookworm/main/source/Sources.gz", true, kindMeta},
		{"/dists/bookworm/main/i18n/Translation-en", true, kindMeta},
		{"/some/other/path", true, kindOther},
		{"", false, kindOther},
		{"/../etc/passwd.deb", false, kindOther},
		{"/dists/../../x/Packages", false, kindOther},
	}
	for _, c := range cases {
		res, ok := classify(c.path)
		if ok != c.ok {
			t.Errorf("classify(%q) ok = %v, want %v", c.path, ok, c.ok)
			continue
		}
		if ok && res.kind != c.kind {
			t.Errorf("classify(%q) kind = %v, want %v", c.path, res.kind, c.kind)
		}
	}
}

func TestSplitDebFilename(t *testing.T) {
	cases := []struct {
		file, name, ver string
	}{
		{"hello_1.0_amd64.deb", "hello", "1.0"},
		{"libfoo-bar_2.3.4-1_arm64.deb", "libfoo-bar", "2.3.4-1"},
		{"weird.deb", "weird", ""},
	}
	for _, c := range cases {
		name, ver := splitDebFilename(c.file, ".deb")
		if name != c.name || ver != c.ver {
			t.Errorf("splitDebFilename(%q) = (%q,%q), want (%q,%q)", c.file, name, ver, c.name, c.ver)
		}
	}
}

func TestParseReleaseDigests(t *testing.T) {
	release := `Origin: Debian
Suite: bookworm
Codename: bookworm
MD5Sum:
 d41d8cd98f00b204e9800998ecf8427e 0 main/binary-amd64/Packages
SHA256:
 aaaa111122223333444455556666777788889999aaaabbbbccccddddeeeeffff 1234 main/binary-amd64/Packages
 bbbb111122223333444455556666777788889999aaaabbbbccccddddeeee0000 567 main/binary-amd64/Packages.gz
`
	rel, err := ParseRelease([]byte(release))
	if err != nil {
		t.Fatalf("ParseRelease: %v", err)
	}
	if rel.Suite != "bookworm" {
		t.Errorf("suite = %q", rel.Suite)
	}
	got, ok := rel.Digest("main/binary-amd64/Packages.gz")
	if !ok {
		t.Fatal("missing Packages.gz digest")
	}
	if got.hex != "bbbb111122223333444455556666777788889999aaaabbbbccccddddeeee0000" {
		t.Errorf("digest = %q", got.hex)
	}
	// MD5 lines must not have leaked into the SHA256 table.
	if _, ok := rel.Digest("main/binary-amd64/Packages"); !ok {
		t.Error("expected Packages SHA256 entry")
	}
}

func TestParseReleaseNoTableFails(t *testing.T) {
	if _, err := ParseRelease([]byte("Origin: x\nSuite: y\n")); err == nil {
		t.Fatal("expected error for Release with no SHA256 table")
	}
}

func TestStripClearsign(t *testing.T) {
	signed := `-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA512

Origin: Debian
SHA256:
 aaaa111122223333444455556666777788889999aaaabbbbccccddddeeeeffff 10 main/Packages
-----BEGIN PGP SIGNATURE-----

iQderp==
-----END PGP SIGNATURE-----
`
	rel, err := ParseRelease([]byte(signed))
	if err != nil {
		t.Fatalf("ParseRelease(clearsigned): %v", err)
	}
	if _, ok := rel.Digest("main/Packages"); !ok {
		t.Error("clearsigned body digest not parsed")
	}
}

func TestParsePackages(t *testing.T) {
	packages := `Package: hello
Filename: pool/main/h/hello/hello_1.0_amd64.deb
SHA256: aaaa111122223333444455556666777788889999aaaabbbbccccddddeeeeffff

Package: world
Description: multi
 line field
 continuation
Filename: pool/main/w/world/world_2.0_amd64.deb
SHA256: bbbb111122223333444455556666777788889999aaaabbbbccccddddeeee0000

Package: nodigest
Filename: pool/main/n/nodigest/nodigest_1.0_amd64.deb
`
	entries, err := ParsePackages([]byte(packages))
	if err != nil {
		t.Fatalf("ParsePackages: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("entries = %d, want 2 (nodigest must be dropped)", len(entries))
	}
	if entries[0].Filename != "pool/main/h/hello/hello_1.0_amd64.deb" {
		t.Errorf("entry[0] filename = %q", entries[0].Filename)
	}
	if entries[1].SHA256 != "bbbb111122223333444455556666777788889999aaaabbbbccccddddeeee0000" {
		t.Errorf("entry[1] sha = %q", entries[1].SHA256)
	}
}

func TestDecompressPackages(t *testing.T) {
	plain := []byte("Package: x\nFilename: pool/x.deb\nSHA256: " +
		"aaaa111122223333444455556666777788889999aaaabbbbccccddddeeeeffff\n")
	gz := gzipBytes(plain)
	out, err := decompressPackages("Packages.gz", gz)
	if err != nil {
		t.Fatalf("decompressPackages gz: %v", err)
	}
	if string(out) != string(plain) {
		t.Errorf("gz roundtrip mismatch")
	}
	out, err = decompressPackages("Packages", plain)
	if err != nil || string(out) != string(plain) {
		t.Errorf("plain passthrough failed: %v", err)
	}
	if _, err := decompressPackages("Packages.xz", plain); err == nil {
		t.Error("expected unsupported-compression error for .xz")
	}
}
