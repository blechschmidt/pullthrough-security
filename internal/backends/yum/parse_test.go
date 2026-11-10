package yum

import "testing"

func TestClassifyTable(t *testing.T) {
	cases := []struct {
		path string
		ok   bool
		kind resourceKind
	}{
		{"/Packages/hello-1.0-1.x86_64.rpm", true, kindRpm},
		{"/hello-1.0-1.noarch.rpm", true, kindRpm},
		{"/repodata/repomd.xml", true, kindRepomd},
		{"/repodata/repomd.xml.asc", true, kindRepomdSig},
		{"/repodata/repomd.xml.key", true, kindRepomdSig},
		{"/repodata/abc-primary.xml.gz", true, kindRepodata},
		{"/some/other", true, kindOther},
		{"", false, kindOther},
		{"/../etc/passwd.rpm", false, kindOther},
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

func TestSplitRPMFilename(t *testing.T) {
	cases := []struct {
		file, name, ver string
	}{
		{"hello-1.0-1.x86_64.rpm", "hello", "1.0"},
		{"kernel-core-6.2.1-300.fc38.x86_64.rpm", "kernel-core", "6.2.1"},
		{"weird.rpm", "weird", ""},
	}
	for _, c := range cases {
		name, ver := splitRPMFilename(c.file)
		if name != c.name || ver != c.ver {
			t.Errorf("splitRPMFilename(%q) = (%q,%q), want (%q,%q)", c.file, name, ver, c.name, c.ver)
		}
	}
}

func TestParseRepoMD(t *testing.T) {
	doc := `<?xml version="1.0"?>
<repomd xmlns="http://linux.duke.edu/metadata/repo">
  <revision>42</revision>
  <data type="primary">
    <checksum type="sha256">aaaa111122223333444455556666777788889999aaaabbbbccccddddeeeeffff</checksum>
    <location href="repodata/abc-primary.xml.gz"/>
  </data>
  <data type="filelists">
    <checksum type="sha1">aaaa11112222333344445555666677778888aaaa</checksum>
    <location href="repodata/def-filelists.xml.gz"/>
  </data>
</repomd>`
	rm, err := ParseRepoMD([]byte(doc))
	if err != nil {
		t.Fatalf("ParseRepoMD: %v", err)
	}
	loc, ok := rm.PrimaryLocation()
	if !ok || loc != "repodata/abc-primary.xml.gz" {
		t.Errorf("PrimaryLocation = %q, %v", loc, ok)
	}
	d, ok := rm.FindByLocation("repodata/def-filelists.xml.gz")
	if !ok || d.Checksum.alg.name != "sha1" {
		t.Errorf("filelists entry = %+v, %v", d, ok)
	}
}

func TestParseRepoMDEmptyFails(t *testing.T) {
	if _, err := ParseRepoMD([]byte(`<repomd></repomd>`)); err == nil {
		t.Fatal("expected error for repomd with no data entries")
	}
	if _, err := ParseRepoMD([]byte("not xml")); err == nil {
		t.Fatal("expected error for non-XML repomd")
	}
}

func TestParsePrimary(t *testing.T) {
	doc := `<metadata xmlns="http://linux.duke.edu/metadata/common" packages="2">
  <package type="rpm">
    <name>hello</name>
    <checksum type="sha256" pkgid="YES">aaaa111122223333444455556666777788889999aaaabbbbccccddddeeeeffff</checksum>
    <location href="Packages/hello-1.0-1.x86_64.rpm"/>
  </package>
  <package type="rpm">
    <name>nochecksum</name>
    <location href="Packages/nochecksum-1.0.rpm"/>
  </package>
</metadata>`
	entries, err := ParsePrimary([]byte(doc))
	if err != nil {
		t.Fatalf("ParsePrimary: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("entries = %d, want 1 (nochecksum dropped)", len(entries))
	}
	if entries[0].Location != "Packages/hello-1.0-1.x86_64.rpm" {
		t.Errorf("location = %q", entries[0].Location)
	}
	if entries[0].Checksum.alg.name != "sha256" {
		t.Errorf("alg = %q", entries[0].Checksum.alg.name)
	}
}

func TestDecompressPrimary(t *testing.T) {
	plain := []byte(`<metadata><package type="rpm"></package></metadata>`)
	gz := gzipBytes(plain)
	out, err := decompressPrimary("abc-primary.xml.gz", gz)
	if err != nil || string(out) != string(plain) {
		t.Fatalf("gz roundtrip: %v", err)
	}
	if _, err := decompressPrimary("primary.xml.zst", plain); err == nil {
		t.Error("expected unsupported-compression error for .zst")
	}
}

func TestAlgForType(t *testing.T) {
	if _, ok := algForType("md5"); ok {
		t.Error("md5 must be rejected")
	}
	if a, ok := algForType("sha"); !ok || a.name != "sha1" {
		t.Errorf("'sha' should alias sha1, got %+v %v", a, ok)
	}
	if a, ok := algForType("SHA256"); !ok || a.name != "sha256" {
		t.Errorf("SHA256 = %+v %v", a, ok)
	}
}
