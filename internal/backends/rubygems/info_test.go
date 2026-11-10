package rubygems

import "testing"

func TestParseInfo(t *testing.T) {
	info, err := ParseInfo([]byte(infoFixture))
	if err != nil {
		t.Fatalf("ParseInfo: %v", err)
	}
	if len(info.Versions) != 3 {
		t.Fatalf("parsed %d versions, want 3: %+v", len(info.Versions), info.Versions)
	}

	v0 := info.Versions[0]
	if v0.Version != "1.0.0" {
		t.Errorf("version[0] = %q", v0.Version)
	}
	if v0.Checksum != zeroSHA256 {
		t.Errorf("version[0] checksum = %q", v0.Checksum)
	}
	if v0.Ruby != ">= 2.5.0" {
		t.Errorf("version[0] ruby = %q", v0.Ruby)
	}

	v1 := info.Versions[1]
	if v1.Version != "1.1.0" || v1.RubyGems != ">= 3.0.0" {
		t.Errorf("version[1] = %+v", v1)
	}

	// Platform-suffixed version token is preserved verbatim.
	v2 := info.Versions[2]
	if v2.Version != "1.1.0-java" {
		t.Errorf("version[2] = %q, want 1.1.0-java", v2.Version)
	}
}

func TestParseInfoChecksumFor(t *testing.T) {
	info, err := ParseInfo([]byte(infoFixture))
	if err != nil {
		t.Fatalf("ParseInfo: %v", err)
	}
	if sum, ok := info.ChecksumFor("1.1.0-java"); !ok || sum != zeroSHA256 {
		t.Errorf("ChecksumFor(platform) = %q,%v", sum, ok)
	}
	if _, ok := info.ChecksumFor("9.9.9"); ok {
		t.Error("ChecksumFor(unknown) should be false")
	}
}

func TestParseInfoLenient(t *testing.T) {
	// Malformed lines are skipped; a bad checksum is dropped rather than accepted.
	doc := `---
1.0.0 |checksum:not-a-valid-hex-digest
2.0.0 |checksum:` + zeroSHA256 + `
garbage line with no bar
`
	info, err := ParseInfo([]byte(doc))
	if err != nil {
		t.Fatalf("ParseInfo: %v", err)
	}
	if _, ok := info.ChecksumFor("1.0.0"); ok {
		t.Error("invalid-hex checksum should not be accepted")
	}
	if sum, ok := info.ChecksumFor("2.0.0"); !ok || sum != zeroSHA256 {
		t.Errorf("ChecksumFor(2.0.0) = %q,%v", sum, ok)
	}
}

func TestParseInfoTooLarge(t *testing.T) {
	big := make([]byte, maxInfoBytes+1)
	if _, err := ParseInfo(big); err == nil {
		t.Error("oversized info document should be rejected")
	}
}
