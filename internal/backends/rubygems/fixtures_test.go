package rubygems

import (
	"crypto/sha256"
	"fmt"
)

// zeroSHA256 is the SHA-256 of the empty input — a convenient placeholder digest
// for fixtures and fuzz seeds.
const zeroSHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

// sha256Hex returns the lowercase hex SHA-256 of b.
func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return fmt.Sprintf("%x", sum)
}

// infoFixture is a recorded-shape compact-index /info/<gem> document covering the
// document header, a plain version, a version with dependencies and Ruby/RubyGems
// requirements, and a platform-suffixed version. The checksums are placeholders;
// tests that verify content substitute the real digest of their fake .gem bytes.
const infoFixture = `---
1.0.0 |checksum:` + zeroSHA256 + `,ruby:>= 2.5.0
1.1.0 rack:>= 2.0&json:>= 1.8|checksum:` + zeroSHA256 + `,ruby:>= 2.6.0,rubygems:>= 3.0.0
1.1.0-java |checksum:` + zeroSHA256 + `
`
