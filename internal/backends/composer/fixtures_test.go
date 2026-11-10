package composer

import (
	"crypto/sha1"
	"fmt"
)

// sha1Hex returns the lowercase hex SHA-1 of b, matching Composer's dist.shasum.
func sha1Hex(b []byte) string {
	sum := sha1.Sum(b)
	return fmt.Sprintf("%x", sum)
}

// metadataFixture is a recorded-shape, non-minified v2 metadata document for a
// single package with two versions.
const metadataFixture = `{
  "packages": {
    "monolog/monolog": [
      {
        "name": "monolog/monolog",
        "version": "3.2.0",
        "license": ["MIT"],
        "dist": {"type": "zip", "url": "https://example.test/raw/monolog-3.2.0.zip", "reference": "ref320", "shasum": "0000000000000000000000000000000000000000"}
      },
      {
        "name": "monolog/monolog",
        "version": "3.1.0",
        "license": ["MIT"],
        "dist": {"type": "zip", "url": "https://example.test/raw/monolog-3.1.0.zip", "reference": "ref310", "shasum": "1111111111111111111111111111111111111111"}
      }
    ]
  }
}`

// minifiedFixture is the Composer v2 "minified" delta encoding: the second
// version object carries only the keys that changed, and "license":"__unset"
// removes the license inherited from the first.
const minifiedFixture = `{
  "minified": "composer/2.0",
  "packages": {
    "vendor/pkg": [
      {
        "name": "vendor/pkg",
        "version": "2.0.0",
        "license": ["Apache-2.0"],
        "dist": {"type": "zip", "url": "https://example.test/raw/pkg-2.0.0.zip", "reference": "rA", "shasum": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
      },
      {
        "version": "1.9.0",
        "license": "__unset",
        "dist": {"type": "zip", "url": "https://example.test/raw/pkg-1.9.0.zip", "reference": "rB", "shasum": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}
      }
    ]
  }
}`
