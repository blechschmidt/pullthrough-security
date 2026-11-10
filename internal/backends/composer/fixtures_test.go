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

// inheritedDistFixture reproduces the shape of the live
// https://repo.packagist.org/p2/ralouphie/getallheaders~dev.json document (as
// recorded while fixing the dist rewrite), which exercises everything the
// minified encoding can do to a dist:
//
//   - "dev-develop" is the complete first object;
//   - "dev-master" points at the same commit, so its delta carries no "dist" (nor
//     "source") at all and inherits dev-develop's;
//   - "dev-hotfix/composer-install" is a branch whose name contains a "/", with a
//     dist of its own;
//
// plus one synthetic entry, "dev-no-dist", whose dist is removed with "__unset".
// The top-level "security-advisories" key is what Packagist appends to release
// documents; it must survive a rewrite.
const inheritedDistFixture = `{
  "minified": "composer/2.0",
  "packages": {
    "ralouphie/getallheaders": [
      {
        "name": "ralouphie/getallheaders",
        "description": "A polyfill for getallheaders <with> & 'specials'.",
        "version": "dev-develop",
        "version_normalized": "dev-develop",
        "license": ["MIT"],
        "source": {"url": "https://github.com/ralouphie/getallheaders.git", "type": "git", "reference": "120b605dfeb996808c31b6477290a714d356e822"},
        "dist": {"url": "https://api.github.com/repos/ralouphie/getallheaders/zipball/120b605dfeb996808c31b6477290a714d356e822", "type": "zip", "shasum": "", "reference": "120b605dfeb996808c31b6477290a714d356e822"},
        "type": "library",
        "time": "2019-03-08T08:55:37+00:00",
        "default-branch": true,
        "require": {"php": ">=5.6"}
      },
      {
        "version": "dev-master",
        "version_normalized": "dev-master",
        "default-branch": "__unset"
      },
      {
        "version": "dev-hotfix/composer-install",
        "version_normalized": "dev-hotfix/composer-install",
        "source": {"url": "https://github.com/ralouphie/getallheaders.git", "type": "git", "reference": "aad26b2e26ba2e877e3f65cf3aa739c581b57967"},
        "dist": {"url": "https://api.github.com/repos/ralouphie/getallheaders/zipball/aad26b2e26ba2e877e3f65cf3aa739c581b57967", "type": "zip", "shasum": "", "reference": "aad26b2e26ba2e877e3f65cf3aa739c581b57967"},
        "time": "2019-03-08T08:42:22+00:00"
      },
      {
        "version": "dev-no-dist",
        "version_normalized": "dev-no-dist",
        "dist": "__unset"
      }
    ]
  },
  "security-advisories": [{"advisoryId": "PKSA-0000-0000-0000", "affectedVersions": "<1.0"}]
}`

// packagistRootFixture is https://repo.packagist.org/packages.json exactly as
// served while this rewrite was written (Composer 2.11 era): lookups that point
// at Packagist's own hosts, a root-relative providers-url, the install-statistics
// endpoint, and the advisory/filter-list configuration.
const packagistRootFixture = `{"packages":[],"notify-batch":"https://packagist.org/downloads/","providers-url":"/p/%package%$%hash%.json","metadata-url":"https://repo.packagist.org/p2/%package%.json","metadata-changes-url":"https://packagist.org/metadata/changes.json","search":"https://packagist.org/search.json?q=%query%&type=%type%","list":"https://packagist.org/packages/list.json","security-advisories":{"metadata":true,"api-url":"https://packagist.org/api/security-advisories/"},"providers-api":"https://packagist.org/providers/%package%.json","warning":"Support for Composer 1 has been shutdown on September 1st 2025. You should upgrade to Composer 2. See https://blog.packagist.com/shutting-down-packagist-org-support-for-composer-1-x/","warning-versions":"<1.999","providers":[],"filter":{"metadata":true,"lists":{"malware":{"enabled":true}},"summary-url":"https://repo.packagist.org/lists/all/summary.json"}}`
