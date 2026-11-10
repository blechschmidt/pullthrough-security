package malfeed

// fixtureFeed is a small OSV "malicious-packages"-shaped feed exercising the
// matcher across ecosystems and affected-set shapes:
//   - a whole-package npm credential stealer (no versions → AllVersions)
//   - a PyPI crypto-miner pinned to two explicit versions
//   - a cargo backdoor expressed as a SEMVER range (introduced..fixed)
//   - a NuGet entry recovered from a purl with a case-different name
const fixtureFeed = `[
  {
    "id": "MAL-2024-0001",
    "aliases": ["GHSA-aaaa-bbbb-cccc"],
    "summary": "npm credential stealer in postinstall script",
    "published": "2024-01-15T00:00:00Z",
    "affected": [
      {
        "package": {"ecosystem": "npm", "name": "Evil-Stealer"},
        "database_specific": {"categories": ["credential-stealer"]}
      }
    ]
  },
  {
    "id": "MAL-2024-0002",
    "summary": "PyPI crypto-miner",
    "affected": [
      {
        "package": {"ecosystem": "PyPI", "name": "crypto_miner_pkg"},
        "versions": ["1.0.0", "1.0.1"],
        "database_specific": {"categories": ["crypto-miner"]}
      }
    ]
  },
  {
    "id": "MAL-2024-0003",
    "summary": "cargo install-script backdoor",
    "affected": [
      {
        "package": {"ecosystem": "crates.io", "name": "bad_crate"},
        "ranges": [
          {"type": "SEMVER", "events": [{"introduced": "1.2.0"}, {"fixed": "1.5.0"}]}
        ],
        "database_specific": {"categories": ["backdoor"]}
      }
    ]
  },
  {
    "id": "MAL-2024-0004",
    "summary": "NuGet backdoor",
    "affected": [
      {
        "package": {"ecosystem": "NuGet", "name": "", "purl": "pkg:nuget/Contoso.Evil@2.0.0"}
      }
    ]
  }
]`
