# opentofu

Generated 2026-11-12 with OpenTofu v1.13.0 (linux_amd64) on the host, in a scratch copy of this
directory, with an empty HOME and no CLI config or plugin cache:

    env -i HOME=<scratch>/home PATH=/usr/bin:/bin \
      tofu init -backend=false -input=false -no-color
    env -i HOME=<scratch>/home PATH=/usr/bin:/bin \
      tofu providers lock -no-color -platform=linux_amd64 -platform=darwin_arm64

About the binary: `tofu` is the newest of the three OpenTofu builds on the host (1.10.10, 1.12.6,
1.13.0). It is byte-identical to the `tofu` in the official `tofu_1.13.0_linux_amd64.zip` from
github.com/opentofu/opentofu. That zip's sha256 `ad494034…` matches the release's `SHA256SUMS`.

`main.tf` was written by hand. `.terraform.lock.hcl` is the tool's output, unedited.
`modules.json.txt` is a byte copy of `.terraform/modules/modules.json`.

- The first comment line names the other tool:
  `# This file is maintained automatically by "tofu init".` The second line is the same as
  Terraform's.
- The provider address host is `registry.opentofu.org`:
  `provider "registry.opentofu.org/hashicorp/null"`. `main.tf` uses the same `hashicorp/null`
  source string as the terraform fixture.
- null `~> 3.2` selected 3.3.2 (`constraints = "~> 3.2"`). random is 3.6.3
  (`constraints = "3.6.3"`).
- `tofu init` already wrote every hash. `tofu providers lock` then said "found no need for changes"
  and left the file unchanged.
- There is an `h1:` for every platform, not just the downloaded ones. null has 15 `h1:` + 15 `zh:`
  (15 platforms) and random has 10 `h1:` + 10 `zh:` (10 platforms).
  - The registry's download response (`/v1/providers/hashicorp/<type>/<version>/download/linux/amd64`)
    has a `packages` object with `"hashes": ["zh:…", "h1:…"]` and `package_size` for each
    platform.
  - The lock's hash set equals the union of those lists. Checked for both providers.
  - OpenTofu 1.13.0 reads `packages` in `internal/getproviders/registry_client.go`.
    `NewRegistryPackageAuthentication` in `package_authentication.go` cites RFC
    20251027-provider-registry-hashes.
  - `init` downloaded only linux_amd64, yet the lock it wrote already held all 25 `h1:`. So the
    `h1:` values for platforms that were never downloaded come from the registry and are not
    computed locally.
- `zh:` is the sha256 of the provider zip.
  - The `zh:` set equals the lines of the `SHA256SUMS` at the registry's `shasums_url`, for example
    https://github.com/opentofu/terraform-provider-random/releases/download/v3.6.3/terraform-provider-random_3.6.3_SHA256SUMS.
  - These `SHA256SUMS` files list only zips, so there is no manifest.json entry here, unlike the
    terraform fixture.
  - Checked by downloading the zips: `zh:21a15ac74adb8ba499aab989a4248321b51946e5431219b56fc827e565776714`
    is the sha256 of `terraform-provider-random_3.6.3_linux_amd64.zip`, which is the registry's
    `download_url` and `shasum`. `zh:3026fcdc…` (random darwin_arm64), `zh:73ac02bc…` (null
    linux_amd64) and `zh:71d64453…` (null darwin_arm64) also match.
- `h1:` is the same dirhash `Hash1` as Terraform's. It was recomputed from those 4 zips and all
  match: random `h1:Ry0Lr0…` (linux_amd64) and `h1:32/UZo…` (darwin_arm64), null `h1:WxS7rj…` and
  `h1:ZLjbXn…`.
- The packages are OpenTofu's own builds. They come from the releases of
  github.com/opentofu/terraform-provider-<type>, are signed with key `0C0AF313E5FD9F80`, and the
  zips contain `CHANGELOG.md`, `LICENSE`, `README.md` and `terraform-provider-<type>`.
  - They are different bytes from HashiCorp's zips, so this file shares no hash with the terraform
    fixture for the same provider versions.
  - Example: random 3.6.3 linux_amd64 is `zh:21a15ac7…` here and `zh:4b4c11cc…` there.
- `modules.json.txt` records `registry.opentofu.org/cloudposse/label/null` 0.25.0.
  - registry.opentofu.org answers the module download with HTTP 200 and the JSON body
    `{"location": "git::https://github.com/cloudposse/terraform-null-label?ref=488ab91e34a24a86957e397d9f7262ec5925586a"}`.
    registry.terraform.io answers with 204 and `X-Terraform-Get` instead.
  - The module was cloned at that commit.
- Format: as in the terraform fixture (2-space indent, sorted `hashes` with a trailing comma, LF,
  trailing newline).
