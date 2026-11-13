# terraform

Generated 2026-11-12 with Terraform v1.15.8 (linux_amd64, `/usr/bin/terraform`) on the host,
in a scratch copy of this directory, with an empty HOME and no CLI config or plugin cache:

    env -i HOME=<scratch>/home PATH=/usr/bin:/bin CHECKPOINT_DISABLE=1 \
      terraform init -backend=false -input=false -no-color
    env -i HOME=<scratch>/home PATH=/usr/bin:/bin CHECKPOINT_DISABLE=1 \
      terraform providers lock -no-color -platform=linux_amd64 -platform=darwin_arm64

`main.tf` and `modules/x/main.tf` were written by hand first. `.terraform.lock.hcl` is the tool's
output, unedited. `modules.json.txt` is a byte copy of `.terraform/modules/modules.json` (renamed so
no parser picks it up). `.terraform/` itself is not kept.

`.terraform.lock.hcl`:

- It starts with two comment lines: `# This file is maintained automatically by "terraform init".`
  and `# Manual edits may be lost in future updates.`
- It has one `provider "registry.terraform.io/hashicorp/<type>"` block per provider, sorted by
  address. The label is the full address with the host, although `main.tf` only says
  `hashicorp/null`.
- `version` is the selected version. null `~> 3.2` selected 3.3.2, the newest 3.x that is >= 3.2.
- `constraints` merges and normalises the constraints from all modules. For null, `~> 3.2` (root)
  and `>= 3.0` (`modules/x`) became `">= 3.0.0, ~> 3.2"`. For random it is `"3.6.3"`. Terraform
  leaves `constraints` out when no module constrains the provider (`SaveLocksToBytes` in
  `internal/depsfile/locks_file.go`).
- `hashes` is a sorted list with a trailing comma: null has 2 `h1:` + 13 `zh:`, random has 2 `h1:`
  + 12 `zh:`.
- `zh:` is the lowercase-hex SHA-256 of a file listed in the provider release's signed
  `SHA256SUMS` (Terraform reported "signed by HashiCorp"). Terraform records every line of that
  file, for all platforms, not only the two locked ones. The `zh:` set equals the lines of
  releases.hashicorp.com `terraform-provider-random_3.6.3_SHA256SUMS` (12) and
  `terraform-provider-null_3.3.2_SHA256SUMS` (13). Code:
  `signatureAuthentication.AcceptableHashes` in `internal/getproviders/package_authentication.go`.
- Checked by downloading the zips from releases.hashicorp.com:
  `zh:4b4c11ccfba7319e901df2dac836b1ae8f12185e37249e8d870ee10bb87a13fe` is the sha256 of
  `terraform-provider-random_3.6.3_linux_amd64.zip`. That zip is the registry's `download_url` for
  linux/amd64, and the hash is the registry's `shasum`. `zh:04ceb652…` is the darwin_arm64 zip.
  For null, `zh:d2855b92…` is linux_amd64 and `zh:62538582…` is darwin_arm64.
- Surprise: one `zh:` per provider is not a package. `zh:78d5eefdd9e494defcb3c68d282b8f96630502cac21d1ea161f53cfe9bb483b3`
  is the sha256 of `terraform-provider-<name>_<version>_manifest.json`. That file is
  `{"version": 1, "metadata": {"protocol_versions": ["5.0"]}}` (pretty-printed, 82 bytes) and is
  byte-identical for both providers. So the same `zh:` appears in both blocks.
- `h1:` is Terraform's hash scheme 1. It is Go's `golang.org/x/mod/sumdb/dirhash.Hash1` over the
  package contents: the SHA-256 of the lines `"<sha256 hex of file>  <path>\n"`, one per file in
  sorted path order, then standard padded base64 with the prefix `h1:`. `PackageHashV1` in
  `internal/getproviders/hash.go` computes it with `HashZip` over a zip or `HashDir` over an
  unpacked directory, and both give the same value. All 4 values were recomputed from the
  releases.hashicorp.com zips (entries `LICENSE.txt` and `terraform-provider-<name>_v<version>_x5`)
  and from the unpacked linux_amd64 directories under `.terraform/providers`. All match.
- `h1:` is per platform, and the lock has one only for platforms that were downloaded. `init` wrote
  the linux_amd64 `h1:`. `providers lock` added the darwin_arm64 `h1:` to each block, and that was
  the only change it made.
- Modules do not appear in the lock file at all.
- Format: 2-space indent, `version     =` padded to line up with `constraints =`, LF, trailing
  newline.

`main.tf` module pins, and what `modules.json.txt` recorded for them:

- `modules.json.txt` is one line of JSON with no trailing newline:
  `{"Modules":[{"Key":"","Source":"","Dir":"."}, …]}`. `Key` is the module call name. `Source` is
  the normalised source address. `Version` is present only for registry modules. `Dir` is the
  install directory.
- `label_exact`: `cloudposse/label/null`, `version = "0.25.0"`. Recorded as Source
  `registry.terraform.io/cloudposse/label/null`, Version `0.25.0`.
- `label_range`: the same module with `version = "~> 0.24.0"`, resolved to Version `0.24.1`.
- `template_dir`: `hashicorp/dir/template` with `version = "~> 1.0"`, resolved to Version `1.0.2`.
- `label_git_commit`:
  `git::https://github.com/cloudposse/terraform-null-label.git?ref=488ab91e34a24a86957e397d9f7262ec5925586a`,
  recorded unchanged with no Version.
- `label_git_tag`: `git::https://github.com/cloudposse/terraform-null-label.git?ref=0.24.1`,
  recorded unchanged.
- `label_github`: the shorthand `github.com/cloudposse/terraform-null-label` (no ref) was recorded
  as `git::https://github.com/cloudposse/terraform-null-label.git`.
- `local_x`: `./modules/x`, recorded with Dir `modules/x`. It is not downloaded.
- How the registry modules were fetched: the registry answers a module download with HTTP 204 and
  `X-Terraform-Get: git::https://github.com/…?ref=<commit>`.
  - cloudposse/label/null 0.25.0 → `488ab91e34a24a86957e397d9f7262ec5925586a`. That is tag
    `0.25.0` and the same commit as `label_git_commit`.
  - 0.24.1 → `dc699992922b452ccc521c3dfe9c9c5c1f8376af`, which is tag `0.24.1`.
  - hashicorp/dir/template 1.0.2 → `556bd64989e7099fabb90c6b883b5d4d92da3ae8`, which is tag
    `v1.0.2`.
  - Checked with `git rev-parse HEAD` in `.terraform/modules/*`.
  - The `0.24.1` and `0.25.0` tags are lightweight: `git ls-remote` shows no `^{}` line, so
    tag = commit.
- The shorthand without a ref cloned the default branch `main` at
  `38364d79c1082de13373666252e1276975919543` (`0.25.0-36-g38364d7`). Neither the lock file nor
  `modules.json` records that commit.
