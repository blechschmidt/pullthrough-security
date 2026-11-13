# terraform-override

`main.tf` and `override.tf` are hand-written; `.terraform.lock.hcl` and `modules.json.txt` (a copy of
`.terraform/modules/modules.json`, renamed so no parser reads it) were written by Terraform v1.15.8 on the
host, 2026-11-13, and not edited:

    HOME=<scratch> TF_IN_AUTOMATION=1 terraform init -backend=false -input=false -no-color

- `main.tf` pins the registry module `cloudposse/label/null` to `0.24.1`. `override.tf` — a Terraform
  override file — declares `module "label" { version = "0.25.0" }`. Terraform merges override files into
  the configuration after loading it, an override's arguments replacing the original's:
  `modules.json.txt` records `label` at **0.25.0**, the version that was installed.
- `module "iam_account"` uses a directory of a registry module,
  `terraform-aws-modules/iam/aws//modules/iam-account`, pinned to `5.48.0`; Terraform queries the registry
  for `terraform-aws-modules/iam/aws` 5.48.0 and uses its `modules/iam-account` directory
  (`modules.json.txt`: `"Dir": ".terraform/modules/iam_account/modules/iam-account"`).
- That module requires the `hashicorp/aws` provider, so `init` also wrote `.terraform.lock.hcl`
  (aws 6.73.0 with the `h1:` hash of the downloaded linux_amd64 package and the `zh:` hashes of the
  release's SHA256SUMS).
