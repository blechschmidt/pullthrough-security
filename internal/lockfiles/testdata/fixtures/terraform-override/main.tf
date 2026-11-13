# The registry module "label" is pinned to 0.24.1 here; override.tf replaces
# the version, and Terraform installs the override's.
module "label" {
  source  = "cloudposse/label/null"
  version = "0.24.1"
}

# A directory of a registry module ("//modules/iam-account"), pinned exactly.
module "iam_account" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-account"
  version = "5.48.0"

  account_alias = "fixture"
}
