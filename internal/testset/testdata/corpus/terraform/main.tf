# Minimal real Terraform/OpenTofu build for the pull-through proxy test set.
# The provider is pulled through the proxy's Terraform registry backend.
terraform {
  required_providers {
    null = {
      source  = "hashicorp/null"
      version = "3.2.2"
    }
  }
}

resource "null_resource" "ok" {}
