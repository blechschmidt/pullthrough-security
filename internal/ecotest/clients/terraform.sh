#!/bin/sh
# terraform — serve registry.terraform.io from the proxy.
set -eu
echo "ECOTEST_CLIENT_VERSION=$(terraform version | awk 'NR==1 {print $2}')"

# A `host` block in the CLI configuration (~/.terraformrc) overrides service
# discovery for registry.terraform.io, so provider and module addresses in .tf
# files stay exactly as they are (hashicorp/null resolves through the proxy).
# The proxy rewrites the download, SHA256SUMS and signature URLs it hands out, so
# Terraform's own checksum and signature verification runs against proxied files.
cat > terraformrc <<TERRAFORMRC
host "registry.terraform.io" {
  services = {
    "providers.v1" = "$MOUNT/v1/providers/"
    "modules.v1"   = "$MOUNT/v1/modules/"
  }
}
TERRAFORMRC
export TF_CLI_CONFIG_FILE="$PWD/terraformrc" CHECKPOINT_DISABLE=1

# PKG_NAME is "<namespace>/<type>", e.g. hashicorp/null.
cat > main.tf <<MAIN
terraform {
  required_providers {
    subject = {
      source  = "$PKG_NAME"
      version = "$PKG_VERSION"
    }
  }
}
MAIN
terraform init -input=false -no-color
