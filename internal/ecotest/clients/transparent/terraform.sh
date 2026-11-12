#!/bin/sh
# terraform — install providers from registry.terraform.io, intercepted by the
# proxy.
set -eu
echo "ECOTEST_CLIENT_VERSION=$(terraform version | awk 'NR==1 {print $2}')"

# No CLI configuration: service discovery for registry.terraform.io is
# Terraform's own. It trusts the proxy's CA through SSL_CERT_FILE; through a
# forward proxy it reads HTTPS_PROXY. The proxy moves the download, SHA256SUMS
# and signature URLs it hands out (releases.hashicorp.com) onto
# registry.terraform.io, so Terraform's checksum and signature verification runs
# against intercepted files.
export SSL_CERT_FILE="$PT_CA_CERT" CHECKPOINT_DISABLE=1

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
