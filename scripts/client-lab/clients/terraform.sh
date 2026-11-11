#!/bin/sh
# lab: client=Terraform
# lab: image=hashicorp/terraform:1.9
# lab: entrypoint=sh
#
# Terraform with a host block in the CLI configuration: the public registry's
# hostname is served by the proxy, so provider and module addresses in .tf files
# stay as they are.
set -eu

# Terraform reads the CA bundle from SSL_CERT_FILE.
export SSL_CERT_FILE=/etc/ssl/corp-ca.pem

# Terraform also checks for new versions of itself at
# checkpoint-api.hashicorp.com, on `terraform version` and `terraform init`;
# disable_checkpoint switches that off.
cat > ~/.terraformrc <<EOF
disable_checkpoint = true

host "registry.terraform.io" {
  services = {
    "providers.v1" = "https://proxy.example.com/v1/terraform/v1/providers/"
    "modules.v1"   = "https://proxy.example.com/v1/terraform/v1/modules/"
  }
}
EOF
if [ -n "${PROXY_TOKEN:-}" ]; then
cat >> ~/.terraformrc <<EOF

credentials "registry.terraform.io" {
  token = "${PROXY_TOKEN}"
}
EOF
fi
echo "LAB_CLIENT_VERSION=$(terraform version | awk 'NR==1 {print $2}')"

# Most registry modules name a Git repository as their source, which
# Terraform clones with git: route that through the proxy's Git upstream.
git config --global url."https://proxy.example.com/v1/github/".insteadOf "https://github.com/"
git config --global http."https://proxy.example.com/".sslCAInfo /etc/ssl/corp-ca.pem
if [ -n "${PROXY_TOKEN:-}" ]; then
    git config --global http."https://proxy.example.com/".extraHeader "Authorization: Bearer ${PROXY_TOKEN}"
fi

mkdir module && cd module
cat > main.tf <<EOF
module "label" {
  source  = "cloudposse/label/null"
  version = "0.25.0"
}
EOF
terraform init -input=false -no-color
test -d .terraform/modules/label
cd ..

mkdir provider && cd provider
cat > main.tf <<EOF
terraform {
  required_providers {
    null = {
      source  = "hashicorp/null"
      version = "3.2.2"
    }
  }
}
EOF
if [ -z "${PROXY_TOKEN:-}" ]; then
    terraform init -input=false -no-color
    # The lock file names the public registry, not the proxy.
    grep -q 'provider "registry.terraform.io/hashicorp/null"' .terraform.lock.hcl
    if grep -q 'proxy.example.com' .terraform.lock.hcl; then echo ".terraform.lock.hcl names the proxy"; exit 1; fi
else
    # A LIMITATION, asserted: Terraform sends its token to the registry API, but
    # fetches the checksums, their signature and the provider package without
    # it — and the proxy answers 401.
    if terraform init -input=false -no-color >init.log 2>&1; then
        echo "Terraform installed a provider with a token: the limitation is gone — update docs/clients/terraform.md"
        cat init.log; exit 1
    fi
    cat init.log
    grep -q "401 Unauthorized" init.log
fi
