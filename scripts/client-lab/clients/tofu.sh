#!/bin/sh
# lab: client=OpenTofu
# lab: image=ghcr.io/opentofu/opentofu:1.8
# lab: entrypoint=sh
#
# OpenTofu with a host block in the CLI configuration: the public registry's
# hostname is served by the proxy, so provider and module addresses in .tf files
# stay as they are.
set -eu
echo "LAB_CLIENT_VERSION=$(tofu version | awk 'NR==1 {print $2}')"

# OpenTofu reads the CA bundle from SSL_CERT_FILE.
export SSL_CERT_FILE=/etc/ssl/corp-ca.pem

cat > ~/.tofurc <<EOF
host "registry.opentofu.org" {
  services = {
    "providers.v1" = "https://proxy.example.com/v1/opentofu/v1/providers/"
    "modules.v1"   = "https://proxy.example.com/v1/opentofu/v1/modules/"
  }
}
EOF
if [ -n "${PROXY_TOKEN:-}" ]; then
cat >> ~/.tofurc <<EOF

credentials "registry.opentofu.org" {
  token = "${PROXY_TOKEN}"
}
EOF
fi

# Most registry modules name a Git repository as their source, which
# OpenTofu clones with git: route that through the proxy's Git upstream.
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
tofu init -input=false -no-color
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
    tofu init -input=false -no-color
    # The lock file names the public registry, not the proxy.
    grep -q 'provider "registry.opentofu.org/hashicorp/null"' .terraform.lock.hcl
    ! grep -q 'proxy.example.com' .terraform.lock.hcl
else
    # A LIMITATION, asserted: OpenTofu sends its token to the registry API, but
    # fetches the checksums, their signature and the provider package without
    # it — and the proxy answers 401.
    if tofu init -input=false -no-color >init.log 2>&1; then
        echo "OpenTofu installed a provider with a token: the limitation is gone — update docs/clients/terraform.md"
        cat init.log; exit 1
    fi
    cat init.log
    grep -q "401 Unauthorized" init.log
fi
