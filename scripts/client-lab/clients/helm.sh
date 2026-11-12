#!/bin/sh
# lab: client=Helm
# lab: image=alpine/helm:3.16.3
# lab: entrypoint=sh
#
# Helm: a classic chart repository, and an OCI registry of charts through the
# proxy's host-root registry endpoint.
set -eu
echo "LAB_CLIENT_VERSION=$(helm version --short)"

if [ -n "${PROXY_TOKEN:-}" ]; then
    helm repo add podinfo https://proxy.example.com/v1/podinfo --ca-file /etc/ssl/corp-ca.pem \
        --username pullthrough --password "${PROXY_TOKEN}"
else
    helm repo add podinfo https://proxy.example.com/v1/podinfo --ca-file /etc/ssl/corp-ca.pem
fi
helm repo update
helm pull podinfo/podinfo --version 6.7.1
test -s podinfo-6.7.1.tgz

# OCI: oci://<proxy>/<upstream>/<repository>.
mkdir oci
if [ -n "${PROXY_TOKEN:-}" ]; then
    # Helm's registry client answers the proxy's challenge (HTTP Basic, for a
    # container registry) with what `helm registry login` stored.
    echo "${PROXY_TOKEN}" | helm registry login proxy.example.com --username pullthrough --password-stdin \
        --ca-file /etc/ssl/corp-ca.pem
fi
helm pull oci://proxy.example.com/helm-oci/stefanprodan/charts/podinfo --version 6.7.1 \
    --ca-file /etc/ssl/corp-ca.pem --destination oci
test -s oci/podinfo-6.7.1.tgz
