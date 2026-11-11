#!/bin/sh
# lab: client=R (install.packages)
# lab: image=r-base:4.4.1
set -eu
echo "LAB_CLIENT_VERSION=$(R --version | awk 'NR==1 {print $3}')"

# R downloads with libcurl, which reads the CA bundle from CURL_CA_BUNDLE.
export CURL_CA_BUNDLE=/etc/ssl/corp-ca.pem

if [ -n "${PROXY_TOKEN:-}" ]; then
cat > ~/.Rprofile <<EOF
options(repos = c(CRAN = "https://pullthrough:${PROXY_TOKEN}@proxy.example.com/v1/cran"))
EOF
else
cat > ~/.Rprofile <<EOF
options(repos = c(CRAN = "https://proxy.example.com/v1/cran"))
EOF
fi

# install.packages() only WARNS when a download fails, so load the package
# afterwards: that is what fails when the proxy refused it.
mkdir lib
Rscript -e 'install.packages("R6", lib = "lib"); library("R6", lib.loc = "lib")'
