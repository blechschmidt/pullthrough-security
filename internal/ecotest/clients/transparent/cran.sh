#!/bin/sh
# cran — install from CRAN, intercepted by the proxy.
set -eu
echo "ECOTEST_CLIENT_VERSION=$(R --version | awk 'NR==1 {print $3}')"

# R keeps its CRAN mirror (cloud.r-project.org, as the image configures it).
# Its downloads (libcurl) trust the proxy's CA through CURL_CA_BUNDLE; through a
# forward proxy they read https_proxy.
#
# install.packages() only WARNS when a download fails, so the script loads the
# package afterwards: that is what fails when the proxy refused it.
export CURL_CA_BUNDLE="$PT_CA_CERT"
mkdir lib
Rscript -e '
  pkg <- Sys.getenv("PKG_NAME")
  install.packages(pkg, lib = "lib")
  library(pkg, lib.loc = "lib", character.only = TRUE)
  cat(pkg, as.character(packageVersion(pkg, lib.loc = "lib")), "ok\n")
'
