#!/bin/sh
# cran — use the proxy as R's package repository.
set -eu
echo "ECOTEST_CLIENT_VERSION=$(R --version | awk 'NR==1 {print $3}')"

# options(repos = ...) (in ~/.Rprofile, or per call) replaces the CRAN mirror.
# The mount is the repository root, so R finds src/contrib/PACKAGES and the
# package tarballs beneath it.
#
# install.packages() only WARNS when a download fails, so the script loads the
# package afterwards: that is what fails when the proxy refused it.
mkdir lib
Rscript -e '
  options(repos = c(CRAN = Sys.getenv("MOUNT")))
  pkg <- Sys.getenv("PKG_NAME")
  install.packages(pkg, lib = "lib")
  library(pkg, lib.loc = "lib", character.only = TRUE)
  cat(pkg, as.character(packageVersion(pkg, lib.loc = "lib")), "ok\n")
'
