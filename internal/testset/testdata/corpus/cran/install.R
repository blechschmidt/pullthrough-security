# Install the dependency declared in DESCRIPTION through the proxy's CRAN
# backend. The mount is the repository root, so R finds src/contrib/PACKAGES
# and the package tarballs beneath it.
options(repos = c(CRAN = "https://proxy.example.com/v1/cran"))
install.packages("R6")
library(R6)
