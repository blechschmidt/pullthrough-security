terraform {
  required_providers {
    random = {
      source  = "hashicorp/random"
      version = "3.6.3"
    }
    null = {
      source  = "hashicorp/null"
      version = "~> 3.2"
    }
  }
}

# Registry module, exact version.
module "label" {
  source  = "cloudposse/label/null"
  version = "0.25.0"
}
