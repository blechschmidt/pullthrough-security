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
module "label_exact" {
  source  = "cloudposse/label/null"
  version = "0.25.0"
}

# The same registry module under another name, with a version range.
module "label_range" {
  source  = "cloudposse/label/null"
  version = "~> 0.24.0"
}

# Another registry module, with a version range.
module "template_dir" {
  source   = "hashicorp/dir/template"
  version  = "~> 1.0"
  base_dir = "${path.module}/modules/x"
}

# Git module pinned to a full commit id.
module "label_git_commit" {
  source = "git::https://github.com/cloudposse/terraform-null-label.git?ref=488ab91e34a24a86957e397d9f7262ec5925586a"
}

# Git module pinned to a tag.
module "label_git_tag" {
  source = "git::https://github.com/cloudposse/terraform-null-label.git?ref=0.24.1"
}

# GitHub shorthand without a ref: the default branch.
module "label_github" {
  source = "github.com/cloudposse/terraform-null-label"
}

# Local module.
module "local_x" {
  source = "./modules/x"
}
