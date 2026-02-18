terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.1"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.2"
    }
  }

  backend "s3" {
    key = "migration-accelerator-graviton/terraform.tfstate"
    # bucket and region will be provided via -backend-config during terraform init
  }
}

provider "aws" {
  region = var.aws_region
}

# Random string for unique resource naming
resource "random_string" "random" {
  length  = 6
  special = false
  upper   = false
}

# Data sources
data "aws_caller_identity" "current" {}

data "aws_availability_zones" "available" {
  state = "available"
}

# Archive migration-accelerator-graviton tool
data "archive_file" "zip_validation_tool" {
  type        = "zip"
  source_dir  = "${path.module}/../"
  output_path = "${path.module}/packaged/migration-accelerator-graviton.zip"

  excludes = [
    "terraform/",
    "terraform/*",
    "terraform_code_build/",
    "terraform_code_build/*",
    "output_files/",
    "output_files/*",
    "*.pyc",
    "__pycache__/",
    "*/__pycache__/*",
    ".git/",
    ".git/*",
    "*.log",
    ".terraform/",
    ".terraform/*",
    "terraform.tfstate*",
    "*.tfplan",
    "tfplan",
    "tests/",
    "tests/*",
    "design-docs/",
    "design-docs/*",
    "docs/",
    "docs/*",
    "examples/",
    "examples/*",
    ".DS_Store",
    "*/.DS_Store",
    "**/.DS_Store",
    "._*",
    ".AppleDouble",
    ".LSOverride",
    "Thumbs.db"
  ]
}
