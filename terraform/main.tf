terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.92"
    }
  }

  required_version = ">= 1.2"

  backend "s3" {
    bucket = "pfs-final2025-terraform-state"
  }
}

provider "aws" {
  region = "eu-central-1"
}
