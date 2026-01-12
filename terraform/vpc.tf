# VPC Configuration - Create new or use existing

# Option 1: Create new VPC using AWS VPC module
module "vpc" {
  count  = var.create_vpc ? 1 : 0
  source = "git::https://github.com/terraform-aws-modules/terraform-aws-vpc.git?ref=26c38a66f12e7c6c93b6a2ba127ad68981a48671"

  name = "graviton-validator-vpc-${random_string.random.result}"
  cidr = "10.0.0.0/16"

  azs             = ["${var.aws_region}a", "${var.aws_region}b"]
  public_subnets  = ["10.0.1.0/24", "10.0.2.0/24"]
  private_subnets = ["10.0.10.0/24", "10.0.11.0/24"]

  enable_nat_gateway   = true
  single_nat_gateway   = true
  enable_dns_hostnames = true
  enable_dns_support   = true
  map_public_ip_on_launch = true

  tags = {
    Name        = "graviton-validator-vpc"
    Environment = "production"
  }
}

# Option 2: Use existing VPC
data "aws_vpc" "existing" {
  count = var.create_vpc ? 0 : 1
  id    = var.existing_vpc_id
}

data "aws_subnets" "existing_public" {
  count = var.create_vpc ? 0 : 1

  filter {
    name   = "vpc-id"
    values = [var.existing_vpc_id]
  }

  filter {
    name   = "subnet-id"
    values = var.existing_public_subnet_ids
  }
}

# Locals for unified access
locals {
  vpc_id             = var.create_vpc ? module.vpc[0].vpc_id : var.existing_vpc_id
  public_subnet_ids  = var.create_vpc ? module.vpc[0].public_subnets : var.existing_public_subnet_ids
  private_subnet_ids = var.create_vpc ? module.vpc[0].private_subnets : var.existing_private_subnet_ids
}
