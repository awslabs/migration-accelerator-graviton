# Security group for AWS Batch EC2 instances
resource "aws_security_group" "batch_ec2" {
  name_prefix = "graviton-validator-batch-ec2-"
  description = "Security group for Graviton Validator Batch EC2 instances"
  vpc_id      = local.vpc_id

  # Outbound: HTTPS for package registries and AWS APIs
  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTPS for package registries and AWS APIs"
  }

  # Outbound: HTTP for package registries (fallback)
  egress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTP for package registries"
  }

  # Outbound: Ephemeral ports for return traffic
  egress {
    from_port   = 1024
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Ephemeral ports for return traffic"
  }

  # No inbound rules - EC2 instances don't need inbound access

  tags = {
    Name = "graviton-validator-batch-ec2-sg"
  }

  lifecycle {
    create_before_destroy = true
  }
}
