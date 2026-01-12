resource "aws_security_group" "batch_ec2" {
  name_prefix = "graviton-validator-batch-ec2-"
  description = "Security group for Graviton Validator Batch EC2 instances"
  vpc_id      = local.vpc_id

  # ✅ Outbound: HTTPS for AWS APIs (ECS, ECR, STS, Logs)
  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTPS for AWS APIs and registries"
  }

  # (Optional) HTTP fallback — can be removed if not needed
  egress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTP for package registries"
  }

  # Ephemeral ports for return traffic
  egress {
    from_port   = 1024
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Ephemeral ports for return traffic"
  }

  tags = {
    Name = "graviton-validator-batch-ec2-sg"
  }

  lifecycle {
    create_before_destroy = true
  }
}
