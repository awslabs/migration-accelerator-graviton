# AWS Batch Resources

# Compute Environment
resource "aws_batch_compute_environment" "main" {
  compute_environment_name = "graviton-validator-${random_string.random.result}"
  type                     = "MANAGED"
  state                    = "ENABLED"
  service_role             = aws_iam_role.batch_service.arn

  compute_resources {
    type                = var.batch_use_spot ? "SPOT" : "EC2"
    allocation_strategy = var.batch_use_spot ? "SPOT_CAPACITY_OPTIMIZED" : "BEST_FIT_PROGRESSIVE"
    bid_percentage      = var.batch_use_spot ? 100 : null

    # Multiple Graviton instance types for better Spot availability
    instance_type = var.batch_use_spot ? var.batch_spot_instance_types : [var.batch_instance_type]

    min_vcpus     = 0
    max_vcpus     = var.batch_max_vcpus
    desired_vcpus = 0
    subnets = local.public_subnet_ids
    security_group_ids = [aws_security_group.batch_ec2.id]

    instance_role = aws_iam_instance_profile.batch_ec2.arn

    tags = {
      Name = "graviton-validator-batch-instance"
    }
  }

  depends_on = [aws_iam_role_policy_attachment.batch_service]
}

# Job Queue
resource "aws_batch_job_queue" "main" {
  name     = "graviton-validator-queue-${random_string.random.result}"
  state    = "ENABLED"
  priority = 1

  compute_environment_order {
    order               = 1
    compute_environment = aws_batch_compute_environment.main.arn
  }

  tags = {
    Name = "graviton-validator-job-queue"
  }
}


# Job Definition
resource "aws_batch_job_definition" "main" {
  name = "graviton-validator-job-${random_string.random.result}"
  type = "container"

  platform_capabilities = ["EC2"]

  container_properties = jsonencode({
    image = "public.ecr.aws/amazonlinux/amazonlinux:2023"

    vcpus  = var.batch_job_vcpus
    memory = var.batch_job_memory

    jobRoleArn = aws_iam_role.batch_job.arn

    privileged = false

    # Use specific Linux capabilities instead of full privileged mode
    linuxParameters = {
      capabilities = {
        add = [
          "SYS_ADMIN",    # Required for system-level operations
          "SYS_PTRACE",   # Required for binary analysis
          "DAC_OVERRIDE"  # Required for file access during validation
        ]
      }
    }

    command = ["/bin/bash", "-c", "echo 'Job will be overridden by Lambda'"]

    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = "/aws/batch/graviton-validator"
        "awslogs-region"        = var.aws_region
        "awslogs-stream-prefix" = "job"
      }
    }
  })

  tags = {
    Name = "graviton-validator-job-definition"
  }
}

# CloudWatch Log Group for Batch jobs
resource "aws_cloudwatch_log_group" "batch" {
  name              = "/aws/batch/graviton-validator"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.s3.arn

  tags = {
    Name = "graviton-validator-batch-logs"
  }
}
