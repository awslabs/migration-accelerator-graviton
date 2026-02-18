# IAM Roles for AWS Batch

# 1. Batch Service Role
resource "aws_iam_role" "batch_service" {
  name = "graviton-validator-batch-service-${random_string.random.result}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "batch.amazonaws.com"
      }
    }]
  })

  tags = {
    Name = "graviton-validator-batch-service-role"
  }
}

resource "aws_iam_role_policy_attachment" "batch_service" {
  role       = aws_iam_role.batch_service.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSBatchServiceRole"
}

# 2. Batch Job Role (for container)
resource "aws_iam_role" "batch_job" {
  name = "graviton-validator-batch-job-${random_string.random.result}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "ecs-tasks.amazonaws.com"
      }
    }]
  })

  tags = {
    Name = "graviton-validator-batch-job-role"
  }
}

resource "aws_iam_role_policy" "batch_job" {
  name = "graviton-validator-batch-job-policy"
  role = aws_iam_role.batch_job.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.main.arn,
          "${aws_s3_bucket.main.arn}/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:Encrypt",
          "kms:GenerateDataKey"
        ]
        Resource = aws_kms_key.s3.arn
      },
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:*:*:*"
      }
    ]
  })
}

# 3. Batch EC2 Instance Role
resource "aws_iam_role" "batch_ec2" {
  name = "graviton-validator-batch-ec2-${random_string.random.result}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "ec2.amazonaws.com"
      }
    }]
  })

  tags = {
    Name = "graviton-validator-batch-ec2-role"
  }
}

resource "aws_iam_role_policy_attachment" "batch_ec2" {
  role       = aws_iam_role.batch_ec2.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonEC2ContainerServiceforEC2Role"
}

resource "aws_iam_role_policy_attachment" "batch_ec2_ssm" {
  role       = aws_iam_role.batch_ec2.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

# S3 access for EC2 instance (needed because privileged containers can't access task role)
resource "aws_iam_role_policy" "batch_ec2_s3" {
  name = "graviton-validator-batch-ec2-s3-policy"
  role = aws_iam_role.batch_ec2.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.main.arn,
          "${aws_s3_bucket.main.arn}/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource = [
          aws_kms_key.s3.arn
        ]
      }
    ]
  })
}

resource "aws_iam_instance_profile" "batch_ec2" {
  name = "graviton-validator-batch-ec2-profile-${random_string.random.result}"
  role = aws_iam_role.batch_ec2.name
}


# IAM Role for Lambda Function

resource "aws_iam_role" "lambda" {
  name = "graviton-validator-lambda-${random_string.random.result}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
    }]
  })

  tags = {
    Name = "graviton-validator-lambda-role"
  }
}

resource "aws_iam_role_policy" "lambda" {
  name = "graviton-validator-lambda-policy"
  role = aws_iam_role.lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/*"
      },
      {
        Effect = "Allow"
        Action = [
          "batch:SubmitJob"
        ]
        Resource = [
          aws_batch_job_queue.main.arn,
          "arn:aws:batch:${var.aws_region}:${data.aws_caller_identity.current.account_id}:job-definition/${aws_batch_job_definition.main.name}",
          aws_batch_job_definition.main.arn
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "batch:ListJobs",
          "batch:DescribeJobs"
        ]
        # These actions do not support resource-level permissions per AWS documentation
        # See: https://docs.aws.amazon.com/IAM/latest/UserGuide/list_awsbatch.html
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "sqs:SendMessage"
        ]
        Resource = aws_sqs_queue.lambda_dlq.arn
      },
      {
        Effect = "Allow"
        Action = [
          "xray:PutTraceSegments",
          "xray:PutTelemetryRecords"
        ]
        # X-Ray requires wildcard - this is an AWS service limitation
        # See checkov exemption CKV_AWS_290 and CKV_AWS_355
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource = aws_kms_key.s3.arn
      },
      {
        Effect = "Allow"
        Action = [
          "ec2:CreateNetworkInterface",
          "ec2:DescribeNetworkInterfaces",
          "ec2:DeleteNetworkInterface",
          "ec2:AssignPrivateIpAddresses",
          "ec2:UnassignPrivateIpAddresses"
        ]
        # Lambda VPC integration requires wildcard for ENI operations
        # See checkov exemption CKV_AWS_290 and CKV_AWS_355
        Resource = "*"
      }
    ]
  })
}
