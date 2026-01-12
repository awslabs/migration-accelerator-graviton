# Lambda Function for triggering Batch jobs

# Package Lambda function
data "archive_file" "lambda" {
  type        = "zip"
  source_file = "${path.module}/lambda_batch_trigger.py"
  output_path = "${path.module}/lambda_batch_trigger.zip"
}

# Security Group for Lambda
resource "aws_security_group" "lambda" {
  name        = "graviton-validator-lambda-${random_string.random.result}"
  description = "Security group for Graviton Validator Lambda function"
  vpc_id      = local.vpc_id

  # Allow all outbound traffic (needed for AWS API calls via NAT Gateway)
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow all outbound traffic for AWS API calls"
  }

  tags = {
    Name = "graviton-validator-lambda-sg"
  }
}

# Lambda Function
# Dead Letter Queue for Lambda
resource "aws_sqs_queue" "lambda_dlq" {
  name                      = "graviton-validator-lambda-dlq-${random_string.random.result}"
  message_retention_seconds = 1209600 # 14 days

  # KMS encryption for SQS queue
  kms_master_key_id                 = aws_kms_key.s3.id
  kms_data_key_reuse_period_seconds = 300

  tags = {
    Name = "graviton-validator-lambda-dlq"
  }
}

# Lambda Code Signing Configuration
resource "aws_signer_signing_profile" "lambda" {
  platform_id = "AWSLambda-SHA384-ECDSA"
  name        = "gravitonvalidatorlambdasigning${random_string.random.result}"

  tags = {
    Name = "graviton-validator-lambda-signing"
  }
}

resource "aws_lambda_code_signing_config" "main" {
  allowed_publishers {
    signing_profile_version_arns = [
      aws_signer_signing_profile.lambda.arn
    ]
  }

  policies {
    untrusted_artifact_on_deployment = "Warn"
  }

  description = "Code signing config for Graviton Validator Lambda"
}

resource "aws_lambda_function" "batch_trigger" {
  filename         = data.archive_file.lambda.output_path
  function_name    = "graviton-validator-batch-trigger-${random_string.random.result}"
  role             = aws_iam_role.lambda.arn
  handler          = "lambda_batch_trigger.lambda_handler"
  runtime          = "python3.11"
  timeout          = 60
  source_code_hash = data.archive_file.lambda.output_base64sha256

  # Concurrent execution limit
  # reserved_concurrent_executions = 50

  # VPC Configuration - Use private subnets with NAT Gateway
  vpc_config {
    subnet_ids         = local.private_subnet_ids
    security_group_ids = [aws_security_group.lambda.id]
  }

  # X-Ray tracing
  tracing_config {
    mode = "Active"
  }

  # Dead Letter Queue
  dead_letter_config {
    target_arn = aws_sqs_queue.lambda_dlq.arn
  }

  # Code signing
  code_signing_config_arn = aws_lambda_code_signing_config.main.arn

  # KMS encryption for environment variables
  kms_key_arn = aws_kms_key.s3.arn

  environment {
    variables = {
      JOB_QUEUE      = aws_batch_job_queue.main.name
      JOB_DEFINITION = aws_batch_job_definition.main.name
      S3_BUCKET      = aws_s3_bucket.main.id
    }
  }

  tags = {
    Name = "graviton-validator-batch-trigger"
  }
}

# CloudWatch Log Group for Lambda
resource "aws_cloudwatch_log_group" "lambda" {
  name              = "/aws/lambda/${aws_lambda_function.batch_trigger.function_name}"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.s3.arn

  tags = {
    Name = "graviton-validator-lambda-logs"
  }
}
