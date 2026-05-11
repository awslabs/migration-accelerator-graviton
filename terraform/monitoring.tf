# CloudWatch Dashboard for monitoring

resource "aws_cloudwatch_dashboard" "main" {
  count          = var.enable_cloudwatch_dashboard ? 1 : 0
  dashboard_name = "Graviton-Validator-${random_string.random.result}"

  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "metric"
        x      = 0
        y      = 0
        width  = 12
        height = 6
        properties = {
          metrics = [
            ["AWS/Lambda", "Invocations", "FunctionName", aws_lambda_function.batch_trigger.function_name, { label = "Jobs Triggered" }],
            [".", "Errors", ".", ".", { label = "Trigger Errors" }]
          ]
          period = 300
          stat   = "Sum"
          region = var.aws_region
          title  = "Job Submissions (via Lambda)"
          yAxis = {
            left = {
              min = 0
            }
          }
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 0
        width  = 12
        height = 6
        properties = {
          metrics = [
            ["AWS/Lambda", "Duration", "FunctionName", aws_lambda_function.batch_trigger.function_name, { stat = "Average", label = "Avg Duration (ms)" }],
            [".", "ConcurrentExecutions", ".", ".", { stat = "Maximum", label = "Concurrent Executions" }]
          ]
          period = 300
          stat   = "Average"
          region = var.aws_region
          title  = "Lambda Performance"
        }
      },
      {
        type   = "log"
        x      = 0
        y      = 6
        width  = 24
        height = 8
        properties = {
          query  = "SOURCE '${aws_cloudwatch_log_group.batch.name}' | fields @timestamp, @message | sort @timestamp desc | limit 50"
          region = var.aws_region
          title  = "Latest Job Logs (Last 50 entries)"
        }
      }
    ]
  })
}

# Optional: CloudWatch Alarm for Batch job failures
resource "aws_cloudwatch_metric_alarm" "batch_failures" {
  count               = var.enable_cloudwatch_dashboard ? 1 : 0
  alarm_name          = "graviton-validator-batch-failures-${random_string.random.result}"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "JobsFailed"
  namespace           = "AWS/Batch"
  period              = 300
  statistic           = "Sum"
  threshold           = 3
  alarm_description   = "Alert when more than 3 Batch jobs fail"
  treat_missing_data  = "notBreaching"

  dimensions = {
    JobQueue = aws_batch_job_queue.main.name
  }

  tags = {
    Name = "graviton-validator-batch-failures-alarm"
  }
}
