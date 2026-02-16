# Migration Accelerator for Graviton - AWS Batch Deployment

Event-driven AWS Batch architecture for analyzing SBOM files for AWS Graviton (ARM64) compatibility.

## Architecture

```
S3 Upload → EventBridge → Lambda → AWS Batch → EC2 (Graviton3) → S3 Results
```

**Key Features**:
- ✅ Auto-scaling (0 to 5 EC2 instances)
- ✅ Job queuing and retry logic (built-in)
- ✅ Spot instance support (for up-to 90% savings)
- ✅ Idempotent job protection
- ✅ Container mode enabled (privileged for Docker-in-Docker)
- ✅ CloudWatch monitoring
- ✅ Private subnet deployment with NAT Gateway
- ✅ IMDSv2 credential retrieval for privileged containers

## Prerequisites

- Terraform >= 1.0
- AWS CLI configured
- AWS account with appropriate permissions

**IMPORTANT**: Job resource allocation must leave overhead for ECS agent:
- m7g.xlarge (4 vCPU, 16GB) → Job can use max 3 vCPU, 15GB
- m7g.large (2 vCPU, 8GB) → Job can use max 1 vCPU, 7GB
- Configured in `terraform.tfvars`: `batch_job_vcpus` and `batch_job_memory`

## Quick Start

### Option 1: Automated Deployment (Recommended)

```bash
# Deploy with auto-managed state bucket
../deploy.sh

# Or use existing state bucket
../deploy.sh deploy --state-bucket my-existing-bucket
```

The deploy script automatically:
- Creates/manages Terraform state bucket
- Deploys infrastructure
- Enables S3 EventBridge notifications
- Verifies deployment

### Option 2: Manual Terraform Deployment

**IMPORTANT**: You must provide a state bucket for remote state storage.

```bash
# 1. Create state bucket (one-time setup)
aws s3 mb s3://my-terraform-state-bucket-$(date +%s)
aws s3api put-bucket-versioning --bucket my-terraform-state-bucket-$(date +%s) --versioning-configuration Status=Enabled

# 2. Configure variables
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars with your settings

# 3. Initialize with state bucket
terraform init \
  -backend-config="bucket=my-terraform-state-bucket-$(date +%s)" \
  -backend-config="region=us-east-1"

# 4. Deploy
terraform plan -out=tfplan
terraform apply tfplan

# 5. Enable S3 EventBridge (REQUIRED)
BUCKET=$(terraform output -raw s3_bucket_name)
aws s3api put-bucket-notification-configuration \
  --bucket $BUCKET \
  --notification-configuration '{"EventBridgeConfiguration": {}}'
```

## Usage

### Individual Mode (One SBOM)

```bash
BUCKET=$(terraform output -raw s3_bucket_name)
aws s3 cp my-app.sbom.json s3://$BUCKET/input/individual/
```

**What happens**:
1. EventBridge detects upload
2. Lambda submits Batch job
3. Batch launches EC2 instance
4. Analysis runs with container testing (--yes for non-interactive mode)
5. Results uploaded to `output/individual/my-app/`
6. EC2 terminates automatically

### Batch Mode (Multiple SBOMs)

```bash
BUCKET=$(terraform output -raw s3_bucket_name)

# Upload SBOMs (no trigger)
aws s3 cp app1.sbom.json s3://$BUCKET/input/batch/my-project/
aws s3 cp app2.sbom.json s3://$BUCKET/input/batch/my-project/
aws s3 cp app3.sbom.json s3://$BUCKET/input/batch/my-project/

# Create manifest (FILENAMES ONLY - no paths)
cat > batch-manifest.txt <<EOF
# My Project Analysis
# Date: $(date)
app1.sbom.json
app2.sbom.json
app3.sbom.json
EOF

# Upload manifest (triggers ONE job)
aws s3 cp batch-manifest.txt s3://$BUCKET/input/batch/my-project/
```

**CRITICAL**: Manifest must contain only filenames, NOT full paths:
- ✅ Correct: `app1.sbom.json`
- ❌ Wrong: `input/batch/my-project/app1.sbom.json`

**What happens**:
1. EventBridge detects `batch-manifest.txt`
2. Lambda submits ONE Batch job for project
3. Batch launches EC2 instance (private subnet)
4. Downloads all SBOMs listed in manifest
5. Generates single consolidated report
6. Results uploaded to `output/batch/my-project/`
7. EC2 terminates automatically

## Monitoring

### Check Job Status

```bash
QUEUE=$(terraform output -raw batch_job_queue_name)
aws batch list-jobs --job-queue $QUEUE --job-status RUNNING
```

### View Logs

```bash
aws logs tail /aws/batch/graviton-validator --follow
```

### Check Results

```bash
BUCKET=$(terraform output -raw s3_bucket_name)
aws s3 ls s3://$BUCKET/output/individual/
aws s3 ls s3://$BUCKET/output/batch/
```

### CloudWatch Dashboard

```bash
echo $(terraform output -raw dashboard_url)
```

## Configuration Options

### Network Architecture

**Default: Private Subnets with NAT Gateway** (recommended for AWS Batch):
```hcl
# Batch compute environment uses private subnets
# Provides better security and network isolation
# NAT Gateway enables outbound internet access
```

### VPC Options

**Create New VPC** (default):
```hcl
create_vpc = true
```

**Use Existing VPC**:
```hcl
create_vpc                  = false
existing_vpc_id             = "vpc-xxxxx"
existing_private_subnet_ids = ["subnet-xxxxx", "subnet-yyyyy"]  # Must have NAT Gateway
existing_public_subnet_ids  = ["subnet-aaaaa", "subnet-bbbbb"]  # For NAT Gateway
```

### Resource Allocation

**CRITICAL**: Leave overhead for ECS agent (1 vCPU, 1GB RAM):
```hcl
# For m7g.xlarge (4 vCPU, 16GB)
batch_job_vcpus  = 3      # Leave 1 vCPU for ECS agent
batch_job_memory = 15360  # Leave 1GB for ECS agent (15GB)

# For m7g.large (2 vCPU, 8GB)
batch_job_vcpus  = 1      # Leave 1 vCPU for ECS agent
batch_job_memory = 7168   # Leave 1GB for ECS agent (7GB)
```

### Cost Optimization

**Enable Spot Instances** (up to 90% savings, optional):
```hcl
batch_use_spot = true  # Default: false
```

When enabled, uses at-least 5 Graviton instance types for better availability:
- `m7g.xlarge` - 4 vCPU, 16GB (Graviton3)
- `m7g.large` - 2 vCPU, 8GB (Graviton3)
- `m6g.xlarge` - 4 vCPU, 16GB (Graviton2)
- `m6g.large` - 2 vCPU, 8GB (Graviton2)
- `c7g.xlarge` - 4 vCPU, 8GB (Graviton3 compute-optimized)

**Customize Spot Instance Types** (optional):
```hcl
batch_spot_instance_types = ["m7g.xlarge", "m7g.large", "m6g.xlarge", "m6g.large", "c7g.xlarge"]
```

**Adjust Instance Size**:
```hcl
batch_instance_type = "m7g.large"   # Smaller (2 vCPU, 8GB)
batch_instance_type = "m7g.xlarge"  # Default (4 vCPU, 16GB)
batch_instance_type = "m7g.2xlarge" # Larger (8 vCPU, 32GB)
```

**Limit Concurrency**:
```hcl
batch_max_vcpus = 20  # Max 5 instances (20 / 4 vCPUs)
batch_max_vcpus = 8   # Max 2 instances (8 / 4 vCPUs)
```

## Cost Estimation

### On-Demand Instances (m7g.xlarge) - Default
- Individual SBOM: ~$0.15 (15 min)
- Batch (10 SBOMs): ~$0.49 (~$0.05 per SBOM)
- Monthly fixed: ~$5-10 (S3, logs, NAT Gateway)

### Spot Instances (up to 90% savings) - Optional
Enable with `batch_use_spot = true`:
- Individual SBOM: ~$0.06
- Batch (10 SBOMs): ~$0.20 (~$0.02 per SBOM)
- Uses 5 Graviton instance types for better availability
- `SPOT_CAPACITY_OPTIMIZED` allocation strategy

**No idle costs** - Batch scales to zero when no jobs

## Troubleshooting

### Jobs Not Starting

**Check Lambda logs**:
```bash
aws logs tail /aws/lambda/graviton-validator-batch-trigger-* --follow
```

**Verify Batch queue**:
```bash
QUEUE=$(terraform output -raw batch_job_queue_name)
aws batch describe-job-queues --job-queues $QUEUE
```

### Jobs Failing

**Check Batch logs**:
```bash
aws logs tail /aws/batch/graviton-validator --follow
```

**Common issues**:
- **Resource misconfiguration**: Job requests 100% of instance resources (4 vCPU/16GB on m7g.xlarge)
  - Error: `MISCONFIGURATION:JOB_RESOURCE_REQUIREMENT`
  - Fix: Reduce to 3 vCPU/15GB in `terraform.tfvars`
- **S3 permissions**: Verify EC2 instance role has S3 and KMS permissions
- **Tool not found**: Check S3 tool upload to `code/graviton-software-validator.zip`
- **Docker issues**: Verify privileged mode enabled in job definition
- **Credential timeout**: Privileged containers use IMDSv2 for EC2 instance credentials
- **Batch manifest path error**: Ensure manifest contains only filenames, not full S3 paths

### EventBridge Not Triggering

**Verify S3 notifications enabled**:
```bash
BUCKET=$(terraform output -raw s3_bucket_name)
aws s3api get-bucket-notification-configuration --bucket $BUCKET
```

Should show: `{"EventBridgeConfiguration": {}}`

**Check EventBridge rules**:
```bash
aws events list-rules --name-prefix graviton-validator
```

### Duplicate Jobs (Batch Mode)

**Protection layers**:
1. EventBridge only triggers on `batch-manifest.txt`
2. Lambda checks if job already running
3. Same project = same job name

**Verify**:
```bash
# Check if job already exists
QUEUE=$(terraform output -raw batch_job_queue_name)
aws batch list-jobs --job-queue $QUEUE --filters name=JOB_NAME,values=batch-my-project
```

## Security

- ✅ VPC with security groups
- ✅ KMS encryption (S3, EBS)
- ✅ Least privilege IAM roles
- ✅ S3 public access blocked
- ✅ CloudWatch logging enabled
- ✅ Container isolation

## Cleanup

### Option 1: Using Deploy Script

```bash
# Destroy infrastructure but keep state bucket
../deploy.sh destroy

# Destroy infrastructure AND delete state bucket
../deploy.sh destroy --delete-state
```

### Option 2: Manual Cleanup

```bash
# Delete all S3 objects first
BUCKET=$(terraform output -raw s3_bucket_name)
aws s3 rm s3://$BUCKET --recursive

# Destroy infrastructure
terraform destroy

# Optionally delete state bucket (manual)
aws s3 rm s3://my-terraform-state-bucket --recursive
aws s3 rb s3://my-terraform-state-bucket
```

## Technical Notes

### Privileged Container Credentials
- Privileged containers cannot access ECS task role credentials (169.254.170.2)
- Solution: Use IMDSv2 to retrieve EC2 instance profile credentials
- EC2 instance role must have all necessary permissions (S3, KMS)

### Resource Overhead
- ECS agent requires ~1 vCPU and ~1GB RAM on each EC2 instance
- Job definitions must leave this headroom
- Misconfiguration prevents compute environment from scaling

### Subnet Architecture
- AWS Batch works best in private subnets with NAT Gateway
- Provides better security posture and network isolation
- NAT Gateway enables outbound access for package downloads

### Container Image
- Uses multi-arch Amazon Linux 2023: `amazonlinux:2023`
- AWS Batch automatically pulls ARM64 variant for Graviton instances
- No need for architecture-specific tags

### Batch Manifest Format
- Must contain only filenames relative to project directory
- Lambda script constructs full S3 path: `s3://bucket/input/batch/PROJECT/$filename`
- Including full paths causes duplication errors
terraform destroy
```

## Architecture Decisions

1. **AWS Batch**: Auto-scaling, queuing, retries (vs manual EC2)
2. **Public Image**: Simpler deployment (vs custom ECR image)
3. **Idempotent Jobs**: Prevents duplicate processing
4. **EventBridge Filters**: Only manifest triggers batch mode
5. **Spot Instances**: Optional up to 90% cost savings

---

**Ready to analyze SBOMs for Graviton compatibility!** 🚀
