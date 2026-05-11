import boto3
import json
import os
import re

batch = boto3.client('batch')

JOB_QUEUE = os.environ['JOB_QUEUE']
JOB_DEFINITION = os.environ['JOB_DEFINITION']
S3_BUCKET = os.environ['S3_BUCKET']

def sanitize_job_name(name):
    """Sanitize job name to match AWS Batch pattern [a-zA-Z0-9_-]+"""
    # Replace dots with hyphens
    name = name.replace('.', '-')
    # Remove any other invalid characters
    name = re.sub(r'[^a-zA-Z0-9_-]', '-', name)
    # Limit to 128 characters
    if len(name) > 128:
        name = name[:128]
    return name

def lambda_handler(event, context):
    """
    Lambda function to submit AWS Batch jobs for SBOM analysis
    """
    try:
        print(f"Received event: {json.dumps(event)}")
        
        s3_key = event['detail']['object']['key']
        
        # Determine mode based on S3 key pattern
        if s3_key.startswith('input/individual/') and s3_key.endswith('.json'):
            mode = 'individual'
            sbom_name = s3_key.split('/')[-1].replace('.json', '')
            job_name = sanitize_job_name(f"individual-{sbom_name}")
        elif s3_key.endswith('batch-manifest.txt'):
            mode = 'batch'
            project = s3_key.split('/')[-2]
            job_name = sanitize_job_name(f"batch-{project}")
        else:
            print(f"Ignoring upload to: {s3_key}")
            return {'statusCode': 200, 'body': 'Ignored'}
        
        print(f"Mode: {mode}, Job Name: {job_name}, S3 Key: {s3_key}")
        
        # Idempotent protection: Check if job already running
        try:
            response = batch.list_jobs(
                jobQueue=JOB_QUEUE,
                filters=[{'name': 'JOB_NAME', 'values': [job_name]}]
            )
            for job in response.get('jobSummaryList', []):
                if job['status'] in ['SUBMITTED', 'PENDING', 'RUNNABLE', 'STARTING', 'RUNNING']:
                    print(f"Job {job_name} already {job['status']}, skipping")
                    return {
                        'statusCode': 200,
                        'body': json.dumps({
                            'message': 'Job already running',
                            'existingJobId': job['jobId'],
                            'status': job['status']
                        })
                    }
        except Exception as e:
            print(f"Error checking existing jobs: {e}")
        
        # Build command based on mode
        if mode == 'individual':
            command_script = f'''
set -e  # Exit on error
yum update -y
yum install -y python3.11 python3.11-pip git jq aws-cli unzip
yum install -y java-17-amazon-corretto-devel maven nodejs npm ruby rubygems ruby-devel gcc make 2>/dev/null || true
gem install bundler 2>/dev/null || true
yum install -y dotnet-sdk-8.0 2>/dev/null || true

cd /opt
echo "=== Getting credentials from EC2 instance metadata ==="
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" 2>/dev/null)
ROLE=$(curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/ 2>/dev/null)
echo "Using IAM role: $ROLE"
CREDS=$(curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE 2>/dev/null)

export AWS_ACCESS_KEY_ID=$(echo $CREDS | jq -r '.AccessKeyId')
export AWS_SECRET_ACCESS_KEY=$(echo $CREDS | jq -r '.SecretAccessKey')
export AWS_SESSION_TOKEN=$(echo $CREDS | jq -r '.Token')
export AWS_DEFAULT_REGION=us-east-1

echo "=== Downloading tool from S3 ==="
aws s3 cp s3://{S3_BUCKET}/code/migration-accelerator-graviton.zip ./ || {{ echo "ERROR: Failed to download tool"; exit 1; }}
echo "=== Extracting tool ==="
unzip -q migration-accelerator-graviton.zip || {{ echo "ERROR: Failed to extract tool"; exit 1; }}
echo "=== Setting up Python virtual environment ==="
PYTHON_BIN=$(command -v python3.11 || command -v python3.12 || command -v python3)
VENV=/tmp/graviton-venv
$PYTHON_BIN -m venv $VENV
$VENV/bin/pip install -r requirements.txt || {{ echo "ERROR: Failed to install dependencies"; exit 1; }}

SBOM_NAME=$(basename "{s3_key}" .json)
echo "=== Downloading SBOM: $SBOM_NAME ==="
aws s3 cp "s3://{S3_BUCKET}/{s3_key}" ./sbom.json || {{ echo "ERROR: Failed to download SBOM"; exit 1; }}
echo "=== Running analysis ==="
$VENV/bin/python graviton_validator.py sbom.json --yes --test-local -f excel -o "$SBOM_NAME.xlsx" --output-dir ./results/ || {{ echo "ERROR: Analysis failed"; exit 1; }}
echo "=== Uploading results to S3 ==="
aws s3 sync ./results/ "s3://{S3_BUCKET}/output/individual/$SBOM_NAME/" || {{ echo "ERROR: Failed to upload results"; exit 1; }}
echo "=== Job completed successfully ==="
'''
        else:  # batch mode
            command_script = f'''
yum update -y
yum install -y python3.11 python3.11-pip git jq aws-cli unzip
yum install -y java-17-amazon-corretto-devel maven nodejs npm ruby rubygems ruby-devel gcc make 2>/dev/null || true
gem install bundler 2>/dev/null || true
yum install -y dotnet-sdk-8.0 2>/dev/null || true

cd /opt

# Get credentials from EC2 instance metadata (IMDSv2)
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" 2>/dev/null)
ROLE=$(curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/ 2>/dev/null)
CREDS=$(curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE 2>/dev/null)

export AWS_ACCESS_KEY_ID=$(echo $CREDS | jq -r '.AccessKeyId')
export AWS_SECRET_ACCESS_KEY=$(echo $CREDS | jq -r '.SecretAccessKey')
export AWS_SESSION_TOKEN=$(echo $CREDS | jq -r '.Token')
export AWS_DEFAULT_REGION=us-east-1

aws s3 cp s3://{S3_BUCKET}/code/migration-accelerator-graviton.zip ./
unzip -q migration-accelerator-graviton.zip
cd migration-accelerator-graviton
PYTHON_BIN=$(command -v python3.11 || command -v python3.12 || command -v python3)
VENV=/tmp/graviton-venv
$PYTHON_BIN -m venv $VENV
$VENV/bin/pip install -r requirements.txt

# Extract project directory from S3 key path
# Example: input/batch/project1/batch-manifest.txt -> project1
# Example: input/batch/batch-manifest.txt -> (empty, root level)
S3_KEY_PATH="{s3_key}"
PROJECT_DIR=$(echo "$S3_KEY_PATH" | sed 's|^input/batch/||' | sed 's|/batch-manifest.txt$||')

# If PROJECT_DIR is empty or equals the filename, we're at root level
if [ -z "$PROJECT_DIR" ] || [ "$PROJECT_DIR" = "batch-manifest.txt" ]; then
    PROJECT_NAME="batch"
    S3_INPUT_PREFIX="input/batch"
    S3_OUTPUT_PREFIX="output/batch"
else
    # Replace slashes with dashes for report name
    PROJECT_NAME=$(echo "$PROJECT_DIR" | tr '/' '-')
    S3_INPUT_PREFIX="input/batch/$PROJECT_DIR"
    S3_OUTPUT_PREFIX="output/batch/$PROJECT_DIR"
fi

echo "=== Configuration ==="
echo "S3 Key: $S3_KEY_PATH"
echo "Project Dir: $PROJECT_DIR"
echo "Project Name: $PROJECT_NAME"
echo "S3 Input Prefix: $S3_INPUT_PREFIX"
echo "S3 Output Prefix: $S3_OUTPUT_PREFIX"

aws s3 cp "s3://{S3_BUCKET}/$S3_KEY_PATH" ./batch-manifest.txt
mkdir -p ./sboms

echo "=== Downloading SBOM files from manifest ==="
grep '\\.json$' batch-manifest.txt | grep -v '^#' | while read sbom_file; do
  if [ -n "$sbom_file" ]; then
    echo "Downloading: $sbom_file"
    aws s3 cp "s3://{S3_BUCKET}/$S3_INPUT_PREFIX/$sbom_file" ./sboms/ || echo "WARNING: Failed to download $sbom_file"
  fi
done

echo "=== Running analysis ==="
$VENV/bin/python graviton_validator.py -d ./sboms --yes --test-local -f excel -o "$PROJECT_NAME-report.xlsx" --output-dir ./results/

echo "=== Uploading results to S3 ==="
aws s3 sync ./results/ "s3://{S3_BUCKET}/$S3_OUTPUT_PREFIX/"
'''
        
        # Submit Batch job
        response = batch.submit_job(
            jobName=job_name,
            jobQueue=JOB_QUEUE,
            jobDefinition=JOB_DEFINITION,
            containerOverrides={
                'command': ['/bin/bash', '-c', command_script]
            },
            retryStrategy={
                'attempts': 3
            }
        )
        
        print(f"Successfully submitted job: {response['jobId']}")
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'jobId': response['jobId'],
                'jobName': response['jobName'],
                'mode': mode,
                's3Key': s3_key
            })
        }
        
    except Exception as e:
        print(f"Error: {str(e)}")
        raise e
