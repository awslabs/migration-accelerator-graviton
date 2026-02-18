#!/bin/bash

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

print_status() { echo -e "${GREEN}[INFO]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
print_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Configuration
AWS_REGION="${AWS_REGION:-us-east-1}"
STATE_BUCKET_FILE="terraform/.terraform-state-bucket"

create_state_bucket() {
    local timestamp=$(date +"%d%m%y-%H%M%S")
    local bucket_name="migration-accelerator-graviton-tfstate-${timestamp}"
    
    print_status "Creating Terraform state bucket: $bucket_name in region: $AWS_REGION"
    
    if [ "$AWS_REGION" = "us-east-1" ]; then
        aws s3api create-bucket \
            --bucket "$bucket_name" \
            --region "$AWS_REGION"
    else
        aws s3api create-bucket \
            --bucket "$bucket_name" \
            --region "$AWS_REGION" \
            --create-bucket-configuration LocationConstraint="$AWS_REGION"
    fi
    
    # Enable versioning
    aws s3api put-bucket-versioning \
        --bucket "$bucket_name" \
        --versioning-configuration Status=Enabled
    
    # Enable server-side encryption
    aws s3api put-bucket-encryption \
        --bucket "$bucket_name" \
        --server-side-encryption-configuration '{
            "Rules": [{
                "ApplyServerSideEncryptionByDefault": {
                    "SSEAlgorithm": "AES256"
                }
            }]
        }'
    
    # Block public access
    aws s3api put-public-access-block \
        --bucket "$bucket_name" \
        --public-access-block-configuration \
            BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
    
    echo "$bucket_name" > "$STATE_BUCKET_FILE"
    echo "$bucket_name"
}

get_state_bucket() {
    local provided_bucket="$1"
    
    if [ -n "$provided_bucket" ]; then
        echo "$provided_bucket" > "$STATE_BUCKET_FILE"
        echo "$provided_bucket"
    elif [ -f "$STATE_BUCKET_FILE" ]; then
        cat "$STATE_BUCKET_FILE"
    else
        create_state_bucket
    fi
}

check_prerequisites() {
    print_status "Checking prerequisites..."
    
    command -v aws >/dev/null 2>&1 || { print_error "AWS CLI not installed"; exit 1; }
    command -v terraform >/dev/null 2>&1 || { print_error "Terraform not installed"; exit 1; }
    aws sts get-caller-identity >/dev/null 2>&1 || { print_error "AWS credentials not configured"; exit 1; }
    
    print_status "Prerequisites check passed!"
}

deploy_terraform() {
    local state_bucket="$1"
    
    print_status "Deploying Terraform infrastructure with state bucket: $state_bucket"
    
    cd terraform
    
    # Initialize with remote state
    terraform init -reconfigure \
        -backend-config="bucket=$state_bucket" \
        -backend-config="region=$AWS_REGION"
    
    terraform plan -out=tfplan
    terraform apply tfplan
    
    BUCKET_NAME=$(terraform output -raw s3_bucket_name)
    print_status "Infrastructure deployed! S3 Bucket: $BUCKET_NAME"
    cd ..
}

enable_eventbridge() {
    local bucket_name="$1"
    
    print_status "Enabling EventBridge notifications for S3 bucket: $bucket_name"
    
    aws s3api put-bucket-notification-configuration \
        --bucket "$bucket_name" \
        --notification-configuration '{"EventBridgeConfiguration": {}}'
    
    print_status "EventBridge notifications enabled!"
}

verify_deployment() {
    local bucket_name="$1"
    
    print_status "Verifying deployment..."
    
    # Check EventBridge configuration
    local eventbridge_config=$(aws s3api get-bucket-notification-configuration --bucket "$bucket_name" 2>/dev/null || echo "{}")
    if echo "$eventbridge_config" | grep -q "EventBridgeConfiguration"; then
        print_status "✓ EventBridge notifications configured"
    else
        print_warning "EventBridge notifications not configured"
    fi
    
    # Check Batch resources
    cd terraform
    local queue_name=$(terraform output -raw batch_job_queue_name 2>/dev/null || echo "")
    if [ -n "$queue_name" ]; then
        local queue_status=$(aws batch describe-job-queues --job-queues "$queue_name" --query 'jobQueues[0].state' --output text 2>/dev/null || echo "")
        if [ "$queue_status" = "ENABLED" ]; then
            print_status "✓ Batch job queue is enabled"
        else
            print_warning "Batch job queue status: $queue_status"
        fi
    fi
    cd ..
}

destroy_terraform() {
    local delete_state="$1"
    
    print_status "Destroying Terraform infrastructure..."
    
    cd terraform
    terraform destroy -auto-approve
    
    if [ "$delete_state" = "true" ] && [ -f "../$STATE_BUCKET_FILE" ]; then
        local state_bucket=$(cat "../$STATE_BUCKET_FILE")
        print_warning "Deleting state bucket: $state_bucket"
        
        # Empty bucket first
        aws s3 rm "s3://$state_bucket" --recursive 2>/dev/null || true
        
        # Delete all versions
        aws s3api list-object-versions --bucket "$state_bucket" --query 'Versions[].{Key:Key,VersionId:VersionId}' --output text 2>/dev/null | while read key version; do
            [ -n "$key" ] && aws s3api delete-object --bucket "$state_bucket" --key "$key" --version-id "$version" 2>/dev/null || true
        done
        
        # Delete bucket
        aws s3api delete-bucket --bucket "$state_bucket" 2>/dev/null || true
        rm -f "../$STATE_BUCKET_FILE"
        
        print_status "State bucket deleted"
    fi
    
    cd ..
}

show_usage() {
    cat << EOF
Migration Accelerator for Graviton - Deployment Script

Usage:
  $0 [deploy|destroy] [options]

Commands:
  deploy                Deploy infrastructure (default)
  destroy               Destroy infrastructure
  
Options:
  --state-bucket NAME   Use existing S3 bucket for Terraform state
  --delete-state        Delete state bucket when destroying (use with destroy)
  --region REGION       AWS region (default: us-east-1)
  --help               Show this help message

Examples:
  $0                                    # Deploy with auto-created state bucket
  $0 deploy --state-bucket my-bucket    # Deploy with existing state bucket
  $0 destroy                           # Destroy but keep state bucket
  $0 destroy --delete-state            # Destroy and delete state bucket

Environment Variables:
  AWS_REGION           AWS region (default: us-east-1)
EOF
}

main() {
    local command="deploy"
    local state_bucket=""
    local delete_state="false"
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            deploy|destroy)
                command="$1"
                shift
                ;;
            --state-bucket)
                state_bucket="$2"
                shift 2
                ;;
            --delete-state)
                delete_state="true"
                shift
                ;;
            --region)
                AWS_REGION="$2"
                shift 2
                ;;
            --help)
                show_usage
                exit 0
                ;;
            *)
                print_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done
    
    check_prerequisites
    
    case $command in
        deploy)
            local bucket=$(get_state_bucket "$state_bucket")
            deploy_terraform "$bucket"
            
            cd terraform
            local s3_bucket=$(terraform output -raw s3_bucket_name)
            cd ..
            
            enable_eventbridge "$s3_bucket"
            verify_deployment "$s3_bucket"
            
            print_status "🎉 Deployment completed successfully!"
            echo
            echo "Next steps:"
            echo "1. Upload SBOM files to: s3://$s3_bucket/input/individual/"
            echo "2. Monitor jobs: aws batch list-jobs --job-queue $(cd terraform && terraform output -raw batch_job_queue_name)"
            echo "3. View results: aws s3 ls s3://$s3_bucket/output/ --recursive"
            echo "4. Dashboard: $(cd terraform && terraform output -raw dashboard_url)"
            ;;
        destroy)
            destroy_terraform "$delete_state"
            print_status "🗑️  Infrastructure destroyed!"
            ;;
    esac
}

main "$@"
