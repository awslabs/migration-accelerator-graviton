#!/bin/bash
# Graviton Fleet Discovery Management Script
set -e

# Config
STACK_NAME="graviton-fleet-discovery"
TEMPLATE_FILE="graviton-fleet-discovery.yaml"
LOG_LEVEL="INFO"

# Colors & Logging
R='\033[0;31m' G='\033[0;32m' Y='\033[1;33m' B='\033[0;34m' N='\033[0m'
log() { local level=$(echo "$1" | tr '[:lower:]' '[:upper:]'); echo -e "${2:-$G}[$level]$N $3" >&2; }
err() { log error "$R" "$1"; return 1; }
warn() { log warn "$Y" "$1"; }
info() { log info "$G" "$1"; }

# AWS Utilities
region() { aws configure get region 2>/dev/null || echo "us-east-1"; }
exists() { aws cloudformation describe-stacks --stack-name "$1" >/dev/null 2>&1; }
output() { aws cloudformation describe-stacks --stack-name "$1" --query "Stacks[0].Outputs[?OutputKey=='$2'].OutputValue" --output text 2>/dev/null; }

# Parse instance IDs from input (file or inline)
parse_instance_ids() {
    local input="$1" ids=""
    
    # Check if input is a file
    if [[ -f "$input" ]]; then
        ids=$(tr '\n' ' ' < "$input" | tr -s ' ' | sed 's/^ *//;s/ *$//')
    else
        ids="$input"
    fi
    
    echo "$ids"
}

# Usage
usage() {
cat << EOF
Graviton Fleet Discovery Management

Usage: $(basename "$0") COMMAND [OPTIONS]

COMMANDS:
  deploy     Deploy infrastructure
  update     Update existing infrastructure
  execute    Execute discovery on targets  
  download   Download results
  delete     Delete infrastructure
  status     Show stack status
  discover   Complete automated workflow

OPTIONS:
  --all              Target all instances
  --instance-id IDS  Target specific instances (space/newline separated or file path)
  --tag KEY=VALUE    Target by tag
  --region REGION    AWS region
  --dry-run          Show commands only
  --help             Show help

Examples:
  $(basename "$0") discover --all --region us-west-2
  $(basename "$0") execute --tag Environment=Production
  $(basename "$0") execute --instance-id "i-123 i-456 i-789"
  $(basename "$0") execute --instance-id instances.txt
EOF
}

# Prompt for missing parameters
prompt() {
    # Prompt for region if needed for commands that require it
    if [[ "$1" =~ ^(deploy|update|delete|status|discover)$ && -z "$REGION" ]]; then
        local r=$(region)
        info "Current region: $r"
        read -p "Region (Enter for $r): " REGION
        REGION=${REGION:-$r}
    fi
    
    # Prompt for target type if needed for execute/discover commands
    if [[ "$1" =~ ^(execute|discover)$ && -z "$TARGET_TYPE" ]]; then
        info "Target: 1)All 2)Instance IDs 3)Tags"
        read -p "Choice (1-3): " c
        case $c in
            1) TARGET_TYPE="all" TARGET_VALUE="all" ;;
            2) read -p "Instance IDs: " TARGET_VALUE; TARGET_TYPE="instance-id" ;;
            3) read -p "Tag (Key=Value): " TARGET_VALUE; TARGET_TYPE="tag" ;;
            *) err "Invalid choice" ;;
        esac
    fi
}

# Upload script to S3
upload() {
    local bucket="$1" region="$2" file="app_identifier.sh"
    [[ ! -f "$file" ]] && err "Script not found: $file"
    
    info "Uploading $file to $bucket"
    aws s3 cp "$file" "s3://$bucket/scripts/$file" --region "$region" >/dev/null || err "Upload failed"
}

# Wait for stack with progress
wait_stack() {
    local name="$1" op="$2" region="$3"
    info "Waiting for stack $op..."
    
    aws cloudformation wait "stack-$op-complete" --stack-name "$name" --region "$region" &
    local pid=$!
    
    local dots=0 prev=""
    while kill -0 $pid 2>/dev/null; do
        local status=$(aws cloudformation describe-stacks --stack-name "$name" --region "$region" \
            --query 'Stacks[0].StackStatus' --output text 2>/dev/null || echo "UNKNOWN")
        
        [[ "$status" != "$prev" ]] && {
            [[ -n "$prev" ]] && printf "\n"
            printf "${B}[INFO]$N Stack: $status"
            prev="$status"; dots=0
        } || {
            printf "."; ((dots++))
            [[ $dots -ge 10 ]] && { printf "\n${B}[INFO]$N Stack: $status"; dots=0; }
        }
        sleep 3
    done
    
    wait $pid && { printf "\n"; info "Stack $op completed!"; } || err "Stack $op failed!"
}

# Stack operations (deploy/update)
stack_op() {
    local op="$1" name="$2" template="$3" dry="$4" region="$5"
    [[ ! -f "$template" ]] && err "Template not found: $template"
    
    if [[ "$op" == "create" ]]; then
        exists "$name" && err "Stack exists. Use update."
    else
        ! exists "$name" && err "Stack missing. Use deploy."
    fi
    
    local cmd="aws cloudformation $op-stack --stack-name $name --template-body file://$template --capabilities CAPABILITY_NAMED_IAM --region $region"
    
    [[ "$dry" == "true" ]] && { warn "DRY RUN: $cmd"; return; }
    
    local action="deploy"
    [[ "$op" == "update" ]] && action="updat"
    info "${action}ing stack: $name"
    eval "$cmd" || err "Stack $op failed"
    
    wait_stack "$name" "$op" "$region"
    
    local bucket=$(output "$name" "S3BucketName")
    [[ -n "$bucket" ]] && upload "$bucket" "$region" >/dev/null
}

# Execute SSM command
execute() {
    local name="$1" type="$2" value="$3" level="$4" dry="$5"
    ! exists "$name" && err "Stack missing. Deploy first."
    
    local doc=$(output "$name" "SSMDocumentName")
    [[ -z "$doc" ]] && err "SSM document not found"
    
    local cmd="aws ssm send-command --document-name \"$doc\""
    
    case "$type" in
        "instance-id") 
            local ids=""
            for id in $value; do ids="$ids \"$id\""; done
            cmd="$cmd --instance-ids$ids" ;;
        "tag")
            local targets=""
            IFS=',' read -ra pairs <<< "$value"
            for pair in "${pairs[@]}"; do
                IFS='=' read -ra parts <<< "$pair"
                [[ ${#parts[@]} -eq 2 ]] || err "Invalid tag: $pair"
                targets="$targets \"Key=tag:${parts[0]},Values=${parts[1]}\""
            done
            cmd="$cmd --targets$targets" ;;
        "all") cmd="$cmd --targets \"Key=tag:aws:ssm:managed-instance,Values=true\"" ;;
        *) err "Invalid target: $type" ;;
    esac
    
    [[ "$level" != "INFO" ]] && cmd="$cmd --parameters logLevel=$level"
    
    info "Target: $type=$value"
    [[ "$dry" == "true" ]] && { warn "DRY RUN: $cmd"; return; }
    
    info "Executing SSM command..."
    local id=$(eval "$cmd" --query 'Command.CommandId' --output text)
    [[ $? -eq 0 && -n "$id" ]] && { info "Command ID: $id"; echo "$id"; } || err "SSM execution failed"
}

# Wait for SSM completion
wait_ssm() {
    local id="$1" timeout="${2:-30}"
    info "Waiting for SSM completion (${timeout}m timeout)..."
    
    local start=$(date +%s) limit=$((timeout * 60))
    
    while true; do
        local status=$(aws ssm list-commands --command-id "$id" --query 'Commands[0].Status' --output text 2>/dev/null || echo "Unknown")
        local targets=$(aws ssm list-commands --command-id "$id" --query 'Commands[0].TargetCount' --output text 2>/dev/null || echo "0")
        local done=$(aws ssm list-commands --command-id "$id" --query 'Commands[0].CompletedCount' --output text 2>/dev/null || echo "0")
        local errors=$(aws ssm list-commands --command-id "$id" --query 'Commands[0].ErrorCount' --output text 2>/dev/null || echo "0")
        
        info "Status: $status | Targets: $targets | Done: $done | Errors: $errors"
        
        case "$status" in
            "Success") info "SSM completed successfully!"; return 0 ;;
            "Failed"|"Cancelled") err "SSM $status!" ;;
        esac
        
        [[ $(( $(date +%s) - start )) -ge $limit ]] && err "SSM timeout after ${timeout}m"
        sleep 10
    done
}

# Download results
download() {
    local name="$1"
    ! exists "$name" && err "Stack missing"
    
    local bucket=$(output "$name" "S3BucketName")
    [[ -z "$bucket" ]] && err "Bucket not found"
    
    local dir="graviton-discovery-$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$dir"
    
    info "Downloading from $bucket to $dir"
    
    # List all SBOM files and download them to the same directory (flatten structure)
    local files=$(aws s3 ls "s3://$bucket/graviton-discovery/" --recursive | grep -E "\.sbom\.json$|sbom_container_.*\.json$" | awk '{print $4}')
    
    if [[ -z "$files" ]]; then
        warn "No SBOM files found in S3 bucket"
        return
    fi
    
    local count=0
    while IFS= read -r file; do
        [[ -n "$file" ]] && {
            local filename=$(basename "$file")
            aws s3 cp "s3://$bucket/$file" "$dir/$filename" || warn "Failed to download $file"
            ((count++))
        }
    done <<< "$files"
    
    info "Downloaded $count SBOM files to: $dir"
}

# Delete stack with cleanup
delete() {
    local name="$1" dry="$2" region="$3"
    ! exists "$name" && err "Stack missing"
    
    local bucket=$(output "$name" "S3BucketName")
    
    [[ "$dry" == "true" ]] && { warn "DRY RUN: Would delete $name and empty $bucket"; return; }
    
    warn "Will delete stack and empty bucket: $bucket"
    read -p "Continue? (y/N): " -n 1 -r; echo
    [[ ! $REPLY =~ ^[Yy]$ ]] && { info "Cancelled"; return; }
    
    # Empty bucket
    if [[ -n "$bucket" ]] && aws s3api head-bucket --bucket "$bucket" --region "$region" >/dev/null 2>&1; then
        local count=$(aws s3api list-objects-v2 --bucket "$bucket" --region "$region" --query 'KeyCount' --output text 2>/dev/null || echo "0")
        [[ "$count" != "0" ]] && {
            info "Emptying bucket ($count objects)..."
            aws s3 rm "s3://$bucket" --recursive --region "$region" || warn "Bucket cleanup failed"
        }
    fi
    
    info "Deleting stack: $name"
    aws cloudformation delete-stack --stack-name "$name" --region "$region" || err "Delete failed"
    wait_stack "$name" "delete" "$region"
}

# Show status
status() {
    local name="$1" region="$2"
    aws cloudformation describe-stacks --stack-name "$name" --region "$region" >/dev/null 2>&1 || err "Stack missing in $region"
    
    info "Stack Status:"
    aws cloudformation describe-stacks --stack-name "$name" --region "$region" \
        --query 'Stacks[0].[StackName,StackStatus,CreationTime]' --output table
    
    info "Outputs:"
    aws cloudformation describe-stacks --stack-name "$name" --region "$region" \
        --query 'Stacks[0].Outputs[*].[OutputKey,OutputValue]' --output table
}

# Complete discovery workflow
discover() {
    local name="$1" template="$2" type="$3" value="$4" level="$5" dry="$6" region="$7"
    
    info "Automated Graviton Fleet Discovery Workflow"
    info "This will:"
    info "  1. Deploy AWS infrastructure (CloudFormation + S3)"
    info "  2. Execute discovery on target instances"
    info "  3. Download SBOM files locally"
    info "  4. Clean up AWS resources"
    echo
    
    [[ "$dry" != "true" ]] && {
        read -p "Continue? (y/N): " -n 1 -r; echo
        [[ ! $REPLY =~ ^[Yy]$ ]] && { info "Cancelled"; return; }
    }
    
    # Deploy
    info "Step 1/4: Deploying infrastructure..."
    stack_op "create" "$name" "$template" "$dry" "$region" || err "Deploy failed"
    
    [[ "$dry" == "true" ]] && { info "DRY RUN: Would continue workflow"; return; }
    
    # Execute
    info "Step 2/4: Executing discovery..."
    local cmd_id=$(execute "$name" "$type" "$value" "$level" "$dry")
    [[ $? -ne 0 || -z "$cmd_id" ]] && err "Execute failed"
    
    wait_ssm "$cmd_id" 30 || err "SSM failed"
    
    # Download
    info "Step 3/4: Downloading results..."
    download "$name" || warn "Download failed - retrieve manually"
    
    # Cleanup
    info "Step 4/4: Cleaning up..."
    local bucket=$(output "$name" "S3BucketName")
    
    # Auto cleanup without prompts
    [[ -n "$bucket" ]] && aws s3api head-bucket --bucket "$bucket" --region "$region" >/dev/null 2>&1 && {
        local count=$(aws s3api list-objects-v2 --bucket "$bucket" --region "$region" --query 'KeyCount' --output text 2>/dev/null || echo "0")
        [[ "$count" != "0" ]] && {
            info "Emptying bucket ($count objects)..."
            aws s3 rm "s3://$bucket" --recursive --region "$region" >/dev/null || warn "Cleanup failed"
        }
    }
    
    info "Deleting stack..."
    aws cloudformation delete-stack --stack-name "$name" --region "$region" >/dev/null || warn "Delete failed"
    wait_stack "$name" "delete" "$region" || warn "Delete incomplete"
    
    info "Workflow completed!"
}

# Parse arguments
CMD="" TARGET_TYPE="" TARGET_VALUE="" DRY="false" REGION=""

[[ $# -eq 0 ]] && { usage; exit 1; }

# Handle help options first
if [[ "$1" == "--help" || "$1" == "-h" ]]; then
    usage
    exit 0
fi

CMD="$1"; shift

while [[ $# -gt 0 ]]; do
    case $1 in
        --all) TARGET_TYPE="all" TARGET_VALUE="all"; shift ;;
        --instance-id) 
            TARGET_TYPE="instance-id"
            shift
            # Collect all instance IDs until next option or end
            ids=""
            while [[ $# -gt 0 && "$1" != --* ]]; do
                ids="$ids $1"
                shift
            done
            TARGET_VALUE=$(parse_instance_ids "$ids")
            ;;
        --tag) TARGET_TYPE="tag" TARGET_VALUE="$2"; shift 2 ;;
        --region) REGION="$2"; shift 2 ;;
        --dry-run) DRY="true"; shift ;;
        --help) usage; exit 0 ;;
        *) log error "$R" "Unknown option: $1"; usage; exit 1 ;;
    esac
done

# Check AWS CLI
command -v aws >/dev/null || err "AWS CLI not found"

# Main
info "Graviton Fleet Discovery Manager"
prompt "$CMD"

case "$CMD" in
    deploy) stack_op "create" "$STACK_NAME" "$TEMPLATE_FILE" "$DRY" "$REGION" ;;
    update) stack_op "update" "$STACK_NAME" "$TEMPLATE_FILE" "$DRY" "$REGION" ;;
    execute) execute "$STACK_NAME" "$TARGET_TYPE" "$TARGET_VALUE" "$LOG_LEVEL" "$DRY" ;;
    download) download "$STACK_NAME" ;;
    delete) delete "$STACK_NAME" "$DRY" "$REGION" ;;
    status) status "$STACK_NAME" "$REGION" ;;
    discover) discover "$STACK_NAME" "$TEMPLATE_FILE" "$TARGET_TYPE" "$TARGET_VALUE" "$LOG_LEVEL" "$DRY" "$REGION" ;;
    *) log error "$R" "Unknown command: $CMD"; usage; exit 1 ;;
esac