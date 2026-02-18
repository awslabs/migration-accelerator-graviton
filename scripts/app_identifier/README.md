# Graviton Migration Fleet Discovery Solution

A comprehensive fleet-wide system discovery solution that automatically identifies running applications, installed packages, and system configuration across multiple VMs/Servers for AWS Graviton migration assessment. The collected data is then formatted into CycloneDX SBOM (Software Bill of Materials) files to support ARM compatibility analysis.

## Table of Contents

1. [About This Solution](#about-this-solution)
2. [Usage Instructions](#usage-instructions)
   - [A. Using AWS Systems Manager (SSM)](#a-using-aws-systems-manager-ssm)
   - [B. Using Ansible (Direct Execution)](#b-using-ansible-direct-execution)
   - [C. Using SSH Directly](#c-using-ssh-directly)
3. [Considerations](#considerations)
4. [Data Collection Information](#data-collection-information)
5. [Data Inspection and Sharing](#data-inspection-and-sharing)
6. [Component Documentation](#component-documentation)
7. [Troubleshooting](#troubleshooting)
8. [Support](#support)

## About This Solution

The Graviton Migration Fleet Discovery Solution consists of two main components:

1. **Application Identifier** (`app_identifier.sh`): Core discovery script that identifies running processes and installed packages on individual VMs/servers, generating SBOM files for Graviton compatibility analysis

2. **Fleet Automation Scripts**: Multiple automation options to run the app identifier across multiple VMs easily:
   - **SSM-based automation** (`graviton-discovery-manager.sh` + CloudFormation): Uses AWS Systems Manager for fleet-wide execution with centralized S3 storage
   - **Ansible playbook** (`graviton-discovery-ansible.yml`): Direct SSH-based execution across multiple hosts
   - **SSH scripts**: Manual execution examples for direct server access

### Key Features

- **Fleet-Wide Discovery**: Collect software inventory data from hundreds of VMs/servers simultaneously
- **Multi-Platform Support**: Works on RPM and Debian-based Linux distributions
- **Multiple Deployment Methods**: SSM, Ansible, or direct SSH execution
- **Container Discovery**: Automatically detects running containers, inspects their filesystems for OS packages and runtime manifests, and generates per-container SBOMs (requires root)

## Usage Instructions

### A. Using AWS Systems Manager (SSM)

Uses AWS Systems Manager to execute the discovery script across your EC2 fleet to collect software inventory. 

#### Prerequisites
- EC2 instances with SSM Agent installed and running
- SSM service role must have S3 permissions (separate from EC2 instance profile)
- AWS CLI configured with appropriate permissions

#### Required IAM Policy for SSM Service Role

**Important**: The SSM service uses its own role (typically `AmazonSSMRoleForInstancesQuickSetup` or similar), which is different from your EC2 instance profile role. This SSM service role needs S3 permissions.

```bash
# Add S3 permissions to SSM service role
aws iam put-role-policy \
    --role-name AmazonSSMRoleForInstancesQuickSetup \
    --policy-name GravitonS3Access \
    --policy-document '{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "s3:GetObject",
                    "s3:PutObject",
                    "s3:ListBucket"
                ],
                "Resource": [
                    "arn:aws:s3:::graviton-discovery-*",
                    "arn:aws:s3:::graviton-discovery-*/*"
                ]
            }
        ]
    }'
```

**Note**: Replace `AmazonSSMRoleForInstancesQuickSetup` with your actual SSM service role name. You can find it in the IAM console under "Roles" or by checking your SSM configuration.

#### Complete Automated Workflow
```bash
# Single command for complete workflow (deploy → execute → download → cleanup)
./graviton-discovery-manager.sh discover --all --region us-west-2

# Target specific instances
./graviton-discovery-manager.sh discover --instance-id "i-1234567890abcdef0 i-0987654321fedcba0" --region us-west-2

# Target by tags
./graviton-discovery-manager.sh discover --tag "Environment=Production" --region us-west-2
```

The `discover` command automatically:
1. Deploys CloudFormation infrastructure (S3 bucket + SSM document)
2. Executes discovery script on target instances
3. Downloads collected SBOM files locally
4. Cleans up AWS infrastructure

#### Output Structure

SBOM files are downloaded to a timestamped directory:
```
graviton-discovery-YYYYMMDD-HHMMSS/
├── hostname1-i-1234567890abcdef0-timestamp.sbom.json
├── hostname2-i-0987654321fedcba0-timestamp.sbom.json
├── hostname3-i-0abcdef1234567890-timestamp.sbom.json
├── sbom_container_i-1234567890abcdef0_myapp_nginx_latest.json
├── sbom_container_i-1234567890abcdef0_webapp_node_22-slim.json
└── ...
```

**File naming convention**:
- Host SBOMs: `hostname-instanceid-timestamp.sbom.json`
- Container SBOMs: `sbom_container_<instance-id>_<container-name>_<image-name>.json` (generated when running as root with containers present)

### B. Using Ansible (Direct Execution)

This Ansible playbook automates the execution of the Discovery script across multiple VMs/Servers to collect software inventory for AWS Graviton migration assessment.

#### Prerequisites

**Control Machine (Where you run Ansible):**
- Ansible installed (version 2.9+)
- SSH access to target hosts
- Private key file for target hosts

**Target Hosts:**
- **Required packages**: `curl` and `jq` must be pre-installed
- SSH access enabled
- Sudo privileges for the SSH user to run the Discovery script

#### Quick Start

**1. Install Required Packages on Target Hosts**

Before running the playbook, ensure `curl` and `jq` are installed on all target hosts:

```bash
# Amazon Linux/RHEL/CentOS
sudo yum install -y curl jq

# Ubuntu/Debian
sudo apt update && sudo apt install -y curl jq

## Curl installation May create issue?
```

**2. Set Up SSH Key**

```bash
chmod 600 ~/.ssh/your-key.pem
```

**3. Configure Inventory**

Edit `inventory.ini` with your vm/server details:

```ini
[graviton_targets]
10.0.1.10 ansible_user=ec2-user
10.0.1.11 ansible_user=ubuntu
10.0.2.10 ansible_user=centos

[graviton_targets:vars]
ansible_ssh_private_key_file=~/.ssh/your-key.pem
```

**Common SSH Users by OS:**
- Amazon Linux/RHEL/SUSE: `ec2-user`
- Ubuntu: `ubuntu`
- CentOS: `centos`
- Debian: `admin` or `debian`

**4. Test Connectivity**

```bash
ansible -i inventory.ini all -m ping
```

**5. Run the Playbook**

```bash
ansible-playbook -i inventory.ini graviton-discovery-ansible.yml
```

#### Playbook Execution Flow

1. **Prerequisites Check**: Verifies `curl` and `jq` are installed
2. **Setup**: Creates working directory and copies discovery script
3. **Validation**: Ensures script is executable and ready
4. **Discovery**: Executes the Graviton discovery script on each host
5. **Collection**: Downloads SBOM files to control machine
6. **Cleanup**: Removes temporary files from target hosts

#### Output Structure

SBOM files are collected in a timestamped directory:
```
graviton-discovery-YYYYMMDD-HHMMSS/
├── hostname1-epoch.sbom.json
├── hostname2-epoch.sbom.json
├── hostname3-epoch.sbom.json
└── ...
```

**Directory naming**: `graviton-discovery-2024-01-15-143052` (timestamped when playbook runs)
**File naming**: `hostname-epoch.sbom.json` (epoch timestamp from each target host)

#### Advanced Usage

**Selective Execution with Tags:**

```bash
# Only setup tasks
ansible-playbook -i inventory.ini graviton-discovery-ansible.yml --tags setup

# Only discovery and collection
ansible-playbook -i inventory.ini graviton-discovery-ansible.yml --tags discovery,collection

# Skip cleanup
ansible-playbook -i inventory.ini graviton-discovery-ansible.yml --skip-tags cleanup
```

**Available Tags:**
- `setup`: Directory creation, script copying
- `packages`: Package verification
- `validation`: Script and file validation
- `discovery`: Script execution
- `collection`: File download
- `cleanup`: Temporary file removal

#### Troubleshooting

**Common Issues:**

1. **Permission Denied**: Ensure SSH key permissions (`chmod 600`)
2. **Package Missing**: Install `curl` and `jq` on target hosts
3. **SSH Host Key**: Playbook automatically accepts new SSH host keys
4. **Script Missing**: Ensure `app_identifier.sh` exists in playbook directory

**Testing Individual Hosts:**
```bash
ansible-playbook -i inventory.ini graviton-discovery-ansible.yml --limit 10.0.1.10
```

**Files included**:
- `graviton-discovery-ansible.yml`: Ansible playbook for direct execution
- `inventory.ini`: Template inventory file (edit to add your servers)

### C. Using SSH Directly

If SSM or Ansible cannot be used in your environment, direct SSH access can be used to execute the discovery script across multiple VMs/servers to gather software inventory details. This method provides maximum flexibility for environments where other automation tools are not available. Steps for the same are provided below:

#### Prerequisites
- Passwordless SSH access to target vm/servers from a central server.
- `app_identifier.sh` script available locally
- Target VMs/Servers have required packages (jq, curl)

#### Direct SSH Execution Script

This script automates the discovery process across multiple servers by copying the `app_identifier.sh` script to each target server via SSH, executing it remotely to collect software inventory, and downloading the generated SBOM files back to the local machine. The script handles dependency installation, execution, and cleanup automatically for each server in the list.

```bash
#!/bin/bash
# Direct SSH execution script for software inventory discovery

INSTANCES=("server1.example.com" "server2.example.com" "server3.example.com")
LOCAL_OUTPUT_DIR="graviton-discovery-$(date +%Y%m%d-%H%M%S)"
USER='ec2-user'

# Create local output directory
mkdir -p "$LOCAL_OUTPUT_DIR"

for instance in "${INSTANCES[@]}"; do
    echo "Processing $instance..."
    
    # Copy script to remote VM/Server and execute
    scp ./app_identifier.sh "${USER}@${instance}:/tmp/app_identifier.sh"
    
    ssh -l $USER "$instance" << 'EOF'
        # Install dependencies if needed
        if ! command -v jq >/dev/null 2>&1; then
            if command -v yum >/dev/null 2>&1; then
                sudo yum install -y jq curl
            elif command -v apt-get >/dev/null 2>&1; then
                sudo apt-get update && sudo apt-get install -y jq curl
            fi
        fi
        
        # Execute discovery
        chmod +x /tmp/app_identifier.sh
        cd /tmp
        ./app_identifier.sh
        
        echo "Discovery completed for $(hostname)"
EOF
    
    # Download SBOM file from remote VM/Server
    TIMESTAMP=$(date +%Y%m%d-%H%M%S)
    
    mkdir -p "$LOCAL_OUTPUT_DIR"
    scp "${USER}@${instance}:/tmp/*sbom.json" "$LOCAL_OUTPUT_DIR/" 2>/dev/null || echo "No SBOM files found on $instance"
    scp "${USER}@${instance}:/tmp/sbom_container_*.json" "$LOCAL_OUTPUT_DIR/" 2>/dev/null  # Container SBOMs
    
    # Cleanup remote files
    ssh -l $USER "$instance" "rm -f /tmp/app_identifier.sh /tmp/*sbom.json /tmp/sbom_container_*.json"
    
    echo "Completed processing $instance"
done

echo "All SBOM files collected in: $LOCAL_OUTPUT_DIR"
ls -la "$LOCAL_OUTPUT_DIR"
```

#### Execute the Script
```bash
# Make script executable
chmod +x graviton-ssh-discovery.sh

# Run discovery across all VMs/Servers
./graviton-ssh-discovery.sh

# SBOM files will be collected in ./graviton-discovery-YYYYMMDD-HHMMSS/
find ./graviton-discovery-YYYYMMDD-HHMMSS -name "*.sbom.json"
```

## Considerations

### Security Considerations
- **SSM Service Role**: Ensure SSM service role (not EC2 instance profile) has minimal required S3 permissions
- **Network Access**: VMs/Servers need internet access for package installation and to upload generated SBOM to S3
- **Data Privacy**: Review collected data before sharing (see data collection section)
- **Temporary Files**: All temporary files are automatically cleaned up
- **Container Inspection**: Container filesystem is read directly from the host overlay mount (read-only). No commands are executed inside containers. If not running as root, container filesystem inspection is skipped gracefully

### Performance Considerations
- **Execution Time**: 10 seconds to 3 minutes per VMs/Server depending on system size
- **Memory Usage**: ~50-100MB during execution
- **Network Usage**: Minimal (only EC2 metadata and S3 operations)
- **CPU Impact**: Low impact, primarily I/O bound
- **Container Scanning**: Adds a few seconds per unique container image; reads only package DB files and manifest filenames from the overlay filesystem

### Operational Considerations
- **SSM Agent**: Required for SSM deployment method
- **Package Dependencies**: jq, curl on remote VMs/Server, and awscli on local VMs/Server must be available
- **Monitoring**: Use CloudWatch for SSM execution monitoring

## Data Collection Information

### What Data is Collected

1. **System Metadata**:
   - Hostname, IP addresses, OS version and distribution
   - CPU architecture, cores, memory, CPU cache (L1d, L1i, L2, L3) information
   - EC2 instance metadata (instance ID, type, region, AZ) when applicable

2. **Installed Packages**:
   - Package name, version, vendor/supplier
   - Package descriptions and metadata
   - Installation source information (RPM/DEB package managers)

3. **Running Applications**:
   - Process name, PID, user context
   - Command line arguments (filtered for security)
   - Version information when detectable
   - Excludes system processes and kernel threads

4. **Container Discovery** (when containers are present):
   - Running container names and image references (added to host SBOM)
   - Base image detection via OCI labels where available
   - Per-container SBOMs with OS packages from container filesystem (requires root)
   - Runtime manifest files discovered inside containers (requirements.txt, package.json, pom.xml, Gemfile, *.csproj, etc.)
   - Container runtime auto-detected: crictl (EKS/containerd), Docker, Podman, nerdctl
   - **Non-mutating**: Reads overlay filesystem directly, no exec/cp into containers

### What Data is NOT Collected
- **No Sensitive Data**: No passwords, keys, or credentials
- **No File Contents**: No application data or configuration files (only manifest filenames and package metadata are read from containers)
- **No Network Traffic**: No network connections or traffic analysis
- **No User Data**: No personal or user-specific information
- **No Container Mutation**: No commands are executed inside running containers

### Network Connections Made
- **EC2 Metadata Service**: `http://169.254.169.254/latest/meta-data/` (IMDSv2 preferred)
- **S3 API**: For uploading SBOM files to designated bucket when used with SSM
- **Package Repositories**: Only during dependency installation (if needed)

## Data Inspection and Sharing

It is always advisable to inspect the collected data before sharing with external parties to ensure no sensitive information is inadvertently included and to verify data quality.

### Inspect Gathered Data

```bash
# Set the data directory (adjust the timestamp as needed)
DATA_DIR=$(ls -tr -d graviton-discovery-* | head -1)  # Auto-detect latest directory
# OR manually specify: DATA_DIR="graviton-discovery-20240115-143052"

echo "Using data directory: $DATA_DIR"

# If using SSM, download data if not already
./graviton-discovery-manager.sh download

# List all collected files
find "$DATA_DIR" -type f -name "*.sbom.json" | sort

# Count total SBOM files
echo "Total SBOM files: $(find "$DATA_DIR" -name "*.sbom.json" | wc -l)"

# Show content of individual SBOM file
ls "$DATA_DIR"/*.sbom.json | head -1 | xargs cat

# Validate SBOM files (check JSON syntax)
for file in "$DATA_DIR"/*.sbom.json; do
    echo "Validating: $file"
    jq empty "$file" && echo "✓ Valid JSON" || echo "✗ Invalid JSON"
done

# Print different sections of the JSON using jq

# Show SBOM metadata section
jq '.metadata' "$DATA_DIR"/*.sbom.json | head -20

# Show system information
jq '.metadata.system' "$DATA_DIR"/*.sbom.json

# Show running applications (components with type="application")
jq '.components[] | select(.type == "application") | {name, version, description}' "$DATA_DIR"/*.sbom.json

# Show installed packages/libraries (components with type="library")
jq '.components[] | select(.type == "library") | {name, version, supplier}' "$DATA_DIR"/*.sbom.json | head -10

# Show component summary by type with hostname
jq '{hostname: .metadata.system.hostname, components: (.components | group_by(.type) | map({type: .[0].type, count: length}))}' "$DATA_DIR"/*.sbom.json

# Show discovered containers in host SBOM
jq '.components[] | select(.type == "container") | {name, version, properties}' "$DATA_DIR"/*.sbom.json

# Inspect container-specific SBOMs
for file in "$DATA_DIR"/sbom_container_*.json; do
    [ -f "$file" ] || continue
    echo "Container SBOM: $file"
    jq '{container: .metadata.component.name, image: .metadata.component.version, packages: (.components | length)}' "$file"
done
```

### Create Package for AWS Team

```bash
#!/bin/bash
# Automated packaging script for AWS team

# Auto-detect the latest data directory
DATA_DIR=$(ls -d graviton-discovery-* | head -1)
if [[ -z "$DATA_DIR" ]]; then
    echo "Error: No graviton-discovery-* directory found"
    exit 1
fi

echo "Packaging data from: $DATA_DIR"

# Create package directory
PACKAGE_NAME="graviton-assessment-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$PACKAGE_NAME"

# Copy SBOM files
cp -r "$DATA_DIR" "$PACKAGE_NAME/sbom-files"

# Generate automated inventory summary
SBOM_COUNT=$(find "$PACKAGE_NAME/sbom-files" -name "*.sbom.json" | wc -l)

cat > "$PACKAGE_NAME/README.txt" << EOF
Graviton Migration Assessment Data Package
==========================================

Generated on: $(date)
Data directory: $DATA_DIR
Total SBOM files: $SBOM_COUNT

Data Collection Details:
- Collection Method: [Please specify: SSM/Ansible/SSH]
- Environment: [Please specify: Production/Staging/Development]
- Date Range: $(stat -f %Sm -t %Y-%m-%d "$DATA_DIR") to $(date +%Y-%m-%d)

Contact Information:
- Name: [Your Name]
- Email: [your.email@company.com]
- Organization: [Your Organization]

File Structure:
- sbom-files/: Contains all SBOM JSON files
- README.txt: This summary file

Next Steps:
1. Review the SBOM files for any sensitive information
2. Update the collection details above
3. Share this package with your AWS team
EOF

# Create compressed package
tar -czf "$PACKAGE_NAME.tar.gz" "$PACKAGE_NAME"

# Display results
echo -e "\n=== Package Created Successfully ==="
echo "Package name: $PACKAGE_NAME.tar.gz"
echo "Package size: $(du -h "$PACKAGE_NAME.tar.gz" | cut -f1)"
echo "Files included: $SBOM_COUNT SBOM files from $HOST_COUNT hosts"
echo -e "\nPackage contents:"
tar -tzf "$PACKAGE_NAME.tar.gz" | head -10
echo -e '\nReady to share with AWS team!'

# Cleanup temporary directory
rm -rf "$PACKAGE_NAME"
```

**Quick execution:**
```bash
# Save the above script as create-aws-package.sh
chmod +x create-aws-package.sh
./create-aws-package.sh
```

### Share with AWS Team

**Sharing Options:**
1. **AWS Support Case**: Attach the compressed package to your support case or ask for S3 bucket link if the file size is higher
2. **Secure File Transfer**: Use your organization's secure file share method (if available)
3. **S3 Bucket Sharing**: Share S3 bucket access with AWS team (coordinate with AWS)

## Component Documentation

### app_identifier.sh

**Purpose**: Core discovery script that generates CycloneDX SBOM files

**Key Features**:
- Multi-platform support (RPM and Debian-based systems)
- Automatic dependency detection and installation
- Process filtering to exclude system processes
- Multiple version detection methods
- Secure temporary file handling

**Usage**:
```bash
# Basic usage
./app_identifier.sh [output_file]

# With custom log level
LOG_LEVEL=DEBUG ./app_identifier.sh custom_output.sbom.json

# Default output file format
# hostname-instanceid-timestamp.sbom.json
```

**Dependencies**:
- `jq`: JSON processing
- `curl`: HTTP requests for metadata
- `uuidgen` or `uuid`: UUID generation
- Package managers: `rpm` or `dpkg`

**Detailed Documentation**: For comprehensive documentation including data collection details, security considerations, and technical specifications, see [README_app_identifier.md](README_app_identifier.md)

### graviton-fleet-discovery.yaml

**Purpose**: CloudFormation template that creates AWS infrastructure

**Resources Created**:
- **S3 Bucket**: Encrypted storage for SBOM files with lifecycle policies
- **SSM Document**: Automated script execution across fleet

**Parameters**:
- `BucketPrefix`: S3 prefix for organizing files (default: 'graviton-discovery')

**Outputs**:
- `S3BucketName`: Name of created S3 bucket
- `SSMDocumentName`: Name of created SSM document

### graviton-discovery-manager.sh

**Purpose**: Management script for complete SSM-based fleet software discovery lifecycle operations

#### Available Commands

**Infrastructure Management**:
- `deploy`: Deploy CloudFormation infrastructure (S3 bucket + SSM document)
- `update`: Update existing CloudFormation stack
- `status`: Show CloudFormation stack status and outputs
- `delete`: Clean up infrastructure (prompts for confirmation)

**Discovery Operations**:
- `execute`: Execute discovery on target instances via SSM
- `download`: Download collected SBOM files from S3 to local directory
- `discover`: Complete automated workflow (deploy → execute → download → cleanup)

#### Available Options

**Targeting Options** (for execute/discover commands):
- `--all`: Target all SSM-managed instances
- `--instance-id IDS`: Target specific instances (space-separated or file path, space or newline separated instance ids)
- `--tag KEY=VALUE`: Target instances by EC2 tags

**Global Options**:
- `--region REGION`: Specify AWS region (required for infrastructure commands)
- `--dry-run`: Show commands without execution (for testing)
- `--help`: Display usage information

#### Instance ID Input Methods

**Inline Instance IDs**:
```bash
./graviton-discovery-manager.sh execute --instance-id "i-123 i-456 i-789"
```

**File Input** (space or newline separated):
```bash
# Create file with instance IDs
echo -e "i-123\ni-456\ni-789" > instances.txt
# OR
echo "i-123 i-456 i-789" > instances.txt

# Use file as input
./graviton-discovery-manager.sh execute --instance-id instances.txt
```

#### Tag Targeting Examples

**Single Tag**:
```bash
./graviton-discovery-manager.sh execute --tag "Environment=Production"
```

**Multiple Tags** (comma-separated):
```bash
./graviton-discovery-manager.sh execute --tag "Environment=Production,Team=WebServices"
```

**Target All Instances**:
```bash
./graviton-discovery-manager.sh discover --all --region us-west-2
```

#### Dry Run Mode

**Test Commands Without Execution**:
```bash
# Test deployment
./graviton-discovery-manager.sh deploy --region us-west-2 --dry-run

# Test execution targeting
./graviton-discovery-manager.sh execute --all --dry-run

# Test complete workflow
./graviton-discovery-manager.sh discover --tag "Environment=Test" --region us-west-2 --dry-run
```

#### Output and Results

**Download Directory Structure**:
```
graviton-discovery-YYYYMMDD-HHMMSS/
├── hostname-i-1234567890abcdef0-timestamp.sbom.json
├── hostname-i-0987654321fedcba0-timestamp.sbom.json
├── hostname-i-0abcdef1234567890-timestamp.sbom.json
└── ...
```

## Support

For issues and questions:
1. Enable debug logging to gather detailed information
2. Check SSM command execution logs in CloudWatch
3. Verify IAM permissions and network connectivity
4. Contact your AWS team for more specific assistance
