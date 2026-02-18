# Application Identifier Script

## Overview

The Application Identifier script (`app_identifier.sh`) is a system discovery tool that generates Software Bill of Materials (SBOM) files in CycloneDX format for AWS Graviton migration assessment. It automatically discovers and catalogs running applications, installed packages, and system information to help assess compatibility with ARM-based Graviton processors.

## Why This Script is Needed

### Migration Assessment Challenge
When migrating from x86 to AWS Graviton (ARM64) processors, organizations need to understand:
- What applications are currently running on their systems
- Which software packages are installed and their versions
- System architecture and configuration details
- Potential compatibility issues with ARM architecture

### Data Collection Purpose
This script collects the following information **locally from your system**:
- **Running processes**: Active applications and services (excluding system/kernel processes)
- **Installed packages**: System packages with versions, vendors, and descriptions
- **Package ownership**: System packages that provided each process executable (RPM, DEB, APK, Pacman, SUSE)
- **System information**: OS details, CPU architecture, memory, and hardware specs
- **EC2 metadata (if available)**: Instance ID and region (only when running on AWS EC2)
- **Container discovery (if containers present)**: Running container names, images, and base images. When running as root, also inspects container filesystems for OS packages and runtime manifest files (requirements.txt, package.json, pom.xml, Gemfile, *.csproj), generating per-container SBOMs

### Network Communication
**Important**: This script makes **NO external network calls** except for:
- **EC2 Instance Metadata Service (IMDS)** calls to `169.254.169.254` (only when running on EC2)
- These calls are local to the EC2 instance and do not leave your network
- No data is transmitted to external services or AWS APIs
- **Container discovery** uses only local commands (`docker`/`crictl`/`podman` inspect) and reads the local overlay filesystem — no network calls

## Usage Instructions

### Prerequisites
Ensure the following commands are available on your system:
- `jq` - JSON processor
- `awk` - Text processing
- `grep` - Pattern matching
- `timeout` - Command timeout utility
- `free` - Memory information
- `uuidgen` - UUID generation

### Basic Usage

1. **Run with default settings**:
   ```bash
   ./app_identifier.sh
   ```
   This creates an SBOM file with automatic naming: `hostname-instanceid-timestamp.sbom.json`

2. **Specify custom output file**:
   ```bash
   ./app_identifier.sh /path/to/custom-output.sbom.json
   ```

3. **Enable debug logging**:
   ```bash
   DEFAULT_LOG_LEVEL=DEBUG ./app_identifier.sh
   ```

4. **View help information**:
   ```bash
   ./app_identifier.sh --help
   ```

### Output File Naming
- **On EC2**: `hostname-instanceid-timestamp.sbom.json`
- **Non-EC2**: `hostname-timestamp.sbom.json`
- **Example**: `ip-10-0-2-193-i-1234567890abcdef0-20250827-065048.sbom.json`

## Security Considerations

### Data Privacy
- **Local Processing**: All data processing occurs locally on your system
- **No External Transmission**: No application or system data is sent to external services
- **Temporary Files**: Uses secure temporary files with restricted permissions (600)
- **Memory Protection**: Prefers `/dev/shm` for temporary storage when available

### Access Requirements
- **Read-only System Access**: Script only reads system information
- **No Root Required**: Can run as regular user (some package info may be limited)
- **Root Recommended for Containers**: Container filesystem inspection requires root access; without root, container image names are still captured but per-container SBOMs are skipped
- **Process Visibility**: Only sees processes visible to the executing user

### EC2 Metadata Access
- **IMDS Only**: Only accesses local EC2 metadata service (169.254.169.254)
- **No AWS API Calls**: Does not use AWS APIs or require AWS credentials
- **Timeout Protection**: IMDS calls timeout after 2 seconds to prevent hanging

### Output Security
- **Structured Data**: Generates standard CycloneDX SBOM format
- **No Sensitive Data**: Does not capture passwords, keys, or sensitive configuration
- **Process Arguments**: May include command-line arguments (review output if concerned)

## Script Functionality

### 1. System Discovery Process

**Package Detection**:
- Detects package manager (RPM, DEB, APK, Pacman, SUSE) across multiple Linux distributions
- Queries installed packages with names, versions, vendors, and descriptions
- Creates searchable index for efficient package lookups
- Identifies which packages own specific executable files

**Process Discovery**:
- Lists all running processes with user, PID, command name, and arguments
- Filters out system processes (kernel threads, filesystem processes, network processes)
- Focuses on user applications and services relevant for migration assessment

**System Information**:
- Collects OS details, architecture, CPU, and memory information
- Gathers EC2 metadata when running on AWS instances
- Records hardware specifications for compatibility analysis

### 2. Version Detection and Package Ownership

The script uses multiple strategies to determine application versions and package ownership:

1. **Binary Interrogation**: Executes `--version`, `-v`, `-V` commands on binaries (most reliable)
2. **Package Matching**: Correlates running processes with installed packages (system verified)
3. **Command Line Parsing**: Extracts version from process arguments (fallback)
4. **Package Ownership**: Identifies which system package provided each executable using:
   - `rpm -qf` for RPM-based systems (Red Hat, CentOS, Fedora)
   - `dpkg -S` for DEB-based systems (Debian, Ubuntu)
   - `apk info --who-owns` for Alpine Linux
   - `pacman -Qo` for Arch Linux
   - `rpm -qf` for SUSE systems

### 3. SBOM Generation

**CycloneDX Format**:
- Generates industry-standard SBOM in CycloneDX 1.5 format
- Includes metadata about the scanning tool and timestamp
- Structures data for compatibility with SBOM analysis tools

**Component Classification**:
- **Applications**: Running processes classified as application components
- **Libraries**: Installed packages classified as library components
- **Containers**: Running container images with base image info (when containers are present)
- **System**: OS and hardware information as system component

**Data Enrichment**:
- Adds process IDs, users, and version sources as component properties
- Includes package vendors and descriptions for better identification
- Records version detection method for transparency
- Links processes to their originating system packages for complete traceability

### 4. Error Handling and Reliability

**Retry Logic**:
- Retries package queries up to 3 times with delays
- Handles temporary system load or permission issues
- Continues processing even if some components fail

**Memory Management**:
- Checks available memory before processing
- Uses efficient temporary file handling
- Cleans up resources automatically

**Validation**:
- Validates generated JSON for correctness
- Verifies SBOM format compliance
- Reports processing errors and statistics

### 5. Filtering and Optimization

**Process Filtering**:
- Excludes kernel threads and system processes
- Filters out temporary utilities and shell processes
- Focuses on long-running applications and services

**Performance Optimization**:
- Uses indexed package lookups for faster processing
- Processes data in batches to manage memory usage
- Implements timeouts to prevent hanging on unresponsive binaries

## Output Format

The generated SBOM file contains:

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "serialNumber": "urn:uuid:...",
  "metadata": {
    "timestamp": "2025-01-27T06:50:48Z",
    "component": {
      "type": "operating-system",
      "name": "hostname",
      "version": "os-version"
    }
  },
  "components": [
    {
      "type": "application",
      "name": "application-name",
      "version": "1.2.3",
      "properties": [
        {"name": "process:pid", "value": "1234"},
        {"name": "process:user", "value": "username"},
        {"name": "version:source", "value": "binary"}
      ]
    },
    {
      "type": "container",
      "name": "my-webapp",
      "version": "node:22-bookworm-slim",
      "description": "Container image: node:22-bookworm-slim",
      "properties": [
        {"name": "container:image", "value": "node:22-bookworm-slim"},
        {"name": "container:base-image", "value": "debian:bookworm-slim"},
        {"name": "package:type", "value": "container-image"}
      ]
    }
  ]
}
```

When running as root with containers present, separate per-container SBOM files are also generated (e.g., `sbom_container_i-1234567890abcdef0_my-webapp_node_22-bookworm-slim.json`) containing OS packages and runtime manifest files discovered inside each container's filesystem.

## Troubleshooting

### Common Issues

1. **Missing Dependencies**: Install required tools (`jq`, `awk`, etc.)
2. **Permission Errors**: Ensure read access to `/proc` and package databases
3. **Empty Output**: Check if processes are being filtered too aggressively
4. **Timeout Issues**: Increase timeout values for slow systems

### Debug Mode
Use `LOG_LEVEL=DEBUG` to see detailed processing information:
```bash
LOG_LEVEL=DEBUG ./app_identifier.sh debug-output.sbom.json
```

### Log Levels
- **ERROR**: Critical failures only
- **WARNING**: Important issues that don't stop processing
- **INFO**: General progress information (default)
- **DEBUG**: Detailed processing steps and decisions

## Integration

This script is designed to work with the broader Graviton Migration Accelerator pipeline:
1. **Generate SBOM**: Use this script to create system inventory
2. **Upload to S3**: Place SBOM in the pipeline's dependency folder
3. **Automated Analysis**: Pipeline analyzes ARM compatibility
4. **Migration Reports**: Receive detailed compatibility assessments

The SBOM output is compatible with AWS Inspector and other security scanning tools for comprehensive dependency analysis.