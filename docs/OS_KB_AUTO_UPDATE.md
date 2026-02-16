# OS Knowledge Base Auto-Update

## Overview

The tool now automatically updates OS knowledge bases based on:
1. **Age-based updates**: Updates OS KBs older than 7 days (configurable)
2. **SBOM-driven updates**: Only updates OS versions present in your SBOM
3. **New OS detection**: Automatically generates KBs for new OS versions not yet in the database

## How It Works

When you run the validator, it:
1. Detects OS from your SBOM file
2. Checks if the OS KB exists and its last update timestamp
3. Updates the KB if it's older than the threshold (default: 7 days)
4. Proceeds with normal analysis using fresh data

## Usage

### Automatic Mode (Default)

```bash
# Auto-update is enabled by default
python graviton_validator.py app.sbom.json
```

### Disable Auto-Update

```bash
# Skip auto-update check
python graviton_validator.py app.sbom.json --disable-os-kb-update
```

### Custom Update Threshold

```bash
# Update if older than 14 days
python graviton_validator.py app.sbom.json --os-kb-max-age-days 14
```

## Manual Updates

### Update OS KB for Specific SBOM

```bash
# Update only OS versions found in SBOM
python scripts/os_kb_updater.py --sbom app.sbom.json
```

### Force Update

```bash
# Force update regardless of age
python scripts/os_kb_updater.py --sbom app.sbom.json --force
```

### Update Specific OS

```bash
# Update a specific OS version
python scripts/os_kb_updater.py --os ubuntu --version 24.04
```

### List Stale KBs

```bash
# Show which OS KBs need updates
python scripts/os_kb_updater.py --list-stale
```

### Update All Stale KBs

```bash
# Update all OS KBs older than threshold
python scripts/os_kb_updater.py --update-all-stale
```

## Metadata Tracking

The updater maintains a metadata file at:
```
knowledge_bases/os_knowledge_bases/.os_kb_metadata.json
```

This tracks:
- Last update timestamp for each OS KB
- OS name and version
- KB filename

Example metadata:
```json
{
  "os_knowledge_bases": {
    "ubuntu-22.04": {
      "os_name": "ubuntu",
      "os_version": "22.04",
      "last_updated": "2026-02-09T10:30:00",
      "kb_file": "ubuntu-22.04-graviton-packages.json"
    }
  }
}
```

## OS Detection from SBOM

The tool detects OS from multiple sources:

### 1. Syft Format
```json
{
  "distro": {
    "name": "ubuntu",
    "version": "22.04"
  }
}
```

### 2. CycloneDX Metadata
```json
{
  "metadata": {
    "component": {
      "type": "operating-system",
      "name": "ubuntu",
      "version": "22.04"
    }
  }
}
```

### 3. Package URLs (PURL)
```
pkg:deb/ubuntu/package@1.0?distro=jammy
```

## Parallel Updates

When multiple OS versions are detected, they're updated in parallel:

```bash
# Updates ubuntu-22.04, debian-11, and alpine-3.18 concurrently
python scripts/os_kb_updater.py --sbom multi-os.sbom.json
```

## Requirements

- Docker must be installed and running (for generating OS KBs)
- Network access to pull Docker images
- Sufficient disk space for temporary containers

## Troubleshooting

### Docker Not Available

```
Error: Docker is not installed or not in PATH
```

**Solution**: Install Docker from https://docs.docker.com/get-docker/

### Update Timeout

```
❌ Timeout updating ubuntu 22.04
```

**Solution**: Increase timeout or check Docker daemon status

### Permission Issues

```
Error: Permission denied accessing metadata file
```

**Solution**: Ensure write permissions to `knowledge_bases/os_knowledge_bases/` directory

## Configuration

### Change Default Update Interval

Edit the CLI argument default in `graviton_validator.py`:

```python
kb_update_group.add_argument(
    '--os-kb-max-age-days',
    type=int,
    default=7,  # Change this value
    help='Maximum age in days before OS KB is updated'
)
```

### Disable Auto-Update Globally

Set environment variable:

```bash
export GRAVITON_VALIDATOR_DISABLE_OS_KB_UPDATE=1
```

Then check in code:

```python
if not args.disable_os_kb_update and not os.getenv('GRAVITON_VALIDATOR_DISABLE_OS_KB_UPDATE'):
    _check_and_update_os_kb(args, logger)
```
