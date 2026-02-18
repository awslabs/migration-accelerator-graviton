# Graviton Compatibility Knowledge Base Guide

## Overview

This guide explains how to create and maintain knowledge base files for the Migration Accelerator for Graviton. The knowledge base contains compatibility information for software packages, helping determine which versions work with AWS Graviton processors.

## Knowledge Base Types

The tool uses two types of knowledge bases for different analysis phases:

### 1. SBOM Analysis Knowledge Bases (Primary)

**Location:** `knowledge_bases/` directory

**Purpose:** Static analysis of SBOM components

**Files:**
- `custom_kb.json` - Application-level software (Java, Tomcat, MySQL, etc.)
- `isv_graviton_packages.json` - ISV commercial software
- `arm_ecosystem_packages.json` - ARM ecosystem packages
- `os_knowledge_bases/*.json` - OS package databases

**Usage:** Automatically loaded for all SBOM analysis

**Maintenance:** Updated using [helper scripts](../scripts/README.md)

### 2. Runtime Analysis Knowledge Bases (Fast-Path Cache)

**Location:** `graviton_validator/knowledge_base/` directory

**Purpose:** Fast-path optimization for common runtime packages

**Files:**
- `python_runtime_dependencies.json` - 10 common PyPI packages (numpy, pandas, tensorflow, etc.)
- `nodejs_runtime_dependencies.json` - 13 common NPM packages
- `java_runtime_dependencies.json` - 13 common Maven packages
- `dotnet_runtime_dependencies.json` - 15 common NuGet packages
- `ruby_runtime_dependencies.json` - 4 common RubyGems

**How Runtime Analysis Works:**

```
┌─────────────────────────────────────────────────────────┐
│ Runtime Analysis Flow (--test-local)                │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  Phase 1: Check Runtime KB (10-15 common packages)      │
│           ├─ Found? → Return curated compatibility      │
│           └─ Not found? → Continue to Phase 2           │
│                                                          │
│  Phase 2: Query Package Registry API                    │
│           ├─ PyPI API (Python)                          │
│           ├─ NPM Registry (Node.js)                     │
│           ├─ Maven Central (Java)                       │
│           ├─ NuGet API (.NET)                           │
│           └─ RubyGems API (Ruby)                        │
│                                                          │
│  Phase 3: Cache Results (.cache/ directory)             │
│           └─ Avoid repeated API calls                   │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

**Why Runtime KBs Exist:**
- **Performance**: Instant lookup vs API call for common packages
- **Offline capability**: Works without internet for popular packages
- **Curated notes**: Hand-written compatibility recommendations
- **Fallback**: Works when package registry APIs are unavailable

**Important Notes:**
- Runtime KBs are **optional fast-path optimizations**, not the source of truth
- Package registry APIs (PyPI, NPM, Maven, NuGet, RubyGems) are authoritative
- Only 10-15 most common packages per runtime are included
- **No maintenance required** - these are static curated lists
- Most packages are analyzed via API calls (Phase 2)

**Example:** When analyzing a Python SBOM with 100 packages:
- 2-3 packages found in runtime KB (numpy, pandas) → instant result
- 97-98 packages queried from PyPI API → cached for future use

### When to Use Each Type

| Analysis Type | Knowledge Base Used | Purpose |
|--------------|---------------------|---------|
| Default (container testing) | Both types | KB analysis + package installation testing |
| Static Only (`--static-only`) | `knowledge_bases/` | Static component compatibility only |
| Local Testing (`--test-local`) | Both types | KB analysis + local package installation |
| Offline Mode | Both types | No API calls, KB only |

## Knowledge Base Structure

### File Format

Knowledge base files use JSON format with a specific schema. Each file should include:

- **Metadata**: Information about the knowledge base version and maintainer
- **Software Compatibility Records**: Detailed compatibility information for each software package
- **Documentation Sections**: Examples and definitions for reference

### Basic Structure

```json
{
  "$schema": "../schemas/schemas/knowledge_base_schema.json",
  "metadata": {
    "version": "1.0",
    "description": "Your knowledge base description",
    "maintainer": "Your Organization"
  },
  "software_compatibility": [
    // Software records go here
  ]
}
```

## Software Compatibility Records

### Required Fields

Each software record must include:

- **name**: Primary software name (used for matching)
- **compatibility**: Compatibility information object

### Optional Fields

- **aliases**: Alternative names for intelligent matching
- **description**: Brief description of the software

### Example Software Record

```json
{
  "name": "nginx",
  "aliases": ["nginx-core", "nginx-full", "nginx-light"],
  "description": "High-performance HTTP server and reverse proxy",
  "compatibility": {
    "supported_versions": [
      {
        "version_range": ">=1.18.0",
        "status": "compatible",
        "notes": "Full Graviton support with optimized performance"
      }
    ],
    "minimum_supported_version": "1.14.0",
    "recommended_version": "1.20.2",
    "migration_notes": "Consider enabling Graviton optimizations"
  }
}
```

## Version Range Specifications

### Supported Operators

| Operator | Description | Example |
|----------|-------------|---------|
| `>=` | Greater than or equal | `>=1.0.0` |
| `<=` | Less than or equal | `<=2.0.0` |
| `>` | Greater than | `>1.0.0` |
| `<` | Less than | `<2.0.0` |
| `==` | Exactly equal | `==1.0.0` |
| `!=` | Not equal | `!=1.0.0` |
| `~` | Compatible with (patch level) | `~1.0.0` (>=1.0.0, <1.1.0) |
| `^` | Compatible with (minor level) | `^1.0.0` (>=1.0.0, <2.0.0) |

### Combining Ranges

Use commas to combine multiple conditions:

```json
{
  "version_range": ">=1.0.0,<2.0.0",
  "status": "compatible"
}
```

### Version Range Examples

```json
"supported_versions": [
  {
    "version_range": ">=2.0.0",
    "status": "compatible",
    "notes": "Full Graviton support"
  },
  {
    "version_range": ">=1.5.0,<2.0.0",
    "status": "compatible_with_notes",
    "notes": "Works but upgrade recommended"
  },
  {
    "version_range": "<1.5.0",
    "status": "incompatible",
    "notes": "Upgrade required"
  }
]
```

## Compatibility Status Values

### Status Definitions

- **compatible**: Full Graviton support, no issues
- **compatible_with_notes**: Works but has limitations or considerations
- **incompatible**: Does not work on Graviton
- **unknown**: Compatibility status not determined

### When to Use Each Status

#### `compatible`
- Software has native ARM64 builds
- No known performance or functionality issues
- Officially supported on Graviton

#### `compatible_with_notes`
- Software works but may have performance limitations
- Requires specific configuration for optimal performance
- Has minor compatibility issues that can be worked around

#### `incompatible`
- Software does not support ARM64 architecture
- Has critical bugs on Graviton
- Requires x86_64 emulation (not recommended)

#### `unknown`
- Compatibility has not been tested
- No information available about Graviton support

## Advanced Features

### Software Aliases

Use aliases to improve matching accuracy:

```json
{
  "name": "nodejs",
  "aliases": ["node", "node.js", "npm"],
  "compatibility": {
    // ... compatibility info
  }
}
```

### Alternative Software

For incompatible software, suggest alternatives:

```json
{
  "name": "legacy-database",
  "compatibility": {
    "supported_versions": [],
    "alternatives": [
      {
        "name": "modern-database",
        "description": "Modern alternative with full Graviton support",
        "migration_effort": "medium"
      }
    ]
  }
}
```

### Documentation Links

Include relevant documentation:

```json
{
  "compatibility": {
    "documentation_links": [
      "https://software.example.com/graviton-guide",
      "https://docs.aws.amazon.com/graviton/latest/devguide/"
    ]
  }
}
```

## Best Practices

### Naming Conventions

1. **Use lowercase names**: `nginx` not `NGINX`
2. **Use canonical names**: `nodejs` not `node.js`
3. **Include common aliases**: Add variations users might search for

### Version Management

1. **Be specific**: Use exact version numbers when possible
2. **Test thoroughly**: Only mark versions as compatible after testing
3. **Update regularly**: Keep compatibility information current
4. **Document changes**: Use metadata to track updates

### Documentation

1. **Provide clear notes**: Explain compatibility issues and solutions
2. **Include migration guidance**: Help users upgrade to compatible versions
3. **Link to resources**: Provide relevant documentation links
4. **Explain performance implications**: Note any performance considerations

## Validation

### Schema Validation

Use the provided JSON schema to validate your knowledge base:

```bash
# Using a JSON schema validator
jsonschema -i your_knowledge_base.json schemas/knowledge_base_schema.json
```

### Common Validation Errors

1. **Missing required fields**: Ensure `name` and `compatibility` are present
2. **Invalid version ranges**: Check version range syntax
3. **Invalid status values**: Use only defined status values
4. **Malformed JSON**: Validate JSON syntax

## Maintenance Workflow

### Regular Updates

1. **Monitor software releases**: Track new versions of included software
2. **Test on Graviton**: Validate compatibility claims
3. **Update recommendations**: Keep recommended versions current
4. **Review performance**: Update performance notes as needed

### Adding New Software

1. **Research compatibility**: Test software on Graviton instances
2. **Document findings**: Create comprehensive compatibility records
3. **Include alternatives**: Suggest alternatives for incompatible software
4. **Validate schema**: Ensure new records follow the schema

### Quality Assurance

1. **Peer review**: Have others review compatibility claims
2. **Automated testing**: Use CI/CD to validate schema compliance
3. **Version control**: Track changes to knowledge base files
4. **Documentation**: Keep this guide updated with new practices

## Example Knowledge Base Files

### Minimal Example

```json
{
  "$schema": "../schemas/schemas/knowledge_base_schema.json",
  "software_compatibility": [
    {
      "name": "python",
      "compatibility": {
        "supported_versions": [
          {
            "version_range": ">=3.8.0",
            "status": "compatible"
          }
        ],
        "minimum_supported_version": "3.8.0",
        "recommended_version": "3.11.5"
      }
    }
  ]
}
```

### Comprehensive Example

See `../schemas/knowledge_base_template.json` for a complete example with all features demonstrated.

## Troubleshooting

### Common Issues

1. **Schema validation fails**: Check JSON syntax and required fields
2. **Software not matched**: Add aliases or check name spelling
3. **Version parsing errors**: Verify version range syntax
4. **Performance issues**: Large knowledge bases may need optimization

### Getting Help

1. **Check the schema**: Refer to `schemas/knowledge_base_schema.json`
2. **Review examples**: Use `../schemas/knowledge_base_template.json` as reference
3. **Validate JSON**: Use online JSON validators
4. **Test with validator**: Run the Migration Accelerator for Graviton with your knowledge base

## Updating Knowledge Bases

The tool uses static knowledge base files in the `knowledge_bases/` directory. These can be updated using helper scripts in the `scripts/` directory.

### OS Package Databases

Generate up-to-date OS package compatibility databases using Docker containers:

```bash
# Generate all supported OS versions
cd scripts
./generate_all_os_kb.sh

# Generate specific OS version
./generate_docker_kb.sh ubuntu 22.04
./generate_docker_kb.sh amazonlinux 2023
```

This creates `os_packages/{os}-{version}-graviton-packages.json` files with all ARM64-compatible packages for each OS.

### ISV Software Database

Update the ISV (Independent Software Vendor) compatibility database from AWS Graviton Getting Started Guide:

```bash
cd scripts
python isv_scraper.py
```

This scrapes the latest ISV compatibility information from the [AWS Graviton Getting Started repository](https://github.com/aws/aws-graviton-getting-started/blob/main/isv.md).

### ARM Ecosystem Database

Update the ARM ecosystem compatibility database from Arm's official ecosystem dashboard:

```bash
cd scripts
python arm_ecosystem_scraper.py
```

This scrapes compatibility data from the [Arm Developer Hub Ecosystem Dashboard](https://www.arm.com/developer-hub/ecosystem-dashboard/).

### Using Updated Knowledge Bases

```bash
# Use custom OS package database
python graviton_validator.py -k os_packages/ubuntu-22.04-graviton-packages.json sbom.json

# Use multiple knowledge bases
python graviton_validator.py \
  -k schemas/isv_graviton_packages.json \
  -k os_packages/amazonlinux-2-graviton-packages.json \
  sbom.json
```

For detailed information about these scripts, see [scripts/README.md](../scripts/README.md).

## Contributing

When contributing to shared knowledge bases:

1. **Follow naming conventions**: Use consistent software names
2. **Provide evidence**: Document testing methodology
3. **Include sources**: Reference official documentation
4. **Update metadata**: Track your contributions
5. **Test thoroughly**: Validate all compatibility claims