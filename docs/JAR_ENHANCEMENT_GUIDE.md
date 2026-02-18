# JAR Analysis Guide

> **🔧 For runtime testing of Java packages, see [CLI Reference - Runtime Testing Guide](CLI_REFERENCE.md#runtime-testing-guide)**

## Overview

The Migration Accelerator for Graviton can analyze Java JAR, WAR, and EAR files to detect components and native libraries that may not be captured in SBOM files. This complements SBOM analysis by providing binary-level inspection.

## Quick Start

### Basic JAR Analysis

```bash
# Analyze SBOM with additional JAR files
python graviton_validator.py sbom.json --jars app.jar

# Multiple JAR files
python graviton_validator.py sbom.json --jars app.jar lib1.jar lib2.jar

# All JARs in directory
python graviton_validator.py sbom.json --jar-dir ./libs/

# With runtime testing
python graviton_validator.py sbom.json --jars ./target/*.jar --yes
```

## Command Line Options

### JAR Analysis Options

#### `--jars [FILES...]`
Analyze specific JAR/WAR/EAR files

```bash
# Single JAR
python graviton_validator.py sbom.json --jars application.jar

# Multiple JARs
python graviton_validator.py sbom.json --jars app.jar lib1.jar lib2.jar

# Wildcard pattern
python graviton_validator.py sbom.json --jars ./target/*.jar
```

#### `--jar-dir DIRECTORY`
Analyze all JAR/WAR/EAR files in a directory

```bash
# Analyze directory
python graviton_validator.py sbom.json --jar-dir ./libs/

# With subdirectories
python graviton_validator.py sbom.json --jar-dir ./application/
```

## What JAR Analysis Detects

### 1. Embedded Dependencies
- Dependencies listed in `MANIFEST.MF`
- Class-Path entries
- Bundled libraries

### 2. Native Libraries
- `.so` files (Linux shared objects)
- `.dll` files (Windows libraries)
- `.dylib` files (macOS libraries)
- `.jnilib` files (JNI libraries)

### 3. Architecture-Specific Code
- JNI (Java Native Interface) usage
- Platform-specific implementations
- Native method declarations

### 4. Component Metadata
- Maven coordinates (groupId, artifactId, version)
- OSGi bundle information
- Implementation details

## Analysis Process

### Step 1: JAR Inspection
```bash
python graviton_validator.py sbom.json --jars app.jar -v
```

The tool:
1. Extracts JAR contents
2. Parses MANIFEST.MF
3. Scans for native libraries
4. Identifies dependencies
5. Adds components to analysis

### Step 2: Compatibility Check
Components found in JARs are checked against:
- Knowledge base
- Deny lists
- Runtime testing (if `--test-local` enabled)

### Step 3: Report Generation
Results include:
- All SBOM components
- Additional components from JARs
- Native library warnings
- Compatibility status for each

## Usage Examples

### Example 1: Spring Boot Application

```bash
# Analyze Spring Boot JAR with embedded dependencies
python graviton_validator.py spring-app.sbom.json \
  --jars ./target/spring-app-1.0.0.jar \
  --yes \
  -f excel -o spring-compatibility.xlsx
```

### Example 2: Multi-Module Maven Project

```bash
# Analyze all modules
python graviton_validator.py project.sbom.json \
  --jar-dir ./target/ \
  --yes \
  -f excel
```

### Example 3: WAR File Analysis

```bash
# Analyze web application
python graviton_validator.py webapp.sbom.json \
  --jars ./target/webapp.war \
  --yes
```

### Example 4: Enterprise Application (EAR)

```bash
# Analyze enterprise archive
python graviton_validator.py enterprise-app.sbom.json \
  --jars ./target/app.ear \
  --jar-dir ./lib/ \
  --yes \
  -f excel -o enterprise-report.xlsx
```

## Native Library Detection

### What Gets Flagged

JAR analysis flags components with:
- Embedded `.so` files (Linux native libraries)
- JNI method declarations
- Platform-specific code paths
- Architecture-dependent implementations

### Example Output

```
⚠️ Native Library Detected:
  Component: netty-transport-native-epoll
  File: libnetty_transport_native_epoll_x86_64.so
  Status: needs_verification
  Recommendation: Check for ARM64 version (libnetty_transport_native_epoll_aarch64.so)
```

## Integration with Runtime Testing

### Combined Analysis

```bash
# SBOM + JAR + Runtime testing
python graviton_validator.py app.sbom.json \
  --jars ./target/*.jar \
  --yes \
  -f excel -o complete-analysis.xlsx
```

This provides:
1. **SBOM components**: From build metadata
2. **JAR components**: From binary inspection
3. **Runtime verification**: Actual installation testing
4. **Comprehensive report**: All findings combined

## Best Practices

### 1. Always Include JARs for Java Applications
```bash
# Good: Complete analysis
python graviton_validator.py java-app.sbom.json --jars ./target/*.jar --yes

# Limited: SBOM only (may miss embedded dependencies)
python graviton_validator.py java-app.sbom.json
```

### 2. Use Runtime Testing with JARs
```bash
# Verify both SBOM and JAR findings
python graviton_validator.py app.sbom.json --jars app.jar --yes
```

### 3. Analyze All Application JARs
```bash
# Include all JARs, not just main application
python graviton_validator.py app.sbom.json --jar-dir ./libs/ --jar-dir ./plugins/
```

### 4. Check for Native Libraries
```bash
# Enable verbose output to see native library detection
python graviton_validator.py app.sbom.json --jars app.jar -v
```

## Troubleshooting

### Issue: JAR Not Found

```bash
# Check file path
ls -la ./target/app.jar

# Use absolute path
python graviton_validator.py sbom.json --jars /full/path/to/app.jar
```

### Issue: Permission Denied

```bash
# Check file permissions
chmod +r ./target/app.jar

# Run with appropriate permissions
python graviton_validator.py sbom.json --jars ./target/app.jar
```

### Issue: Large JAR Files

```bash
# Use verbose logging to track progress
python graviton_validator.py sbom.json --jars large-app.jar -v

# Keep temp files for debugging
python graviton_validator.py sbom.json --jars large-app.jar --no-cleanup
```

## Limitations

### What JAR Analysis Cannot Do

1. **Cannot execute code**: Only inspects JAR contents
2. **Cannot test runtime behavior**: Use `--test-local` for that
3. **Cannot detect all native code**: Some JNI usage may not be visible
4. **Cannot analyze obfuscated JARs**: Requires readable MANIFEST.MF

### Complementary Analysis

For complete coverage:
```bash
# Combine all analysis methods
python graviton_validator.py app.sbom.json \
  --jars ./target/*.jar \
  --jar-dir ./libs/ \
  --yes \
  -k custom-java-kb.json \
  -f excel -o comprehensive-report.xlsx
```

## Advanced Usage

### Custom Knowledge Base for Java

```json
{
  "software_compatibility": [
    {
      "name": "netty-transport-native-epoll",
      "compatibility": {
        "supported_versions": [
          {
            "version_range": ">=4.1.50",
            "status": "compatible",
            "notes": "ARM64 native library available"
          }
        ]
      }
    }
  ]
}
```

### Filtering System JARs

```bash
# Exclude system/JDK JARs if needed
python graviton_validator.py app.sbom.json \
  --jars ./target/app.jar \
  --no-system
```

## See Also

- [CLI Reference - Runtime Testing Guide](CLI_REFERENCE.md#runtime-testing-guide) - Runtime testing overview
- [Java Package Installer](JAVA_PACKAGE_INSTALLER_TECH_USAGE.md) - Technical details
- [CLI Reference](CLI_REFERENCE.md) - Complete command reference
