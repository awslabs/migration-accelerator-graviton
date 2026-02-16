# Output Files Directory

Default output directory for analysis results. Files are created here when no explicit output path is specified with `-o` or `--output-dir`.

## What Gets Stored Here

- SBOM analysis results (JSON, Excel, Markdown)
- Runtime testing results
- Intermediate files for multi-stage analysis
- Merged final reports

## File Naming Patterns

### Standard Analysis
```
<sbom-name>_analysis.json          # JSON report (default)
<sbom-name>.xlsx                   # Excel report (-f excel)
<sbom-name>_analysis.md            # Markdown report (-f markdown)
```

### Multi-Stage Analysis

**Stage 1** (`--extract-manifests`):
```
<sbom-name>_sbom_analysis.json     # Initial SBOM analysis
<sbom-name>_runtime_config.json    # Detected runtimes
<sbom-name>_<runtime>_manifest.*   # Runtime manifests
```

**Stage 2** (`--test-manifests <runtime>`):
```
<runtime>_runtime_analysis.json    # Runtime-specific results
```

**Stage 3** (`--merge-results`):
```
<sbom-name>_final_report.json      # Merged results
<sbom-name>_final_report.xlsx      # Excel format (if -f excel)
```

## Usage

### Default Output (to this directory)
```bash
python graviton_validator.py sbom.json
# Creates: output_files/sbom_analysis.json
```

### Custom Output Location
```bash
# Specify output file
python graviton_validator.py sbom.json -o /path/to/report.xlsx

# Specify output directory
python graviton_validator.py sbom.json --output-dir /path/to/results/
```

## Cleaning Up

```bash
# Remove all analysis files (keep README)
find output_files/ -type f ! -name 'README.md' -delete

# Remove files older than 7 days
find output_files/ -type f -mtime +7 ! -name 'README.md' -delete
```

## See Also

- **[CLI Reference](../docs/CLI_REFERENCE.md)** - Output format options and flags
- **[Architecture Documentation](../docs/ARCHITECTURE_AND_WORKFLOWS.md)** - Multi-stage workflow details
- **[Quick Start Guide](../docs/QUICK_START.md)** - Usage examples
