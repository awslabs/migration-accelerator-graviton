#!/usr/bin/env python3
"""
Graviton Compatibility Validator

Main entry point for the Graviton Compatibility Validator tool.
"""

import argparse
import sys
from pathlib import Path
from typing import List

# Add current directory to Python path to avoid import conflicts
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from graviton_validator.config import Config, get_default_config_path, load_config
from graviton_validator.exceptions import GravitonValidatorError
from graviton_validator.logging_config import setup_logging, get_logger


def _get_version() -> str:
    """Get version from centralized location."""
    try:
        from graviton_validator.version import get_version
        return get_version()
    except ImportError:
        return "0.0.1"  # Fallback


class RequiredSBOMAction(argparse.Action):
    """Custom action to validate SBOM files or directory is provided."""
    def __call__(self, parser, namespace, values, option_string=None):
        setattr(namespace, self.dest, values)
        # Validation will be done in parse_args override


def create_argument_parser() -> argparse.ArgumentParser:
    """Create and configure the command-line argument parser."""
    class CustomArgumentParser(argparse.ArgumentParser):
        def parse_args(self, args=None, namespace=None):
            parsed_args = super().parse_args(args, namespace)
            # Validate that either SBOM files or directory is provided (unless using independent modes)
            if (not parsed_args.sbom_files and not parsed_args.sbom_directory and 
                not parsed_args.merge_report_files and not parsed_args.merge_runtime_directory and
                not parsed_args.sbom_only and not parsed_args.runtime_only):
                self.error("No input specified. Use SBOM files, --directory, --merge-reports, --extract-manifests, or --test-manifests")
            return parsed_args
    
    parser = CustomArgumentParser(
        description="Analyze SBOM files for AWS Graviton (ARM64) compatibility and identify migration blockers",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
QUICK START:
  %(prog)s sbom.json                    # Full analysis (container testing if Docker available)
  %(prog)s sbom.json --static-only      # Fast static analysis only (no installation testing)
  %(prog)s sbom.json -f excel           # Generate Excel report

CI/CD PIPELINE:
  %(prog)s sbom.json --yes -f excel -o report.xlsx  # Non-interactive mode

COMMON OPTIONS:
  %(prog)s sbom.json --test-local       # Test packages on local system
  %(prog)s sbom.json -k custom_kb.json  # Use custom knowledge base
  %(prog)s -d ./sboms --jars ./libs/*.jar           # Include JAR analysis

MULTI-STAGE BUILDS:
  %(prog)s --extract-manifests -d ./sboms  # Stage 1: Extract manifests
  %(prog)s --test-manifests auto           # Stage 2: Test dependencies
  %(prog)s --merge-results ./results/      # Stage 3: Combine results

MERGE REPORTS:
  %(prog)s --merge-reports report1.json report2.json -f excel -o combined.xlsx

For detailed documentation, see README.md
        """
    )
    
    # === BASIC INPUT ===
    input_group = parser.add_argument_group('Basic Input (choose one)')
    input_group.add_argument(
        'sbom_files',
        nargs='*',
        help='SBOM file(s) to analyze (most common usage)'
    )
    input_group.add_argument(
        '-d', '--directory',
        dest='sbom_directory',
        help='Directory containing SBOM files (*.json)'
    )
    
    # === ADVANCED MODES ===
    advanced_group = parser.add_argument_group('Advanced Execution Modes')
    advanced_group.add_argument(
        '--merge-reports',
        dest='merge_report_files',
        nargs='*',
        help='Merge existing JSON analysis reports into single report'
    )
    advanced_group.add_argument(
        '--merge-results',
        dest='merge_runtime_directory',
        nargs='?',
        const='output_files',
        help='Merge SBOM and runtime test results from directory (default: output_files)'
    )
    advanced_group.add_argument(
        '--extract-manifests',
        dest='sbom_only',
        action='store_true',
        help='Extract package manifests from SBOM (for multi-stage builds)'
    )
    advanced_group.add_argument(
        '--test-manifests',
        dest='runtime_only',
        nargs='?',
        const='auto',
        choices=['nodejs', 'python', 'java', 'dotnet', 'ruby', 'auto'],
        help='Test extracted package manifests (requires --input-dir)'
    )
    advanced_group.add_argument(
        '--input-file',
        help='Specific manifest file (pom.xml, requirements.txt, package.json)'
    )
    advanced_group.add_argument(
        '--input-dir',
        default='output_files',
        help='Directory with manifests from --extract-manifests (default: output_files)'
    )
    
    # === CONFIGURATION ===
    config_group = parser.add_argument_group('Configuration & Knowledge Base')
    config_group.add_argument(
        '-k', '--knowledge-base',
        dest='knowledge_base_files',
        action='append',
        default=[],
        help='Custom knowledge base file (repeatable)'
    )
    config_group.add_argument(
        '--deny-list',
        dest='deny_list_file',
        help='File with packages known to be incompatible'
    )
    config_group.add_argument(
        '-c', '--config',
        dest='config_file',
        help='Configuration file for advanced settings'
    )
    
    # === ANALYSIS MODE ===
    analysis_group = parser.add_argument_group('Analysis Mode')
    analysis_group.add_argument(
        '--static-only',
        action='store_true',
        help='Skip package installation testing. Only use knowledge base analysis (fast).'
    )
    analysis_group.add_argument(
        '--test-local',
        action='store_true',
        help='Test packages on local system instead of in containers. Use for development. Not recommended for production.'
    )
    
    # === ADDITIONAL ANALYSIS ===
    additional_group = parser.add_argument_group('Additional Analysis')
    additional_group.add_argument(
        '--jars',
        dest='jar_files',
        nargs='*',
        help='Additional JAR/WAR/EAR files to analyze'
    )
    additional_group.add_argument(
        '--jar-dir',
        dest='jar_directory',
        help='Directory with JAR/WAR/EAR files'
    )
    
    # === FILTERING ===
    filter_group = parser.add_argument_group('Filtering Options')
    filter_group.add_argument(
        '--no-system',
        dest='exclude_system',
        action='store_true',
        help='Exclude system packages from analysis'
    )
    
    # === OUTPUT ===
    output_group = parser.add_argument_group('Output Options')
    output_group.add_argument(
        '-f', '--format',
        dest='output_format',
        choices=['text', 'json', 'excel', 'markdown'],
        default='text',
        help='Report format: text (console), json (data), excel (spreadsheet), markdown (docs)'
    )
    output_group.add_argument(
        '-o', '--output',
        dest='output_filename',
        help='Custom output filename (auto-generated if not specified)'
    )
    output_group.add_argument(
        '--output-dir',
        dest='output_directory',
        default='output_files',
        help='Directory for all output files (default: output_files)'
    )
    output_group.add_argument(
        '--verbose-output',
        dest='detailed',
        action='store_true',
        help='Include detailed component information in text reports'
    )
    
    # === EXPERT OPTIONS ===
    expert_group = parser.add_argument_group('Expert Options (advanced users only)')
    expert_group.add_argument(
        '--runtime-config',
        dest='runtime_config_file',
        help='Runtime config file (YAML/JSON) for version overrides'
    )
    expert_group.add_argument(
        '--no-cleanup',
        dest='skip_cleanup',
        action='store_true',
        help='Keep temporary files for debugging'
    )
    expert_group.add_argument(
        '--container-timeout',
        type=int,
        default=180,
        help='Timeout in seconds for container-based package testing (default: 180)'
    )
    
    # === LOGGING ===
    logging_group = parser.add_argument_group('Logging & Debugging')
    logging_group.add_argument(
        '-v', '--verbose',
        action='count',
        default=0,
        help='Increase verbosity. Use -v for INFO, -vv for DEBUG'
    )
    logging_group.add_argument(
        '-q', '--quiet',
        action='store_true',
        help='Show only errors'
    )
    logging_group.add_argument(
        '--log-file',
        help='Save all logs to file'
    )
    logging_group.add_argument(
        '--log-level',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
        default='INFO',
        help='Set logging level (default: INFO)'
    )
    
    # === OS KNOWLEDGE BASE AUTO-UPDATE ===
    kb_update_group = parser.add_argument_group('OS Knowledge Base Auto-Update')
    kb_update_group.add_argument(
        '--disable-os-kb-update',
        action='store_true',
        help='Disable automatic OS knowledge base updates'
    )
    kb_update_group.add_argument(
        '--os-kb-max-age-days',
        type=int,
        default=7,
        help='Maximum age in days before OS KB is updated (default: 7)'
    )
    
    # === SYSTEM ===
    system_group = parser.add_argument_group('System Options')
    system_group.add_argument(
        '-y', '--yes',
        action='store_true',
        help='Non-interactive mode. Bypass all prompts and use defaults.'
    )
    
    # === UTILITY ===
    parser.add_argument(
        '--version',
        action='version',
        version=f'%(prog)s {_get_version()}'
    )
    
    return parser


def _detect_sbom_format(sbom_data: dict) -> str:
    """
    Detect SBOM format using simplified logic.
    
    Args:
        sbom_data: Parsed SBOM data
        
    Returns:
        Format identifier: 'CycloneDX', 'SPDX', or 'Syft'
    """
    # Check for CycloneDX format first
    if "bomFormat" in sbom_data and "CycloneDX" in str(sbom_data.get("bomFormat", "")):
        return "CycloneDX"
    
    # Check for Syft format
    syft_indicators = ["artifacts", "artifactRelationships", "descriptor", "source"]
    if all(key in sbom_data for key in syft_indicators):
        return "Syft"
    
    # Check for SPDX format by looking for SPDX-specific top-level keys
    sbom_keys_lower = [k.lower() for k in sbom_data.keys()]
    if "spdxversion" in sbom_keys_lower or "spdxid" in sbom_keys_lower:
        return "SPDX"
    
    # Throw error if format cannot be determined
    available_keys = list(sbom_data.keys())
    raise ValueError(f"Could not detect SBOM format. Available top-level keys: {available_keys}")


def _create_parser(sbom_format: str):
    """Create SBOM parser based on format."""
    parser_map = {
        "CycloneDX": lambda: __import__('graviton_validator.parsers.cyclonedx', fromlist=['CycloneDXParser']).CycloneDXParser(),
        "SPDX": lambda: __import__('graviton_validator.parsers.spdx', fromlist=['SPDXParser']).SPDXParser(),
        "Syft": lambda: __import__('graviton_validator.parsers.syft', fromlist=['SyftParser']).SyftParser()
    }
    if sbom_format not in parser_map:
        raise ValueError(f"Unsupported SBOM format: {sbom_format}")
    return parser_map[sbom_format]()

def _get_manifest_patterns():
    """Get manifest file patterns for SBOM name extraction."""
    return ['_pom.xml', '_requirements.txt', '_package.json', '_test.csproj', '_Gemfile']

def _extract_sbom_name(manifest_file, patterns=None):
    """Extract SBOM name from manifest filename."""
    if patterns is None:
        patterns = _get_manifest_patterns()
    manifest_name = manifest_file.name if hasattr(manifest_file, 'name') else str(manifest_file)
    return next((manifest_name.replace(pattern, '') for pattern in patterns if pattern in manifest_name), Path(manifest_file).stem)

def _collect_sbom_files(sbom_files_arg, sbom_directory_arg, logger=None):
    """Collect SBOM files from arguments and directory."""
    sbom_files = []
    if sbom_files_arg:
        sbom_files.extend(sbom_files_arg)
    if sbom_directory_arg:
        dir_path = Path(sbom_directory_arg)
        if dir_path.is_dir():
            json_files = list(dir_path.glob('*.json'))
            if json_files:
                sbom_files.extend([str(f) for f in json_files])
                if logger:
                    logger.info(f"Found {len(json_files)} JSON files in directory: {sbom_directory_arg}")
            elif logger:
                logger.warning(f"No JSON files found in directory: {sbom_directory_arg}")
        elif logger:
            logger.error(f"Directory not found: {sbom_directory_arg}")
    return sbom_files

def _generate_output_filename(output_filename_arg, output_format, sbom_files):
    """Generate output filename based on format and input files."""
    if output_filename_arg:
        return output_filename_arg
    
    format_extensions = {'json': '.json', 'markdown': '.md', 'excel': '.xlsx', 'text': '.txt'}
    if len(sbom_files) == 1:
        input_file = Path(sbom_files[0])
        return f"{input_file.stem}{format_extensions[output_format]}"
    else:
        return f"graviton_compatibility_report{format_extensions[output_format]}"

def _detect_sbom_source(sbom_data: dict, sbom_format: str) -> str:
    """
    Detect the source/generator of the SBOM.
    
    Args:
        sbom_data: Parsed SBOM data
        sbom_format: Detected SBOM format (CycloneDX, SPDX, etc.)
        
    Returns:
        Source identifier: 'app_identifier' or 'third_party'
    """
    # Check metadata for graviton-migration-accelerator tool
    metadata = sbom_data.get("metadata", {})
    tools = metadata.get("tools", [])
    
    for tool in tools:
        if isinstance(tool, dict):
            tool_name = tool.get("name", "")
            if "graviton-migration-accelerator" in tool_name:
                return "app_identifier"
    
    # Default to third_party if not generated by app_identifier
    return "third_party"


def _check_docker_availability():
    """Check if Docker or Podman is available."""
    import shutil
    return shutil.which('docker') is not None or shutil.which('podman') is not None


def _determine_analysis_mode(args, logger):
    """
    Determine the analysis mode based on flags and Docker availability.
    Returns: 'static', 'test-container', or 'test-local'
    """
    # Explicit modes
    if args.static_only:
        logger.info("Running static analysis only (--static-only)")
        return 'static'
    
    if args.test_local:
        logger.warning("Testing packages on local system (--test-local)")
        logger.warning("This will install packages on your system. Use --static-only for safe analysis.")
        return 'test-local'
    
    # Default mode: test in container if available
    docker_available = _check_docker_availability()
    
    if docker_available:
        logger.info("Docker/Podman detected. Running comprehensive analysis with container testing.")
        return 'test-container'
    
    # Docker not available - prompt user
    logger.warning("=" * 70)
    logger.warning("Docker/Podman not detected")
    logger.warning("=" * 70)
    logger.warning("")
    logger.warning("Installation testing requires Docker or Podman for safe isolated testing.")
    logger.warning("")
    logger.warning("Options:")
    logger.warning("  1. Install Docker/Podman and run again for comprehensive testing")
    logger.warning("  2. Continue with static analysis only (faster, less comprehensive)")
    logger.warning("  3. Test on local system with --test-local (not recommended)")
    logger.warning("")
    
    # Non-interactive mode
    if args.yes:
        logger.warning("Non-interactive mode (--yes): Continuing with static analysis only.")
        return 'static'
    
    # Interactive prompt
    try:
        response = input("Continue with static analysis only? [y/N]: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()  # New line after Ctrl+C
        logger.info("Interrupted by user.")
        sys.exit(0)
    
    if response in ['y', 'yes']:
        logger.info("Continuing with static analysis only.")
        return 'static'
    else:
        logger.info("Exiting. Install Docker/Podman for comprehensive testing.")
        logger.info("  - Docker: https://docs.docker.com/get-docker/")
        logger.info("  - Podman: https://podman.io/getting-started/installation")
        sys.exit(0)


def _check_cpu_architecture(args, logger):
    """Warn if running installation tests on non-ARM64 machine."""
    import platform
    arch = platform.machine().lower()
    is_arm64 = arch in ('aarch64', 'arm64')
    
    if is_arm64:
        return
    
    logger.warning("=" * 70)
    logger.warning(f"Non-ARM64 architecture detected: {arch}")
    logger.warning("=" * 70)
    logger.warning("")
    logger.warning("Installation test results on this machine may be inaccurate.")
    logger.warning("Some packages with native C/C++ extensions may install successfully")
    logger.warning("on x86 but fail on ARM64/Graviton (or vice versa).")
    logger.warning("")
    logger.warning("For accurate results, run on an ARM64/Graviton instance.")
    logger.warning("")
    
    if args.yes:
        logger.warning("Non-interactive mode (--yes): Continuing with potentially inaccurate results.")
        return
    
    try:
        response = input("Continue with installation testing on non-ARM64? [y/N]: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        sys.exit(0)
    
    if response not in ['y', 'yes']:
        logger.info("Exiting. Run on an ARM64/Graviton instance for accurate results.")
        sys.exit(0)


def _validate_files_exist(files, error_msg):
    """Helper to validate file existence."""
    if files:
        missing = [f for f in files if not Path(f).exists()]
        if missing:
            print(f"Error: {error_msg}:", file=sys.stderr)
            for f in missing: print(f"  {f}", file=sys.stderr)
            sys.exit(1)

def _validate_directory_exists(path, name):
    """Helper to validate directory existence."""
    if path and not Path(path).exists():
        print(f"Error: {name} not found: {path}", file=sys.stderr)
        sys.exit(1)
    if path and not Path(path).is_dir():
        print(f"Error: Not a directory: {path}", file=sys.stderr)
        sys.exit(1)

def validate_arguments(args: argparse.Namespace) -> None:
    """Validate command-line arguments with improved error messages."""
    # Check for conflicting modes
    modes = [('merge mode', args.merge_report_files), ('merge runtime mode', args.merge_runtime_directory), ('runtime-only mode', args.runtime_only)]
    active_modes = [name for name, active in modes if active]
    
    has_sbom_input = args.sbom_files or args.sbom_directory
    if has_sbom_input and not args.sbom_only:
        active_modes.append('SBOM analysis')
    elif args.sbom_only and not has_sbom_input:
        print("Error: --extract-manifests requires SBOM files or --directory", file=sys.stderr)
        sys.exit(1)
    
    if len(active_modes) == 0 and not (has_sbom_input or args.sbom_only):
        print("Error: No input specified. Use: SBOM files, --directory, --merge-reports, --extract-manifests, or --test-manifests", file=sys.stderr)
        sys.exit(1)
    elif len(active_modes) > 1:
        print(f"Error: Cannot use multiple input modes: {', '.join(active_modes)}", file=sys.stderr)
        sys.exit(1)
    
    # Validate paths and files
    if args.runtime_only and not Path(args.input_dir).exists():
        print(f"Error: Input directory not found: {args.input_dir}\nHint: Run --extract-manifests first to generate manifests", file=sys.stderr)
        sys.exit(1)
    
    _validate_files_exist(args.sbom_files, "SBOM files not found")
    _validate_directory_exists(args.sbom_directory, "Directory")
    _validate_files_exist(args.knowledge_base_files, "Knowledge base files not found")
    _validate_files_exist(args.merge_report_files, "Report files not found")
    
    # Validate analysis mode flags
    if args.static_only and args.test_local:
        print("Error: Cannot use both --static-only and --test-local", file=sys.stderr)
        sys.exit(1)
    
    if args.sbom_only and (args.static_only or args.test_local):
        print("Warning: Analysis mode flags ignored in --extract-manifests mode (only generates manifests)", file=sys.stderr)


def _map_new_flags_to_legacy_attributes(args, analysis_mode):
    """Map new analysis mode flags to legacy internal attributes for backward compatibility."""
    # Set legacy attributes based on analysis mode
    if analysis_mode == 'static':
        args.runtime_analysis = False
        args.runtime_test = False
        args.use_containers = False
    elif analysis_mode == 'test-local':
        args.runtime_analysis = True
        args.runtime_test = True
        args.use_containers = False
    elif analysis_mode == 'test-container':
        args.runtime_analysis = True
        args.runtime_test = True
        args.use_containers = True
    
    # runtime-only mode always enables runtime testing
    if args.runtime_only:
        args.runtime_analysis = True
        args.runtime_test = True
        # use_containers depends on analysis mode


def perform_sbom_only_analysis(args, config, logger) -> int:
    """Perform SBOM-only analysis and generate manifests."""
    import json
    
    logger.info("Starting SBOM-only analysis mode")
    
    # Import required modules
    from graviton_validator.parsers import SBOMParserFactory
    from graviton_validator.knowledge_base.loader import KnowledgeBaseLoader
    from graviton_validator.analysis import create_analyzer
    from graviton_validator.deny_list import DenyListLoader
    from graviton_validator.analysis.manifest_generators import RuntimeAnalyzerManager
    
    # Load knowledge base (same as main function)
    kb_loader = KnowledgeBaseLoader()
    all_kb_files = []
    
    kb_dir = Path('./knowledge_bases')
    if kb_dir.exists() and kb_dir.is_dir():
        json_files = list(kb_dir.glob('*.json'))
        all_kb_files.extend([str(f) for f in json_files])
    
    if args.knowledge_base_files:
        all_kb_files.extend(args.knowledge_base_files)
    
    knowledge_base = None
    if all_kb_files:
        knowledge_base = kb_loader.load_multiple(all_kb_files)
        logger.info(f"Loaded knowledge base with {len(knowledge_base.software_entries)} entries")
    
    # Load deny lists
    deny_list_loader = DenyListLoader()
    deny_list_dir = Path('./deny_lists')
    if deny_list_dir.exists():
        deny_list_loader.load_from_directory(str(deny_list_dir))
    if args.deny_list_file:
        deny_list_loader.load_from_file(args.deny_list_file)
    if not deny_list_loader.deny_entries:
        deny_list_loader = None
    
    # Create analyzer
    analyzer = create_analyzer(knowledge_base=knowledge_base, matching_config=config.matching, deny_list_loader=deny_list_loader)
    
    # Collect SBOM files
    sbom_files = _collect_sbom_files(args.sbom_files, args.sbom_directory)
    
    if not sbom_files:
        logger.error("No SBOM files found")
        return 1
    
    # Create output directory structure
    output_dir = Path(args.output_directory)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Process SBOM files
    for sbom_file in sbom_files:
        logger.info(f"Processing SBOM file: {sbom_file}")
        
        with open(sbom_file, 'r') as f:
            sbom_data = json.load(f)
        
        # Detect SBOM format and source
        sbom_format = _detect_sbom_format(sbom_data)
        sbom_source = _detect_sbom_source(sbom_data, sbom_format)
        
        # Create parser based on format
        parser = _create_parser(sbom_format)
        
        components = parser._parse_components(sbom_data, sbom_file)
        detected_os = getattr(parser, 'os_config_manager', None)
        if detected_os:
            detected_os = detected_os.detect_os_from_sbom_data(sbom_data)
        
        # Apply filtering
        from graviton_validator.analysis.sbom_filters import get_filter_strategy
        filter_strategy = get_filter_strategy(sbom_format, sbom_source)
        components = filter_strategy.filter_components(components)
        
        # Analyze compatibility
        analysis_result = analyzer.analyze_components(components, detected_os, sbom_file)
        
        # Save SBOM analysis results
        sbom_filename = Path(sbom_file).stem
        sbom_json_path = output_dir / f"{sbom_filename}_sbom_analysis.json"
        
        from graviton_validator.analysis.sbom_runtime_merger import _write_analysis_result_to_file
        _write_analysis_result_to_file(analysis_result, sbom_json_path)
        logger.info(f"SBOM analysis saved to: {sbom_json_path}")
        
        # Generate runtime manifests ONLY (no actual analysis)
        runtime_analyzer_manager = RuntimeAnalyzerManager(use_containers=False)
        runtime_results = runtime_analyzer_manager.generate_manifests_only(
            components, str(output_dir), sbom_data, 
            sbom_name=sbom_filename, detected_os=detected_os
        )
        
        # Use existing runtime version detection
        from graviton_validator.analysis.runtime_config import RuntimeConfig
        runtime_config_manager = RuntimeConfig()
        detected_versions = runtime_config_manager.detect_versions_from_sbom(sbom_data)
        
        # Use class constant for supported versions
        def get_supported_versions(runtime: str) -> list:
            return runtime_config_manager.COMPATIBLE_VERSIONS.get(runtime, [])
        
        # Save enhanced runtime configuration with version info
        runtime_config = {
            'sbom_file': sbom_file,
            'detected_os': {
                'name': detected_os.split('-')[0] if detected_os and '-' in detected_os else detected_os,
                'version': detected_os.split('-', 1)[1] if detected_os and '-' in detected_os else 'unknown',
                'full_name': detected_os
            } if detected_os else {'name': 'unknown', 'version': 'unknown', 'full_name': 'unknown'},
            'runtimes': {
                runtime: {
                    'detected': True,
                    'version': detected_versions.get(runtime, 'unknown'),
                    'version_source': 'detected' if detected_versions.get(runtime) else 'not_detected',
                    'default_version': runtime_config_manager.DEFAULT_VERSIONS.get(runtime, 'latest'),
                    'supported_versions': get_supported_versions(runtime)
                } for runtime in runtime_results.keys()
            } if runtime_results else {}
        }
        
        runtime_config_path = output_dir / f"{sbom_filename}_runtime_config.json"
        with open(runtime_config_path, 'w') as f:
            json.dump(runtime_config, f, indent=2)
        
        logger.info(f"Runtime configuration saved to: {runtime_config_path}")
    
    logger.info("SBOM-only analysis completed")
    return 0


def perform_runtime_only_analysis(runtime: str, args, config, logger) -> int:
    """Perform runtime-only analysis for specified runtime or all detected runtimes."""
    import subprocess
    import json
    
    # Auto-detect runtimes from runtime config if runtime is 'auto'
    if runtime == 'auto':
        logger.info("Auto-detecting runtimes from runtime config files")
        input_dir = Path(args.input_dir)
        runtime_config_files = list(input_dir.glob('*_runtime_config.json'))
        
        if not runtime_config_files:
            logger.error(f"No runtime config files found in {input_dir}")
            return 1
        
        # Load runtime config to get detected runtimes
        with open(runtime_config_files[0], 'r') as f:
            runtime_config = json.load(f)
        
        # Extract runtime names from enhanced config format
        detected_runtimes = list(runtime_config.get('runtimes', {}).keys())
        
        logger.info(f"Detected runtimes from config: {detected_runtimes}")
        
        # Run analysis for each detected runtime
        overall_success = True
        for detected_runtime in detected_runtimes:
            logger.info(f"Running runtime analysis for: {detected_runtime}")
            result = _run_single_runtime_analysis(detected_runtime, args, config, logger)
            if result != 0:
                overall_success = False
        
        return 0 if overall_success else 1
    else:
        # Single runtime analysis
        return _run_single_runtime_analysis(runtime, args, config, logger)


def _run_single_runtime_analysis(runtime: str, args, config, logger) -> int:
    """Run runtime analysis for a single runtime with enriched data."""
    import json
    
    logger.info(f"Starting runtime-only analysis for: {runtime}")
    
    # Load runtime config for OS and version information
    input_dir = Path(args.input_dir)
    runtime_config_files = list(input_dir.glob('*_runtime_config.json'))
    runtime_version = None
    os_version = None
    
    if runtime_config_files:
        try:
            with open(runtime_config_files[0], 'r') as f:
                runtime_config = json.load(f)
            
            # Extract OS version info
            detected_os = runtime_config.get('detected_os', {})
            if isinstance(detected_os, dict):
                os_version = detected_os.get('full_name', 'amazon-linux-2023')
            else:
                os_version = detected_os or 'amazon-linux-2023'
            
            # Extract runtime version info with fallback to defaults
            runtime_info = runtime_config.get('runtimes', {}).get(runtime, {})
            detected_version = runtime_info.get('version', 'unknown')
            default_version = runtime_info.get('default_version')
            supported_versions = runtime_info.get('supported_versions', [])
            
            # Use detected version if valid and supported, otherwise fallback to default
            from graviton_validator.runtime_configs import get_runtime_default_version
            if (detected_version and detected_version not in ['unknown', '', 'not_detected'] and 
                any(detected_version.startswith(v) for v in supported_versions)):
                runtime_version = detected_version
                logger.info(f"Using detected {runtime} version: {runtime_version}")
            else:
                runtime_version = default_version or get_runtime_default_version(runtime)
                if detected_version not in ['unknown', '', 'not_detected']:
                    logger.info(f"Using default {runtime} version: {runtime_version} (detected {detected_version} not supported)")
                else:
                    logger.info(f"Using default {runtime} version: {runtime_version} (detected: {detected_version})")
                
        except Exception as e:
            logger.warning(f"Failed to load runtime config: {e}")
            # Fallback to defaults
            from graviton_validator.runtime_configs import get_runtime_default_version
            runtime_version = get_runtime_default_version(runtime)
            os_version = 'amazon-linux-2023'
            logger.info(f"Using fallback defaults - Runtime: {runtime_version}, OS: {os_version}")
    else:
        # No config file found, use defaults
        from graviton_validator.runtime_configs import get_runtime_default_version
        runtime_version = get_runtime_default_version(runtime)
        os_version = 'amazon-linux-2023'
        logger.info(f"No runtime config found, using defaults - Runtime: {runtime_version}, OS: {os_version}")
    
    # Handle different input modes: direct file vs directory search
    if args.input_file:
        # Direct manifest file specified
        manifest_files = {runtime: [Path(args.input_file)]}
    else:
        # Directory search mode - try nested subdirectories first, then fallback to root
        input_dir = Path(args.input_dir)
        
        # First try nested runtime subdirectories (default behavior)
        manifest_files = {
            'nodejs': list(input_dir.glob('nodejs/*package.json')),
            'python': list(input_dir.glob('python/*requirements.txt')),
            'java': list(input_dir.glob('java/*pom.xml')),
            'dotnet': list(input_dir.glob('dotnet/*.csproj')),
            'ruby': list(input_dir.glob('ruby/*Gemfile'))
        }
        
        # Fallback to root directory if no files found in subdirectories
        if not any(manifest_files.values()):
            manifest_files = {
                'nodejs': list(input_dir.glob('package.json')),
                'python': list(input_dir.glob('requirements.txt')),
                'java': list(input_dir.glob('pom.xml')),
                'dotnet': list(input_dir.glob('*.csproj')),
                'ruby': list(input_dir.glob('Gemfile'))
            }
    
    runtime_manifests = manifest_files.get(runtime, [])
    if not runtime_manifests:
        logger.warning(f"No {runtime} manifest files found in {input_dir}")
        return 0  # Not an error, just no manifests for this runtime
    
    # Create output directory
    output_dir = Path(args.output_directory)
    runtime_output_dir = output_dir / runtime
    runtime_output_dir.mkdir(parents=True, exist_ok=True)
    
    # Initialize runtime analyzer manager for enriched analysis
    from graviton_validator.analysis.manifest_generators import RuntimeAnalyzerManager
    runtime_analyzer_manager = RuntimeAnalyzerManager(use_containers=False)
    
    # Get the specific analyzer for this runtime
    analyzer_map = {
        'java': next((a for a in runtime_analyzer_manager.analyzers if a.get_runtime_type() == 'java'), None),
        'python': next((a for a in runtime_analyzer_manager.analyzers if a.get_runtime_type() == 'python'), None),
        'nodejs': next((a for a in runtime_analyzer_manager.analyzers if a.get_runtime_type() == 'nodejs'), None),
        'dotnet': next((a for a in runtime_analyzer_manager.analyzers if a.get_runtime_type() == 'dotnet'), None),
        'ruby': next((a for a in runtime_analyzer_manager.analyzers if a.get_runtime_type() == 'ruby'), None)
    }
    
    analyzer = analyzer_map.get(runtime)
    if not analyzer:
        logger.error(f"No analyzer found for runtime: {runtime}")
        return 1
    
    for manifest_file in runtime_manifests:
        logger.info(f"Analyzing {runtime} manifest: {manifest_file}")
        
        # Extract SBOM name from manifest filename
        sbom_name = _extract_sbom_name(manifest_file)
        
        # Use enriched analysis instead of direct package installer call
        try:
            analysis_kwargs = {
                'execution_env': runtime_analyzer_manager.execution_env,
                'output_dir': str(output_dir),
                'sbom_name': sbom_name,
                'runtime_version': runtime_version,
                'os_version': os_version
            }
            
            logger.info(f"Running enriched {runtime} analysis on: {manifest_file}")
            analysis_result = analyzer.analyze_dependencies(str(manifest_file), **analysis_kwargs)
            
            # Save enriched result
            output_file = runtime_output_dir / f"{sbom_name}_{runtime}_analysis.json"
            with open(output_file, 'w') as f:
                json.dump(analysis_result, f, indent=2)
            
            if 'error' in analysis_result:
                logger.error(f"Runtime analysis failed for {manifest_file}: {analysis_result['error']}")
            else:
                summary = analysis_result.get('summary', {})
                logger.info(f"Runtime analysis completed: {output_file} - Total: {summary.get('total_components', 0)}, Compatible: {summary.get('compatible', 0)}")
                
        except Exception as e:
            logger.error(f"Runtime analysis error for {manifest_file}: {e}")
    
    logger.info(f"Runtime-only analysis completed for {runtime}")
    return 0


def merge_runtime_results(directory_path: str):
    """Merge SBOM and runtime analysis results from directory structure."""
    from graviton_validator.analysis.sbom_runtime_merger import _load_runtime_components, _append_components, _create_merged_result
    from graviton_validator.reporting.json_reporter import JSONReporter
    import json
    import glob
    
    directory = Path(directory_path)
    
    # Find SBOM analysis file
    sbom_files = list(directory.glob('*_sbom_analysis.json'))
    if not sbom_files:
        raise ValueError(f"No SBOM analysis file found in {directory}")
    
    # Load SBOM result
    with open(sbom_files[0], 'r') as f:
        sbom_data = json.load(f)
    
    # Convert to AnalysisResult format
    from graviton_validator.models import AnalysisResult, ComponentResult, SoftwareComponent, CompatibilityResult, CompatibilityStatus
    
    # Extract components from structured data
    components = []
    for comp_data in sbom_data.get('components', []):
        component = SoftwareComponent(
            name=comp_data['name'],
            version=comp_data['version'],
            component_type=comp_data['type'],
            source_sbom=comp_data['source_sbom'],
            properties=comp_data.get('properties', {})
        )
        compatibility = CompatibilityResult(
            status=CompatibilityStatus(comp_data['compatibility']['status']),
            current_version_supported=comp_data['compatibility']['current_version_supported'],
            minimum_supported_version=comp_data['compatibility'].get('minimum_supported_version'),
            recommended_version=comp_data['compatibility'].get('recommended_version'),
            notes=comp_data['compatibility']['notes'],
            confidence_level=comp_data['compatibility']['confidence_level']
        )
        components.append(ComponentResult(component=component, compatibility=compatibility))
    
    # Create AnalysisResult from summary data
    summary = sbom_data['summary']
    sbom_result = AnalysisResult(
        components=components,
        total_components=summary['total_components'],
        compatible_count=summary['compatible'],
        incompatible_count=summary['incompatible'],
        needs_upgrade_count=summary['needs_upgrade'],
        needs_verification_count=summary['needs_verification'],
        needs_version_verification_count=summary.get('needs_version_verification', 0),
        unknown_count=summary['unknown'],
        errors=sbom_data.get('errors', []),
        processing_time=summary.get('processing_time_seconds', 0),
        detected_os=sbom_data.get('metadata', {}).get('detected_os'),
        sbom_file=sbom_data.get('metadata', {}).get('sbom_file')
    )
    
    # Create runtime results structure for _load_runtime_components
    runtime_results = {}
    
    # First, check runtime-specific subdirectories
    for runtime_dir in directory.iterdir():
        if runtime_dir.is_dir() and runtime_dir.name in ['java', 'python', 'nodejs', 'dotnet', 'ruby']:
            runtime_files = list(runtime_dir.glob('*_analysis.json'))
            if runtime_files:
                runtime_results[runtime_dir.name] = {
                    'result_path': str(runtime_files[0])
                }
    
    # Fallback: check for *_<runtime>_analysis.json files in root directory
    # Extract SBOM name from SBOM analysis file to match correct pattern
    sbom_name = None
    if sbom_files:
        sbom_filename = sbom_files[0].name
        if sbom_filename.endswith('_sbom_analysis.json'):
            sbom_name = sbom_filename.replace('_sbom_analysis.json', '')
    
    for runtime in ['java', 'python', 'nodejs', 'dotnet', 'ruby']:
        if runtime not in runtime_results:
            if sbom_name:
                # Look for exact pattern: <sbom_name>_<runtime>_analysis.json
                exact_pattern_files = list(directory.glob(f"{sbom_name}_{runtime}_analysis.json"))
                if exact_pattern_files:
                    runtime_results[runtime] = {
                        'result_path': str(exact_pattern_files[0])
                    }
                    continue
            
            # Fallback to any file ending with _<runtime>_analysis.json
            fallback_files = list(directory.glob(f"*_{runtime}_analysis.json"))
            if fallback_files:
                # Filter out files with manifest type in name (e.g., requirements_python)
                correct_files = [f for f in fallback_files if not any(manifest in f.name for manifest in ['requirements', 'pom', 'package', 'Gemfile', 'csproj'])]
                if correct_files:
                    runtime_results[runtime] = {
                        'result_path': str(correct_files[0])
                    }
                elif fallback_files:  # Use any file as last resort
                    runtime_results[runtime] = {
                        'result_path': str(fallback_files[0])
                    }
    
    # Load and merge runtime components
    runtime_components = _load_runtime_components(runtime_results, str(directory))
    merged_components = _append_components(sbom_result.components, runtime_components)
    
    return _create_merged_result(sbom_result, merged_components)


def _check_and_update_os_kb(args, logger):
    """
    Check and update OS knowledge bases if needed.
    Simple wrapper that calls the os_kb_updater script.
    """
    try:
        # Get SBOM files to analyze
        sbom_files = []
        if args.sbom_files:
            sbom_files.extend(args.sbom_files)
        if args.sbom_directory:
            sbom_dir = Path(args.sbom_directory)
            if sbom_dir.exists():
                sbom_files.extend(sbom_dir.glob('*.json'))
        
        if not sbom_files:
            logger.debug("No SBOM files provided, skipping OS KB auto-update check")
            return  # No SBOM files to analyze
        
        # Use first SBOM file for OS detection
        sbom_file = Path(sbom_files[0])
        logger.debug(f"Checking OS KB freshness for SBOM: {sbom_file.name}")
        
        # Import and run updater
        import subprocess
        scripts_dir = Path(__file__).parent / "scripts"
        updater_script = scripts_dir / "os_kb_updater.py"
        
        if not updater_script.exists():
            logger.debug("OS KB updater script not found, skipping auto-update")
            return
        
        logger.info("Checking OS knowledge base freshness...")
        
        # Run updater with SBOM file
        max_age = getattr(args, 'os_kb_max_age_days', 7)
        logger.debug(f"OS KB max age threshold: {max_age} days")
        
        result = subprocess.run(
            [sys.executable, str(updater_script), '--sbom', str(sbom_file), '--max-age-days', str(max_age)],
            capture_output=True,
            text=True,
            timeout=600  # 10 minute timeout
        )
        
        if result.returncode == 0:
            if result.stdout:
                # Parse output for better logging
                output = result.stdout.strip()
                if "No OS detected" in output:
                    logger.debug("No OS detected in SBOM, skipping KB updates")
                elif "up-to-date" in output:
                    logger.info("✅ All required OS knowledge bases are up-to-date")
                elif "Successfully updated" in output:
                    logger.info(f"✅ {output}")
                else:
                    logger.info(output)
        else:
            logger.warning(f"OS KB update check completed with warnings")
            if result.stderr:
                logger.debug(f"Update details: {result.stderr.strip()}")
    
    except subprocess.TimeoutExpired:
        logger.warning("OS KB update check timed out, continuing with existing knowledge bases")
    except Exception as e:
        logger.debug(f"OS KB auto-update skipped: {e}")
        # Don't fail the entire analysis if update check fails


def main() -> int:
    """
    Main entry point for the application.
    
    Returns:
        Exit code (0 for success, non-zero for error)
    """
    try:
        # Parse command-line arguments
        parser = create_argument_parser()
        args = parser.parse_args()
        
        # Validate arguments
        try:
            validate_arguments(args)
        except SystemExit as e:
            return e.code
        
        # Load configuration
        config_path = args.config_file or get_default_config_path()
        config = load_config(config_path)
        
        # Override config with command-line arguments
        if args.quiet:
            config.logging.level = 'ERROR'
        elif args.verbose >= 2:  # -vv or more
            config.logging.verbose = True
            config.logging.level = 'DEBUG'
        elif args.verbose == 1:  # -v
            config.logging.verbose = True
            config.logging.level = 'INFO'
        else:
            config.logging.level = args.log_level
        
        if args.log_file:
            config.logging.log_file = args.log_file
        
        # Set up logging
        logger = setup_logging(
            level=config.logging.level,
            log_file=config.logging.log_file,
            verbose=config.logging.verbose
        )
        
        logger.info("Starting Graviton Compatibility Validator")
        
        # Determine analysis mode (for non-special modes)
        if not (args.sbom_only or args.runtime_only or args.merge_report_files or args.merge_runtime_directory):
            analysis_mode = _determine_analysis_mode(args, logger)
            _map_new_flags_to_legacy_attributes(args, analysis_mode)
            # Warn if running installation tests on non-ARM64
            if analysis_mode in ('test-container', 'test-local'):
                _check_cpu_architecture(args, logger)
        else:
            # For special modes, set defaults
            _map_new_flags_to_legacy_attributes(args, 'static')
        
        # Handle independent execution modes
        if args.sbom_only:
            return perform_sbom_only_analysis(args, config, logger)
        elif args.runtime_only:
            return perform_runtime_only_analysis(args.runtime_only, args, config, logger)
        
        # Continue with existing logic for all other modes (unchanged)
        logger.debug(f"Processing SBOM files: {args.sbom_files}")
        logger.debug(f"Knowledge base files: {args.knowledge_base_files}")
        
        # Import required modules
        from graviton_validator.parsers import SBOMParserFactory
        from graviton_validator.knowledge_base.loader import KnowledgeBaseLoader
        from graviton_validator.analysis import create_analyzer
        from graviton_validator.analysis.sbom_jar_enhancer import JARAnalyzer
        from graviton_validator.deny_list import DenyListLoader
        from graviton_validator.reporting import JSONReporter
        from graviton_validator.reporting.text_reporter import TextReporter
        from graviton_validator.reporting.markdown_reporter import MarkdownReporter
        from graviton_validator.reporting.excel_reporter import ExcelReporter
        from graviton_validator.models import AnalysisResult
        
        # Initialize components
        parser_factory = SBOMParserFactory()
        kb_loader = KnowledgeBaseLoader()
        
        # Auto-update OS knowledge bases if enabled
        if not args.disable_os_kb_update:
            _check_and_update_os_kb(args, logger)
        
        # Load knowledge base
        logger.info("Loading knowledge base...")
        knowledge_base = None
        
        # Collect all knowledge base files (default + command line)
        all_kb_files = []
        
        # Load all JSON files from knowledge_bases directory (generic KB files)
        kb_dir = Path('./knowledge_bases')
        if kb_dir.exists() and kb_dir.is_dir():
            json_files = list(kb_dir.glob('*.json'))
            for json_file in json_files:
                all_kb_files.append(str(json_file))
                logger.debug(f"Found generic knowledge base file: {json_file}")
            if json_files:
                logger.info(f"Found {len(json_files)} generic knowledge base files in {kb_dir}")
        else:
            logger.debug(f"Knowledge base directory not found: {kb_dir}")
        
        # Store OS-specific KB directory for later use after OS detection
        os_kb_dir = kb_dir / 'os_knowledge_bases'
        if os_kb_dir.exists() and os_kb_dir.is_dir():
            os_kb_files = list(os_kb_dir.glob('*.json'))
            logger.debug(f"Found {len(os_kb_files)} OS-specific knowledge base files in {os_kb_dir}")
        else:
            logger.debug(f"OS knowledge base directory not found: {os_kb_dir}")
        
        # Add command line specified files
        if args.knowledge_base_files:
            all_kb_files.extend(args.knowledge_base_files)
        
        if all_kb_files:
            try:
                knowledge_base = kb_loader.load_multiple(all_kb_files)
                logger.info(f"Loaded knowledge base with {len(knowledge_base.software_entries)} entries from {len(all_kb_files)} files")
            except Exception as e:
                logger.error(f"Failed to load knowledge base: {e}")
                return 1
        else:
            logger.warning("No knowledge base files found - using built-in compatibility data only")
        
        # Load deny lists
        deny_list_loader = DenyListLoader()
        
        # Load from default directory
        deny_list_dir = Path('./deny_lists')
        if deny_list_dir.exists():
            deny_list_loader.load_from_directory(str(deny_list_dir))
        
        # Load additional file if specified
        if args.deny_list_file:
            deny_list_loader.load_from_file(args.deny_list_file)
        
        # Only use deny_list_loader if it has entries
        if not deny_list_loader.deny_entries:
            deny_list_loader = None
        
        # Create analyzer with matching configuration
        analyzer = create_analyzer(knowledge_base=knowledge_base, matching_config=config.matching, deny_list_loader=deny_list_loader)
        
        # Create shared analysis cache for cross-SBOM deduplication
        from graviton_validator.analysis.analysis_cache import AnalysisCache
        analysis_cache = AnalysisCache()
        
        # Collect JAR files for enhancement if specified
        jar_files = []
        if args.jar_files:
            jar_files.extend(args.jar_files)
        
        if args.jar_directory:
            jar_dir = Path(args.jar_directory)
            if jar_dir.exists() and jar_dir.is_dir():
                jar_extensions = ['*.jar', '*.war', '*.ear']
                for ext in jar_extensions:
                    jar_files.extend([str(f) for f in jar_dir.glob(ext)])
                logger.info(f"Found {len(jar_files)} archive files in {args.jar_directory}")
            else:
                logger.warning(f"JAR directory not found: {args.jar_directory}")
        
        # Initialize JAR analyzer if enhancement is requested
        jar_analyzer = None
        if jar_files:
            jar_analyzer = JARAnalyzer(analyzer)
            logger.info(f"JAR enhancement enabled with {len(jar_files)} archive files")
        
        # Check all prerequisites upfront based on flags
        from graviton_validator.prerequisites import PrerequisiteChecker
        prereq_checker = PrerequisiteChecker()
        
        prereq_ok, missing_tools = prereq_checker.check_all_prerequisites(args)
        if not prereq_ok:
            logger.error(f"Missing prerequisites: {missing_tools}")
            print(f"Error: Missing required tools: {', '.join(missing_tools)}", file=sys.stderr)
            print(prereq_checker.get_installation_instructions(missing_tools), file=sys.stderr)
            return 1
        
        logger.info("All prerequisites check passed")
        
        # Initialize runtime analyzer if requested
        runtime_analyzer_manager = None
        if args.runtime_analysis:
            from graviton_validator.analysis.manifest_generators import RuntimeAnalyzerManager
            
            use_containers = args.use_containers
            if use_containers is None:
                import os
                use_containers = os.environ.get('CODEBUILD_BUILD_ID') is None
            
            mode = "containerized" if use_containers else "native"
            logger.info(f"Runtime-specific analysis enabled ({mode} mode)")
            
            runtime_analyzer_manager = RuntimeAnalyzerManager(
                config_file=args.runtime_config_file,
                use_containers=use_containers
            )
            
            if args.runtime_config_file:
                logger.info(f"Using runtime configuration: {args.runtime_config_file}")
        
        # Check if merge mode
        if args.merge_report_files:
            logger.info(f"Merging {len(args.merge_report_files)} reports...")
            
            from graviton_validator.analysis.sbom_runtime_merger import _create_merged_result, _load_runtime_components
            from graviton_validator.models import AnalysisResult
            
            # Create fake runtime results structure to reuse existing loader
            runtime_results = {f"file_{i}": {"result_path": file_path} for i, file_path in enumerate(args.merge_report_files)}
            
            # Use existing function to load components from JSON files
            all_components = _load_runtime_components(runtime_results, ".", None)
            
            # Create result with auto-calculated counts
            base_result = AnalysisResult(components=[], total_components=0, compatible_count=0, 
                                       incompatible_count=0, needs_upgrade_count=0, 
                                       needs_verification_count=0, needs_version_verification_count=0, 
                                       unknown_count=0, errors=[], processing_time=0.0)
            merged_result = _create_merged_result(base_result, all_components)
            
            # Generate report using existing infrastructure from main function
            if args.output_format == 'excel':
                reporter = ExcelReporter()
            elif args.output_format == 'json':
                reporter = JSONReporter()
            elif args.output_format == 'markdown':
                reporter = MarkdownReporter()
            else:
                reporter = TextReporter(detailed=args.detailed)
            
            output_filename = args.output_filename or f"merged_report.{args.output_format if args.output_format != 'text' else 'txt'}"
            output_path = Path(args.output_directory) / output_filename
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            if args.output_format == 'excel':
                reporter.generate_report(merged_result, str(output_path))
            else:
                report_content = reporter.generate_report(merged_result)
                with open(output_path, 'w', encoding='utf-8') as f:
                    f.write(report_content)
                if args.output_format == 'text' and not args.output_filename:
                    print(report_content)
            
            logger.info(f"Merged report saved to: {output_path}")
            return 0

        elif args.merge_runtime_directory:
            logger.info(f"Merging SBOM and runtime results from: {args.merge_runtime_directory}")
            merged_result = merge_runtime_results(args.merge_runtime_directory)
            
            # Generate report using existing infrastructure
            if args.output_format == 'json':
                reporter = JSONReporter()
            elif args.output_format == 'markdown':
                reporter = MarkdownReporter()
            elif args.output_format == 'excel':
                reporter = ExcelReporter()
            else:
                reporter = TextReporter(detailed=args.detailed)
            
            # Determine output filename
            if args.output_filename:
                output_filename = args.output_filename
            else:
                format_extensions = {'json': '.json', 'markdown': '.md', 'excel': '.xlsx', 'text': '.txt'}
                output_filename = f"merged_runtime_report{format_extensions[args.output_format]}"
            
            output_dir = Path(args.output_directory)
            output_dir.mkdir(parents=True, exist_ok=True)
            output_path = output_dir / output_filename
            
            if args.output_format == 'excel':
                reporter.generate_report(merged_result, str(output_path))
            else:
                report_content = reporter.generate_report(merged_result)
                with open(output_path, 'w', encoding='utf-8') as f:
                    f.write(report_content)
            
            logger.info(f"Merged runtime report saved to: {output_path}")
            return 0

        else:
            # Regular SBOM analysis mode (UNCHANGED - preserves 100% existing behavior)
            # Collect SBOM files from arguments and directory
            sbom_files = _collect_sbom_files(args.sbom_files, args.sbom_directory, logger)
            
            if not sbom_files:
                logger.error("No SBOM files specified. Use positional arguments or --directory option.")
                return 1
        
            # Process each SBOM file
            all_results = []
            
            total_files = len(sbom_files) if sbom_files else 0
        
            for i, sbom_file in enumerate(sbom_files, 1):
                if config.logging.verbose or total_files > 1:
                    print(f"Processing SBOM file {i}/{total_files}: {Path(sbom_file).name}", file=sys.stderr)
                logger.info(f"Processing SBOM file {i}/{total_files}: {sbom_file}")
                
                try:
                    # Load SBOM data for format detection
                    import json
                    with open(sbom_file, 'r') as f:
                        sbom_data = json.load(f)
                    
                    # Detect SBOM format and source
                    sbom_format = _detect_sbom_format(sbom_data)
                    sbom_source = _detect_sbom_source(sbom_data, sbom_format)
                    logger.info(f"Detected SBOM format: {sbom_format}, source: {sbom_source}")
                    
                    # Process SBOM using strategy pattern
                    from graviton_validator.analysis.sbom_filters import get_filter_strategy
                    
                    # Create parser based on format
                    parser = _create_parser(sbom_format)
                    
                    components = parser._parse_components(sbom_data, sbom_file)
                    detected_os = getattr(parser, 'os_config_manager', None)
                    if detected_os:
                        detected_os = detected_os.detect_os_from_sbom_data(sbom_data)
                    
                    # Apply format-specific filtering
                    filter_strategy = get_filter_strategy(sbom_format, sbom_source)
                    components = filter_strategy.filter_components(components)
                
                    logger.debug(f"Parsed {len(components)} components")
                    
                    # Load OS-specific knowledge base if OS detected
                    os_specific_kb = None
                    if detected_os:
                        logger.info(f"Detected OS: {detected_os}")
                        
                        # Add detected OS to each component's properties for multi-SBOM tracking
                        for component in components:
                            if not component.properties:
                                component.properties = {}
                            component.properties["sbom_detected_os"] = detected_os
                        if os_kb_dir.exists():
                            kb_filename = f"{detected_os}-graviton-packages.json"
                            kb_file_path = os_kb_dir / kb_filename
                            
                            if kb_file_path.exists():
                                try:
                                    os_kb_loader = KnowledgeBaseLoader()
                                    os_specific_kb = os_kb_loader.load_multiple([str(kb_file_path)])
                                    logger.info(f"Loaded OS-specific KB for {detected_os}")
                                    
                                    # Merge OS-specific entries into main knowledge base
                                    for name, record in os_specific_kb.compatibility_records.items():
                                        if name not in knowledge_base.compatibility_records:
                                            knowledge_base.compatibility_records[name] = record
                                            # Also merge aliases
                                            for alias in record.aliases or []:
                                                knowledge_base.software_aliases[alias.lower()] = name
                                    
                                    logger.info(f"Merged {len(os_specific_kb.compatibility_records)} OS-specific entries into main KB")
                                    logger.debug(f"Total KB entries after merge: {len(knowledge_base.compatibility_records)}")
                                except Exception as e:
                                    logger.warning(f"Failed to load OS-specific KB: {e}")
                
                    # Create analyzer after all knowledge bases are loaded and merged
                    analyzer = create_analyzer(knowledge_base=knowledge_base, matching_config=config.matching, deny_list_loader=deny_list_loader, analysis_cache=analysis_cache)
                    
                    # Apply format and source specific filtering (already done in processing functions)
                    logger.info(f"Ready to analyze {len(components)} components")
                
                    # Apply OS-specific KB priority filtering
                    if detected_os and os_specific_kb:
                        original_count = len(components)
                        final_components = []
                        
                        for component in components:
                            # Check if component exists in OS-specific KB
                            if hasattr(os_specific_kb, 'find_software'):
                                software_entry = os_specific_kb.find_software(component.name)
                                if software_entry:
                                    final_components.append(component)  # Always include OS KB components
                                    continue
                            
                            # Keep component if not in OS KB
                            final_components.append(component)
                        
                        components = final_components
                        if len(components) != original_count:
                            logger.debug(f"OS KB filtering: {original_count} -> {len(components)} components")
                    
                    # Additional manual filtering if requested
                    if args.exclude_system:
                        from graviton_validator.analysis.filters import ComponentFilter, ComponentCategory
                        component_filter = ComponentFilter()
                        manual_original_count = len(components)
                        filtered_manual = []
                        
                        for component in components:
                            component_dict = {
                                "name": component.name,
                                "version": component.version,
                                "type": component.component_type,
                                "properties": component.properties
                            }
                            
                            category = component_filter.categorize_component(component_dict, detected_os, os_specific_kb)
                            if category not in [ComponentCategory.SYSTEM_COMPATIBLE, ComponentCategory.SYSTEM_UNKNOWN]:
                                filtered_manual.append(component)
                        
                        components = filtered_manual
                        if manual_original_count != len(components):
                            logger.debug(f"Manual filter removed {manual_original_count - len(components)} components")
                    
                    # Analyze compatibility with OS awareness
                    component_count = len(components)
                    if config.logging.verbose and component_count > 100:
                        print(f"  Analyzing {component_count} components...", file=sys.stderr)
                    logger.info(f"Analyzing compatibility for {component_count} components...")
                    
                    analysis_result = analyzer.analyze_components(
                        components, detected_os, sbom_file
                    )
                    logger.debug(f"Analysis completed for {component_count} components")
                    
                    # Enhance with JAR analysis if requested
                    if jar_analyzer and jar_files:
                        logger.info("Enhancing SBOM analysis with JAR analysis...")
                        try:
                            enhancement_result = jar_analyzer.enhance_sbom_with_jars(analysis_result.components, jar_files)
                            
                            # Update analysis result with enhanced components
                            analysis_result.components = enhancement_result['enhanced_components']
                            analysis_result.total_components = len(enhancement_result['enhanced_components'])
                            
                            # Add enhancement metadata
                            if not hasattr(analysis_result, 'enhancement_metadata'):
                                analysis_result.enhancement_metadata = {}
                            analysis_result.enhancement_metadata.update(enhancement_result['enhancement_summary'])
                            analysis_result.enhancement_metadata['gaps_found'] = enhancement_result['gaps_found']
                            
                            # Recalculate counts with enhanced components
                            from graviton_validator.models import CompatibilityStatus
                            analysis_result.compatible_count = sum(1 for c in analysis_result.components if c.compatibility.status == CompatibilityStatus.COMPATIBLE)
                            analysis_result.incompatible_count = sum(1 for c in analysis_result.components if c.compatibility.status == CompatibilityStatus.INCOMPATIBLE)
                            analysis_result.needs_verification_count = sum(1 for c in analysis_result.components if c.compatibility.status == CompatibilityStatus.NEEDS_VERIFICATION)
                            analysis_result.unknown_count = sum(1 for c in analysis_result.components if c.compatibility.status == CompatibilityStatus.UNKNOWN)
                            
                            logger.info(f"JAR enhancement completed. Found {enhancement_result['gap_count']} additional components")
                        except Exception as e:
                            logger.error(f"JAR enhancement failed: {e}")
                            # Continue with original SBOM analysis
                    
                    # Enhanced runtime analysis integration
                    if runtime_analyzer_manager:
                        from graviton_validator.analysis.sbom_runtime_merger import analyze_with_runtime_integration
                        
                        runtime_output_dir = Path(args.output_directory)
                        runtime_output_dir.mkdir(parents=True, exist_ok=True)
                        
                        runtime_kwargs = {
                            'deep_scan': True,
                            'runtime_test': args.runtime_test,
                            'verbose': config.logging.verbose,
                            'sbom_name': Path(sbom_file).stem,
                            'analysis_cache': analysis_cache,
                            'container_timeout': args.container_timeout
                        }
                        
                        # Only pass skip_cleanup if explicitly set by user
                        if args.skip_cleanup:
                            runtime_kwargs['skip_cleanup'] = True
                        
                        # Replace complex logic with single function call
                        analysis_result = analyze_with_runtime_integration(
                            components, detected_os, sbom_file, sbom_data,
                            analyzer, runtime_analyzer_manager, str(runtime_output_dir), **runtime_kwargs
                        )
                    else:
                        # Write SBOM-only analysis to disk for troubleshooting
                        sbom_filename = Path(sbom_file).stem
                        sbom_output_dir = Path(args.output_directory)
                        sbom_output_dir.mkdir(parents=True, exist_ok=True)
                        sbom_json_path = sbom_output_dir / f"{sbom_filename}_sbom_analysis.json"
                        
                        from graviton_validator.analysis.sbom_runtime_merger import _write_analysis_result_to_file
                        _write_analysis_result_to_file(analysis_result, sbom_json_path)
                        logger.info(f"SBOM analysis saved to: {sbom_json_path}")
                    
                    all_results.append(analysis_result)
                    
                    # Log summary
                    compatible_count = analysis_result.compatible_count
                    incompatible_count = analysis_result.incompatible_count
                    unknown_count = analysis_result.unknown_count
                    
                    logger.info(f"Analysis complete: {compatible_count} compatible, "
                               f"{incompatible_count} incompatible, {unknown_count} unknown")
                    
                except Exception as e:
                    logger.error(f"Failed to process SBOM file {sbom_file}: {e}")
                    if len(args.sbom_files) == 1:
                        return 1
                    continue
        
            if not all_results:
                logger.error("No SBOM files were successfully processed")
                return 1
            
            # Prepare analysis result for reporting  
            if len(all_results) == 1:
                final_result = all_results[0]
            else:
                # For multiple files, create a combined report
                all_components = []
                total_compatible = 0
                total_incompatible = 0
                total_needs_upgrade = 0
                total_needs_verification = 0
                total_needs_version_verification = 0
                total_unknown = 0
                all_errors = []
                total_processing_time = 0
                
                for result in all_results:
                    all_components.extend(result.components)
                    total_compatible += result.compatible_count
                    total_incompatible += result.incompatible_count
                    total_needs_upgrade += result.needs_upgrade_count
                    total_needs_verification += result.needs_verification_count
                    total_needs_version_verification += result.needs_version_verification_count
                    total_unknown += result.unknown_count
                    all_errors.extend(result.errors)
                    total_processing_time += result.processing_time
                
                final_result = AnalysisResult(
                    components=all_components,
                    total_components=len(all_components),
                    compatible_count=total_compatible,
                    incompatible_count=total_incompatible,
                    needs_upgrade_count=total_needs_upgrade,
                    needs_verification_count=total_needs_verification,
                    needs_version_verification_count=total_needs_version_verification,
                    unknown_count=total_unknown,
                    errors=all_errors,
                    processing_time=total_processing_time
                )
        
        # Generate report
        logger.info("Generating report...")
        try:
            # Create appropriate reporter
            if args.output_format == 'json':
                reporter = JSONReporter()
            elif args.output_format == 'markdown':
                reporter = MarkdownReporter()
            elif args.output_format == 'excel':
                reporter = ExcelReporter()
            else:  # text
                reporter = TextReporter(detailed=args.detailed)
            
            # Generate output filename
            output_filename = _generate_output_filename(args.output_filename, args.output_format, sbom_files)
            
            # Use output directory directly
            output_dir = Path(args.output_directory)
            
            output_dir.mkdir(parents=True, exist_ok=True)
            output_path = output_dir / output_filename
            
            # Generate and save report
            if args.output_format == 'excel':
                # Excel reporter handles file writing internally
                reporter.generate_report(final_result, str(output_path))
                logger.info(f"Report saved to: {output_path}")
            else:
                # Text-based formats - generate content first
                report_content = reporter.generate_report(final_result)
                with open(output_path, 'w', encoding='utf-8') as f:
                    f.write(report_content)
                logger.info(f"Report saved to: {output_path}")
                
                # Also output to stdout for text format if no custom filename provided
                if args.output_format == 'text' and not args.output_filename:
                    print(report_content)
            
        except Exception as e:
            import traceback
            logger.error(f"Failed to generate report: {e}")
            logger.error(f"Full traceback: {traceback.format_exc()}")
            return 1
        
        logger.info("Analysis complete")
        analysis_cache.log_stats()
        return 0
        
    except GravitonValidatorError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nOperation cancelled by user", file=sys.stderr)
        return 130
    except Exception as e:
        import traceback
        print(f"Unexpected error: {e}", file=sys.stderr)
        print("\nFull traceback:", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        return 1


# Functions are available as module attributes
__all__ = ['main', 'create_argument_parser', 'validate_arguments']

if __name__ == '__main__':
    sys.exit(main())