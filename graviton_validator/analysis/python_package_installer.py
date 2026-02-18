#!/usr/bin/env python3
"""
Python Package Installer - Runtime Analysis Tool
Rewritten to use ComponentResult schema from models.py
"""

import subprocess
import json
import sys
import os
import logging
import time
import datetime
import re
import argparse
from typing import List, Dict, Optional

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from graviton_validator.models import ComponentResult, SoftwareComponent, CompatibilityResult, CompatibilityStatus
except ImportError:
    try:
        # Try relative import
        from ..models import ComponentResult, SoftwareComponent, CompatibilityResult, CompatibilityStatus
    except ImportError:
        # Fallback for standalone execution
        import sys
        from pathlib import Path
        sys.path.insert(0, str(Path(__file__).parent.parent))
        from models import ComponentResult, SoftwareComponent, CompatibilityResult, CompatibilityStatus

# Initialize logger with structured tags
logger = logging.getLogger(__name__)
handler = logging.StreamHandler(sys.stderr)
formatter = logging.Formatter('[%(asctime)s] %(levelname)s: %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.DEBUG if os.environ.get('DEBUG') else logging.INFO)

def debug(msg: str, tag: str = "PYTHON_MAIN"):
    logger.debug(f"[{tag}] {msg}")

def info(msg: str, tag: str = "PYTHON_MAIN"):
    logger.info(f"[{tag}] {msg}")

def warn(msg: str, tag: str = "PYTHON_MAIN"):
    logger.warning(f"[{tag}] {msg}")

def error(msg: str, tag: str = "PYTHON_MAIN"):
    logger.error(f"[{tag}] {msg}")

# Critical packages that should never be uninstalled
CRITICAL_PACKAGES = {'pip', 'pip3', 'setuptools', 'wheel', 'distutils', 'requests', 'urllib3', 'certifi'}

def get_pip_command() -> str:
    """Detect available pip command with fallback mechanism."""
    pip_commands = ['pip3', 'pip', 'python3 -m pip', 'python -m pip']
    
    for cmd in pip_commands:
        try:
            cmd_parts = cmd.split()
            result = subprocess.run(cmd_parts + ['--version'], capture_output=True, timeout=10)
            if result.returncode == 0:
                debug(f"Found working pip command: {cmd}", "PYTHON_INSTALLER")
                return cmd
        except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError):
            continue
    
    # Fallback to pip3 if nothing works
    warn("No pip command found, falling back to pip3", "PYTHON_INSTALLER")
    return 'pip3'

def analyze_python_packages(requirements_file: str) -> List[ComponentResult]:
    """Test Python packages with intelligent multi-version handling."""
    info(f"Starting Python package analysis for: {requirements_file}", "PYTHON_ANALYZER")
    
    if not os.path.exists(requirements_file):
        error(f"Requirements file not found: {requirements_file}", "PYTHON_ANALYZER")
        raise FileNotFoundError(f"Requirements file {requirements_file} not found")
    
    debug("Requirements file exists, proceeding with parsing", "PYTHON_PARSER")
    
    # Read requirements file
    with open(requirements_file, 'r') as f:
        lines = [line.strip() for line in f.readlines() if line.strip() and not line.startswith('#')]
    
    info(f"Read {len(lines)} package entries from requirements file", "PYTHON_PARSER")
    debug(f"Raw package entries: {lines}", "PYTHON_PARSER")
    
    # Group packages by name and sort versions
    package_groups = {}
    for i, line in enumerate(lines, 1):
        # Parse package name from various version specifiers
        package = line
        version = 'latest'
        
        # Handle different version specifiers
        for operator in ['==', '>=', '<=', '>', '<', '~=', '!=']:
            if operator in line:
                package, version = line.split(operator, 1)
                break
        
        package = package.strip()
        version = version.strip()
        
        debug(f"Line {i}: Found package '{package}' version '{version}'", "PYTHON_PARSER")
        
        if package not in package_groups:
            package_groups[package] = []
        package_groups[package].append(version)
    
    info(f"Grouped into {len(package_groups)} unique packages", "PYTHON_PARSER")
    debug(f"Package groups: {list(package_groups.keys())}", "PYTHON_PARSER")
    
    # Sort versions for each package
    for package in package_groups:
        original_versions = package_groups[package].copy()
        package_groups[package] = sort_versions(package_groups[package])
        debug(f"Package {package}: sorted versions {original_versions} -> {package_groups[package]}", "PYTHON_PARSER")
    
    results = []
    for i, (package_name, versions) in enumerate(package_groups.items(), 1):
        info(f"Processing package {i}/{len(package_groups)}: {package_name} (versions: {', '.join(versions)})", "PYTHON_ANALYZER")
        package_results = analyze_package_versions(package_name, versions)
        debug(f"Package {package_name} produced {len(package_results)} results", "PYTHON_ANALYZER")
        results.extend(package_results)
    
    info(f"Python package analysis complete. Total results: {len(results)}", "PYTHON_ANALYZER")
    return results

def analyze_package_versions(package_name: str, versions: List[str]) -> List[ComponentResult]:
    """Test multiple versions of a package intelligently with version inheritance."""
    debug(f"Testing package versions for {package_name}: {', '.join(versions)}", "PYTHON_TESTER")
    
    results = []
    working_version = None
    working_native_build = 'No'
    failed_versions = {}
    
    # Test versions in order (lowest first)
    for i, version in enumerate(versions, 1):
        if version == 'latest':
            debug("Skipping 'latest' version for now (will process at end)", "PYTHON_TESTER")
            continue
            
        debug(f"Processing version {i}/{len([v for v in versions if v != 'latest'])}: {package_name}@{version}", "PYTHON_TESTER")
        
        if working_version:
            debug(f"Found working version {working_version}, inheriting compatibility for {version}", "PYTHON_TESTER")
            # Inherit compatibility for higher versions
            results.append(create_component_result(
                package_name=package_name,
                version=version,
                status=CompatibilityStatus.COMPATIBLE,
                notes=f'Compatible (inherited from working version {working_version})',
                test_output='',
                install_status='Success',
                fallback_used=False,
                original_version=version,
                native_build_detected=working_native_build,
                test_execution_output='N/A - Compatible with working version',
                error_details='',
                error_type='unknown'
            ))
        else:
            debug(f"No working version yet, testing {package_name}@{version}", "PYTHON_TESTER")
            # Test this version
            test_result = pip_install_test(f"{package_name}=={version}")
            
            if test_result['success']:
                info(f"✓ Successfully installed {package_name}@{version}", "PYTHON_INSTALLER")
                # Found working version
                working_version = version
                working_native_build = detect_native_build(test_result['output'], package_name)
                debug(f"Native build detected: {working_native_build}", "PYTHON_VALIDATOR")
                
                # Determine status based on native build detection
                if working_native_build == 'needs_verification':
                    status = CompatibilityStatus.NEEDS_VERIFICATION
                    notes = f'Successfully installed {package_name}=={version}. Needs manual verification: native .so files detected but could not confirm ARM64 compatibility'
                elif working_native_build == 'Yes':
                    status = CompatibilityStatus.COMPATIBLE
                    notes = f'Successfully installed {package_name}=={version} (ARM64 native compilation successful)'
                else:
                    status = CompatibilityStatus.COMPATIBLE
                    notes = f'Successfully installed {package_name}=={version}'
                
                results.append(create_component_result(
                    package_name=package_name,
                    version=version,
                    status=status,
                    notes=notes,
                    test_output=test_result['output'],
                    install_status='Success',
                    fallback_used=False,
                    original_version=version,
                    native_build_detected=working_native_build,
                    test_execution_output='N/A - No test script available',
                    error_details='',
                    error_type='unknown'
                ))
            else:
                warn(f"✗ Failed to install {package_name}@{version}: {test_result['error'][:100]}...", "PYTHON_INSTALLER")
                # Store failed version for later use
                failed_versions[version] = test_result['error']
                debug(f"Error details for {package_name}@{version}: {test_result['error']}", "PYTHON_INSTALLER")
    
    # Process failed versions - if we found a working version, mark earlier failures as needs_upgrade
    for version in versions:
        if version == 'latest' or version in [r.component.version for r in results]:
            continue
            
        if working_version:
            # We found a working version, so this failed version needs upgrade
            results.append(create_component_result(
                package_name=package_name,
                version=version,
                status=CompatibilityStatus.NEEDS_UPGRADE,
                notes=f'Version {version} failed, but version {working_version} works',
                test_output=failed_versions.get(version, ''),
                install_status='Failed',
                fallback_used=False,
                original_version=version,
                native_build_detected=working_native_build,
                test_execution_output='',
                error_details=extract_error_details(failed_versions.get(version, '')),
                error_type=classify_error(failed_versions.get(version, ''))
            ))
        else:
            # No working version found yet, try latest version fallback
            debug(f"No working version found, trying latest version fallback for {package_name}@{version}", "PYTHON_TESTER")
            latest_result = pip_install_test(package_name)
            
            if latest_result['success']:
                installed_version = extract_pip_version(latest_result['output'], package_name)
                native_build = detect_native_build(latest_result['output'], package_name)
                
                # Mark original version as needs_upgrade since latest works
                results.append(create_component_result(
                    package_name=package_name,
                    version=version,
                    status=CompatibilityStatus.NEEDS_UPGRADE,
                    notes=f'Version {version} failed, but latest version {installed_version} works',
                    test_output=failed_versions.get(version, ''),
                    install_status='Failed',
                    fallback_used=True,
                    original_version=version,
                    native_build_detected=native_build,
                    test_execution_output='',
                    error_details=extract_error_details(failed_versions.get(version, '')),
                    error_type=classify_error(failed_versions.get(version, ''))
                ))
                
                # Add latest version result if not already present
                if 'latest' not in [r.component.version for r in results]:
                    latest_status = CompatibilityStatus.NEEDS_VERIFICATION if native_build == 'needs_verification' else CompatibilityStatus.COMPATIBLE
                    latest_notes = f'Latest version {installed_version} works'
                    if native_build == 'needs_verification':
                        latest_notes += '. Needs manual verification: native .so files detected but could not confirm ARM64 compatibility'
                    elif native_build == 'Yes':
                        latest_notes += ' (ARM64 native compilation successful)'
                    
                    results.append(create_component_result(
                        package_name=package_name,
                        version='latest',
                        status=latest_status,
                        notes=latest_notes,
                        test_output=latest_result['output'],
                        install_status='Success',
                        fallback_used=True,
                        original_version='latest',
                        native_build_detected=native_build,
                        test_execution_output='N/A - No test script available',
                        error_details='',
                        error_type='unknown'
                    ))
            else:
                # Both specific and latest versions failed
                results.append(create_component_result(
                    package_name=package_name,
                    version=version,
                    status=CompatibilityStatus.INCOMPATIBLE,
                    notes=f'Version {version} and latest version both failed',
                    test_output=failed_versions.get(version, ''),
                    install_status='Failed',
                    fallback_used=True,
                    original_version=version,
                    native_build_detected='No',
                    test_execution_output='',
                    error_details=extract_error_details(failed_versions.get(version, '')),
                    error_type=classify_error(failed_versions.get(version, ''))
                ))
    
    # Handle failed versions with latest version fallback (like old script)
    for version in versions:
        if version == 'latest' or version in [r.component.version for r in results]:
            continue
            
        if version in failed_versions:
            debug(f"Testing latest version fallback for failed version {version}", "PYTHON_TESTER")
            # Try latest version installation like old script
            latest_result = pip_install_test(package_name)
            
            if latest_result['success']:
                installed_version = extract_pip_version(latest_result['output'], package_name)
                native_build = detect_native_build(latest_result['output'], package_name)
                
                # Mark failed version as needs_upgrade since latest works
                status = CompatibilityStatus.NEEDS_UPGRADE
                notes = f'Version {version} failed, but latest version {installed_version} works'
                
                results.append(create_component_result(
                    package_name=package_name,
                    version=version,
                    status=status,
                    notes=notes,
                    test_output=failed_versions[version],
                    install_status='Failed',
                    fallback_used=True,
                    original_version=version,
                    native_build_detected=native_build,
                    test_execution_output='',
                    error_details=extract_error_details(failed_versions[version]),
                    error_type=classify_error(failed_versions[version])
                ))
                
                # Add latest version result
                latest_status = CompatibilityStatus.NEEDS_VERIFICATION if native_build == 'needs_verification' else CompatibilityStatus.COMPATIBLE
                latest_notes = f'Latest version {installed_version} works'
                if native_build == 'needs_verification':
                    latest_notes += '. Needs manual verification: native .so files detected but could not confirm ARM64 compatibility'
                elif native_build == 'Yes':
                    latest_notes += ' (ARM64 native compilation successful)'
                
                results.append(create_component_result(
                    package_name=package_name,
                    version='latest',
                    status=latest_status,
                    notes=latest_notes,
                    test_output=latest_result['output'],
                    install_status='Success',
                    fallback_used=True,
                    original_version='latest',
                    native_build_detected=native_build,
                    test_execution_output='N/A - No test script available',
                    error_details='',
                    error_type='unknown'
                ))
            else:
                # Both specific and latest versions failed
                results.append(create_component_result(
                    package_name=package_name,
                    version=version,
                    status=CompatibilityStatus.INCOMPATIBLE,
                    notes=f'Version {version} and latest version both failed',
                    test_output=failed_versions[version],
                    install_status='Failed',
                    fallback_used=True,
                    original_version=version,
                    native_build_detected='No',
                    test_execution_output='',
                    error_details=extract_error_details(failed_versions[version]),
                    error_type=classify_error(failed_versions[version])
                ))
    
    # Handle explicit 'latest' version if present
    if 'latest' in versions and 'latest' not in [r.component.version for r in results]:
        if working_version:
            # We have a working version, latest is likely compatible
            results.append(create_component_result(
                package_name=package_name,
                version='latest',
                status=CompatibilityStatus.COMPATIBLE,
                notes=f'Latest version likely compatible (working version {working_version} found)',
                test_output='',
                install_status='Success',
                fallback_used=False,
                original_version='latest',
                native_build_detected=working_native_build,
                test_execution_output='N/A - Compatible with working version',
                error_details='',
                error_type='unknown'
            ))
        else:
            # No working version found, test latest
            latest_result = pip_install_test(package_name)
            
            if latest_result['success']:
                installed_version = extract_pip_version(latest_result['output'], package_name)
                native_build = detect_native_build(latest_result['output'], package_name)
                
                status = CompatibilityStatus.NEEDS_VERIFICATION if native_build == 'needs_verification' else CompatibilityStatus.COMPATIBLE
                notes = f'Latest version {installed_version} works'
                if native_build == 'needs_verification':
                    notes += '. Needs manual verification: native .so files detected but could not confirm ARM64 compatibility'
                elif native_build == 'Yes':
                    notes += ' (ARM64 native compilation successful)'
                
                results.append(create_component_result(
                    package_name=package_name,
                    version='latest',
                    status=status,
                    notes=notes,
                    test_output=latest_result['output'],
                    install_status='Success',
                    fallback_used=True,
                    original_version='latest',
                    native_build_detected=native_build,
                    test_execution_output='N/A - No test script available',
                    error_details='',
                    error_type='unknown'
                ))
            else:
                # Latest also failed
                results.append(create_component_result(
                    package_name=package_name,
                    version='latest',
                    status=CompatibilityStatus.INCOMPATIBLE,
                    notes='Latest version also failed to install',
                    test_output=latest_result['error'],
                    install_status='Failed',
                    fallback_used=True,
                    original_version='latest',
                    native_build_detected='No',
                    test_execution_output='',
                    error_details=extract_error_details(latest_result['error']),
                    error_type=classify_error(latest_result['error'])
                ))
    
    return results

def pip_install_test(package_spec: str) -> Dict[str, any]:
    """Test pip install for a package specification with pip freeze verification."""
    package_name = package_spec.split('==')[0] if '==' in package_spec else package_spec
    debug(f"Starting pip install test for: {package_spec}", "PYTHON_INSTALLER")
    
    try:
        pip_cmd = get_pip_command()
        cmd = pip_cmd.split() + ['install', package_spec, '--force-reinstall']
        debug(f"Executing command: {' '.join(cmd)}", "PYTHON_INSTALLER")
        
        start_time = time.time()
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        duration = time.time() - start_time
        
        debug(f"Command completed in {duration:.2f}s with exit code: {result.returncode}", "PYTHON_INSTALLER")
        debug(f"STDOUT ({len(result.stdout)} chars): {result.stdout[:200]}{'...' if len(result.stdout) > 200 else ''}", "PYTHON_INSTALLER")
        debug(f"STDERR ({len(result.stderr)} chars): {result.stderr[:200]}{'...' if len(result.stderr) > 200 else ''}", "PYTHON_INSTALLER")
        
        # Verify installation with pip freeze --all
        success = False
        if result.returncode == 0:
            debug(f"Verifying installation with pip freeze", "PYTHON_INSTALLER")
            try:
                freeze_cmd = pip_cmd.split() + ['freeze', '--all']
                freeze_result = subprocess.run(freeze_cmd, capture_output=True, text=True, timeout=30)
                if freeze_result.returncode == 0:
                    freeze_output = freeze_result.stdout
                    debug(f"Freeze output ({len(freeze_output)} chars): {freeze_output[:200]}{'...' if len(freeze_output) > 200 else ''}", "PYTHON_INSTALLER")
                    
                    # Triple verification like old script
                    success_match = re.search(f'Successfully installed.*{package_name}', result.stdout)
                    already_satisfied = re.search(f'Requirement already satisfied', result.stdout)
                    in_freeze_list = re.search(f'{package_name}', freeze_output, re.MULTILINE)
                    
                    success = bool(success_match or already_satisfied or in_freeze_list)
                    debug(f"Verification results - success_match: {bool(success_match)}, already_satisfied: {bool(already_satisfied)}, in_freeze: {bool(in_freeze_list)}", "PYTHON_INSTALLER")
                else:
                    debug(f"Pip freeze failed with exit code: {freeze_result.returncode}", "PYTHON_INSTALLER")
            except Exception as freeze_error:
                debug(f"Pip freeze verification failed: {freeze_error}", "PYTHON_INSTALLER")
        
        # Cleanup: uninstall the package after testing (skip critical packages)
        debug(f"Starting cleanup for {package_name}", "PYTHON_INSTALLER")
        if package_name.lower() not in CRITICAL_PACKAGES:
            try:
                cleanup_cmd = pip_cmd.split() + ['uninstall', package_name, '-y']
                cleanup_result = subprocess.run(cleanup_cmd, capture_output=True, timeout=30)
                debug(f"Cleanup completed with exit code: {cleanup_result.returncode}", "PYTHON_INSTALLER")
            except Exception as cleanup_error:
                debug(f"Cleanup failed (ignoring): {cleanup_error}", "PYTHON_INSTALLER")
        else:
            debug(f"Skipping cleanup for critical package: {package_name}", "PYTHON_INSTALLER")
        
        test_result = {
            'success': success,
            'output': result.stdout,
            'error': result.stderr
        }
        debug(f"Install test result: success={test_result['success']}", "PYTHON_INSTALLER")
        return test_result
        
    except subprocess.TimeoutExpired:
        duration = time.time() - start_time
        warn(f"Pip install timed out after {duration:.2f}s", "PYTHON_INSTALLER")
        
        # Try to cleanup even on timeout (skip critical packages)
        debug("Attempting cleanup after timeout", "PYTHON_INSTALLER")
        if package_name.lower() not in CRITICAL_PACKAGES:
            try:
                cleanup_cmd = pip_cmd.split() + ['uninstall', package_name, '-y']
                subprocess.run(cleanup_cmd, capture_output=True, timeout=30)
                debug("Timeout cleanup completed", "PYTHON_INSTALLER")
            except Exception as cleanup_error:
                debug(f"Timeout cleanup failed (ignoring): {cleanup_error}", "PYTHON_INSTALLER")
        else:
            debug(f"Skipping timeout cleanup for critical package: {package_name}", "PYTHON_INSTALLER")
        
        return {
            'success': False,
            'output': '',
            'error': 'Installation timed out after 120 seconds'
        }
    except Exception as e:
        error(f"Pip install test exception: {e}", "PYTHON_INSTALLER")
        debug(f"Exception details: {e.__class__.__name__}: {e}", "PYTHON_INSTALLER")
        return {
            'success': False,
            'output': '',
            'error': f'Installation failed: {str(e)}'
        }

def create_component_result(package_name: str, version: str, status: CompatibilityStatus, 
                          notes: str, test_output: str, install_status: str,
                          fallback_used: bool, original_version: str, 
                          native_build_detected: str, test_execution_output: str,
                          error_details: str, error_type: str) -> ComponentResult:
    """Create ComponentResult using schema from models.py."""
    import platform
    
    # Determine minimum supported version and recommended version
    minimum_supported_version = version if status == CompatibilityStatus.COMPATIBLE else None
    recommended_version = None
    if status == CompatibilityStatus.NEEDS_UPGRADE:
        # Extract recommended version from notes if available
        if 'version' in notes and 'works' in notes:
            import re
            match = re.search(r'version (\S+) works', notes)
            if match:
                recommended_version = match.group(1)
    
    # Create SoftwareComponent
    component = SoftwareComponent(
        name=package_name,
        version=version,
        component_type="python-3.11",  # Default Python version
        source_sbom="runtime_analysis",
        properties={
            "environment": f"native_python_3.11_{platform.system().lower()}-{platform.release()}",
            "native_build_detected": native_build_detected,
            "install_status": install_status,
            "fallback_used": str(fallback_used).lower(),
            "original_version": original_version,
            "test_output": test_output,
            "test_execution_output": test_execution_output,
            "error_details": error_details,
            "error_type": error_type,
            "timestamp": datetime.datetime.now().isoformat(),
            "runtime_analysis": "true"
        }
    )
    
    # Create CompatibilityResult
    compatibility = CompatibilityResult(
        status=status,
        current_version_supported=(status in [CompatibilityStatus.COMPATIBLE, CompatibilityStatus.NEEDS_VERIFICATION]),
        minimum_supported_version=minimum_supported_version,
        recommended_version=recommended_version,
        notes=notes,
        confidence_level=0.9  # High confidence for runtime testing
    )
    
    return ComponentResult(
        component=component,
        compatibility=compatibility,
        matched_name=None
    )

def extract_pip_version(output: str, package: str) -> str:
    """Extract installed version from pip output."""
    lines = output.split('\n')
    for line in lines:
        if 'Successfully installed' in line and package in line:
            parts = line.split()
            for part in parts:
                if part.startswith(f"{package}-"):
                    return part.replace(f"{package}-", "")
    return 'unknown'

def detect_native_build(output: str, package_name: str) -> str:
    """Detect native build from pip output and file system."""
    debug(f"Detecting native build for package: {package_name}", "PYTHON_VALIDATOR")
    
    # Method 1: Check pip output for compilation indicators
    native_indicators = [
        'building wheel', 'running build_ext', 'gcc', 'g++', 'clang',
        'compiling', 'linking', 'building extension', 'cython'
    ]
    
    output_lower = output.lower()
    for indicator in native_indicators:
        if indicator in output_lower:
            debug(f"Native build indicator found in output: '{indicator}'", "PYTHON_VALIDATOR")
            return 'Yes'
    
    debug("No native build indicators in pip output, checking installed files", "PYTHON_VALIDATOR")
    # Method 2: Check installed files for native extensions
    result = detect_native_files(package_name)
    debug(f"Native files detection result: {result}", "PYTHON_VALIDATOR")
    return result

def detect_native_files(package_name: str) -> str:
    """Detect native files and check their architecture compatibility."""
    debug(f"Checking for native files in package: {package_name}", "PYTHON_VALIDATOR")
    
    try:
        import site
        
        # Get site-packages directory
        site_packages = site.getsitepackages()[0] if site.getsitepackages() else None
        debug(f"Site-packages directory: {site_packages}", "PYTHON_VALIDATOR")
        
        if not site_packages:
            debug("No site-packages directory found", "PYTHON_VALIDATOR")
            return 'No'
        
        # Check package directory for native files
        package_dir = os.path.join(site_packages, package_name)
        debug(f"Checking package directory: {package_dir}", "PYTHON_VALIDATOR")
        
        if not os.path.exists(package_dir):
            # Try with underscores (some packages use different naming)
            alt_package_dir = os.path.join(site_packages, package_name.replace('-', '_'))
            debug(f"Primary directory not found, trying alternative: {alt_package_dir}", "PYTHON_VALIDATOR")
            
            if not os.path.exists(alt_package_dir):
                debug("No package directory found", "PYTHON_VALIDATOR")
                return 'No'
            package_dir = alt_package_dir
        
        debug(f"Using package directory: {package_dir}", "PYTHON_VALIDATOR")
        
        # Native file extensions
        native_extensions = ['.so', '.dylib', '.dll', '.pyd']
        native_files = []
        
        # Recursively search for native files
        for root, dirs, files in os.walk(package_dir):
            for file in files:
                if any(file.endswith(ext) for ext in native_extensions):
                    native_files.append(os.path.join(root, file))
        
        debug(f"Found {len(native_files)} native files: {[os.path.basename(f) for f in native_files[:5]]}{'...' if len(native_files) > 5 else ''}", "PYTHON_VALIDATOR")
        
        if not native_files:
            debug("No native files found", "PYTHON_VALIDATOR")
            return 'No'
        
        # Check architecture of native files
        result = check_native_file_architecture(native_files)
        debug(f"Native file architecture check result: {result}", "PYTHON_VALIDATOR")
        return result
        
    except Exception as e:
        debug(f"Native files detection exception: {e}", "PYTHON_VALIDATOR")
        return 'No'

def check_native_file_architecture(native_files: List[str]) -> str:
    """Check architecture compatibility of native files."""
    debug(f"Checking architecture of {len(native_files)} native files", "PYTHON_VALIDATOR")
    
    try:
        import platform
        
        current_arch = platform.machine().lower()
        debug(f"Current architecture: {current_arch}", "PYTHON_VALIDATOR")
        
        x86_only_files = []
        
        for i, file_path in enumerate(native_files[:5], 1):  # Check first 5 files
            debug(f"Checking file {i}/5: {os.path.basename(file_path)}", "PYTHON_VALIDATOR")
            
            try:
                # Use 'file' command to check architecture
                result = subprocess.run(['file', file_path], capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    file_info = result.stdout.lower()
                    debug(f"File command output: {file_info.strip()}", "PYTHON_VALIDATOR")
                    
                    # Check for x86_64 only files
                    if 'x86_64' in file_info or 'x86-64' in file_info:
                        if not ('arm64' in file_info or 'aarch64' in file_info):
                            debug(f"x86-only file detected: {os.path.basename(file_path)}", "PYTHON_VALIDATOR")
                            x86_only_files.append(file_path)
                    
                    # Check for ARM64 files
                    elif 'arm64' in file_info or 'aarch64' in file_info:
                        debug(f"ARM64 compatible file: {os.path.basename(file_path)}", "PYTHON_VALIDATOR")
                        continue
                    
                    # Check for universal/fat binaries (macOS)
                    elif 'universal binary' in file_info or 'fat file' in file_info:
                        debug(f"Universal binary detected: {os.path.basename(file_path)}", "PYTHON_VALIDATOR")
                        continue
                else:
                    debug(f"File command failed for {os.path.basename(file_path)}: exit code {result.returncode}", "PYTHON_VALIDATOR")
                        
            except (subprocess.TimeoutExpired, subprocess.SubprocessError) as e:
                debug(f"File command exception for {os.path.basename(file_path)}: {e}", "PYTHON_VALIDATOR")
                continue
        
        if x86_only_files:
            debug(f"Found {len(x86_only_files)} x86-only files, returning 'needs_verification'", "PYTHON_VALIDATOR")
            return 'needs_verification'
        elif native_files:
            debug("All native files are ARM64 compatible, returning 'Yes'", "PYTHON_VALIDATOR")
            return 'Yes'
        else:
            debug("No native files found, returning 'No'", "PYTHON_VALIDATOR")
            return 'No'
            
    except Exception as e:
        debug(f"Native file architecture check exception: {e}", "PYTHON_VALIDATOR")
        return 'Yes'  # Default to Yes if we can't determine

def extract_error_details(error: str) -> str:
    """Extract relevant error details."""
    if not error:
        return ''
    
    lines = error.split('\n')
    relevant_lines = []
    
    for line in lines:
        line = line.strip()
        if any(keyword in line.lower() for keyword in ['error', 'failed', 'exception', 'timeout']):
            relevant_lines.append(line)
            if len(relevant_lines) >= 3:
                break
    
    return '; '.join(relevant_lines) if relevant_lines else error

def sort_versions(versions: List[str]) -> List[str]:
    """Sort versions semantically, with 'latest' at the end."""
    if not versions:
        return versions
    
    # Separate 'latest' from versioned entries
    versioned = [v for v in versions if v != 'latest']
    has_latest = 'latest' in versions
    
    # Simple semantic version sorting
    def version_key(version):
        try:
            parts = []
            for part in version.replace('-', '.').replace('_', '.').split('.'):
                try:
                    parts.append(int(part))
                except ValueError:
                    parts.append(part)
            return parts
        except:
            return [version]
    
    try:
        versioned.sort(key=version_key)
    except:
        versioned.sort()
    
    if has_latest:
        versioned.append('latest')
    
    return versioned

def classify_error(error: str) -> str:
    """Classify error type."""
    if not error:
        return 'unknown'
    
    error_lower = error.lower()
    
    if any(keyword in error_lower for keyword in ['timeout', 'network', 'connection', 'resolve']):
        return 'network'
    elif any(keyword in error_lower for keyword in ['gcc', 'compile', 'build', 'cython']):
        return 'native_build'
    elif any(keyword in error_lower for keyword in ['permission', 'access']):
        return 'permissions'
    elif any(keyword in error_lower for keyword in ['dependency', 'requirement']):
        return 'dependency'
    else:
        return 'unknown'

def serialize_results(results: List[ComponentResult]) -> List[Dict]:
    """Serialize ComponentResult objects to flattened JSON format (matching SBOM structure)."""
    serialized = []
    for result in results:
        # Flattened structure matching SBOM format but preserving all fields
        result_dict = {
            "name": result.component.name,
            "version": result.component.version,
            "type": result.component.component_type,
            "source_sbom": result.component.source_sbom,
            "compatibility": {
                "status": result.compatibility.status.value,
                "current_version_supported": result.compatibility.current_version_supported,
                "minimum_supported_version": result.compatibility.minimum_supported_version,
                "recommended_version": result.compatibility.recommended_version,
                "notes": result.compatibility.notes,
                "confidence_level": result.compatibility.confidence_level
            },
            "parent_component": result.component.parent_component,
            "child_components": result.component.child_components,
            "source_package": result.component.source_package
        }
        
        # Add matched name if available
        if result.matched_name:
            result_dict["matched_name"] = result.matched_name
        
        # Add properties if available
        if result.component.properties:
            result_dict["properties"] = result.component.properties
        
        serialized.append(result_dict)
    return serialized

def show_help():
    """Display help information for Python package installer."""
    help_text = """
Python Package Installer - ARM64 Compatibility Analyzer

USAGE:
    python python_package_installer.py <requirements_file> [OPTIONS]

ARGUMENTS:
    requirements_file   Path to requirements.txt file to analyze

OPTIONS:
    -o, --output FILE  Save analysis results to specified JSON file
    -h, --help         Show this help message and exit

ENVIRONMENT VARIABLES:
    DEBUG              Enable debug logging with detailed output

DESCRIPTION:
    Analyzes Python packages from requirements.txt for ARM64/Graviton compatibility.
    Tests package installation with pip, detects native builds, and performs
    architecture verification. Supports version inheritance and fallback testing.

EXAMPLES:
    python python_package_installer.py requirements.txt
    python python_package_installer.py requirements.txt -o results.json
    DEBUG=1 python python_package_installer.py requirements.txt
    python python_package_installer.py my-requirements.txt

OUTPUT:
    JSON format with compatibility status, installation results, native build
    detection, and architecture verification for each package dependency.
    """
    print(help_text)

if __name__ == '__main__':
    import argparse
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Python Package Installer - ARM64 Compatibility Analyzer', add_help=False)
    parser.add_argument('requirements_file', nargs='?', help='Path to requirements.txt file')
    parser.add_argument('-o', '--output', help='Output JSON file path')
    parser.add_argument('-h', '--help', action='store_true', help='Show help message')
    
    args = parser.parse_args()
    
    # Enable debug logging if DEBUG environment variable is set
    if os.environ.get('DEBUG'):
        logger.setLevel(logging.DEBUG)
        debug("Debug logging enabled")
    
    # Check for help request or missing arguments
    if args.help or not args.requirements_file:
        show_help()
        if not args.requirements_file:
            print("\nError: requirements.txt file is required.", file=sys.stderr)
            sys.exit(1)
        sys.exit(0)
    
    info("Python Package Installer starting...")
    debug(f"Command line arguments: requirements_file={args.requirements_file}, output={args.output}")
    debug(f"Environment variables: DEBUG={os.environ.get('DEBUG')}, PATH={os.environ.get('PATH', '')[:100]}...")
    
    requirements_file = args.requirements_file
    info(f"Processing requirements file: {requirements_file}")
    
    start_time = time.time()
    try:
        results = analyze_python_packages(requirements_file)
        duration = time.time() - start_time
        
        info(f"Analysis completed in {duration:.2f}s")
        info(f"Generated {len(results)} results")
        
        # Output results summary to debug log
        if results:
            status_counts = {}
            for result in results:
                status = result.compatibility.status.value
                status_counts[status] = status_counts.get(status, 0) + 1
            debug(f"Results summary: {status_counts}")
        
        # Serialize and output results
        serialized_results = serialize_results(results)
        output_json = json.dumps(serialized_results, indent=2)
        
        if args.output:
            debug(f"Writing results to file: {args.output}")
            with open(args.output, 'w') as f:
                f.write(output_json)
            info(f"Results saved to: {args.output}")
        else:
            print(output_json)
        
        info("Python Package Installer finished successfully")
        
    except Exception as e:
        error(f"Python Package Installer failed: {e}")
        debug(f"Exception details: {e.__class__.__name__}: {e}")
        print(f"Error: {e}", file=sys.stderr)
        print("Use -h or --help for usage information.", file=sys.stderr)
        sys.exit(1)