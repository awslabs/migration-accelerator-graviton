#!/usr/bin/env python3
"""
Enhanced Node.js package tester with Python implementation.
Includes test execution, file system native detection, and enhanced error handling.
Uses the ComponentResult schema from models.py.
"""

import json
import os
import sys
import subprocess
import tempfile
import shutil
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
import argparse

# Import schema classes from models.py with fallback
try:
    from ..models import SoftwareComponent, CompatibilityResult, ComponentResult, CompatibilityStatus
except ImportError:
    try:
        # Try absolute import from graviton_validator
        from graviton_validator.models import SoftwareComponent, CompatibilityResult, ComponentResult, CompatibilityStatus
    except ImportError:
        # Handle direct script execution
        import sys
        from pathlib import Path
        script_dir = Path(__file__).parent
        sys.path.insert(0, str(script_dir.parent))  # Add graviton_validator to path
        from models import SoftwareComponent, CompatibilityResult, ComponentResult, CompatibilityStatus

# Configure logging
LOG_LEVELS = {'ERROR': logging.ERROR, 'WARN': logging.WARNING, 'INFO': logging.INFO, 'DEBUG': logging.DEBUG}
current_log_level = LOG_LEVELS.get(os.environ.get('NODE_LOG_LEVEL', 'INFO'), logging.INFO)

logging.basicConfig(
    level=current_log_level,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    datefmt='%Y-%m-%dT%H:%M:%S.%fZ',
    stream=sys.stderr
)

logger = logging.getLogger(__name__)


class NodeJSPackageInstaller:
    """Node.js package installer and compatibility tester."""
    
    def __init__(self):
        self.temp_dirs = []
        self.environment = self._detect_environment()
    
    def _detect_environment(self) -> str:
        """Detect the current runtime environment."""
        try:
            result = subprocess.run(['node', '--version'], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                node_version = result.stdout.strip()
                return f"native_nodejs_{node_version}_amazon-linux-2023"
        except Exception:
            pass
        return "native_nodejs_unknown_amazon-linux-2023"
    
    def test_nodejs_packages(self, package_json_path: str) -> List[ComponentResult]:
        """Test Node.js packages for compatibility."""
        logger.info(f"Starting Node.js package analysis for: {os.path.basename(package_json_path)}")
        logger.debug(f"Full path: {package_json_path}")
        
        try:
            actual_path = self._find_package_json(package_json_path)
            with open(actual_path, 'r') as f:
                package_data = json.load(f)
            
            dependencies = package_data.get('dependencies', {})
            logger.info(f"Found {len(dependencies)} dependencies to analyze")
            logger.debug(f"Dependencies: {', '.join(dependencies.keys())}")
            
            package_groups = self._group_and_sort_packages(dependencies)
            results = []
            
            for package_name, versions in package_groups.items():
                package_results = self._test_package_versions(package_name, versions, package_data)
                results.extend(package_results)
            
            return results
            
        except Exception as error:
            logger.error(f"Failed to analyze package.json: {error}")
            logger.debug(f"Error details: {error}", exc_info=True)
            raise
    
    def _find_package_json(self, package_json_path: str) -> str:
        """Find package.json file, supporting alternative naming patterns."""
        logger.debug(f"Looking for package.json at: {package_json_path}")
        
        if os.path.exists(package_json_path):
            logger.debug("Found package.json at specified path")
            return package_json_path
        
        directory = os.path.dirname(package_json_path)
        logger.debug(f"Searching for alternative package.json files in: {directory}")
        
        files = os.listdir(directory)
        package_json_files = [f for f in files if f.endswith('_package.json') or f.endswith('-package.json') or f == 'package.json']
        
        logger.debug(f"Found potential package.json files: {', '.join(package_json_files)}")
        
        if package_json_files:
            selected_file = os.path.join(directory, package_json_files[0])
            logger.info(f"Using alternative package.json: {package_json_files[0]}")
            return selected_file
        
        raise FileNotFoundError(f"No package.json files found in {directory}")
    
    def _group_and_sort_packages(self, dependencies: Dict[str, str]) -> Dict[str, List[str]]:
        """Group and deduplicate packages."""
        logger.debug("Grouping and deduplicating packages")
        groups = {}
        duplicates_found = 0
        
        for package_spec, version in dependencies.items():
            # Handle scoped packages correctly (e.g., @datadog/libdatadog)
            if package_spec.startswith('@'):
                # For scoped packages, the package name is the full spec
                package_name = package_spec
            else:
                # For regular packages, split on @ to handle package@version format
                package_name = package_spec.split('@')[0]
            
            if package_name not in groups:
                groups[package_name] = set()
            
            size_before = len(groups[package_name])
            groups[package_name].add(version)
            
            if len(groups[package_name]) == size_before:
                duplicates_found += 1
                logger.debug(f"Duplicate found: {package_name}@{version}")
        
        # Convert sets to sorted lists
        for package_name in groups:
            groups[package_name] = sorted(list(groups[package_name]))
            logger.debug(f"Package {package_name} has versions: {', '.join(groups[package_name])}")
        
        if duplicates_found > 0:
            logger.info(f"Removed {duplicates_found} duplicate package entries")
        
        return groups
    
    def _test_package_versions(self, package_name: str, versions: List[str], package_data: Dict[str, Any]) -> List[ComponentResult]:
        """Test all versions of a package."""
        logger.info(f"Testing package: {package_name} ({len(versions)} version{'s' if len(versions) > 1 else ''})")
        logger.debug(f"Versions to test: {', '.join(versions)}")
        
        results = []
        working_version = None
        failed_versions = {}
        
        for i, version in enumerate(versions):
            logger.debug(f"Processing version {i+1}/{len(versions)}: {package_name}@{version}")
            
            if working_version:
                logger.debug(f"Using working version {working_version} for {package_name}@{version}")
                # Use working version for remaining versions
                native_build = self._detect_native_build('', package_name)
                result = self._create_compatible_result(package_name, version, working_version, native_build, package_data, failed_versions)
                results.append(result)
                logger.debug(f"Created compatible result for {package_name}@{version} with status: {result.compatibility.status.value}")
            else:
                logger.debug(f"Testing installation: {package_name}@{version}")
                install_result = self._npm_install_test(f"{package_name}@{version}")
                
                if install_result['success']:
                    logger.debug(f"Installation successful: {package_name}@{version}")
                    native_build = self._detect_native_build(install_result['output'], package_name, install_result.get('temp_dir'))
                    logger.debug(f"Native build detection result: {native_build}")
                    
                    # Run tests if available
                    test_result = self._run_package_tests(package_name, package_data)
                    logger.debug(f"Test execution result: success={test_result['success']}, has_tests={test_result.get('has_tests', False)}")
                    
                    result = self._create_success_result(package_name, version, install_result, native_build, package_data, test_result)
                    results.append(result)
                    working_version = version
                    logger.debug(f"Set working version to {working_version} for remaining versions")
                else:
                    logger.debug(f"Installation failed: {package_name}@{version} - {install_result['error'][:100]}...")
                    failed_versions[version] = install_result['error']
                    logger.debug(f"Stored failure for version {version}, total failed versions: {len(failed_versions)}")
        
        # If no version worked, try latest
        if not working_version:
            logger.debug(f"No working version found for {package_name}, trying latest version")
            latest_result = self._npm_install_test(package_name)
            
            if latest_result['success']:
                installed_version = self._extract_npm_version(latest_result['output'], package_name, latest_result.get('temp_dir'))
                logger.debug(f"Latest version installation successful: {installed_version}")
                native_build = self._detect_native_build(latest_result['output'], package_name, latest_result.get('temp_dir'))
                
                for version in versions:
                    original_error = failed_versions.get(version, 'version installation failed')
                    result = self._create_fallback_result(package_name, version, installed_version, latest_result, native_build, package_data, original_error)
                    results.append(result)
                    logger.debug(f"Created fallback result for {package_name}@{version} -> {installed_version}")
            else:
                logger.debug(f"Latest version also failed for {package_name}: {latest_result['error'][:100]}")
                for version in versions:
                    result = self._create_failed_result(package_name, version, latest_result, package_data)
                    results.append(result)
                    logger.debug(f"Created failed result for {package_name}@{version}")
        
        logger.debug(f"Completed testing {package_name}: {len(results)} results generated")
        return results
    
    def _npm_install_test(self, package_spec: str) -> Dict[str, Any]:
        """Test npm package installation in isolated environment."""
        logger.debug(f"Starting npm install: {package_spec}")
        
        # Create temporary directory for isolated testing
        import tempfile
        temp_dir = tempfile.mkdtemp(prefix='npm_test_')
        self.temp_dirs.append(temp_dir)
        
        try:
            # Create minimal package.json in temp directory to avoid dependency conflicts
            temp_package_json = os.path.join(temp_dir, 'package.json')
            with open(temp_package_json, 'w') as f:
                json.dump({
                    "name": "test-package",
                    "version": "1.0.0",
                    "dependencies": {}
                }, f)
            
            cmd = ['npm', 'install', package_spec, '--no-save', '--no-optional', '--ignore-scripts']
            logger.debug(f"Executing command in {temp_dir}: {' '.join(cmd)}")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
                cwd=temp_dir  # Run in isolated directory
            )
            
            logger.debug(f"npm install completed: {package_spec} (exit code: {result.returncode})")
            logger.debug(f"stdout length: {len(result.stdout)}, stderr length: {len(result.stderr)}")
            
            if result.returncode != 0:
                logger.debug(f"Install error (first 200 chars): {result.stderr[:200]}")
                logger.debug(f"Install stdout (first 200 chars): {result.stdout[:200]}")
            else:
                logger.debug(f"Install success output (first 100 chars): {result.stdout[:100]}")
            
            return {
                'success': result.returncode == 0,
                'output': result.stdout,
                'error': result.stderr,
                'temp_dir': temp_dir
            }
        except subprocess.TimeoutExpired:
            logger.warning(f"npm install timeout after 120s: {package_spec}")
            return {
                'success': False,
                'output': '',
                'error': 'Installation timeout after 120 seconds',
                'temp_dir': temp_dir
            }
        except Exception as error:
            logger.warning(f"npm install process error: {package_spec} - {error}")
            logger.debug(f"Exception details: {error}", exc_info=True)
            return {
                'success': False,
                'output': '',
                'error': str(error),
                'temp_dir': temp_dir
            }
        # Note: temp_dir cleanup is now handled by _cleanup_temp_files() after analysis
    
    def _run_package_tests(self, package_name: str, package_data: Dict[str, Any]) -> Dict[str, Any]:
        """Run package tests if available."""
        has_test_script = package_data.get('scripts', {}).get('test')
        
        if not has_test_script:
            logger.debug(f"No test script found for {package_name}")
            return {
                'success': True,
                'output': 'N/A - No test script',
                'has_tests': False
            }
        
        logger.debug(f"Running tests for {package_name}: {has_test_script}")
        
        try:
            cmd = ['npm', 'test']
            logger.debug(f"Executing test command: {' '.join(cmd)}")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            logger.debug(f"Test execution completed for {package_name}: exit code {result.returncode}")
            logger.debug(f"Test stdout length: {len(result.stdout)}, stderr length: {len(result.stderr)}")
            
            if result.returncode != 0:
                logger.debug(f"Test failure output (first 200 chars): {(result.stdout + result.stderr)[:200]}")
            else:
                logger.debug(f"Test success output (first 100 chars): {result.stdout[:100]}")
            
            return {
                'success': result.returncode == 0,
                'output': result.stdout + result.stderr,
                'has_tests': True
            }
        except subprocess.TimeoutExpired:
            logger.warning(f"Test execution timeout after 60s for {package_name}")
            return {
                'success': False,
                'output': 'Test execution timeout after 60 seconds',
                'has_tests': True
            }
        except Exception as error:
            logger.warning(f"Test execution error for {package_name}: {error}")
            logger.debug(f"Test exception details: {error}", exc_info=True)
            return {
                'success': False,
                'output': str(error),
                'has_tests': True
            }
    
    def _detect_native_build(self, output: str, package_name: str, temp_dir: str = None) -> str:
        """Detect native build requirements."""
        logger.debug(f"Detecting native build for {package_name}")
        
        # Check npm output for native build indicators
        native_indicators = [
            'node-gyp', 'binding.gyp', 'gyp info', 'node-pre-gyp',
            'prebuild-install', 'make:', 'gcc', 'g++', 'clang', 'compiled successfully'
        ]
        
        output_lower = output.lower()
        for indicator in native_indicators:
            if indicator.lower() in output_lower:
                logger.debug(f"Native build detected via npm output: {indicator}")
                return 'Yes'
        
        # Check file system for native files
        file_system_result = self._detect_native_files(package_name, temp_dir)
        logger.debug(f"File system native detection for {package_name}: {file_system_result}")
        return file_system_result
    
    def _detect_native_files(self, package_name: str, temp_dir: str = None) -> str:
        """Detect native files in package directory."""
        try:
            if temp_dir:
                node_modules_path = os.path.join(temp_dir, 'node_modules', package_name)
            else:
                node_modules_path = os.path.join('node_modules', package_name)
            logger.debug(f"Scanning for native files in: {node_modules_path}")
            
            if not os.path.exists(node_modules_path):
                logger.debug(f"Package directory not found: {node_modules_path}")
                return 'No'
            
            native_files = [
                'binding.gyp', 'wscript', 'Makefile', 'CMakeLists.txt',
                'configure', 'configure.ac', 'configure.in'
            ]
            
            native_extensions = ['.so', '.dylib', '.dll', '.node']
            
            def check_directory(directory):
                try:
                    for root, dirs, files in os.walk(directory):
                        # Skip node_modules subdirectories
                        dirs[:] = [d for d in dirs if d != 'node_modules']
                        
                        for file in files:
                            if file in native_files or any(file.endswith(ext) for ext in native_extensions):
                                logger.debug(f"Native file found: {file}")
                                return True
                except PermissionError:
                    # Ignore permission errors
                    pass
                return False
            
            result = 'Yes' if check_directory(node_modules_path) else 'No'
            logger.debug(f"Native file scan result for {package_name}: {result}")
            return result
        except Exception as e:
            logger.debug(f"Error scanning native files for {package_name}: {e}")
            return 'No'
    
    def _extract_error_details(self, error: str, error_type: str = 'install') -> str:
        """Extract relevant error details with head/tail extraction like old script."""
        if not error:
            return 'N/A'
        
        lines = error.split('\n')
        total_lines = len(lines)
        
        logger.debug(f"Extracting error details from {total_lines} lines for {error_type} error")
        
        # If error is short, return as-is
        if total_lines <= 40:
            logger.debug(f"Short error ({total_lines} lines), returning full content")
            return error.strip()
        
        # Extract head and tail like old bash script (first 20 + last 20 lines)
        head_lines = lines[:20]
        tail_lines = lines[-20:]
        
        # Filter for relevant error lines in head
        relevant_head = [line for line in head_lines if any(keyword in line.lower() for keyword in [
            'error', 'failed', 'enoent', 'permission denied', 'network', 'timeout', 'enotfound'
        ])]
        
        # Filter for relevant error lines in tail  
        relevant_tail = [line for line in tail_lines if any(keyword in line.lower() for keyword in [
            'error', 'failed', 'enoent', 'permission denied', 'network', 'timeout', 'enotfound'
        ])]
        
        # Build error snippet
        error_snippet_parts = []
        
        # Add relevant head lines
        if relevant_head:
            error_snippet_parts.extend(relevant_head)
            logger.debug(f"Added {len(relevant_head)} relevant lines from head")
        else:
            # Fallback to first few lines if no relevant ones found
            error_snippet_parts.extend(head_lines[:5])
            logger.debug(f"No relevant head lines, added first 5 lines")
        
        # Add separator if we have both head and tail
        if total_lines > 40:
            error_snippet_parts.append('...')
        
        # Add relevant tail lines
        if relevant_tail and total_lines > 40:
            error_snippet_parts.extend(relevant_tail)
            logger.debug(f"Added {len(relevant_tail)} relevant lines from tail")
        elif total_lines > 40:
            # Fallback to last few lines if no relevant ones found
            error_snippet_parts.extend(tail_lines[-5:])
            logger.debug(f"No relevant tail lines, added last 5 lines")
        
        result = '\n'.join(error_snippet_parts).strip()
        
        # Limit total length to prevent excessive output
        if len(result) > 2000:
            result = result[:2000] + '\n... (truncated)'
            logger.debug(f"Truncated error snippet to 2000 characters")
        
        logger.debug(f"Final error snippet: {len(result)} characters, {len(error_snippet_parts)} parts")
        return result
    
    def _classify_error(self, error: str) -> str:
        """Classify error type."""
        error_lower = error.lower()
        
        if any(keyword in error_lower for keyword in ['enotfound', 'network', 'timeout', '404', 'not found', 'registry']):
            error_type = 'network'
        elif any(keyword in error_lower for keyword in ['gyp', 'make', 'compile']):
            error_type = 'native_build'
        elif any(keyword in error_lower for keyword in ['permission', 'eacces']):
            error_type = 'permissions'
        elif any(keyword in error_lower for keyword in ['dependency', 'peer dep']):
            error_type = 'dependency'
        else:
            error_type = 'unknown'
        
        logger.debug(f"Error classified as: {error_type}")
        return error_type
    
    def _extract_npm_version(self, output: str, package_name: str, temp_dir: str = None) -> str:
        """Extract installed version from npm output using multiple methods."""
        logger.debug(f"Extracting version for {package_name} from npm output")
        
        # Method 1: Look for + package@version in npm output
        for line in output.split('\n'):
            line = line.strip()
            if line.startswith(f'+ {package_name}@'):
                version = line.split('@')[-1].strip()
                logger.debug(f"Found version via npm output: {version}")
                return version
            # Also check for lines containing package@version
            elif f"{package_name}@" in line:
                parts = line.split('@')
                if len(parts) > 1:
                    version = parts[-1].strip().split()[0]  # Remove any trailing text
                    logger.debug(f"Found version via line parsing: {version}")
                    return version
        
        # Method 2: Check package.json in node_modules (most reliable)
        if temp_dir:
            package_json_path = os.path.join(temp_dir, 'node_modules', package_name, 'package.json')
            if os.path.exists(package_json_path):
                try:
                    with open(package_json_path, 'r') as f:
                        pkg_data = json.load(f)
                        version = pkg_data.get('version', 'unknown')
                        logger.debug(f"Found version via package.json: {version}")
                        return version
                except Exception as e:
                    logger.debug(f"Failed to read package.json: {e}")
        
        # Method 3: Run npm ls as fallback
        if temp_dir:
            try:
                result = subprocess.run(
                    ['npm', 'ls', package_name, '--depth=0', '--json'],
                    capture_output=True, text=True, cwd=temp_dir, timeout=10
                )
                if result.returncode == 0:
                    ls_data = json.loads(result.stdout)
                    deps = ls_data.get('dependencies', {})
                    if package_name in deps:
                        version = deps[package_name].get('version', 'unknown')
                        logger.debug(f"Found version via npm ls: {version}")
                        return version
            except Exception as e:
                logger.debug(f"npm ls fallback failed: {e}")
        
        logger.debug(f"No version found for {package_name} using any method")
        return 'unknown'
    
    def _create_success_result(self, package_name: str, version: str, install_result: Dict[str, Any], 
                             native_build: str, package_data: Dict[str, Any], test_result: Dict[str, Any]) -> ComponentResult:
        """Create result for successful installation."""
        status = CompatibilityStatus.NEEDS_VERIFICATION if native_build == 'Yes' else CompatibilityStatus.COMPATIBLE
        current_version_supported = True
        
        notes = f"Successfully installed {package_name}@{version}"
        if native_build == 'Yes':
            notes += '. Needs manual verification: native addon detected, confirm ARM64 compatibility'
        if test_result['success']:
            notes += '. Tests passed.'
        else:
            notes += '. Tests failed.' if test_result['has_tests'] else ' (No test script available)'
        
        logger.debug(f"Creating success result for {package_name}@{version}: status={status.value}, native_build={native_build}")
        
        component = SoftwareComponent(
            name=package_name,
            version=version,
            component_type='nodejs',
            source_sbom='runtime_analysis',
            properties={
                'environment': self.environment,
                'native_build_detected': native_build,
                'install_status': 'Success',
                'fallback_used': 'false',
                'original_version': version,
                'test_output': install_result['output'],
                'test_execution_output': test_result['output'],
                'error_details': '',
                'error_type': 'unknown',
                'timestamp': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
                'runtime_analysis': 'true'
            },
            parent_component=None,
            child_components=[],
            source_package=None
        )
        
        compatibility = CompatibilityResult(
            status=status,
            current_version_supported=current_version_supported,
            minimum_supported_version=version,
            recommended_version=None,
            notes=notes,
            confidence_level=0.9
        )
        
        return ComponentResult(
            component=component,
            compatibility=compatibility,
            matched_name=None
        )
    
    def _create_fallback_result(self, package_name: str, version: str, installed_version: str, 
                              install_result: Dict[str, Any], native_build: str, package_data: Dict[str, Any], 
                              original_error: str = '') -> ComponentResult:
        """Create result for fallback installation."""
        status = CompatibilityStatus.NEEDS_VERIFICATION if native_build == 'Yes' else CompatibilityStatus.NEEDS_UPGRADE
        current_version_supported = False
        
        notes = f"Version {version} failed ({self._extract_error_details(original_error, 'install')}), but latest version {installed_version} works"
        
        logger.debug(f"Creating fallback result for {package_name}@{version} -> {installed_version}: status={status.value}")
        
        component = SoftwareComponent(
            name=package_name,
            version=version,
            component_type='nodejs',
            source_sbom='runtime_analysis',
            properties={
                'environment': self.environment,
                'native_build_detected': native_build,
                'install_status': 'Success',
                'fallback_used': 'true',
                'original_version': version,
                'test_output': install_result['output'],
                'test_execution_output': '',
                'error_details': self._extract_error_details(original_error, 'install'),
                'error_type': self._classify_error(original_error),
                'timestamp': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
                'runtime_analysis': 'true'
            },
            parent_component=None,
            child_components=[],
            source_package=None
        )
        
        compatibility = CompatibilityResult(
            status=status,
            current_version_supported=current_version_supported,
            minimum_supported_version=installed_version,
            recommended_version=installed_version,
            notes=notes,
            confidence_level=0.85
        )
        
        return ComponentResult(
            component=component,
            compatibility=compatibility,
            matched_name=None
        )
    
    def _create_failed_result(self, package_name: str, version: str, install_result: Dict[str, Any], 
                            package_data: Dict[str, Any]) -> ComponentResult:
        """Create result for failed installation."""
        notes = f"All versions including latest failed to install: {self._extract_error_details(install_result['error'], 'install')}"
        
        logger.debug(f"Creating failed result for {package_name}@{version}: all versions failed")
        
        component = SoftwareComponent(
            name=package_name,
            version=version,
            component_type='nodejs',
            source_sbom='runtime_analysis',
            properties={
                'environment': self.environment,
                'native_build_detected': 'No',
                'install_status': 'Failed',
                'fallback_used': 'true',
                'original_version': version,
                'test_output': install_result['error'],
                'test_execution_output': '',
                'error_details': self._extract_error_details(install_result['error'], 'install'),
                'error_type': self._classify_error(install_result['error']),
                'timestamp': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
                'runtime_analysis': 'true'
            },
            parent_component=None,
            child_components=[],
            source_package=None
        )
        
        compatibility = CompatibilityResult(
            status=CompatibilityStatus.INCOMPATIBLE,
            current_version_supported=False,
            minimum_supported_version=None,
            recommended_version=None,
            notes=notes,
            confidence_level=0.9
        )
        
        return ComponentResult(
            component=component,
            compatibility=compatibility,
            matched_name=None
        )
    
    def _create_compatible_result(self, package_name: str, version: str, working_version: str, 
                                native_build: str, package_data: Dict[str, Any], failed_versions: Dict[str, str]) -> ComponentResult:
        """Create result for compatible version based on working version."""
        status = CompatibilityStatus.NEEDS_VERIFICATION if native_build == 'Yes' else CompatibilityStatus.COMPATIBLE
        current_version_supported = True
        
        notes = f"Compatible with minimum working version {working_version}"
        error_details = ''
        error_type = 'unknown'
        
        if version in failed_versions:
            version_error = failed_versions[version]
            notes += f" (This version failed: {self._extract_error_details(version_error, 'install')})"
            error_details = self._extract_error_details(version_error, 'install')
            error_type = self._classify_error(version_error)
        
        logger.debug(f"Creating compatible result for {package_name}@{version} using working version {working_version}: status={status.value}")
        
        component = SoftwareComponent(
            name=package_name,
            version=version,
            component_type='nodejs',
            source_sbom='runtime_analysis',
            properties={
                'environment': self.environment,
                'native_build_detected': native_build,
                'install_status': 'Success',
                'fallback_used': 'false',
                'original_version': version,
                'test_output': '',
                'test_execution_output': '',
                'error_details': error_details,
                'error_type': error_type,
                'timestamp': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
                'runtime_analysis': 'true'
            },
            parent_component=None,
            child_components=[],
            source_package=None
        )
        
        compatibility = CompatibilityResult(
            status=status,
            current_version_supported=current_version_supported,
            minimum_supported_version=working_version,
            recommended_version=None,
            notes=notes,
            confidence_level=0.9
        )
        
        return ComponentResult(
            component=component,
            compatibility=compatibility,
            matched_name=None
        )
    
    def _cleanup_temp_files(self):
        """Clean up temporary files and directories."""
        logger.info('Starting cleanup of temporary files')
        
        files_to_clean = ['node_modules', 'package-lock.json']
        cleanup_results = []
        
        # Clean up main directory files
        for file_path in files_to_clean:
            if os.path.exists(file_path):
                logger.debug(f"Found file/directory to remove: {file_path}")
                try:
                    if os.path.isdir(file_path):
                        logger.debug(f"Removing directory recursively: {file_path}")
                        shutil.rmtree(file_path)
                    else:
                        logger.debug(f"Removing file: {file_path}")
                        os.unlink(file_path)
                    logger.debug(f"Successfully removed {file_path}")
                    cleanup_results.append(f"{file_path}: removed")
                except Exception as error:
                    logger.warning(f"Failed to remove {file_path}: {error}")
                    cleanup_results.append(f"{file_path}: failed - {error}")
            else:
                logger.debug(f"{file_path} does not exist, skipping")
                cleanup_results.append(f"{file_path}: not found")
        
        # Clean up any remaining temp directories
        for temp_dir in self.temp_dirs[:]:
            try:
                if os.path.exists(temp_dir):
                    logger.debug(f"Removing temp directory: {temp_dir}")
                    shutil.rmtree(temp_dir)
                    cleanup_results.append(f"{temp_dir}: removed")
                self.temp_dirs.remove(temp_dir)
            except Exception as error:
                logger.warning(f"Failed to remove temp directory {temp_dir}: {error}")
                cleanup_results.append(f"{temp_dir}: failed - {error}")
        
        logger.debug(f"Cleanup summary: {'; '.join(cleanup_results)}")
        logger.info('Cleanup completed')


def show_help():
    """Display help information for Node.js package installer."""
    help_text = """
Node.js Package Installer - ARM64 Compatibility Analyzer

USAGE:
    python nodejs_package_installer.py <package_json> [OPTIONS]

ARGUMENTS:
    package_json        Path to package.json file to analyze

OPTIONS:
    -o, --output FILE  Save analysis results to specified JSON file
    -h, --help         Show this help message and exit

ENVIRONMENT VARIABLES:
    NODE_LOG_LEVEL     Set logging level (ERROR, WARN, INFO, DEBUG)
    DEBUG              Enable debug logging (same as NODE_LOG_LEVEL=DEBUG)

DESCRIPTION:
    Analyzes Node.js packages from package.json for ARM64/Graviton compatibility.
    Tests package installation, detects native builds, and runs functionality
    tests when available. Supports version inheritance and fallback testing.

EXAMPLES:
    python nodejs_package_installer.py package.json
    python nodejs_package_installer.py package.json -o results.json
    NODE_LOG_LEVEL=DEBUG python nodejs_package_installer.py package.json
    DEBUG=1 python nodejs_package_installer.py my-package.json

OUTPUT:
    JSON format with compatibility status, installation results, native build
    detection, and test execution results for each package dependency.
    """
    print(help_text)

def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Node.js Package Installer - Enhanced compatibility analyzer',
        add_help=False
    )
    parser.add_argument('package_json', nargs='?', help='Path to package.json file')
    parser.add_argument('-o', '--output', help='Output JSON file path')
    parser.add_argument('-h', '--help', action='store_true', help='Show help message')
    
    args = parser.parse_args()
    
    if args.help or not args.package_json:
        show_help()
        if not args.package_json:
            print("\nError: package.json file is required.", file=sys.stderr)
            return 1
        return 0
    
    logger.info(f"Node.js Package Installer starting (log level: {'DEBUG' if current_log_level == logging.DEBUG else 'INFO'})")
    logger.debug(f"Command line arguments: {args}")
    logger.debug(f"Working directory: {os.getcwd()}")
    logger.debug(f"Python version: {sys.version}")
    
    installer = NodeJSPackageInstaller()
    logger.debug(f"Environment detected: {installer.environment}")
    
    try:
        start_time = datetime.now(timezone.utc)
        logger.debug(f"Analysis started at: {start_time.isoformat()}Z")
        
        results = installer.test_nodejs_packages(args.package_json)
        
        end_time = datetime.now(timezone.utc)
        duration = (end_time - start_time).total_seconds()
        logger.info(f"Analysis completed: {len(results)} package{'s' if len(results) != 1 else ''} processed in {duration:.2f}s")
        logger.debug(f"Analysis ended at: {end_time.isoformat()}Z")
        
        # Log result summary
        status_counts = {}
        for result in results:
            status = result.compatibility.status.value
            status_counts[status] = status_counts.get(status, 0) + 1
        # Log result summary
        status_counts = {}
        for result in results:
            status = result.compatibility.status.value
            status_counts[status] = status_counts.get(status, 0) + 1
        logger.debug(f"Result summary: {status_counts}")
        
        # Output results to stdout
        logger.debug("Writing results to stdout in flattened format")
        # Convert ComponentResult objects to flattened dictionaries (matching SBOM structure)
        results_dict = []
        for result in results:
            # Flattened structure matching SBOM format but preserving all fields
            result_dict = {
                'name': result.component.name,
                'version': result.component.version,
                'type': result.component.component_type,
                'source_sbom': result.component.source_sbom,
                'compatibility': {
                    'status': result.compatibility.status.value,
                    'current_version_supported': result.compatibility.current_version_supported,
                    'minimum_supported_version': result.compatibility.minimum_supported_version,
                    'recommended_version': result.compatibility.recommended_version,
                    'notes': result.compatibility.notes,
                    'confidence_level': result.compatibility.confidence_level
                },
                'parent_component': result.component.parent_component,
                'child_components': result.component.child_components,
                'source_package': result.component.source_package
            }
            
            # Add matched name if available
            if result.matched_name:
                result_dict['matched_name'] = result.matched_name
            
            # Add properties if available
            if result.component.properties:
                result_dict['properties'] = result.component.properties
            
            results_dict.append(result_dict)
        
        output_json = json.dumps(results_dict, indent=2)
        
        if args.output:
            logger.debug(f"Writing results to file: {args.output}")
            with open(args.output, 'w') as f:
                f.write(output_json)
            logger.info(f"Results saved to: {args.output}")
        else:
            print(output_json)
        
        # Cleanup
        logger.debug("Starting cleanup phase")
        installer._cleanup_temp_files()
        logger.info('Script execution completed successfully')
        
    except Exception as error:
        logger.error(f"Analysis failed: {error}")
        logger.debug(f"Error details: {error}", exc_info=True)
        
        # Attempt cleanup even on failure
        logger.debug("Attempting cleanup after failure")
        try:
            installer._cleanup_temp_files()
        except Exception as cleanup_error:
            logger.debug(f"Cleanup also failed: {cleanup_error}")
        
        print(f"Error: {error}", file=sys.stderr)
        print("Use -h or --help for usage information.", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()