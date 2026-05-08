#!/usr/bin/env python3

import json
import subprocess
import sys
import time
import re
import os
import tempfile
import logging
from datetime import datetime
from typing import List, Dict, Optional, Tuple
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from graviton_validator.models import ComponentResult, SoftwareComponent, CompatibilityResult, CompatibilityStatus
except ImportError:
    # Fallback for standalone execution
    try:
        from models import ComponentResult, SoftwareComponent, CompatibilityResult, CompatibilityStatus
    except ImportError:
        # Final fallback - direct path
        from graviton_validator.models import ComponentResult, SoftwareComponent, CompatibilityResult, CompatibilityStatus

# Configure logging
logging.basicConfig(
    level=logging.DEBUG if os.getenv('DEBUG') else logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)


class RubyCompatibilityAnalyzer:
    """Ruby gem compatibility analyzer for ARM64/Graviton."""
    
    def __init__(self):
        self.timeout = 120
        self.validation_timeout = 10
        self.api_timeout = 5
    
    def _validate_url(self, url: str) -> str:
        """Validate URL scheme to prevent file:// and other unsafe schemes."""
        from urllib.parse import urlparse
        parsed = urlparse(url)
        if parsed.scheme not in ('http', 'https'):
            raise ValueError(f"Invalid URL scheme: {parsed.scheme}. Only http/https allowed.")
        return url
        
    def analyze_gemfile(self, gemfile_path: str) -> List[ComponentResult]:
        """Analyze Ruby gems from Gemfile for ARM64 compatibility."""
        logger.info(f"[RUBY_ANALYZER] Starting Ruby package analysis for: {gemfile_path}")
        
        if not os.path.exists(gemfile_path):
            logger.error(f"[RUBY_ANALYZER] Gemfile not found: {gemfile_path}")
            raise FileNotFoundError(f"Gemfile {gemfile_path} not found")
        
        logger.debug(f"[RUBY_ANALYZER] Gemfile exists, proceeding with parsing")
        gems = self._parse_gemfile(gemfile_path)
        logger.info(f"[RUBY_ANALYZER] Parsed {len(gems)} gem entries from Gemfile")
        logger.debug(f"[RUBY_ANALYZER] Raw gem entries: {gems}")
        
        gem_groups = self._group_gems_by_name(gems)
        logger.info(f"[RUBY_ANALYZER] Grouped into {len(gem_groups)} unique gems")
        logger.debug(f"[RUBY_ANALYZER] Gem groups: {list(gem_groups.keys())}")
        
        results = []
        total_gems = len(gem_groups)
        analysis_start = time.time()
        compatible_count = 0
        upgrade_count = 0
        for index, (gem_name, versions) in enumerate(gem_groups.items()):
            if index == 0 or (index + 1) % 10 == 0 or total_gems <= 20:
                logger.info(f"[RUBY_ANALYZER] Processing gem {index + 1}/{total_gems}: {gem_name} (versions: {versions})")
                sys.stderr.flush()
            gem_results = self._test_gem_versions(gem_name, versions)
            logger.debug(f"[RUBY_ANALYZER] Gem {gem_name} produced {len(gem_results)} results")
            for r in gem_results:
                if r.compatibility.status == CompatibilityStatus.COMPATIBLE:
                    compatible_count += 1
                elif r.compatibility.status == CompatibilityStatus.NEEDS_UPGRADE:
                    upgrade_count += 1
            results.extend(gem_results)
        
        elapsed = time.time() - analysis_start
        logger.info(f"[RUBY_ANALYZER] Ruby analysis complete: {len(results)} packages processed in {elapsed:.1f}s — {compatible_count} compatible, {upgrade_count} need upgrade")
        sys.stderr.flush()
        return results
    
    def _parse_gemfile(self, gemfile_path: str) -> List[Tuple[str, str]]:
        """Parse Gemfile and extract gem declarations."""
        logger.debug(f"[RUBY_PARSER] Parsing Gemfile: {gemfile_path}")
        gems = []
        line_count = 0
        
        with open(gemfile_path, 'r', encoding='utf-8') as f:
            for line in f:
                line_count += 1
                original_line = line.strip()
                
                if not original_line or original_line.startswith('#'):
                    logger.debug(f"[RUBY_PARSER] Line {line_count}: Skipping empty/comment line")
                    continue
                
                # Match gem declarations like: gem 'name', '~> 1.0'
                match = re.search(r"gem\s+['\"]([^'\"]+)['\"](?:\s*,\s*['\"]([^'\"]+)['\"])?", original_line)
                if match:
                    gem_name = match.group(1)
                    version = match.group(2) or 'latest'
                    gems.append((gem_name, version))
                    logger.debug(f"[RUBY_PARSER] Line {line_count}: Found gem '{gem_name}' version '{version}'")
                else:
                    logger.debug(f"[RUBY_PARSER] Line {line_count}: No gem match for: {original_line}")
        
        logger.debug(f"[RUBY_PARSER] Gemfile parsing complete. Found {len(gems)} gems")
        return gems
    
    def _group_gems_by_name(self, gems: List[Tuple[str, str]]) -> Dict[str, List[str]]:
        """Group gems by name and sort versions."""
        groups = {}
        for gem_name, version in gems:
            if gem_name not in groups:
                groups[gem_name] = []
            groups[gem_name].append(version)
        
        # Sort versions for each gem
        for gem_name in groups:
            groups[gem_name] = self._sort_versions(groups[gem_name])
        
        return groups
    
    def _sort_versions(self, versions: List[str]) -> List[str]:
        """Sort versions semantically."""
        versioned = [v for v in versions if v != 'latest']
        has_latest = 'latest' in versions
        
        def version_key(version):
            try:
                # Clean version string and split into numeric parts
                clean_version = re.sub(r'[^0-9.]', '', version)
                return [int(x) for x in clean_version.split('.') if x]
            except:
                return [0]
        
        versioned.sort(key=version_key)
        if has_latest:
            versioned.append('latest')
        
        return versioned
    
    def _test_gem_versions(self, gem_name: str, versions: List[str]) -> List[ComponentResult]:
        """Test multiple versions of a gem with inheritance logic."""
        logger.debug(f"[RUBY_TESTER] Testing gem versions for {gem_name}: {versions}")
        results = []
        working_version = None
        working_native_build = 'No'
        failed_versions = {}
        
        for index, version in enumerate(versions):
            logger.debug(f"[RUBY_TESTER] Processing version {index + 1}/{len(versions)}: {gem_name}@{version}")
            
            if version == 'latest':
                logger.debug(f"[RUBY_TESTER] Skipping 'latest' version for now (will process at end)")
                continue
            
            if working_version:
                logger.debug(f"[RUBY_TESTER] Found working version {working_version}, inheriting compatibility for {version}")
                # Inherit compatibility from working version
                results.append(self._create_component_result(
                    gem_name, version, CompatibilityStatus.COMPATIBLE,
                    f"Compatible (inherited from working version {working_version})",
                    '', 'Success', False, version, working_native_build, '', '', 'unknown'
                ))
            else:
                logger.debug(f"[RUBY_TESTER] No working version yet, testing {gem_name}@{version}")
                # Test this version
                test_result = self._gem_install_test(gem_name, version)
                
                if test_result['success']:
                    logger.info(f"[RUBY_TESTER] ✓ Successfully installed {gem_name}@{version}")
                    working_version = version
                    working_native_build = self._detect_native_build(test_result['output'], gem_name)
                    logger.debug(f"[RUBY_TESTER] Native build detected: {working_native_build}")
                    
                    # Use enhanced compatibility check
                    logger.debug(f"[RUBY_TESTER] Running enhanced compatibility check for {gem_name}@{version}")
                    status = self._enhanced_compatibility_check(gem_name, version, test_result['output'], True)
                    logger.debug(f"[RUBY_TESTER] Enhanced compatibility status: {status}")
                    
                    notes = self._generate_enhanced_notes(True, test_result['output'], test_result['error'], gem_name, version, status)
                    
                    results.append(self._create_component_result(
                        gem_name, version, status, notes,
                        test_result['output'], 'Success', False, version,
                        working_native_build, 'N/A - No test script available',
                        '', 'unknown'
                    ))
                else:
                    logger.warning(f"[RUBY_TESTER] ✗ Failed to install {gem_name}@{version}: {test_result['error'][:100]}...")
                    failed_versions[version] = test_result['error']
                    error_type = self._classify_error(test_result['error'])
                    logger.debug(f"[RUBY_TESTER] Error classified as: {error_type}")
                    
                    results.append(self._create_component_result(
                        gem_name, version, CompatibilityStatus.INCOMPATIBLE,
                        f"Installation failed for version {version}",
                        test_result['error'], 'Failed', False, version,
                        'No', '', self._extract_error_details(test_result['error']),
                        error_type
                    ))
        
        # Update failed versions to needs_upgrade if we found a working version
        if working_version:
            for result in results:
                if result.compatibility.status == CompatibilityStatus.INCOMPATIBLE:
                    result.compatibility.status = CompatibilityStatus.NEEDS_UPGRADE
                    result.compatibility.notes = f"Version {result.component.version} failed, but version {working_version} works"
                    result.component.properties['native_build_detected'] = working_native_build
        
        # Handle 'latest' version if present
        if 'latest' in versions:
            if working_version:
                results.append(self._create_component_result(
                    gem_name, 'latest', CompatibilityStatus.COMPATIBLE,
                    f"Latest version likely compatible (working version {working_version} found)",
                    '', 'Success', False, 'latest', working_native_build,
                    'N/A - Compatible with working version', '', 'unknown'
                ))
            else:
                latest_result = self._gem_install_test(gem_name, 'latest')
                
                if latest_result['success']:
                    native_build = self._detect_native_build(latest_result['output'], gem_name)
                    status = self._enhanced_compatibility_check(gem_name, 'latest', latest_result['output'], True)
                    notes = self._generate_enhanced_notes(True, latest_result['output'], latest_result['error'], gem_name, 'latest', status)
                    
                    # Update failed versions to needs_upgrade
                    for result in results:
                        if result.compatibility.status == CompatibilityStatus.INCOMPATIBLE:
                            result.compatibility.status = CompatibilityStatus.NEEDS_UPGRADE
                            result.compatibility.notes = f"Version {result.component.version} failed, but latest version works"
                            result.component.properties['native_build_detected'] = native_build
                    
                    results.append(self._create_component_result(
                        gem_name, 'latest', status, notes,
                        latest_result['output'], 'Success', True, 'latest',
                        native_build, 'N/A - No test script available', '', 'unknown'
                    ))
                else:
                    results.append(self._create_component_result(
                        gem_name, 'latest', CompatibilityStatus.INCOMPATIBLE,
                        'Latest version also failed to install',
                        latest_result['error'], 'Failed', True, 'latest',
                        'No', '', self._extract_error_details(latest_result['error']),
                        self._classify_error(latest_result['error'])
                    ))
        
        return results
    
    def _gem_install_test(self, gem_name: str, version: str) -> Dict[str, any]:
        """Test gem installation."""
        gem_spec = gem_name if version == 'latest' else f"{gem_name}:{version}"
        logger.debug(f"[RUBY_INSTALLER] Starting gem install test for: {gem_spec}")
        
        try:
            cmd = ['gem', 'install', gem_spec, '--no-document']
            logger.debug(f"[RUBY_INSTALLER] Executing command: {' '.join(cmd)}")
            
            start_time = time.time()
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                timeout=self.timeout
            )
            duration = time.time() - start_time
            
            logger.debug(f"[RUBY_INSTALLER] Command completed in {duration:.2f}s with exit code: {result.returncode}")
            logger.debug(f"[RUBY_INSTALLER] STDOUT ({len(result.stdout)} chars): {result.stdout[:200]}{'...' if len(result.stdout) > 200 else ''}")
            logger.debug(f"[RUBY_INSTALLER] STDERR ({len(result.stderr)} chars): {result.stderr[:200]}{'...' if len(result.stderr) > 200 else ''}")
            
            # Cleanup: uninstall the gem after testing
            logger.debug(f"[RUBY_INSTALLER] Starting cleanup for {gem_name}")
            try:
                cleanup_result = subprocess.run(
                    ['gem', 'uninstall', gem_name, '-x', '-I'],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                logger.debug(f"[RUBY_INSTALLER] Cleanup completed with exit code: {cleanup_result.returncode}")
            except Exception as cleanup_error:
                logger.debug(f"[RUBY_INSTALLER] Cleanup failed (ignoring): {cleanup_error}")
            
            test_result = {
                'success': result.returncode == 0,
                'output': result.stdout,
                'error': result.stderr
            }
            logger.debug(f"[RUBY_INSTALLER] Install test result: success={test_result['success']}")
            return test_result
            
        except subprocess.TimeoutExpired:
            duration = time.time() - start_time
            logger.warning(f"[RUBY_INSTALLER] Gem install timed out after {duration:.2f}s")
            
            # Try to cleanup even on timeout
            logger.debug(f"[RUBY_INSTALLER] Attempting cleanup after timeout")
            try:
                subprocess.run(['gem', 'uninstall', gem_name, '-x', '-I'], timeout=30)
                logger.debug(f"[RUBY_INSTALLER] Timeout cleanup completed")
            except Exception as cleanup_error:
                logger.debug(f"[RUBY_INSTALLER] Timeout cleanup failed (ignoring): {cleanup_error}")
            
            return {
                'success': False,
                'output': '',
                'error': 'Installation timed out after 120 seconds'
            }
        except Exception as e:
            logger.error(f"[RUBY_INSTALLER] Gem install test exception: {e}")
            return {
                'success': False,
                'output': '',
                'error': f"Installation failed: {e}"
            }
    
    def _detect_native_build(self, output: str, gem_name: str) -> str:
        """Detect if gem requires native compilation."""
        native_indicators = [
            'building native extensions', 'compiling', 'gcc', 'g++', 'clang',
            'make', 'extconf.rb', 'mkmf.rb'
        ]
        
        output_lower = output.lower()
        for indicator in native_indicators:
            if indicator in output_lower:
                return 'Yes'
        
        return 'No'
    
    def _test_gem_require(self, gem_name: str) -> str:
        """Priority 1: Runtime loading test."""
        logger.debug(f"[RUBY_VALIDATOR] Testing runtime loading for gem: {gem_name}")
        
        try:
            cmd = ['ruby', '-e', f"require '{gem_name}'"]
            logger.debug(f"[RUBY_VALIDATOR] Runtime test command: {' '.join(cmd)}")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.validation_timeout
            )
            
            test_result = 'Yes' if result.returncode == 0 else 'needs_verification'
            logger.debug(f"[RUBY_VALIDATOR] Runtime loading test completed: exit_code={result.returncode}, result={test_result}")
            
            if result.returncode != 0:
                logger.debug(f"[RUBY_VALIDATOR] Runtime loading failed - STDERR: {result.stderr[:200]}{'...' if len(result.stderr) > 200 else ''}")
            
            return test_result
            
        except subprocess.TimeoutExpired:
            logger.debug(f"[RUBY_VALIDATOR] Runtime loading test timed out after {self.validation_timeout}s")
            return 'needs_verification'
        except Exception as e:
            logger.debug(f"[RUBY_VALIDATOR] Runtime loading test exception: {e}")
            return 'needs_verification'
    
    def _check_native_architecture(self, gem_name: str) -> str:
        """Priority 2: Native extension architecture check."""
        logger.debug(f"[RUBY_VALIDATOR] Checking native architecture for gem: {gem_name}")
        
        try:
            # Get gem path
            result = subprocess.run(
                ['gem', 'which', gem_name],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            gem_path = result.stdout.strip()
            logger.debug(f"[RUBY_VALIDATOR] Gem path lookup result: '{gem_path}'")
            
            if not gem_path or result.returncode != 0:
                logger.debug(f"[RUBY_VALIDATOR] No gem path found, returning 'No'")
                return 'No'
            
            gem_dir = os.path.dirname(gem_path)
            logger.debug(f"[RUBY_VALIDATOR] Gem directory: {gem_dir}")
            
            # Find native files
            native_extensions = ['.so', '.bundle', '.dll']
            native_files = []
            for ext in native_extensions:
                for root, dirs, files in os.walk(gem_dir):
                    for file in files:
                        if file.endswith(ext):
                            native_files.append(os.path.join(root, file))
            
            logger.debug(f"[RUBY_VALIDATOR] Found {len(native_files)} native files: {native_files}")
            
            if not native_files:
                logger.debug(f"[RUBY_VALIDATOR] No native files found, returning 'No'")
                return 'No'
            
            # Check architecture of native files
            for file_path in native_files:
                logger.debug(f"[RUBY_VALIDATOR] Checking architecture of: {file_path}")
                try:
                    file_result = subprocess.run(
                        ['file', file_path],
                        capture_output=True,
                        text=True,
                        timeout=5
                    )
                    arch_info = file_result.stdout.lower()
                    logger.debug(f"[RUBY_VALIDATOR] File command output: {arch_info.strip()}")
                    
                    # Check for x86-only files without ARM64 counterpart
                    if 'x86_64' in arch_info and not ('aarch64' in arch_info or 'arm64' in arch_info):
                        logger.debug(f"[RUBY_VALIDATOR] x86-only files detected without ARM64 counterpart, returning 'needs_verification'")
                        return 'needs_verification'
                        
                except Exception as e:
                    logger.debug(f"[RUBY_VALIDATOR] File command failed for {file_path}: {e}")
                    continue
            
            logger.debug(f"[RUBY_VALIDATOR] All native files have ARM64 support or are universal, returning 'Yes'")
            return 'Yes'
            
        except Exception as e:
            logger.debug(f"[RUBY_VALIDATOR] Native architecture check exception: {e}")
            return 'No'
    
    def _check_known_problematic_gems(self, gem_name: str) -> str:
        """Priority 3: Known problematic gem detection."""
        problematic_gems = [
            'therubyracer',    # V8 engine - x86 only
            'libv8',           # V8 library - architecture specific
            'fast_xs',         # Has x86 assembly
            'hiredis',         # Redis client with x86 optimizations
            'eventmachine',    # Older versions have ARM64 issues
            'thin',            # Web server with native extensions
            'unicorn'          # Web server with native code
        ]
        
        return 'needs_verification' if gem_name.lower() in problematic_gems else 'compatible'
    
    def _check_gem_platforms(self, gem_name: str, version: str) -> str:
        """Priority 4: RubyGems.org platform check."""
        logger.debug(f"[RUBY_VALIDATOR] Checking RubyGems.org platform info for: {gem_name}")
        
        try:
            import urllib.request
            import urllib.parse
            
            # Validate gem_name to prevent URL manipulation
            if not gem_name or not isinstance(gem_name, str):
                logger.debug(f"[RUBY_VALIDATOR] Invalid gem name: {gem_name}")
                return 'unknown'
            
            # Remove any URL scheme or path characters from gem_name
            safe_gem_name = gem_name.replace('/', '').replace('\\', '').replace(':', '')
            if not safe_gem_name or safe_gem_name != gem_name:
                logger.debug(f"[RUBY_VALIDATOR] Gem name contains invalid characters: {gem_name}")
                return 'unknown'
            
            url = f"https://rubygems.org/api/v1/gems/{safe_gem_name}.json"
            logger.debug(f"[RUBY_VALIDATOR] Making API request to: {url}")
            
            # Validate URL scheme for security (inline to satisfy static analysis)
            parsed_url = urllib.parse.urlparse(url)
            if parsed_url.scheme not in ('http', 'https'):
                raise ValueError(f"Invalid URL scheme: {parsed_url.scheme}. Only http and https are allowed.")
            
            request = urllib.request.Request(url)
            # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
            with urllib.request.urlopen(request, timeout=self.api_timeout) as response:  # nosec B310
                if response.status != 200:
                    logger.debug(f"[RUBY_VALIDATOR] API request failed with status: {response.status}")
                    return 'unknown'
                
                gem_info = json.loads(response.read().decode())
                platform_specific = gem_info.get('platform_uri') or gem_info.get('gem_uri', '')
                logger.debug(f"[RUBY_VALIDATOR] Platform info: {platform_specific}")
                
                # Check if ARM64 platform is available
                if 'aarch64' in platform_specific or 'arm64' in platform_specific:
                    logger.debug(f"[RUBY_VALIDATOR] ARM64 platform detected, returning 'compatible'")
                    return 'compatible'
                elif 'x86_64' in platform_specific and 'ruby' not in platform_specific:
                    logger.debug(f"[RUBY_VALIDATOR] x86-only platform detected, returning 'needs_verification'")
                    return 'needs_verification'
                else:
                    logger.debug(f"[RUBY_VALIDATOR] Pure Ruby gem or universal platform, returning 'compatible'")
                    return 'compatible'
                    
        except Exception as e:
            logger.debug(f"[RUBY_VALIDATOR] Platform check exception: {e}")
            return 'unknown'
    
    def _test_basic_functionality(self, gem_name: str) -> str:
        """Priority 5: Basic functionality test."""
        logger.debug(f"[RUBY_VALIDATOR] Testing basic functionality for gem: {gem_name}")
        
        test_scripts = {
            'nokogiri': 'Nokogiri::HTML("<html></html>")',
            'json': 'JSON.parse("{\"test\": true}")',
            'pg': 'PG.library_version',
            'mysql2': 'Mysql2::VERSION',
            'ffi': 'FFI::Platform::ARCH'
        }
        
        script = test_scripts.get(gem_name)
        if not script:
            logger.debug(f"[RUBY_VALIDATOR] No functionality test defined for {gem_name}, returning 'No'")
            return 'No'
        
        logger.debug(f"[RUBY_VALIDATOR] Running functionality test: require '{gem_name}'; {script}")
        
        try:
            cmd = ['ruby', '-e', f"require '{gem_name}'; {script}"]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.validation_timeout
            )
            
            test_result = 'Yes' if result.returncode == 0 else 'needs_verification'
            logger.debug(f"[RUBY_VALIDATOR] Functionality test completed: exit_code={result.returncode}, result={test_result}")
            
            if result.returncode != 0:
                logger.debug(f"[RUBY_VALIDATOR] Functionality test failed - STDERR: {result.stderr[:200]}{'...' if len(result.stderr) > 200 else ''}")
            
            return test_result
            
        except subprocess.TimeoutExpired:
            logger.debug(f"[RUBY_VALIDATOR] Functionality test timed out after {self.validation_timeout}s")
            return 'needs_verification'
        except Exception as e:
            logger.debug(f"[RUBY_VALIDATOR] Functionality test exception: {e}")
            return 'needs_verification'
    
    def _enhanced_compatibility_check(self, gem_name: str, version: str, install_output: str, install_success: bool) -> CompatibilityStatus:
        """Enhanced compatibility check using 5-priority validation."""
        logger.debug(f"[RUBY_VALIDATOR] Starting enhanced compatibility check for {gem_name}@{version}")
        
        # Current detection
        native_build = self._detect_native_build(install_output, gem_name)
        logger.debug(f"[RUBY_VALIDATOR] Native build detection: {native_build}")
        
        # Enhanced checks (Priority 1 & 2)
        logger.debug(f"[RUBY_VALIDATOR] Running Priority 1: Runtime loading test")
        require_test = self._test_gem_require(gem_name)
        logger.debug(f"[RUBY_VALIDATOR] Runtime loading test result: {require_test}")
        
        logger.debug(f"[RUBY_VALIDATOR] Running Priority 2: Native architecture check")
        arch_check = self._check_native_architecture(gem_name)
        logger.debug(f"[RUBY_VALIDATOR] Architecture check result: {arch_check}")
        
        logger.debug(f"[RUBY_VALIDATOR] Running Priority 3: Known problematic gems check")
        known_issues = self._check_known_problematic_gems(gem_name)
        logger.debug(f"[RUBY_VALIDATOR] Known issues check result: {known_issues}")
        
        # Optional checks (Priority 4-5)
        logger.debug(f"[RUBY_VALIDATOR] Running Priority 4: Platform API check")
        platform_check = self._check_gem_platforms(gem_name, version)
        logger.debug(f"[RUBY_VALIDATOR] Platform check result: {platform_check}")
        
        logger.debug(f"[RUBY_VALIDATOR] Running Priority 5: Basic functionality test")
        functionality_test = self._test_basic_functionality(gem_name)
        logger.debug(f"[RUBY_VALIDATOR] Functionality test result: {functionality_test}")
        
        # Determine final status with enhanced logic
        logger.debug(f"[RUBY_VALIDATOR] Determining final compatibility status...")
        logger.debug(f"[RUBY_VALIDATOR] Logic inputs: require_test={require_test}, arch_check={arch_check}, known_issues={known_issues}")
        logger.debug(f"[RUBY_VALIDATOR] Logic inputs: native_build={native_build}, install_success={install_success}")
        
        if (require_test == 'needs_verification' or 
            arch_check == 'needs_verification' or 
            known_issues == 'needs_verification'):
            logger.debug(f"[RUBY_VALIDATOR] Status: needs_verification (failed enhanced checks)")
            return CompatibilityStatus.NEEDS_VERIFICATION
        elif native_build == 'Yes' and arch_check == 'Yes' and require_test == 'Yes':
            logger.debug(f"[RUBY_VALIDATOR] Status: compatible (native build with successful checks)")
            return CompatibilityStatus.COMPATIBLE
        elif install_success and require_test == 'Yes':
            logger.debug(f"[RUBY_VALIDATOR] Status: compatible (successful install and runtime loading)")
            return CompatibilityStatus.COMPATIBLE
        else:
            logger.debug(f"[RUBY_VALIDATOR] Status: needs_verification (fallback case)")
            return CompatibilityStatus.NEEDS_VERIFICATION
    
    def _classify_error(self, error: str) -> str:
        """Classify error type."""
        if not error:
            return 'unknown'
        
        error_lower = error.lower()
        
        # Check for network errors first (including "timed out")
        if any(keyword in error_lower for keyword in ['network', 'timeout', 'timed out', 'connection', 'resolve']):
            return 'network'
        # Check for native build errors (including "extconf")
        elif any(keyword in error_lower for keyword in ['compile', 'build', 'gcc', 'make', 'extconf']):
            return 'native_build'
        elif any(keyword in error_lower for keyword in ['not found', 'could not find']):
            return 'dependency'
        elif any(keyword in error_lower for keyword in ['permission', 'access']):
            return 'permissions'
        else:
            return 'unknown'
    
    def _extract_error_details(self, error: str) -> str:
        """Extract relevant error details."""
        if not error:
            return ''
        
        lines = error.split('\n')
        relevant_lines = []
        
        for line in lines:
            line_lower = line.lower()
            if any(keyword in line_lower for keyword in ['error', 'failed', 'not found', 'timeout']):
                relevant_lines.append(line)
                if len(relevant_lines) >= 3:
                    break
        
        result = '; '.join(relevant_lines)
        return result
    
    def _generate_notes(self, success: bool, output: str, error: str, gem_name: str, version: str) -> str:
        """Generate human-readable notes."""
        if success:
            if 'building native extensions' in output.lower():
                return f"Successfully installed {gem_name}=={version} (native compilation successful)"
            else:
                return f"Successfully installed {gem_name}=={version}"
        else:
            if not error:
                return f"Gem {gem_name}=={version} failed to install (unknown reason)"
            
            error_lower = error.lower()
            
            if 'could not find' in error_lower or 'not found' in error_lower:
                return f"Gem {gem_name} version {version} not found in registry"
            elif 'network' in error_lower or 'resolve' in error_lower:
                return "Network connectivity issue - unable to reach gem registry"
            elif 'compile' in error_lower or 'build' in error_lower:
                return f"Native compilation failed for {gem_name}=={version}"
            else:
                return f"Gem {gem_name}=={version} failed to install"
    
    def _generate_enhanced_notes(self, success: bool, output: str, error: str, gem_name: str, version: str, status: CompatibilityStatus) -> str:
        """Generate enhanced notes with validation details."""
        base_notes = self._generate_notes(success, output, error, gem_name, version)
        
        if success and status == CompatibilityStatus.NEEDS_VERIFICATION:
            # Add enhanced validation details
            require_test = self._test_gem_require(gem_name)
            arch_check = self._check_native_architecture(gem_name)
            known_issues = self._check_known_problematic_gems(gem_name)
            
            reasons = []
            if require_test == 'needs_verification':
                reasons.append("runtime 'require' test could not confirm loading")
            if arch_check == 'needs_verification':
                reasons.append("native extension architecture could not be verified")
            if known_issues == 'needs_verification':
                reasons.append("gem has known ARM64 compatibility concerns")
            
            if reasons:
                return f"{base_notes}. Needs manual verification: {'; '.join(reasons)}"
        
        return base_notes
    
    def _create_component_result(self, component_name: str, version: str, status: CompatibilityStatus,
                               notes: str, test_output: str, install_status: str,
                               fallback_used: bool, original_version: str, native_build_detected: str,
                               test_execution_output: str, error_details: str, error_type: str) -> ComponentResult:
        """Create ComponentResult using models.py schema."""
        
        # Create SoftwareComponent
        component = SoftwareComponent(
            name=component_name,
            version=version,
            component_type="ruby",
            source_sbom="runtime_analysis",
            properties={
                "environment": "ruby",
                "native_build_detected": native_build_detected,
                "install_status": install_status,
                "fallback_used": str(fallback_used).lower(),
                "original_version": original_version,
                "test_output": test_output,
                "test_execution_output": test_execution_output,
                "error_details": error_details,
                "error_type": error_type,
                "timestamp": datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ'),
                "runtime_analysis": "true"
            }
        )
        
        # Create CompatibilityResult
        compatibility = CompatibilityResult(
            status=status,
            current_version_supported=status in [CompatibilityStatus.COMPATIBLE, CompatibilityStatus.NEEDS_VERIFICATION],
            minimum_supported_version=version if status == CompatibilityStatus.COMPATIBLE else None,
            recommended_version=None,
            notes=notes,
            confidence_level=0.9
        )
        
        return ComponentResult(
            component=component,
            compatibility=compatibility,
            matched_name=None
        )


def show_help():
    """Display help information for Ruby package installer."""
    help_text = """
Ruby Package Installer - ARM64 Compatibility Analyzer

USAGE:
    python ruby_package_installer.py <Gemfile> [OPTIONS]

ARGUMENTS:
    Gemfile             Path to Gemfile to analyze

OPTIONS:
    -o, --output FILE  Save analysis results to specified JSON file
    -h, --help         Show this help message and exit

ENVIRONMENT VARIABLES:
    DEBUG              Enable debug logging with detailed output

DESCRIPTION:
    Analyzes Ruby gems from Gemfile for ARM64/Graviton compatibility.
    Tests gem installation, detects native builds, performs runtime loading
    tests, and checks architecture compatibility with enhanced validation.

FEATURES:
    - Runtime loading tests for installed gems
    - Native architecture compatibility checks
    - Known problematic gem detection
    - RubyGems.org platform verification
    - Basic functionality testing for common gems

EXAMPLES:
    python ruby_package_installer.py Gemfile
    python ruby_package_installer.py Gemfile -o results.json
    DEBUG=1 python ruby_package_installer.py Gemfile

OUTPUT:
    JSON format with compatibility status, installation results, native build
    detection, and enhanced validation results for each gem dependency.
    """
    print(help_text)

def main():
    """Main entry point for CLI usage."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Ruby Package Installer - ARM64 Compatibility Analyzer', add_help=False)
    parser.add_argument('gemfile', nargs='?', help='Path to Gemfile to analyze')
    parser.add_argument('-o', '--output', help='Output JSON file path')
    parser.add_argument('-h', '--help', action='store_true', help='Show help message')
    
    args = parser.parse_args()
    
    if args.help or not args.gemfile:
        show_help()
        if not args.gemfile:
            print("\nError: Gemfile is required.", file=sys.stderr)
            sys.exit(1)
        sys.exit(0)
    
    gemfile_path = args.gemfile
    logger.info(f"[RUBY_MAIN] Processing Gemfile: {gemfile_path}")
    logger.debug(f"[RUBY_MAIN] Output file: {args.output if args.output else 'stdout'}")
    
    try:
        analyzer = RubyCompatibilityAnalyzer()
        start_time = time.time()
        results = analyzer.analyze_gemfile(gemfile_path)
        duration = time.time() - start_time
        
        logger.info(f"[RUBY_MAIN] Analysis completed in {duration:.2f}s")
        logger.info(f"[RUBY_MAIN] Generated {len(results)} results")
        
        # Output results summary to debug log
        if results:
            status_counts = {}
            for result in results:
                status = result.compatibility.status.value
                status_counts[status] = status_counts.get(status, 0) + 1
            logger.debug(f"[RUBY_MAIN] Results summary: {status_counts}")
        
        if args.output:
            logger.info(f"[RUBY_MAIN] Results will be saved to: {args.output}")
        
        # Convert to flattened JSON format (matching SBOM structure)
        output_data = []
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
            
            output_data.append(result_dict)
        
        output_json = json.dumps(output_data, indent=2)
        
        if args.output:
            with open(args.output, 'w') as f:
                f.write(output_json)
            logger.info(f"[RUBY_MAIN] Analysis results saved to: {args.output}")
        else:
            print(output_json)
        
        logger.info("[RUBY_MAIN] Ruby Package Installer finished successfully")
        
    except Exception as e:
        logger.error(f"[RUBY_MAIN] Analysis failed: {e}")
        print(f"Error: {e}", file=sys.stderr)
        print("Use -h or --help for usage information.", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()