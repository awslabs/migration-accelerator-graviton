#!/usr/bin/env python3
"""
Java Package Installer for ARM64 Compatibility Analysis
Rewritten to use models.py schema with ComponentResult structure
"""

import os
import sys
import json
import requests
import subprocess
import defusedxml.ElementTree as ET
import re
import tempfile
import argparse
import time
import logging
import shutil
import zipfile
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime

# Add parent directories to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))  # Add graviton_validator/
sys.path.insert(0, str(Path(__file__).parent.parent.parent))  # Add project root

# Import models from the main validator
try:
    from graviton_validator.models import (
        SoftwareComponent, CompatibilityResult, ComponentResult, 
        CompatibilityStatus
    )
except ImportError:
    # Fallback for standalone execution
    try:
        from models import (
            SoftwareComponent, CompatibilityResult, ComponentResult, 
            CompatibilityStatus
        )
    except ImportError:
        # Final fallback - direct path
        from graviton_validator.models import (
            SoftwareComponent, CompatibilityResult, ComponentResult, 
            CompatibilityStatus
        )

# Initialize logger
logger = logging.getLogger(__name__)
handler = logging.StreamHandler(sys.stderr)
formatter = logging.Formatter('[%(asctime)s] %(levelname)s: %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.DEBUG if os.environ.get('DEBUG') else logging.INFO)

def debug(msg): logger.debug(msg)
def info(msg): logger.info(msg)
def warn(msg): logger.warning(msg)
def error(msg): logger.error(msg)

# Known problematic libraries with ARM compatibility issues
KNOWN_PROBLEMATIC_LIBRARIES = {
    'com.github.jnr:jnr-ffi': {'fixed_in': '2.2.0', 'issue': 'Native code compatibility issues', 'details': 'Uses native code for FFI that requires ARM-specific builds'},
    'net.java.dev.jna:jna': {'fixed_in': '5.5.0', 'issue': 'Native code compatibility issues', 'details': 'JNA provides Java access to native libraries, requires ARM-compatible native components'},
    'org.xerial:sqlite-jdbc': {'fixed_in': '3.34.0', 'issue': 'Native code compatibility issues', 'details': 'Contains native SQLite libraries that need ARM-specific builds'},
    'io.netty:netty-transport-native-epoll': {'fixed_in': '4.1.46.Final', 'issue': 'Native code compatibility issues', 'details': 'Uses native epoll libraries that require ARM-specific builds'},
    'org.rocksdb:rocksdbjni': {'fixed_in': '6.15.2', 'issue': 'Native code compatibility issues', 'details': 'RocksDB JNI bindings require ARM-compatible native libraries'},
    'org.lwjgl:lwjgl': {'fixed_in': '3.3.0', 'issue': 'Native code compatibility issues', 'details': 'Lightweight Java Game Library uses native code that needs ARM support'},
    'com.github.luben:zstd-jni': {'fixed_in': '1.5.0-4', 'issue': 'Native code compatibility issues', 'details': 'JNI bindings to Zstandard compression library require ARM-compatible builds'},
    'org.lz4:lz4-java': {'fixed_in': '1.8.0', 'issue': 'Native code compatibility issues', 'details': 'LZ4 compression algorithm implementation with JNI bindings needs ARM support'},
    'org.apache.hadoop:hadoop-native': {'fixed_in': '3.3.0', 'issue': 'Native code compatibility issues', 'details': 'Hadoop native libraries need ARM-specific builds'},
    'io.netty:netty-transport-native-unix-common': {'fixed_in': '4.1.46.Final', 'issue': 'Native code compatibility issues', 'details': 'Unix-specific native transport libraries need ARM support'},
    'org.apache.arrow:arrow-vector': {'fixed_in': '5.0.0', 'issue': 'Native code compatibility issues', 'details': 'Arrow memory management uses native code that needs ARM support'},
    'org.bytedeco:javacpp': {'fixed_in': '1.5.5', 'issue': 'Native code compatibility issues', 'details': 'JavaCPP provides native C++ integration that requires ARM-specific builds'}
}

NATIVE_CODE_LIBRARIES = [
    'org.lwjgl', 'com.github.jnr', 'net.java.dev.jna', 'org.xerial', 'io.netty',
    'org.rocksdb', 'org.bytedeco', 'org.apache.hadoop:hadoop-common', 'org.apache.hadoop:hadoop-hdfs',
    'org.apache.hadoop:hadoop-native', 'org.apache.spark', 'org.tensorflow',
    'org.apache.tinkerpop:gremlin-driver', 'com.sun.jna', 'org.eclipse.swt', 'org.fusesource',
    'com.github.luben:zstd-jni', 'org.lz4:lz4-java', 'org.apache.arrow',
    'io.netty:netty-transport-native', 'org.hdrhistogram:HdrHistogram', 'com.github.oshi:oshi-core',
    'org.apache.commons:commons-crypto', 'org.apache.commons:commons-compress',
    'org.apache.lucene:lucene-core', 'org.eclipse.jetty:jetty-native', 'com.github.jbellis:jamm',
    'org.lmdbjava:lmdbjava', 'org.neo4j:neo4j-native', 'org.apache.cassandra:cassandra-all',
    'native-lib-loader'
]

ARM_CLASSIFIER_LIBRARIES = {
    'io.netty:netty-transport-native-epoll': ['linux-aarch_64', 'linux-arm_64'],
    'org.lwjgl:lwjgl': ['natives-linux-arm64', 'natives-linux-arm32'],
    'org.bytedeco:javacpp': ['linux-arm64', 'linux-armhf'],
    'org.xerial:sqlite-jdbc': ['linux-aarch64', 'linux-arm'],
    'org.rocksdb:rocksdbjni': ['linux-aarch64', 'linux-arm64'],
    'com.github.luben:zstd-jni': ['linux-aarch64', 'linux-arm64'],
    'org.lz4:lz4-java': ['linux-aarch64', 'linux-arm64']
}

class JavaCompatibilityAnalyzer:
    """Main analyzer for Java dependency ARM64 compatibility."""
    
    def __init__(self):
        self.runtime_tester = None
        self.is_arm = self._detect_architecture()
        self.dependency_installer = None
    
    def cleanup(self):
        """Clean up all temporary resources."""
        debug(f"[JAVA_ANALYZER_CLEANUP] Starting cleanup of analyzer resources")
        
        if self.runtime_tester:
            self.runtime_tester.cleanup()
        
        if self.dependency_installer:
            self.dependency_installer.cleanup()
        
        debug(f"[JAVA_ANALYZER_CLEANUP] Analyzer cleanup completed")
    
    def _detect_architecture(self) -> bool:
        """Detect if running on ARM architecture with cross-platform support."""
        try:
            # Try Linux/macOS first
            arch = subprocess.run(['uname', '-m'], capture_output=True, text=True).stdout.strip()
            is_arm = arch in ['aarch64', 'arm64']
            debug(f"[ARCH_DETECT] Linux/macOS architecture: {arch}, is_arm: {is_arm}")
            if not is_arm:
                warn(f"Not running on ARM architecture ({arch}). Test results may not be accurate for ARM compatibility.")
            return is_arm
        except:
            # Try Windows
            try:
                arch = subprocess.run(['wmic', 'os', 'get', 'OSArchitecture'], 
                                    capture_output=True, text=True).stdout
                is_arm = 'ARM' in arch.upper()
                debug(f"[ARCH_DETECT] Windows architecture: {arch.strip()}, is_arm: {is_arm}")
                if not is_arm:
                    warn(f"Not running on ARM architecture. Test results may not be accurate for ARM compatibility.")
                return is_arm
            except:
                warn("Could not determine system architecture. Assuming x86.")
                return False
    
    def analyze_dependency(self, dep: Dict[str, Any], deep_scan: bool = False, 
                          runtime_test: bool = False) -> ComponentResult:
        """Analyze single dependency for ARM64 compatibility."""
        dep_key = f"{dep.get('groupId', '')}:{dep['artifactId']}:{dep.get('version', 'unknown')}"
        debug(f"[ANALYZE_START] Starting analysis for dependency: {dep_key}")
        debug(f"[ANALYZE_CONFIG] Analysis configuration - deep_scan: {deep_scan}, runtime_test: {runtime_test}")
        debug(f"[ANALYZE_INPUT] Full dependency data: {dep}")
        
        # Create SoftwareComponent
        component = SoftwareComponent(
            name=dep['artifactId'],
            version=dep.get('version', 'unknown'),
            component_type="java-17",
            source_sbom="runtime_analysis",
            properties={
                'environment': 'native_java_17_amazon-linux-2023',
                'groupId': dep.get('groupId', ''),
                'artifactId': dep['artifactId'],
                'runtime_analysis': 'true',
                'timestamp': datetime.utcnow().isoformat() + 'Z'
            }
        )
        
        # Initialize compatibility result
        compatibility = CompatibilityResult(
            status=CompatibilityStatus.UNKNOWN,
            current_version_supported=False,
            minimum_supported_version=None,
            recommended_version=None,
            notes="",
            confidence_level=0.9
        )
        
        try:
            debug(f"[ANALYZE_STEP1] Starting basic compatibility check for {dep_key}")
            # Basic compatibility check
            self._check_basic_compatibility(dep, component, compatibility)
            debug(f"[ANALYZE_STEP1_RESULT] Basic compatibility status: {compatibility.status.value}, supported: {compatibility.current_version_supported}")
            
            # Runtime testing first (to download JARs if needed)
            if runtime_test:
                debug(f"[ANALYZE_STEP2] Starting runtime testing for {dep_key}")
                self._perform_runtime_test(dep, component, compatibility)
                debug(f"[ANALYZE_STEP2_RESULT] Post-runtime test status: {compatibility.status.value}")
            
            # Deep JAR analysis after runtime test (so JARs are available)
            if deep_scan:
                debug(f"[ANALYZE_STEP3] Starting deep JAR analysis for {dep_key}")
                self._analyze_jar_file(dep, component, compatibility)
                debug(f"[ANALYZE_STEP3_RESULT] Post-JAR analysis status: {compatibility.status.value}")
            elif not runtime_test:
                debug(f"[ANALYZE_STEP3] Skipping deep JAR analysis (not requested)")
                
        except Exception as e:
            error(f"[ANALYZE_ERROR] Analysis failed for {dep_key}: {str(e)}")
            debug(f"[ANALYZE_ERROR_DETAILS] Exception type: {type(e).__name__}, traceback available in logs")
            compatibility.status = CompatibilityStatus.UNKNOWN
            compatibility.notes = f"Analysis failed: {str(e)}"
            component.properties['error_details'] = str(e)
            component.properties['error_type'] = 'dependency'
        
        debug(f"[ANALYZE_COMPLETE] Final result for {dep_key}: status={compatibility.status.value}, notes='{compatibility.notes[:100]}...'")
        return ComponentResult(component=component, compatibility=compatibility, matched_name=None)
    
    def _check_basic_compatibility(self, dep: Dict[str, Any], 
                                 component: SoftwareComponent, 
                                 compatibility: CompatibilityResult):
        """Perform basic compatibility analysis."""
        group_id = dep.get('groupId', '')
        artifact_id = dep.get('artifactId', '')
        version = dep.get('version', 'unknown')
        classifier = dep.get('classifier', '')
        
        dep_key = f"{group_id}:{artifact_id}" if group_id else artifact_id
        debug(f"[BASIC_CHECK_START] Checking basic compatibility for {dep_key}")
        debug(f"[BASIC_CHECK_DATA] groupId='{group_id}', artifactId='{artifact_id}', version='{version}', classifier='{classifier}'")
        
        # Check ARM-specific classifier
        debug(f"[BASIC_CHECK_CLASSIFIER] Checking classifier '{classifier}' for ARM indicators")
        if classifier and any(arm_arch in classifier.lower() for arm_arch in 
                             ['arm64', 'aarch64', 'arm', 'aarch32']):
            debug(f"[BASIC_CHECK_CLASSIFIER_MATCH] ARM-specific classifier detected: '{classifier}'")
            compatibility.status = CompatibilityStatus.COMPATIBLE
            compatibility.current_version_supported = True
            compatibility.notes = f"ARM-specific classifier '{classifier}' detected"
            component.properties['native_build_detected'] = 'Yes'
            debug(f"[BASIC_CHECK_RESULT] ARM classifier match - marking as COMPATIBLE")
            return
        else:
            debug(f"[BASIC_CHECK_CLASSIFIER_NO_MATCH] No ARM-specific classifier found")
        
        # Check Maven Central for ARM classifiers
        debug(f"[BASIC_CHECK_MAVEN_CENTRAL] Checking Maven Central for ARM classifiers for {dep_key}")
        arm_classifiers = MavenCentralChecker.check_arm_classifiers(dep)
        if arm_classifiers:
            debug(f"[BASIC_CHECK_MAVEN_CENTRAL_FOUND] Found ARM classifiers: {arm_classifiers}")
            component.properties['available_arm_classifiers'] = ','.join(arm_classifiers)
            if not classifier:
                compatibility.notes = f"ARM classifiers available: {', '.join(arm_classifiers)}. Consider using one."
        
        # Check known problematic libraries
        debug(f"[BASIC_CHECK_KNOWN_ISSUES] Checking if {dep_key} is in known problematic libraries list")
        if dep_key in KNOWN_PROBLEMATIC_LIBRARIES:
            issue_info = KNOWN_PROBLEMATIC_LIBRARIES[dep_key]
            debug(f"[BASIC_CHECK_KNOWN_ISSUES_FOUND] Found in problematic list - issue: '{issue_info['issue']}', fixed_in: '{issue_info['fixed_in']}'")
            version_comparison = self._compare_versions(version, issue_info['fixed_in'])
            debug(f"[BASIC_CHECK_VERSION_COMPARE] Comparing current version '{version}' with fixed version '{issue_info['fixed_in']}': result={version_comparison}")
            
            if version_comparison < 0:
                debug(f"[BASIC_CHECK_KNOWN_ISSUES_NEEDS_UPGRADE] Current version {version} is older than fixed version {issue_info['fixed_in']}")
                compatibility.status = CompatibilityStatus.NEEDS_UPGRADE
                compatibility.current_version_supported = False
                compatibility.minimum_supported_version = issue_info['fixed_in']
                compatibility.recommended_version = issue_info['fixed_in']
                compatibility.notes = f"Known ARM64 issue in v{version}, fixed in v{issue_info['fixed_in']}"
                component.properties['error_type'] = 'dependency'
            else:
                debug(f"[BASIC_CHECK_KNOWN_ISSUES_FIXED] Current version {version} includes the fix")
                compatibility.status = CompatibilityStatus.COMPATIBLE
                compatibility.current_version_supported = True
                compatibility.notes = f"ARM64 issues fixed in v{version}"
        else:
            debug(f"[BASIC_CHECK_KNOWN_ISSUES_NOT_FOUND] {dep_key} not found in known problematic libraries")
        # Check native code libraries
        debug(f"[BASIC_CHECK_NATIVE] Checking if {dep_key} matches any native code library patterns")
        native_lib_match = None
        for native_lib in NATIVE_CODE_LIBRARIES:
            if dep_key.startswith(native_lib):
                native_lib_match = native_lib
                debug(f"[BASIC_CHECK_NATIVE_MATCH] Matched native library pattern: '{native_lib}'")
                component.properties['native_build_detected'] = 'Yes'
                if compatibility.status == CompatibilityStatus.UNKNOWN:
                    compatibility.status = CompatibilityStatus.NEEDS_VERIFICATION
                    compatibility.notes = 'Native code detected. Needs manual verification: could not confirm ARM64 compatibility'
                    debug(f"[BASIC_CHECK_NATIVE_RESULT] Marked as NEEDS_VERIFICATION due to native code")
                break
        
        if not native_lib_match:
            debug(f"[BASIC_CHECK_NATIVE_NO_MATCH] No native code library patterns matched")
        
        # Default to compatible if no issues found
        if compatibility.status == CompatibilityStatus.UNKNOWN:
            debug(f"[BASIC_CHECK_DEFAULT] No specific issues found, defaulting to COMPATIBLE")
            compatibility.status = CompatibilityStatus.COMPATIBLE
            compatibility.current_version_supported = True
            compatibility.notes = "Pure Java library - fully compatible with ARM64"
            component.properties['native_build_detected'] = 'No'
        
        debug(f"[BASIC_CHECK_COMPLETE] Basic compatibility check complete for {dep_key}: status={compatibility.status.value}")
    
    def _analyze_jar_file(self, dep: Dict[str, Any], 
                         component: SoftwareComponent, 
                         compatibility: CompatibilityResult):
        """Analyze JAR file for native code and compatibility issues."""
        dep_key = f"{dep.get('groupId', '')}:{dep['artifactId']}"
        debug(f"[JAR_ANALYSIS_START] Starting JAR file analysis for {dep_key}")
        
        jar_path = self._get_jar_path(dep)
        debug(f"[JAR_ANALYSIS_PATH] Expected JAR path: {jar_path}")
        
        if not jar_path or not os.path.exists(jar_path):
            debug(f"[JAR_ANALYSIS_NOT_FOUND] JAR file not found at expected path")
            component.properties['error_details'] = f"JAR file not found: {jar_path}"
            return
        
        try:
            debug(f"[JAR_ANALYSIS_SCAN] Scanning JAR file for native code: {jar_path}")
            native_info = self._check_jar_native_code(jar_path)
            debug(f"[JAR_ANALYSIS_RESULTS] Native code scan results: {native_info}")
            
            if native_info['has_native_code']:
                debug(f"[JAR_ANALYSIS_NATIVE_FOUND] Native code detected in JAR")
                component.properties['native_build_detected'] = 'Yes'
                
                if native_info['arm_specific'] and not native_info['x86_specific']:
                    debug(f"[JAR_ANALYSIS_ARM_ONLY] ARM-only native libraries found")
                    compatibility.status = CompatibilityStatus.COMPATIBLE
                    compatibility.current_version_supported = True
                    compatibility.notes = "ARM64 native libraries found"
                elif native_info['x86_specific'] and not native_info['arm_specific']:
                    debug(f"[JAR_ANALYSIS_X86_ONLY] x86-only native libraries found")
                    compatibility.status = CompatibilityStatus.INCOMPATIBLE
                    compatibility.current_version_supported = False
                    compatibility.notes = "x86-only native libraries detected. Needs manual verification: may not work on ARM64/Graviton"
                    component.properties['error_type'] = 'native_build'
                elif native_info['has_jni'] and not native_info['fallback_available']:
                    debug(f"[JAR_ANALYSIS_JNI_NO_FALLBACK] JNI methods without fallback detected")
                    compatibility.status = CompatibilityStatus.NEEDS_VERIFICATION
                    compatibility.notes = "JNI methods without fallback detected"
                else:
                    debug(f"[JAR_ANALYSIS_MIXED_OR_UNCLEAR] Mixed architecture or unclear native code situation")
            else:
                debug(f"[JAR_ANALYSIS_NO_NATIVE] No native code found in JAR")
                
        except Exception as e:
            error(f"[JAR_ANALYSIS_ERROR] JAR analysis failed for {dep_key}: {str(e)}")
            component.properties['error_details'] = f"JAR analysis failed: {str(e)}"
    
    def _perform_runtime_test(self, dep: Dict[str, Any], 
                            component: SoftwareComponent, 
                            compatibility: CompatibilityResult):
        """Perform runtime compatibility testing and download dependencies."""
        dep_key = f"{dep.get('groupId', '')}:{dep['artifactId']}"
        debug(f"[RUNTIME_TEST_START] Starting runtime test for {dep_key}")
        
        if not self.dependency_installer:
            debug(f"[RUNTIME_TEST_INIT] Initializing dependency installer")
            self.dependency_installer = DependencyInstaller()
        
        try:
            debug(f"[RUNTIME_TEST_EXECUTE] Executing dependency installation test for {dep_key}")
            install_result = self.dependency_installer.test_dependency_installation(dep)
            debug(f"[RUNTIME_TEST_RESULT] Installation test result: {install_result['success']}")
            
            if install_result['success']:
                debug(f"[RUNTIME_TEST_SUCCESS] Dependency installation successful")
                if compatibility.status in [CompatibilityStatus.NEEDS_VERIFICATION, CompatibilityStatus.UNKNOWN]:
                    debug(f"[RUNTIME_TEST_UPGRADE_STATUS] Upgrading status from {compatibility.status.value} to COMPATIBLE")
                    compatibility.status = CompatibilityStatus.COMPATIBLE
                    compatibility.current_version_supported = True
                    compatibility.notes = "Dependency installation successful on ARM64"
                else:
                    debug(f"[RUNTIME_TEST_KEEP_STATUS] Keeping existing status {compatibility.status.value}")
            else:
                debug(f"[RUNTIME_TEST_FAILURE] Dependency installation failed")
                compatibility.status = CompatibilityStatus.INCOMPATIBLE
                compatibility.current_version_supported = False
                compatibility.notes = f"Dependency installation failed: {install_result.get('output', 'Unknown error')}"
                component.properties['error_details'] = install_result.get('output', 'Installation failed')
                
        except Exception as e:
            error(f"[RUNTIME_TEST_ERROR] Runtime test error for {dep_key}: {str(e)}")
            component.properties['error_details'] = f"Runtime test error: {str(e)}"
    
    def _get_jar_path(self, dep: Dict[str, Any]) -> str:
        """Get local JAR file path."""
        return os.path.expanduser(
            f"~/.m2/repository/{dep['groupId'].replace('.', '/')}/{dep['artifactId']}/{dep['version']}/{dep['artifactId']}-{dep['version']}.jar"
        )
    
    def _check_jar_native_code(self, jar_path: str) -> Dict[str, Any]:
        """Enhanced JAR analysis for native code, platform directories, JNI methods, and native library loaders."""
        debug(f"[JAR_NATIVE_CHECK_START] Checking JAR for native code: {jar_path}")
        native_info = {
            'has_native_code': False,
            'native_files': [],
            'arm_specific': False,
            'x86_specific': False,
            'has_jni': False,
            'jni_methods': [],
            'fallback_available': False,
            'platform_dirs': [],
            'native_lib_loaders': False,
            'errors': []
        }
        
        try:
            debug(f"[JAR_NATIVE_CHECK_OPEN] Opening JAR file for analysis")
            with zipfile.ZipFile(jar_path, 'r') as jar:
                jar_contents = jar.namelist()
                debug(f"[JAR_NATIVE_CHECK_CONTENTS] JAR contains {len(jar_contents)} entries")
                
                native_files_found = []
                platform_dirs_found = set()
                
                for entry in jar_contents:
                    entry_lower = entry.lower()
                    
                    # Check for native libraries
                    if entry_lower.endswith(('.so', '.dll', '.dylib', '.jnilib')):
                        debug(f"[JAR_NATIVE_CHECK_FOUND] Native library found: {entry}")
                        native_info['has_native_code'] = True
                        native_info['native_files'].append(entry)
                        native_files_found.append(entry)
                        
                        # Check for ARM-specific libraries
                        arm_indicators = ['arm64', 'aarch64', 'arm', 'aarch32', 'armv7', 'armv8']
                        arm_match = [arch for arch in arm_indicators if arch in entry_lower]
                        if arm_match:
                            debug(f"[JAR_NATIVE_CHECK_ARM] ARM-specific library detected: {entry} (matched: {arm_match})")
                            native_info['arm_specific'] = True
                        
                        # Check for x86-specific libraries
                        x86_indicators = ['x86_64', 'x86', 'amd64', 'i386', 'i686']
                        x86_match = [arch for arch in x86_indicators if arch in entry_lower]
                        if x86_match:
                            debug(f"[JAR_NATIVE_CHECK_X86] x86-specific library detected: {entry} (matched: {x86_match})")
                            native_info['x86_specific'] = True
                    
                    # Check for platform-specific directories
                    platform_patterns = [
                        'linux-arm', 'linux-arm64', 'linux-aarch64', 'linux-x86', 'linux-x86_64', 'linux-amd64',
                        'windows-arm', 'windows-arm64', 'windows-x86', 'windows-x86_64', 'windows-amd64',
                        'darwin-arm64', 'darwin-x86_64', 'darwin-amd64', 'macos-arm64', 'macos-x86_64',
                        'lib/arm', 'lib/arm64', 'lib/aarch64', 'lib/x86', 'lib/x86_64', 'lib/amd64',
                        'native/arm', 'native/arm64', 'native/aarch64', 'native/x86', 'native/x86_64',
                        'META-INF/native', 'natives-linux-arm64', 'natives-linux-arm32'
                    ]
                    
                    for pattern in platform_patterns:
                        if pattern in entry_lower:
                            native_info['has_native_code'] = True
                            platform_dirs_found.add(pattern)
                            debug(f"[JAR_NATIVE_CHECK_PLATFORM] Platform-specific directory found: {entry} (pattern: {pattern})")
                            
                            # Determine architecture from platform directory
                            if any(arm_dir in pattern for arm_dir in ['arm', 'aarch']):
                                native_info['arm_specific'] = True
                            if any(x86_dir in pattern for x86_dir in ['x86', 'amd64', 'i386', 'i686']):
                                native_info['x86_specific'] = True
                            break
                    
                    # Check for native library loaders
                    if any(loader in entry_lower for loader in ['native-lib-loader', 'nativelibraryloader', 'jniloader']):
                        debug(f"[JAR_NATIVE_CHECK_LOADER] Native library loader found: {entry}")
                        native_info['native_lib_loaders'] = True
                        native_info['has_native_code'] = True
                    
                    # Check for JNI-related files
                    if '.class' in entry_lower:
                        try:
                            # Read class file and check for JNI methods (simplified check)
                            class_data = jar.read(entry)
                            if b'native' in class_data:
                                native_info['has_jni'] = True
                                debug(f"[JAR_NATIVE_CHECK_JNI] Potential JNI methods found in: {entry}")
                        except:
                            pass
                
                native_info['platform_dirs'] = list(platform_dirs_found)
                debug(f"[JAR_NATIVE_CHECK_SUMMARY] Found {len(native_files_found)} native files, {len(platform_dirs_found)} platform dirs, ARM-specific: {native_info['arm_specific']}, x86-specific: {native_info['x86_specific']}, JNI: {native_info['has_jni']}, loaders: {native_info['native_lib_loaders']}")
                            
        except Exception as e:
            error(f"[JAR_NATIVE_CHECK_ERROR] JAR analysis error for {jar_path}: {str(e)}")
            native_info['errors'].append(f"JAR analysis error: {str(e)}")
        
        return native_info
    
    def _compare_versions(self, version1: str, version2: str) -> int:
        """Compare version strings. Returns -1, 0, or 1."""
        def normalize(v):
            # Handle None and strip whitespace
            if not v:
                return [0]
            v = str(v).strip().lower().replace('final', '').replace('release', '').strip()
            parts = []
            for x in re.split(r'[.\-]', v):
                x = x.strip()  # Strip whitespace from each part
                if x:
                    if x.isdigit():
                        parts.append(int(x))
                    else:
                        parts.append(x)
            return parts if parts else [0]
        
        parts1, parts2 = normalize(version1), normalize(version2)
        
        for i in range(max(len(parts1), len(parts2))):
            v1 = parts1[i] if i < len(parts1) else 0
            v2 = parts2[i] if i < len(parts2) else 0
            
            if isinstance(v1, int) and isinstance(v2, int):
                if v1 != v2:
                    return -1 if v1 < v2 else 1
            else:
                if str(v1) != str(v2):
                    return -1 if str(v1) < str(v2) else 1
        
        return 0

class MavenCentralChecker:
    """Check Maven Central for ARM-specific classifiers and dependency information."""
    
    @staticmethod
    def check_arm_classifiers(dep: Dict[str, Any]) -> List[str]:
        """Check Maven Central for ARM-specific classifiers."""
        arm_classifiers = []
        try:
            group_id = dep.get('groupId', '')
            artifact_id = dep.get('artifactId', '')
            version = dep.get('version', 'unknown')
            
            if not group_id or not artifact_id or version == 'unknown':
                return arm_classifiers
            
            # Maven Central REST API URL
            base_url = "https://search.maven.org/solrsearch/select"
            query = f'g:"{group_id}" AND a:"{artifact_id}" AND v:"{version}"'
            params = {'q': query, 'rows': 100, 'wt': 'json'}
            
            debug(f"[MAVEN_CENTRAL] Checking for ARM classifiers: {group_id}:{artifact_id}:{version}")
            response = requests.get(base_url, params=params, timeout=10)
            response.raise_for_status()
            
            data = response.json()
            for doc in data.get('response', {}).get('docs', []):
                classifier = doc.get('c')
                if classifier and any(arm_arch in classifier.lower() for arm_arch in 
                                   ['arm64', 'aarch64', 'arm', 'aarch32', 'armv7', 'armv8']):
                    arm_classifiers.append(classifier)
                    debug(f"[MAVEN_CENTRAL] Found ARM classifier: {classifier}")
            
            return arm_classifiers
        except Exception as e:
            debug(f"[MAVEN_CENTRAL] Error checking for ARM classifiers: {str(e)}")
            return []

class DependencyInstaller:
    """Test individual dependency installation via Maven."""
    
    def __init__(self, temp_dir: str = None):
        self.temp_dir = temp_dir or tempfile.mkdtemp()
        self.error_log = []
        self.temp_dirs_to_cleanup = []
    
    def cleanup(self):
        """Clean up temporary directories and files."""
        debug(f"[DEP_INSTALL_CLEANUP] Starting cleanup of {len(self.temp_dirs_to_cleanup)} temporary directories")
        
        for temp_dir in self.temp_dirs_to_cleanup:
            try:
                if os.path.exists(temp_dir):
                    shutil.rmtree(temp_dir)
                    debug(f"[DEP_INSTALL_CLEANUP] Removed directory: {temp_dir}")
            except Exception as e:
                debug(f"[DEP_INSTALL_CLEANUP] Failed to remove {temp_dir}: {e}")
        
        # Clean up main temp directory
        try:
            if os.path.exists(self.temp_dir):
                shutil.rmtree(self.temp_dir)
                debug(f"[DEP_INSTALL_CLEANUP] Removed main temp directory: {self.temp_dir}")
        except Exception as e:
            debug(f"[DEP_INSTALL_CLEANUP] Failed to remove main temp dir {self.temp_dir}: {e}")
        
        debug(f"[DEP_INSTALL_CLEANUP] Cleanup completed")
    
    def test_dependency_installation(self, dep: Dict[str, Any]) -> Dict[str, Any]:
        """Test if a dependency can be installed via Maven."""
        dep_key = f"{dep.get('groupId', '')}:{dep.get('artifactId', '')}:{dep.get('version', 'unknown')}"
        debug(f"[DEP_INSTALL] Testing installation for: {dep_key}")
        
        try:
            # Create temporary test project
            project_dir = self._create_minimal_project(dep)
            
            # Try to resolve dependency
            result = subprocess.run(
                ['mvn', 'dependency:resolve', '-q'], 
                cwd=project_dir, capture_output=True, text=True, timeout=60
            )
            
            success = result.returncode == 0
            output = result.stdout + result.stderr
            
            if not success:
                self.error_log.append(f"{dep_key}: {output}")
                debug(f"[DEP_INSTALL] Installation failed for {dep_key}: {output[:200]}...")
            else:
                debug(f"[DEP_INSTALL] Installation successful for {dep_key}")
            
            return {
                'success': success,
                'output': output,
                'dependency': dep_key
            }
            
        except Exception as e:
            error_msg = f"Installation test failed: {str(e)}"
            self.error_log.append(f"{dep_key}: {error_msg}")
            debug(f"[DEP_INSTALL] Exception during installation test for {dep_key}: {str(e)}")
            return {
                'success': False,
                'output': error_msg,
                'dependency': dep_key
            }
    
    def _create_minimal_project(self, dep: Dict[str, Any]) -> str:
        """Create minimal Maven project for dependency testing."""
        project_dir = os.path.join(self.temp_dir, f"test-install-{dep.get('artifactId', 'unknown')}")
        os.makedirs(project_dir, exist_ok=True)
        self.temp_dirs_to_cleanup.append(project_dir)
        
        pom_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.amazon.graviton-test</groupId>
    <artifactId>dependency-install-test</artifactId>
    <version>1.0</version>
    <dependencies>
        <dependency>
            <groupId>{dep.get('groupId', '')}</groupId>
            <artifactId>{dep.get('artifactId', '')}</artifactId>
            <version>{dep.get('version', 'LATEST')}</version>
        </dependency>
    </dependencies>
</project>"""
        
        with open(os.path.join(project_dir, "pom.xml"), "w") as f:
            f.write(pom_xml)
        
        return project_dir
    
    def get_error_log(self) -> List[str]:
        """Get list of installation errors."""
        return self.error_log.copy()

class JavaRuntimeTester:
    """Runtime testing framework for ARM64 compatibility."""
    
    def __init__(self, temp_dir: str = None):
        self.temp_dir = temp_dir or tempfile.mkdtemp()
        self.is_arm = self._detect_architecture()
        self.temp_dirs_to_cleanup = []
    
    def cleanup(self):
        """Clean up temporary directories and files."""
        debug(f"[RUNTIME_TEST_CLEANUP] Starting cleanup of {len(self.temp_dirs_to_cleanup)} temporary directories")
        
        for temp_dir in self.temp_dirs_to_cleanup:
            try:
                if os.path.exists(temp_dir):
                    shutil.rmtree(temp_dir)
                    debug(f"[RUNTIME_TEST_CLEANUP] Removed directory: {temp_dir}")
            except Exception as e:
                debug(f"[RUNTIME_TEST_CLEANUP] Failed to remove {temp_dir}: {e}")
        
        # Clean up main temp directory
        try:
            if os.path.exists(self.temp_dir):
                shutil.rmtree(self.temp_dir)
                debug(f"[RUNTIME_TEST_CLEANUP] Removed main temp directory: {self.temp_dir}")
        except Exception as e:
            debug(f"[RUNTIME_TEST_CLEANUP] Failed to remove main temp dir {self.temp_dir}: {e}")
        
        debug(f"[RUNTIME_TEST_CLEANUP] Cleanup completed")
    
    def _detect_architecture(self) -> bool:
        """Detect if running on ARM architecture with cross-platform support."""
        try:
            # Try Linux/macOS first
            arch = subprocess.run(['uname', '-m'], capture_output=True, text=True).stdout.strip()
            return arch in ['aarch64', 'arm64']
        except:
            # Try Windows
            try:
                arch = subprocess.run(['wmic', 'os', 'get', 'OSArchitecture'], 
                                    capture_output=True, text=True).stdout
                return 'ARM' in arch.upper()
            except:
                return False
    
    def test_dependency(self, dep: Dict[str, Any], component: SoftwareComponent) -> bool:
        """Test dependency runtime compatibility."""
        try:
            project_dir = self._create_test_project(dep)
            test_result = self._compile_and_run(project_dir)
            
            component.properties['test_output'] = test_result.get('output', '')
            component.properties['test_execution_output'] = test_result.get('execution_output', '')
            
            if not test_result['success']:
                component.properties['error_details'] = test_result.get('error', 'Runtime test failed')
                component.properties['error_type'] = self._classify_runtime_error(test_result.get('error', ''))
                return False
            
            return True
            
        except Exception as e:
            component.properties['error_details'] = f"Runtime test setup failed: {str(e)}"
            component.properties['error_type'] = 'dependency'
            return False
    
    def _create_test_project(self, dep: Dict[str, Any]) -> str:
        """Create temporary Maven project for testing."""
        project_dir = os.path.join(self.temp_dir, f"test-{dep['artifactId']}")
        os.makedirs(project_dir, exist_ok=True)
        self.temp_dirs_to_cleanup.append(project_dir)
        
        # Create test class
        package_dir = os.path.join(project_dir, "src", "main", "java", "com", "amazon", "gravitontest")
        os.makedirs(package_dir, exist_ok=True)
        
        test_class = f"""
package com.amazon.gravitontest;

public class DependencyTest {{
    public static void main(String[] args) {{
        System.out.println("Testing {dep['groupId']}:{dep['artifactId']}:{dep['version']}");
        try {{
            System.out.println("Maven successfully resolved the dependency");
            System.out.println("Dependency test completed successfully");
        }} catch (Exception e) {{
            System.out.println("Error testing dependency: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }}
    }}
}}"""
        
        with open(os.path.join(package_dir, "DependencyTest.java"), "w") as f:
            f.write(test_class)
        
        # Create pom.xml
        pom_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.amazon.graviton-compatibility</groupId>
    <artifactId>dependency-test</artifactId>
    <version>1.0</version>
    <dependencies>
        <dependency>
            <groupId>{dep['groupId']}</groupId>
            <artifactId>{dep['artifactId']}</artifactId>
            <version>{dep['version']}</version>
        </dependency>
    </dependencies>
    <build>
        <plugins>
            <plugin>
                <groupId>org.apache.maven.plugins</groupId>
                <artifactId>maven-compiler-plugin</artifactId>
                <version>3.8.1</version>
                <configuration>
                    <source>1.8</source>
                    <target>1.8</target>
                </configuration>
            </plugin>
        </plugins>
    </build>
</project>"""
        
        with open(os.path.join(project_dir, "pom.xml"), "w") as f:
            f.write(pom_xml)
        
        return project_dir
    
    def _compile_and_run(self, project_dir: str) -> Dict[str, Any]:
        """Compile and run test project."""
        try:
            # Compile
            compile_result = subprocess.run(
                ['mvn', 'compile'], cwd=project_dir,
                capture_output=True, text=True, timeout=120
            )
            
            if compile_result.returncode != 0:
                return {
                    'success': False,
                    'error': f"{compile_result.stderr}\nStdout: {compile_result.stdout}",
                    'output': compile_result.stdout
                }
            
            # Run
            run_result = subprocess.run(
                ['mvn', 'exec:java', '-Dexec.mainClass=com.amazon.gravitontest.DependencyTest'], 
                cwd=project_dir, capture_output=True, text=True, timeout=60
            )
            
            return {
                'success': run_result.returncode == 0,
                'output': run_result.stdout,
                'execution_output': run_result.stderr,
                'error': f"{run_result.stderr}\nStdout: {run_result.stdout}" if run_result.returncode != 0 else ''
            }
            
        except subprocess.TimeoutExpired:
            return {'success': False, 'error': 'Test execution timed out', 'output': ''}
        except Exception as e:
            return {'success': False, 'error': str(e), 'output': ''}
    
    def _classify_runtime_error(self, error_msg: str) -> str:
        """Classify runtime errors."""
        if 'ClassNotFoundException' in error_msg or 'UnsatisfiedLinkError' in error_msg:
            return 'native_build'
        elif 'permission' in error_msg.lower():
            return 'permissions'
        elif 'network' in error_msg.lower() or 'connection' in error_msg.lower():
            return 'network'
        else:
            return 'dependency'

class PomPluginAnalyzer:
    """Analyze POM files for ARM-specific plugin configurations."""
    
    @staticmethod
    def check_arm_plugins(pom_path: str) -> List[str]:
        """Check a pom.xml file for Maven plugins with ARM-specific configurations."""
        arm_configs = []
        try:
            tree = ET.parse(pom_path)
            root = tree.getroot()
            ns = {'maven': 'http://maven.apache.org/POM/4.0.0'}
            
            # Check for Spring Boot Maven plugin with imagePlatform configuration
            spring_boot_plugins = root.findall('.//maven:plugin[maven:artifactId="spring-boot-maven-plugin"]', ns)
            for plugin in spring_boot_plugins:
                image_platform_elements = plugin.findall('.//maven:imagePlatform', ns)
                for platform_elem in image_platform_elements:
                    if platform_elem is not None and 'arm' in platform_elem.text.lower():
                        arm_configs.append(f"Spring Boot Maven Plugin with imagePlatform={platform_elem.text}")
            
            # Check for Docker Maven plugin with platform configuration
            docker_plugins = root.findall('.//maven:plugin[maven:artifactId="docker-maven-plugin"]', ns)
            for plugin in docker_plugins:
                platform_elements = plugin.findall('.//maven:platform', ns)
                for platform_elem in platform_elements:
                    if platform_elem is not None and 'arm' in platform_elem.text.lower():
                        arm_configs.append(f"Docker Maven Plugin with platform={platform_elem.text}")
            
            # Check for Jib Maven plugin with platform configuration
            jib_plugins = root.findall('.//maven:plugin[maven:artifactId="jib-maven-plugin"]', ns)
            for plugin in jib_plugins:
                platform_elements = plugin.findall('.//maven:platform', ns)
                for platform_elem in platform_elements:
                    if platform_elem is not None and 'arm' in platform_elem.text.lower():
                        arm_configs.append(f"Jib Maven Plugin with platform={platform_elem.text}")
            
            debug(f"Found ARM plugin configurations: {arm_configs}")
            return arm_configs
        except Exception as e:
            debug(f"Error checking POM for ARM plugins: {str(e)}")
            return []
    
    @staticmethod
    def check_dependency_management(pom_path: str) -> List[Dict[str, Any]]:
        """Check a pom.xml file for dependency management section."""
        managed_deps = []
        try:
            tree = ET.parse(pom_path)
            root = tree.getroot()
            ns = {'maven': 'http://maven.apache.org/POM/4.0.0'}
            
            # Get dependencies in dependencyManagement section
            for dep in root.findall('.//maven:dependencyManagement/maven:dependencies/maven:dependency', ns):
                group_id_elem = dep.find('./maven:groupId', ns)
                artifact_id_elem = dep.find('./maven:artifactId', ns)
                version_elem = dep.find('./maven:version', ns)
                
                if group_id_elem is not None and artifact_id_elem is not None:
                    # Get optional fields
                    scope_elem = dep.find('./maven:scope', ns)
                    type_elem = dep.find('./maven:type', ns)
                    classifier_elem = dep.find('./maven:classifier', ns)
                    
                    managed_deps.append({
                        'groupId': group_id_elem.text.strip() if group_id_elem.text else '',
                        'artifactId': artifact_id_elem.text.strip() if artifact_id_elem.text else '',
                        'version': version_elem.text.strip() if version_elem is not None and version_elem.text else 'unknown',
                        'scope': scope_elem.text.strip() if scope_elem is not None and scope_elem.text else None,
                        'type': type_elem.text.strip() if type_elem is not None and type_elem.text else 'jar',
                        'classifier': classifier_elem.text.strip() if classifier_elem is not None and classifier_elem.text else None
                    })
            
            debug(f"Found {len(managed_deps)} dependencies in dependencyManagement")
            return managed_deps
        except Exception as e:
            debug(f"Error checking POM for dependency management: {str(e)}")
            return []

class PomParser:
    """POM file parser."""
    
    def __init__(self):
        self.properties = {}
    
    def parse(self, pom_path: str) -> List[Dict[str, Any]]:
        """Parse POM file and extract dependencies."""
        dependencies = []
        
        try:
            tree = ET.parse(pom_path)
            root = tree.getroot()
            ns = {'maven': 'http://maven.apache.org/POM/4.0.0'}
            
            # Extract properties first
            self._extract_properties(root, ns)
            
            # Extract dependencies
            for dep in root.findall('.//maven:dependencies/maven:dependency', ns):
                dep_info = self._extract_dependency_info(dep, ns)
                if dep_info:
                    dependencies.append(dep_info)
        
        except Exception as e:
            error(f"Error parsing POM: {e}")
        
        return dependencies
    
    def _extract_properties(self, root, ns):
        """Extract Maven properties from POM."""
        for prop in root.findall('.//maven:properties/*', ns):
            if prop.tag and prop.text:
                # Remove namespace prefix from tag
                prop_name = prop.tag.split('}')[-1] if '}' in prop.tag else prop.tag
                self.properties[prop_name] = prop.text.strip()
    
    def _extract_dependency_info(self, dep, ns) -> Optional[Dict[str, Any]]:
        """Extract dependency information from XML element."""
        try:
            group_id_elem = dep.find('./maven:groupId', ns)
            artifact_id_elem = dep.find('./maven:artifactId', ns)
            version_elem = dep.find('./maven:version', ns)
            
            if group_id_elem is None or artifact_id_elem is None:
                return None
            
            # Strip whitespace from all text content
            dep_info = {
                'groupId': group_id_elem.text.strip() if group_id_elem.text else '',
                'artifactId': artifact_id_elem.text.strip() if artifact_id_elem.text else '',
                'version': version_elem.text.strip() if version_elem is not None and version_elem.text else 'unknown'
            }
            
            # Optional fields
            scope_elem = dep.find('./maven:scope', ns)
            if scope_elem is not None and scope_elem.text:
                dep_info['scope'] = scope_elem.text.strip()
            
            classifier_elem = dep.find('./maven:classifier', ns)
            if classifier_elem is not None and classifier_elem.text:
                dep_info['classifier'] = classifier_elem.text.strip()
            
            return dep_info
            
        except Exception as e:
            warn(f"Error extracting dependency info: {e}")
            return None

def analyze_pom_file(pom_path: str, deep_scan: bool = False, runtime_test: bool = False) -> List[ComponentResult]:
    """Analyze POM file for ARM64 compatibility with version grouping and inheritance."""
    debug(f"[POM_ANALYSIS_START] Starting POM analysis: {pom_path}")
    debug(f"[POM_ANALYSIS_CONFIG] Configuration - deep_scan: {deep_scan}, runtime_test: {runtime_test}")
    info(f"Starting Java package analysis for: {pom_path}")
    
    # Parse dependencies first
    debug(f"[POM_PARSE_START] Starting dependency parsing from {pom_path}")
    parser = PomParser()
    dependencies = parser.parse(pom_path)
    # Make parser available for property resolution
    globals()['parser'] = parser
    debug(f"[POM_PARSE_RESULT] Extracted {len(dependencies)} dependencies from POM")
    
    if not dependencies:
        debug(f"[POM_PARSE_NO_DEPS] No dependencies found in POM file")
        return []
    
    # Group dependencies by groupId:artifactId
    debug(f"[POM_GROUP_START] Grouping dependencies by groupId:artifactId")
    dependency_groups = {}
    for dep in dependencies:
        key = f"{dep['groupId']}:{dep['artifactId']}"
        if key not in dependency_groups:
            dependency_groups[key] = []
        dependency_groups[key].append(dep)
    
    debug(f"[POM_GROUP_RESULT] Grouped {len(dependencies)} dependencies into {len(dependency_groups)} groups")
    
    # Analyze each dependency group with version inheritance
    debug(f"[POM_ANALYZE_START] Starting analysis of {len(dependency_groups)} dependency groups")
    analyzer = JavaCompatibilityAnalyzer()
    
    # Test dependency installation first
    debug(f"[POM_DEP_INSTALL_START] Testing dependency installation")
    installer = DependencyInstaller()
    analyzer.dependency_installer = installer
    
    if dependencies:
        debug(f"[POM_DEP_INSTALL] Testing installation for {min(len(dependencies), 5)} dependencies")
        install_results = []
        for dep in dependencies[:5]:  # Test first 5 dependencies to avoid long delays
            result = installer.test_dependency_installation(dep)
            install_results.append(result)
        
        success_count = sum(1 for r in install_results if r['success'])
        failure_count = len(install_results) - success_count
        debug(f"[POM_DEP_INSTALL_RESULT] Installation test: {success_count} successful, {failure_count} failed")
        
        if failure_count > 0:
            error_log = installer.get_error_log()
            debug(f"[POM_DEP_INSTALL_ERRORS] Installation errors: {len(error_log)} total")
            for error_entry in error_log[:3]:  # Log first 3 errors
                debug(f"[POM_DEP_INSTALL_ERROR] {error_entry}")
    
    # Check for Maven plugins and configurations related to ARM
    debug(f"[POM_PLUGINS_START] Checking for ARM-specific Maven plugins in {pom_path}")
    pom_analyzer = PomPluginAnalyzer()
    arm_plugin_configs = pom_analyzer.check_arm_plugins(pom_path)
    debug(f"[POM_PLUGINS_RESULT] Found {len(arm_plugin_configs)} ARM plugin configurations")
    
    if arm_plugin_configs:
        debug(f"[POM_PLUGINS_DETAILS] ARM plugin configurations found:")
        info("Found Maven plugins with ARM-specific configurations:")
        for i, config in enumerate(arm_plugin_configs):
            debug(f"[POM_PLUGINS_DETAILS] {i+1}. {config}")
            info(f"  - {config}")
    else:
        debug(f"[POM_PLUGINS_NONE] No ARM-specific plugin configurations found")
    
    # Check for dependency management section
    debug(f"[POM_DEP_MGMT_START] Checking dependency management section in {pom_path}")
    dependency_management = pom_analyzer.check_dependency_management(pom_path)
    debug(f"[POM_DEP_MGMT_RESULT] Found {len(dependency_management)} managed dependencies")
    
    if dependency_management:
        debug(f"[POM_DEP_MGMT_DETAILS] Dependency management entries:")
        for i, dep in enumerate(dependency_management[:5]):  # Log first 5 for brevity
            debug(f"[POM_DEP_MGMT_DETAILS] {i+1}. {dep.get('groupId', '')}:{dep.get('artifactId', '')}:{dep.get('version', 'unknown')}")
        if len(dependency_management) > 5:
            debug(f"[POM_DEP_MGMT_DETAILS] ... and {len(dependency_management) - 5} more")
        info(f"Found {len(dependency_management)} dependencies in dependencyManagement section")
    else:
        debug(f"[POM_DEP_MGMT_NONE] No dependency management section found")
    
    if dependencies:
        debug(f"[POM_PARSE_DETAILS] First few dependencies:")
        for i, dep in enumerate(dependencies[:3]):  # Log first 3 for brevity
            debug(f"[POM_PARSE_DETAILS] {i+1}. {dep.get('groupId', '')}:{dep.get('artifactId', '')}:{dep.get('version', 'unknown')}")
        if len(dependencies) > 3:
            debug(f"[POM_PARSE_DETAILS] ... and {len(dependencies) - 3} more dependencies")
    

    
    results = []
    total_groups = len(dependency_groups)
    analysis_start = time.time()
    compatible_count = 0
    upgrade_count = 0
    
    try:
        for i, (group_key, group_deps) in enumerate(dependency_groups.items(), 1):
            if i == 1 or i % 10 == 0 or total_groups <= 20:
                info(f"Processing dependency {i}/{total_groups}: {group_key}...")
                sys.stderr.flush()
            debug(f"[POM_ANALYZE_GROUP] Analyzing group {i}/{total_groups}: {group_key} ({len(group_deps)} versions)")
            group_results = analyze_dependency_versions(group_key, group_deps, analyzer, 
                                                       deep_scan, runtime_test)
            debug(f"[POM_ANALYZE_GROUP_RESULT] Group {group_key} produced {len(group_results)} results")
            results.extend(group_results)
            for r in group_results:
                if r.compatibility.status == CompatibilityStatus.COMPATIBLE:
                    compatible_count += 1
                elif r.compatibility.status == CompatibilityStatus.NEEDS_UPGRADE:
                    upgrade_count += 1
    
        elapsed = time.time() - analysis_start
        info(f"Java analysis complete: {len(results)} packages processed in {elapsed:.1f}s — {compatible_count} compatible, {upgrade_count} need upgrade")
        sys.stderr.flush()
    
    finally:
        # Cleanup analyzer resources
        debug(f"[POM_ANALYZE_CLEANUP] Starting cleanup phase")
        analyzer.cleanup()
        debug(f"[POM_ANALYZE_CLEANUP] Cleanup phase completed")
    
    # Add summary information about ARM plugin configurations and dependency management
    if arm_plugin_configs or dependency_management:
        summary_component = SoftwareComponent(
            name="pom-configuration-summary",
            version="N/A",
            component_type="java-17",
            source_sbom="runtime_analysis",
            properties={
                'environment': 'native_java_17_amazon-linux-2023',
                'runtime_analysis': 'true',
                'timestamp': datetime.utcnow().isoformat() + 'Z',
                'arm_plugin_configs': str(len(arm_plugin_configs)),
                'dependency_management_entries': str(len(dependency_management))
            }
        )
        
        summary_notes = []
        if arm_plugin_configs:
            summary_notes.append(f"ARM plugin configurations: {len(arm_plugin_configs)} found")
        if dependency_management:
            summary_notes.append(f"Dependency management: {len(dependency_management)} entries")
        
        summary_compatibility = CompatibilityResult(
            status=CompatibilityStatus.COMPATIBLE,
            current_version_supported=True,
            minimum_supported_version=None,
            recommended_version=None,
            notes='; '.join(summary_notes),
            confidence_level=0.9
        )
        
        results.insert(0, ComponentResult(component=summary_component, compatibility=summary_compatibility, matched_name=None))
    
    return results

def analyze_dependency_versions(group_key: str, versions: List[Dict[str, Any]], 
                               analyzer: JavaCompatibilityAnalyzer, deep_scan: bool, 
                               runtime_test: bool) -> List[ComponentResult]:
    """Analyze multiple versions of same dependency with inheritance logic."""
    debug(f"[VERSION_ANALYSIS_START] Testing {len(versions)} versions for {group_key}")
    debug(f"[VERSION_ANALYSIS_INPUT] Versions to test: {[v.get('version', 'unknown') for v in versions]}")
    
    # Sort versions semantically (lowest to highest) with error handling
    debug(f"[VERSION_ANALYSIS_SORT] Sorting versions semantically")
    try:
        # Get properties from parser if available
        properties = getattr(parser, 'properties', {}) if 'parser' in locals() else {}
        sorted_versions = sorted(versions, key=lambda v: _parse_version(v.get('version', 'unknown'), properties))
        sorted_version_list = [v.get('version', 'unknown') for v in sorted_versions]
        debug(f"[VERSION_ANALYSIS_SORT_RESULT] Sorted order: {sorted_version_list}")
    except Exception as e:
        # Fallback: use original order without sorting
        sorted_versions = versions
        debug(f"[VERSION_ANALYSIS_SORT_FALLBACK] Using original order due to sorting error")
    
    results = []
    working_version_found = False
    failed_versions = []
    
    for i, dep in enumerate(sorted_versions, 1):
        version = dep.get('version', 'unknown')
        debug(f"[VERSION_ANALYSIS_TEST] Testing version {i}/{len(sorted_versions)}: {group_key}:{version}")
        
        result = analyzer.analyze_dependency(dep, deep_scan, runtime_test)
        debug(f"[VERSION_ANALYSIS_TEST_RESULT] Version {version} result: {result.compatibility.status.value}")
        
        # Version inheritance logic
        if result.compatibility.status == CompatibilityStatus.COMPATIBLE:
            working_version_found = True
            debug(f"[VERSION_ANALYSIS_COMPATIBLE] Compatible version found: {version}")
            debug(f"[VERSION_ANALYSIS_INHERITANCE] Applying inheritance logic to {len(failed_versions)} failed versions")
            
            # Mark all previous failed versions as needs_upgrade
            for j, failed_result in enumerate(failed_versions):
                old_status = failed_result.compatibility.status.value
                failed_result.compatibility.status = CompatibilityStatus.NEEDS_UPGRADE
                failed_result.compatibility.current_version_supported = False
                failed_result.compatibility.recommended_version = version
                failed_result.compatibility.notes = f"Upgrade to v{version} for ARM64 compatibility"
                failed_result.component.properties['fallback_used'] = 'true'
                debug(f"[VERSION_ANALYSIS_INHERITANCE] Updated failed version {j+1}: {failed_result.component.version} status {old_status} -> NEEDS_UPGRADE")
            
            # Add all results
            results.extend(failed_versions)
            results.append(result)
            
            # Mark remaining higher versions as compatible (inheritance)
            remaining_versions = sorted_versions[sorted_versions.index(dep) + 1:]
            debug(f"[VERSION_ANALYSIS_INHERITANCE] Marking {len(remaining_versions)} higher versions as compatible by inheritance")
            for k, remaining_dep in enumerate(remaining_versions):
                remaining_version = remaining_dep.get('version', 'unknown')
                debug(f"[VERSION_ANALYSIS_INHERITANCE] Inheriting compatibility for version {k+1}: {remaining_version}")
                inherited_component = SoftwareComponent(
                    name=remaining_dep['artifactId'],
                    version=remaining_dep['version'],
                    component_type="java-17",
                    source_sbom="runtime_analysis",
                    properties={
                        'environment': 'native_java_17_amazon-linux-2023',
                        'groupId': remaining_dep.get('groupId', ''),
                        'artifactId': remaining_dep['artifactId'],
                        'runtime_analysis': 'true',
                        'timestamp': datetime.utcnow().isoformat() + 'Z'
                    }
                )
                
                inherited_compatibility = CompatibilityResult(
                    status=CompatibilityStatus.COMPATIBLE,
                    current_version_supported=True,
                    minimum_supported_version=dep['version'],
                    recommended_version=None,
                    notes=f"ARM64 compatibility inherited from working version {dep['version']}",
                    confidence_level=0.85
                )
                
                results.append(ComponentResult(
                    component=inherited_component, 
                    compatibility=inherited_compatibility,
                    matched_name=None
                ))
            
            break
        else:
            # Store failed version for potential upgrade marking
            debug(f"[VERSION_ANALYSIS_FAILED] Version {version} failed with status: {result.compatibility.status.value}")
            failed_versions.append(result)
    
    # If no working version found, add all failed versions as-is
    if not working_version_found:
        debug(f"[VERSION_ANALYSIS_NO_COMPATIBLE] No compatible version found for {group_key}")
        debug(f"[VERSION_ANALYSIS_NO_COMPATIBLE] Adding {len(failed_versions)} failed versions as-is")
        results.extend(failed_versions)
    
    debug(f"[VERSION_ANALYSIS_COMPLETE] Analysis complete for {group_key}: {len(results)} results generated")
    
    return results

def _parse_version(version_str: str, properties: dict = None) -> tuple:
    """Parse version string into comparable tuple."""
    if not version_str or version_str == 'unknown':
        return (0,)
    
    # Handle Maven property placeholders like ${spring-dep.version}
    if version_str.startswith('${') and version_str.endswith('}'):
        if properties:
            prop_name = version_str[2:-1]  # Remove ${ and }
            resolved_version = properties.get(prop_name)
            if resolved_version:
                return _parse_version(resolved_version, properties)
        return (999999,)  # Put unresolved placeholders at the end
    
    # Strip whitespace and normalize version string
    version_str = str(version_str).strip().lower().replace('final', '').replace('release', '').strip()
    parts = re.split(r'[.\-]', version_str)
    parsed_parts = []
    
    for part in parts:
        part = part.strip()  # Strip whitespace from each part
        if part.isdigit():
            parsed_parts.append(int(part))
        elif part:
            parsed_parts.append(part)
    
    return tuple(parsed_parts) if parsed_parts else (0,)

def analyze_jar_directory(jar_dir: str, runtime_test: bool = False) -> List[ComponentResult]:
    """Analyze JAR files in directory for ARM64 compatibility."""
    debug(f"[JAR_DIR_ANALYSIS_START] Starting JAR directory analysis: {jar_dir}")
    debug(f"[JAR_DIR_ANALYSIS_CONFIG] Runtime test enabled: {runtime_test}")
    info(f"Starting JAR directory analysis: {jar_dir}")
    
    jar_dir_path = Path(jar_dir)
    if not jar_dir_path.exists():
        component = SoftwareComponent(
            name="jar-directory-analysis",
            version="unknown",
            component_type="jar",
            source_sbom="runtime_analysis",
            properties={'environment': 'jar', 'error_details': f'Directory not found: {jar_dir}'}
        )
        compatibility = CompatibilityResult(
            status=CompatibilityStatus.INCOMPATIBLE,
            current_version_supported=False,
            minimum_supported_version=None,
            recommended_version=None,
            notes=f'Directory not found: {jar_dir}',
            confidence_level=0.9
        )
        return [ComponentResult(component=component, compatibility=compatibility, matched_name=None)]
    
    # Find JAR files
    debug(f"[JAR_DIR_ANALYSIS_SEARCH] Searching for JAR files with patterns: *.jar, *.war, *.ear")
    jar_files = []
    for pattern in ['*.jar', '*.war', '*.ear']:
        pattern_matches = list(jar_dir_path.glob(pattern))
        debug(f"[JAR_DIR_ANALYSIS_SEARCH] Pattern '{pattern}' found {len(pattern_matches)} files")
        jar_files.extend([str(f) for f in pattern_matches])
    
    debug(f"[JAR_DIR_ANALYSIS_SEARCH_RESULT] Total JAR files found: {len(jar_files)}")
    if jar_files:
        debug(f"[JAR_DIR_ANALYSIS_FILES] Files to analyze: {[os.path.basename(f) for f in jar_files[:5]]}{'...' if len(jar_files) > 5 else ''}")
    
    if not jar_files:
        debug(f"[JAR_DIR_ANALYSIS_NO_FILES] No JAR files found in directory")
        info("No JAR files found in directory")
        return []
    
    analyzer = JavaCompatibilityAnalyzer()
    results = []
    
    try:
        for i, jar_file in enumerate(jar_files, 1):
            jar_name = Path(jar_file).name
            debug(f"[JAR_DIR_ANALYSIS_FILE] Analyzing JAR {i}/{len(jar_files)}: {jar_name}")
            jar_metadata = _extract_jar_metadata(jar_file)
            debug(f"[JAR_DIR_ANALYSIS_METADATA] Extracted metadata: {jar_metadata}")
            
            # Create JAR-specific component
            component = SoftwareComponent(
                name=jar_metadata['component'],
                version=jar_metadata['version'],
                component_type="jar",
                source_sbom="runtime_analysis",
                properties={
                    'environment': 'jar',
                    'groupId': jar_metadata['groupId'],
                    'artifactId': jar_metadata['artifactId'],
                    'runtime_analysis': 'true',
                    'timestamp': datetime.utcnow().isoformat() + 'Z'
                }
            )
            
            compatibility = CompatibilityResult(
                status=CompatibilityStatus.UNKNOWN,
                current_version_supported=False,
                minimum_supported_version=None,
                recommended_version=None,
                notes="",
                confidence_level=0.9
            )
            
            # Perform JAR analysis
            debug(f"[JAR_DIR_ANALYSIS_NATIVE] Starting native code analysis for: {jar_name}")
            native_info = analyzer._check_jar_native_code(jar_file)
            debug(f"[JAR_DIR_ANALYSIS_NATIVE_RESULT] Native analysis result: {native_info}")
            
            # Set compatibility based on analysis
            if native_info['has_native_code']:
                debug(f"[JAR_DIR_ANALYSIS_COMPAT] Native code detected in {jar_name}")
                component.properties['native_build_detected'] = 'Yes'
                
                if native_info['arm_specific'] and native_info['x86_specific']:
                    debug(f"[JAR_DIR_ANALYSIS_COMPAT] Multi-architecture support detected")
                    compatibility.status = CompatibilityStatus.COMPATIBLE
                    compatibility.current_version_supported = True
                    compatibility.notes = 'Multi-architecture native libraries (ARM64 + x86)'
                elif native_info['arm_specific']:
                    debug(f"[JAR_DIR_ANALYSIS_COMPAT] ARM64-only support detected")
                    compatibility.status = CompatibilityStatus.COMPATIBLE
                    compatibility.current_version_supported = True
                    compatibility.notes = 'ARM64-specific native libraries detected'
                elif native_info['x86_specific']:
                    debug(f"[JAR_DIR_ANALYSIS_COMPAT] x86-only support detected")
                    compatibility.status = CompatibilityStatus.NEEDS_VERIFICATION
                    compatibility.notes = 'x86-only native libraries detected. Needs manual verification: ARM64 support unclear'
                else:
                    debug(f"[JAR_DIR_ANALYSIS_COMPAT] Native code with unclear architecture")
                    compatibility.status = CompatibilityStatus.NEEDS_VERIFICATION
                    compatibility.notes = 'Native libraries detected. Needs manual verification: could not determine architecture'
            else:
                debug(f"[JAR_DIR_ANALYSIS_COMPAT] Pure Java JAR detected")
                component.properties['native_build_detected'] = 'No'
                compatibility.status = CompatibilityStatus.COMPATIBLE
                compatibility.current_version_supported = True
                compatibility.notes = 'Pure Java JAR, no native dependencies'
            
            debug(f"[JAR_DIR_ANALYSIS_RESULT] Final compatibility for {jar_name}: {compatibility.status.value}")
            
            results.append(ComponentResult(component=component, compatibility=compatibility, matched_name=None))
        
        info(f"JAR directory analysis complete. Generated {len(results)} results")
        return results
    
    finally:
        # Cleanup analyzer resources
        debug(f"[JAR_DIR_CLEANUP] Starting cleanup phase")
        analyzer.cleanup()
        debug(f"[JAR_DIR_CLEANUP] Cleanup phase completed")

def _extract_jar_metadata(jar_file: str) -> Dict[str, str]:
    """Extract metadata from JAR file."""
    jar_name = Path(jar_file).name
    jar_stem = Path(jar_file).stem
    
    metadata = {
        'component': jar_stem,
        'version': 'unknown',
        'groupId': '',
        'artifactId': jar_stem
    }
    
    try:
        with zipfile.ZipFile(jar_file, 'r') as jar:
            # Try to read pom.properties first
            for file_info in jar.filelist:
                if file_info.filename.endswith('pom.properties'):
                    try:
                        pom_data = jar.read(file_info.filename).decode('utf-8')
                        for line in pom_data.split('\n'):
                            if '=' in line and not line.startswith('#'):
                                key, value = line.split('=', 1)
                                key = key.strip()
                                value = value.strip()
                                if key == 'groupId':
                                    metadata['groupId'] = value
                                elif key == 'artifactId':
                                    metadata['artifactId'] = value
                                    metadata['component'] = value
                                elif key == 'version':
                                    metadata['version'] = value
                        break
                    except Exception:
                        pass
            
            # Try to extract version from MANIFEST.MF if not found
            if metadata['version'] == 'unknown':
                try:
                    manifest_data = jar.read('META-INF/MANIFEST.MF').decode('utf-8')
                    for line in manifest_data.split('\n'):
                        if line.startswith('Implementation-Version:'):
                            metadata['version'] = line.split(':', 1)[1].strip()
                            break
                except Exception:
                    pass
            
            # Try to extract version from filename if still unknown
            if metadata['version'] == 'unknown':
                version_match = re.search(r'-([0-9]+(?:\.[0-9]+)*(?:-[A-Za-z0-9]+)?)', jar_stem)
                if version_match:
                    metadata['version'] = version_match.group(1)
    
    except Exception:
        pass
    
    return metadata

def show_help():
    """Display help information for Java package installer."""
    help_text = """
Java Package Installer - ARM64 Compatibility Analyzer

USAGE:
    python java_package_installer.py <input_path> [OPTIONS]

ARGUMENTS:
    input_path          Path to pom.xml file or JAR directory to analyze

OPTIONS:
    --jar-dir DIR      Additional JAR directory to analyze
    -v, --verbose      Enable verbose output with detailed logging
    --deep-scan        Perform deep scanning of JAR files for native code
    --runtime-test     Perform runtime testing with dependency installation
    -o, --output FILE  Save analysis results to specified JSON file
    -h, --help         Show this help message and exit

DESCRIPTION:
    Analyzes Java projects and JAR files for ARM64/Graviton compatibility.
    Supports Maven pom.xml files and JAR directory analysis with optional
    deep scanning for native code detection and runtime testing.

EXAMPLES:
    python java_package_installer.py pom.xml
    python java_package_installer.py pom.xml --deep-scan --runtime-test
    python java_package_installer.py /path/to/jars --jar-dir /additional/jars
    python java_package_installer.py pom.xml -v -o results.json

OUTPUT:
    JSON format with compatibility status, native code analysis, and
    runtime test results for each dependency.
    """
    print(help_text)

def main():
    """Main function for Java package installer."""
    debug(f"[MAIN_START] Java Package Installer starting with args: {sys.argv[1:]}")
    
    parser = argparse.ArgumentParser(description='Analyze Java dependencies for ARM compatibility', add_help=False)
    parser.add_argument('input_path', nargs='?', help='Path to pom.xml, SBOM JSON file, or JAR directory')
    parser.add_argument('--jar-dir', help='Additional JAR directory to analyze')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--deep-scan', action='store_true', help='Perform deep scanning of JAR files')
    parser.add_argument('--runtime-test', action='store_true', help='Perform runtime testing')
    parser.add_argument('-o', '--output', help='Output JSON file path')
    parser.add_argument('-h', '--help', action='store_true', help='Show help message')
    
    args = parser.parse_args()
    
    if args.help:
        show_help()
        return 0
    
    debug(f"[MAIN_ARGS] Parsed arguments: input_path='{args.input_path}', jar_dir='{args.jar_dir}', verbose={args.verbose}, deep_scan={args.deep_scan}, runtime_test={args.runtime_test}, output='{args.output}'")
    
    if args.verbose or os.environ.get('DEBUG'):
        debug(f"[MAIN_LOGGING] Enabling DEBUG logging level")
        logger.setLevel(logging.DEBUG)
    else:
        debug(f"[MAIN_LOGGING] Using INFO logging level")
    
    if not args.input_path:
        error(f"[MAIN_ERROR] No input file provided. Please provide a path to a pom.xml or JAR directory")
        print("Error: No input file provided.", file=sys.stderr)
        print("Use -h or --help for usage information.", file=sys.stderr)
        return 1
    
    input_path = os.path.abspath(args.input_path)
    debug(f"[MAIN_INPUT] Resolved input path: {input_path}")
    
    if not os.path.exists(input_path):
        error(f"[MAIN_ERROR] File not found: {input_path}")
        print(f"Error: File not found: {input_path}", file=sys.stderr)
        print("Use -h or --help for usage information.", file=sys.stderr)
        return 1
    
    debug(f"[MAIN_INPUT_TYPE] Input path exists, checking type: isdir={os.path.isdir(input_path)}, isfile={os.path.isfile(input_path)}")
    
    # Determine input type and analyze accordingly
    results = []
    
    if os.path.isdir(input_path):
        debug(f"[MAIN_ANALYSIS] Input is directory, starting JAR directory analysis")
        # JAR directory analysis
        jar_results = analyze_jar_directory(input_path, args.runtime_test)
        debug(f"[MAIN_ANALYSIS_RESULT] JAR directory analysis produced {len(jar_results)} results")
        results.extend(jar_results)
    elif input_path.endswith('.xml'):
        debug(f"[MAIN_ANALYSIS] Input is XML file, starting POM file analysis")
        # POM file analysis
        pom_results = analyze_pom_file(input_path, args.deep_scan, args.runtime_test)
        debug(f"[MAIN_ANALYSIS_RESULT] POM file analysis produced {len(pom_results)} results")
        results.extend(pom_results)
    else:
        error(f"[MAIN_ERROR] Unsupported file type: {input_path}")
        return 1
    
    # Additional JAR directory analysis if specified
    if args.jar_dir:
        debug(f"[MAIN_ADDITIONAL_JAR] Additional JAR directory specified: {args.jar_dir}")
        if not os.path.exists(args.jar_dir) or not os.path.isdir(args.jar_dir):
            error(f"[MAIN_ERROR] JAR directory not found or not a directory: {args.jar_dir}")
            return 1
        
        debug(f"[MAIN_ADDITIONAL_JAR] Starting additional JAR directory analysis")
        jar_results = analyze_jar_directory(args.jar_dir, args.runtime_test)
        debug(f"[MAIN_ADDITIONAL_JAR_RESULT] Additional JAR analysis produced {len(jar_results)} results")
        results.extend(jar_results)
    
    if not results:
        debug(f"[MAIN_NO_RESULTS] No dependencies or JARs found to analyze")
        info("No dependencies or JARs found to analyze")
        return 0
    
    debug(f"[MAIN_RESULTS_SUMMARY] Total results collected: {len(results)}")
    
    try:
        debug(f"[MAIN_JSON_CONVERSION] Converting {len(results)} ComponentResult objects to flattened JSON format")
        # Convert ComponentResult objects to flattened JSON format (matching SBOM structure)
        results_json = []
        for i, result in enumerate(results):
            if i < 3:  # Log details for first 3 results
                debug(f"[MAIN_JSON_CONVERSION] Converting result {i+1}: {result.component.name}:{result.component.version} -> {result.compatibility.status.value}")
            
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
            
            results_json.append(result_dict)
        
        debug(f"[MAIN_JSON_CONVERSION_COMPLETE] Successfully converted all results to JSON format")
        
        # Output results
        debug(f"[MAIN_OUTPUT] Generating JSON output")
        output_json = json.dumps(results_json, indent=2)
        debug(f"[MAIN_OUTPUT] JSON output size: {len(output_json)} characters")
        
        if args.output:
            debug(f"[MAIN_OUTPUT_FILE] Writing results to file: {args.output}")
            with open(args.output, 'w') as f:
                f.write(output_json)
            debug(f"[MAIN_OUTPUT_FILE_COMPLETE] Results written to file successfully")
            if args.verbose:
                info(f"Analysis results saved to: {args.output}")
        else:
            debug(f"[MAIN_OUTPUT_STDOUT] Writing results to stdout")
            print(output_json)
        
        # Summary
        if args.verbose and results_json:
            debug(f"[MAIN_SUMMARY] Generating analysis summary")
            total = len(results_json)
            compatible = sum(1 for r in results_json if r['compatibility']['status'] == 'compatible')
            incompatible = sum(1 for r in results_json if r['compatibility']['status'] == 'incompatible')
            needs_verification = sum(1 for r in results_json if r['compatibility']['status'] == 'needs_verification')
            needs_upgrade = sum(1 for r in results_json if r['compatibility']['status'] == 'needs_upgrade')
            unknown = sum(1 for r in results_json if r['compatibility']['status'] == 'unknown')
            
            debug(f"[MAIN_SUMMARY_STATS] total={total}, compatible={compatible}, incompatible={incompatible}, needs_upgrade={needs_upgrade}, needs_verification={needs_verification}, unknown={unknown}")
            
            info(f"Analysis Summary:")
            info(f"  Total components: {total}")
            info(f"  Compatible: {compatible}")
            info(f"  Incompatible: {incompatible}")
            info(f"  Needs upgrade: {needs_upgrade}")
            info(f"  Needs verification: {needs_verification}")
            info(f"  Unknown: {unknown}")
        
        # Return appropriate exit code
        if results_json:
            incompatible_count = sum(1 for r in results_json if r['compatibility']['status'] == 'incompatible')
            debug(f"[MAIN_EXIT_CODE] Found {incompatible_count} incompatible components")
            if incompatible_count > 0:
                debug(f"[MAIN_EXIT_CODE] Returning exit code 2 due to incompatible components")
                return 2
            else:
                debug(f"[MAIN_EXIT_CODE] Returning exit code 0 (success)")
                return 0
        else:
            debug(f"[MAIN_EXIT_CODE] No results, returning exit code 0")
            return 0
    
    except Exception as e:
        error(f"[MAIN_ERROR] Java Package Installer failed: {e}")
        debug(f"[MAIN_ERROR_DETAILS] Exception type: {type(e).__name__}")
        import traceback
        debug(f"[MAIN_ERROR_TRACEBACK] {traceback.format_exc()}")
        return 1

if __name__ == '__main__':
    start_time = time.time()
    debug(f"[MAIN_ENTRY] Java Package Installer starting at {datetime.utcnow().isoformat()}Z")
    debug(f"[MAIN_ENTRY] Python version: {sys.version}")
    debug(f"[MAIN_ENTRY] Working directory: {os.getcwd()}")
    debug(f"[MAIN_ENTRY] Environment DEBUG: {os.environ.get('DEBUG', 'not set')}")
    
    try:
        exit_code = main()
        duration = time.time() - start_time
        debug(f"[MAIN_EXIT] Execution completed in {duration:.2f}s with exit code {exit_code}")
        info(f"Java Package Installer finished in {duration:.2f}s with exit code {exit_code}")
        sys.exit(exit_code)
    except KeyboardInterrupt:
        duration = time.time() - start_time
        debug(f"[MAIN_INTERRUPT] Execution interrupted after {duration:.2f}s")
        info(f"Java Package Installer interrupted after {duration:.2f}s")
        sys.exit(130)
    except Exception as e:
        duration = time.time() - start_time
        error(f"[MAIN_EXCEPTION] Unhandled exception after {duration:.2f}s: {e}")
        import traceback
        debug(f"[MAIN_EXCEPTION_TRACEBACK] {traceback.format_exc()}")
        sys.exit(1)