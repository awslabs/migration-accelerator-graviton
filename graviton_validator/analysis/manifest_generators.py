#!/usr/bin/env python3
"""
Runtime-specific analyzers for enhanced SBOM analysis.
Modular system to support Java, Python, Node.js, etc.
"""

import json
import tempfile
import subprocess
import datetime
import re
import shutil
import os
import defusedxml.ElementTree as ET
import logging
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from ..validation.runtime_result_validator import RuntimeResultValidator

# Configure logger for runtime analysis
logger = logging.getLogger(__name__)

def calculate_summary(results: List[Dict[str, Any]]) -> Dict[str, int]:
    """Calculate comprehensive summary from flattened structure results."""
    total = len(results)
    status_counts = {}
    
    # Count all status values
    for r in results:
        status = r.get('compatibility', {}).get('status', 'unknown')
        status_counts[status] = status_counts.get(status, 0) + 1
    
    # Ensure compatible and incompatible are always present
    summary = {
        'total_components': total,
        'compatible': status_counts.get('compatible', 0),
        'incompatible': status_counts.get('incompatible', 0)
    }
    
    # Add other status counts if they exist
    for status, count in status_counts.items():
        if status not in ['compatible', 'incompatible']:
            summary[status] = count
    
    return summary


class RuntimeAnalyzer(ABC):
    """Base class for runtime-specific analyzers."""
    
    # Runtime configuration mapping
    RUNTIME_CONFIGS = {
        'java': {'purl_prefix': 'pkg:maven/', 'indicators': ['jar', 'maven', 'java', 'war', 'ear'], 'manifest_template': 'pom.xml', 'success_message': 'Maven analysis successful', 'error_message': 'Maven analysis failed'},
        'python': {'purl_prefix': 'pkg:pypi/', 'indicators': ['pypi'], 'manifest_template': 'requirements.txt', 'success_message': 'Installation test successful', 'error_message': 'Installation failed'},
        'nodejs': {'purl_prefix': 'pkg:npm/', 'indicators': ['npm'], 'manifest_template': 'package.json', 'success_message': 'npm install test successful', 'error_message': 'npm install failed'},
        'dotnet': {'purl_prefix': 'pkg:nuget/', 'indicators': ['nuget'], 'manifest_template': 'test.csproj', 'success_message': 'Package restored successfully for Graviton', 'error_message': 'dotnet restore failed'},
        'ruby': {'purl_prefix': 'pkg:gem/', 'indicators': ['gem'], 'manifest_template': 'Gemfile', 'success_message': 'Gem bundle install test successful', 'error_message': 'bundle install failed'}
    }
    
    def __init__(self):
        self.validator = RuntimeResultValidator()
    
    def _extract_simple_dependencies(self, components: List[Any], purl_prefix: str, dep_type: str) -> List[Dict[str, Any]]:
        """Common dependency extraction logic for simple runtimes (Python, Node.js, .NET, Ruby)."""
        dependencies, seen = [], set()
        for component in components:
            purl = getattr(component, 'purl', '') or getattr(component, 'properties', {}).get('purl', '')
            if purl.startswith(purl_prefix):
                name, version = getattr(component, 'name', ''), getattr(component, 'version', '')
                unique_key = (name, version)
                if unique_key not in seen:
                    seen.add(unique_key)
                    dependencies.append({'name': name, 'version': version, 'type': dep_type})
        return dependencies
    
    def _create_basic_fallback_result(self, name: str, version: str, compatible: str, log_snippet: str, result: Dict, **extra_fields) -> Dict:
        """Create basic fallback result structure using standard format."""
        # Convert compatible string to proper status
        if compatible == 'Yes':
            status = 'compatible'
        elif compatible == 'No':
            status = 'incompatible'
        else:
            status = 'unknown'
        
        base_result = {
            'name': name,
            'version': version,
            'type': 'library',
            'source_sbom': 'runtime_analysis',
            'compatibility': {
                'status': status,
                'current_version_supported': compatible == 'Yes',
                'notes': log_snippet,
                'confidence_level': 0.9
            },
            'properties': {
                'timestamp': datetime.datetime.now().isoformat(),
                'environment': result.get('environment', 'unknown')
            }
        }
        
        # Add extra fields to properties
        if extra_fields:
            base_result['properties'].update(extra_fields)
        
        return base_result
    
    @abstractmethod
    def get_runtime_type(self) -> str:
        """Return the runtime type (e.g., 'java', 'python', 'nodejs')."""
        pass
    
    def can_analyze_components(self, components: List[Any]) -> bool:
        """Check if this analyzer can process the given components."""
        config = self.RUNTIME_CONFIGS[self.get_runtime_type()]
        
        for component in components:
            purl = getattr(component, 'purl', '') or getattr(component, 'properties', {}).get('purl', '')
            if purl.startswith(config['purl_prefix']):
                return True
            
            # Check component type and name for indicators (Java specific)
            if self.get_runtime_type() == 'java':
                component_type = str(getattr(component, 'component_type', '')).lower()
                name = str(getattr(component, 'name', '')).lower()
                if any(indicator in component_type or indicator in name for indicator in config['indicators']):
                    return True
        return False
    
    @abstractmethod
    def extract_dependencies(self, components: List[Any]) -> List[Dict[str, Any]]:
        """Extract runtime-specific dependencies from SBOM components."""
        pass
    
    @abstractmethod
    def generate_manifest_file(self, dependencies: List[Dict[str, Any]], output_dir: str, sbom_name: str = None) -> str:
        """Generate runtime-specific manifest file (pom.xml, requirements.txt, etc.)."""
        pass
    
    def analyze_dependencies(self, manifest_path: str, **kwargs) -> Dict[str, Any]:
        """Unified dependency analysis using execution environment."""
        runtime_type = self.get_runtime_type()
        config = self.RUNTIME_CONFIGS[runtime_type]
        
        logger.info(f"Starting {runtime_type} dependency analysis")
        logger.debug(f"Manifest path: {manifest_path}")
        logger.debug(f"Analysis kwargs: {list(kwargs.keys())}")
        
        try:
            execution_env = kwargs.get('execution_env')
            if not execution_env:
                logger.error(f"No execution environment provided for {runtime_type} analysis")
                return {
                    'runtime_type': runtime_type,
                    'error': 'No execution environment provided',
                    'summary': {'total_components': 0, 'compatible': 0, 'incompatible': 0},
                    'components': []
                }
            
            logger.debug(f"Using execution environment: {type(execution_env).__name__}")
            result = execution_env.execute_analysis(runtime_type, manifest_path, **kwargs)
            error_preview = result.get('error') or 'None'
            logger.debug(f"Execution environment result: success={result.get('success')}, error={str(error_preview)[:100]}...")
            
            # Load results from file if available
            file_results = self._load_results_from_file(runtime_type, **kwargs)
            
            if file_results:
                results = file_results
                logger.info(f"Loaded {len(results)} {runtime_type} package results from file")
                # Log stderr as debug if process succeeded
                if result.get('success') and result.get('stderr'):
                    logger.debug(f"{runtime_type} analysis stderr (success): {result['stderr'][:200]}...")
            else:
                # Fallback: parse from stdout if file-based approach fails
                try:
                    package_results = json.loads(result.get('output', '[]'))
                    logger.info(f"Fallback: parsed {len(package_results)} {runtime_type} package results from stdout")
                    results = self.validator.validate_batch(package_results) if package_results else []
                    if results:
                        logger.info(f"Validated {len(results)} {runtime_type} package results")
                    # Log stderr as debug if process succeeded
                    if result.get('success') and result.get('stderr'):
                        logger.debug(f"{runtime_type} analysis stderr (success): {result['stderr'][:200]}...")
                except json.JSONDecodeError:
                    logger.warning(f"Failed to parse {runtime_type} package test results, falling back to basic analysis")
                    results = []
            
            # If no detailed results, create basic fallback
            if not results:
                results = self._create_fallback_results(manifest_path, result, config, runtime_type)
            
            summary = calculate_summary(results)
            logger.info(f"{runtime_type} analysis summary: {summary['total_components']} total, {summary['compatible']} compatible, {summary['incompatible']} incompatible")
            
            return {
                'runtime_type': runtime_type,
                'summary': summary,
                'components': results,
                'execution_result': result
            }
            
        except Exception as e:
            logger.error(f"{runtime_type} analysis exception: {str(e)}")
            logger.exception(f"Full {runtime_type} analysis exception traceback:")
            return {
                'runtime_type': runtime_type,
                'error': f'{runtime_type} analysis failed: {str(e)}',
                'summary': {'total_components': 0, 'compatible': 0, 'incompatible': 0},
                'components': []
            }
    
    def _create_fallback_results(self, manifest_path: str, result: Dict, config: Dict, runtime_type: str) -> List[Dict]:
        """Create fallback results when detailed analysis is not available."""
        compatible, log_snippet = ('Yes', config['success_message']) if result.get('success') else ('No', str(result.get('error') or result.get('stderr', config['error_message'])))
        logger.info(f"{runtime_type} dependency analysis: {'SUCCESS' if compatible == 'Yes' else 'FAILED - ' + log_snippet[:200]}...")
        if result.get('success') and result.get('stderr'):
            logger.debug(f"{runtime_type} analysis stderr (success): {result['stderr'][:200]}...")
        return self._parse_manifest_for_fallback(manifest_path, compatible, log_snippet, result, runtime_type)
    
    @abstractmethod
    def _parse_manifest_for_fallback(self, manifest_path: str, compatible: str, log_snippet: str, result: Dict, runtime_type: str) -> List[Dict]:
        """Parse manifest file for fallback results - runtime specific implementation."""
        pass
    
    def _load_results_from_file(self, runtime_type: str, **kwargs) -> Optional[List[Dict]]:
        """Load results from file if available."""
        output_dir, sbom_name = kwargs.get('output_dir'), kwargs.get('sbom_name')
        if not output_dir or not sbom_name:
            return None
        
        result_file_path = os.path.join(output_dir, runtime_type, f'{sbom_name}_{runtime_type}_analysis.json')
        if not os.path.exists(result_file_path):
            logger.debug(f"Result file not found: {result_file_path}")
            return None
        
        try:
            with open(result_file_path, 'r') as f:
                data = json.load(f)
            return data['components'] if isinstance(data, dict) and 'components' in data else data if isinstance(data, list) else None
        except Exception as e:
            logger.warning(f"Failed to load results from {result_file_path}: {e}")
            return None


class JavaRuntimeAnalyzer(RuntimeAnalyzer):
    """Java/Maven runtime analyzer."""
    
    def get_runtime_type(self) -> str:
        return "java"
    
    def extract_dependencies(self, components: List[Any]) -> List[Dict[str, Any]]:
        """Extract Maven dependencies from SBOM components."""
        dependencies = []
        seen = set()  # Track unique (groupId, artifactId, version) combinations
        
        for component in components:
            # Check if it's a Java component by type or PURL
            component_type = getattr(component, 'component_type', '').lower()
            purl = getattr(component, 'purl', '') or getattr(component, 'properties', {}).get('purl', '')
            
            # Check for Java/Maven components
            is_java_component = (
                'jar' in component_type or 
                'maven' in component_type or 
                'java-archive' in component_type or
                purl.startswith('pkg:maven/')
            )
            
            if is_java_component:
                name = getattr(component, 'name', '')
                version = getattr(component, 'version', '')
                
                # Extract groupId and artifactId from PURL if available
                if purl.startswith('pkg:maven/'):
                    # Parse PURL: pkg:maven/groupId/artifactId@version
                    maven_part = purl.replace('pkg:maven/', '')
                    if '@' in maven_part:
                        coords, purl_version = maven_part.split('@', 1)
                        # Use PURL version if component version is missing
                        if not version:
                            version = purl_version
                    else:
                        coords = maven_part
                    
                    if '/' in coords:
                        group_id, artifact_id = coords.rsplit('/', 1)
                    else:
                        group_id = 'unknown'
                        artifact_id = coords
                else:
                    # Fallback: try to parse group:artifact format from name
                    if ':' in name:
                        parts = name.split(':')
                        group_id = parts[0] if len(parts) > 0 else 'unknown'
                        artifact_id = parts[1] if len(parts) > 1 else name
                    else:
                        group_id = 'unknown'
                        artifact_id = name
                
                # Create unique key for deduplication
                unique_key = (group_id, artifact_id, version)
                if unique_key not in seen:
                    seen.add(unique_key)
                    dependencies.append({
                        'groupId': group_id,
                        'artifactId': artifact_id,
                        'version': version,
                        'scope': 'compile'
                    })
        
        return dependencies
    
    def generate_manifest_file(self, dependencies: List[Dict[str, Any]], output_dir: str, sbom_name: str = None) -> str:
        """Generate pom.xml file."""
        filename = f"{sbom_name}_pom.xml" if sbom_name else "pom.xml"
        pom_path = Path(output_dir) / filename
        
        pom_content = '''<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.graviton.analysis</groupId>
    <artifactId>sbom-analysis</artifactId>
    <version>1.0.0</version>
    <dependencies>
'''
        
        for dep in dependencies:
            pom_content += f'''        <dependency>
            <groupId>{dep['groupId']}</groupId>
            <artifactId>{dep['artifactId']}</artifactId>
            <version>{dep['version']}</version>
        </dependency>
'''
        
        pom_content += '''    </dependencies>
</project>'''
        
        with open(pom_path, 'w') as f:
            f.write(pom_content)
        
        return str(pom_path)
    
    def _parse_manifest_for_fallback(self, manifest_path: str, compatible: str, log_snippet: str, result: Dict, runtime_type: str) -> List[Dict]:
        """Parse pom.xml for fallback results."""
        results = []
        try:
            logger.debug(f"Reading pom.xml file: {manifest_path}")
            tree = ET.parse(manifest_path)
            root = tree.getroot()
            
            dependencies = root.findall('.//{http://maven.apache.org/POM/4.0.0}dependency')
            logger.debug(f"Found {len(dependencies)} dependencies in pom.xml")
            
            for dep in dependencies:
                group_id = dep.find('.//{http://maven.apache.org/POM/4.0.0}groupId')
                artifact_id = dep.find('.//{http://maven.apache.org/POM/4.0.0}artifactId')
                version = dep.find('.//{http://maven.apache.org/POM/4.0.0}version')
                
                if group_id is not None and artifact_id is not None:
                    results.append(self._create_basic_fallback_result(
                        artifact_id.text,
                        version.text if version is not None else 'unknown',
                        compatible,
                        log_snippet,
                        result,
                        groupId=group_id.text
                    ))
        except Exception as e:
            logger.warning(f"Failed to parse pom.xml for fallback: {e}")
        
        return results


class PythonRuntimeAnalyzer(RuntimeAnalyzer):
    """Python/pip runtime analyzer adapted from src/python_dependency.py."""
    
    def get_runtime_type(self) -> str:
        return "python"
    
    def extract_dependencies(self, components: List[Any]) -> List[Dict[str, Any]]:
        """Extract Python dependencies from SBOM components."""
        return self._extract_simple_dependencies(components, 'pkg:pypi/', 'python')
    
    def generate_manifest_file(self, dependencies: List[Dict[str, Any]], output_dir: str, sbom_name: str = None) -> str:
        """Generate requirements.txt file."""
        filename = f"{sbom_name}_requirements.txt" if sbom_name else "requirements.txt"
        requirements_path = Path(output_dir) / filename
        
        with open(requirements_path, 'w') as f:
            for dep in dependencies:
                f.write(f"{dep['name']}=={dep['version']}\n")
        
        return str(requirements_path)
    
    def _parse_manifest_for_fallback(self, manifest_path: str, compatible: str, log_snippet: str, result: Dict, runtime_type: str) -> List[Dict]:
        """Parse requirements.txt for fallback results."""
        results = []
        try:
            with open(manifest_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and '==' in line:
                        name, version = line.split('==', 1)
                        results.append(self._create_basic_fallback_result(name.strip(), version.strip(), compatible, log_snippet, result))
        except Exception as e:
            logger.warning(f"Failed to parse requirements.txt for fallback: {e}")
        return results


class NodeJSRuntimeAnalyzer(RuntimeAnalyzer):
    """Node.js/npm runtime analyzer adapted from src/npm_dependency.py."""
    
    def get_runtime_type(self) -> str:
        return "nodejs"
    
    def extract_dependencies(self, components: List[Any]) -> List[Dict[str, Any]]:
        """Extract Node.js dependencies from SBOM components."""
        return self._extract_simple_dependencies(components, 'pkg:npm/', 'nodejs')
    
    def generate_manifest_file(self, dependencies: List[Dict[str, Any]], output_dir: str, sbom_name: str = None) -> str:
        """Generate package.json file."""
        filename = f"{sbom_name}_package.json" if sbom_name else "package.json"
        package_path = Path(output_dir) / filename
        
        package_data = {
            "name": "graviton-compatibility-test",
            "version": "1.0.0",
            "description": "Temporary package.json for Graviton compatibility testing",
            "dependencies": {}
        }
        
        for dep in dependencies:
            package_data["dependencies"][dep['name']] = dep['version']
        
        with open(package_path, 'w') as f:
            json.dump(package_data, f, indent=2)
        
        return str(package_path)
    
    def _parse_manifest_for_fallback(self, manifest_path: str, compatible: str, log_snippet: str, result: Dict, runtime_type: str) -> List[Dict]:
        """Parse package.json for fallback results."""
        results = []
        try:
            output = result.get('output', '')
            native_build = 'Yes' if any(indicator in output.lower() for indicator in ['gyp', 'node-gyp', 'binding.gyp', 'compile']) else 'No'
            
            with open(manifest_path, 'r') as f:
                dependencies = json.load(f).get('dependencies', {})
            
            for package_name, version in dependencies.items():
                results.append(self._create_basic_fallback_result(package_name, version, compatible, log_snippet, result, native_build_detected=native_build))
        except Exception as e:
            logger.warning(f"Failed to parse package.json for fallback: {e}")
        return results


class DotNetRuntimeAnalyzer(RuntimeAnalyzer):
    """DotNet/NuGet runtime analyzer adapted from src/dotnet_dependency.py."""
    
    def get_runtime_type(self) -> str:
        return "dotnet"
    
    def extract_dependencies(self, components: List[Any]) -> List[Dict[str, Any]]:
        """Extract .NET dependencies from SBOM components."""
        return self._extract_simple_dependencies(components, 'pkg:nuget/', 'dotnet')
    
    def generate_manifest_file(self, dependencies: List[Dict[str, Any]], output_dir: str, sbom_name: str = None) -> str:
        """Generate .csproj file."""
        filename = f"{sbom_name}_test.csproj" if sbom_name else "test.csproj"
        csproj_path = Path(output_dir) / filename
        
        csproj_content = '''<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net6.0</TargetFramework>
    <RuntimeIdentifier>linux-arm64</RuntimeIdentifier>
  </PropertyGroup>
  <ItemGroup>
'''
        for dep in dependencies:
            csproj_content += f'    <PackageReference Include="{dep["name"]}" Version="{dep["version"]}" />\n'
        
        csproj_content += '''  </ItemGroup>
</Project>'''
        
        with open(csproj_path, 'w') as f:
            f.write(csproj_content)
        
        return str(csproj_path)
    
    def _parse_manifest_for_fallback(self, manifest_path: str, compatible: str, log_snippet: str, result: Dict, runtime_type: str) -> List[Dict]:
        """Parse .csproj for fallback results."""
        results = []
        try:
            with open(manifest_path, 'r') as f:
                root = ET.fromstring(f.read())
            
            for pkg_ref in root.findall('.//ItemGroup/PackageReference'):
                name, version = pkg_ref.get('Include'), pkg_ref.get('Version')
                if name and version:
                    results.append(self._create_basic_fallback_result(name, version, compatible, log_snippet, result))
        except Exception as e:
            logger.warning(f"Failed to parse .csproj for fallback: {e}")
        return results


class RubyRuntimeAnalyzer(RuntimeAnalyzer):
    """Ruby/Gem runtime analyzer (new implementation)."""
    
    def get_runtime_type(self) -> str:
        return "ruby"
    
    def extract_dependencies(self, components: List[Any]) -> List[Dict[str, Any]]:
        """Extract Ruby dependencies from SBOM components."""
        return self._extract_simple_dependencies(components, 'pkg:gem/', 'ruby')
    
    def generate_manifest_file(self, dependencies: List[Dict[str, Any]], output_dir: str, sbom_name: str = None) -> str:
        """Generate Gemfile."""
        filename = f"{sbom_name}_Gemfile" if sbom_name else "Gemfile"
        gemfile_path = Path(output_dir) / filename
        
        with open(gemfile_path, 'w') as f:
            f.write('source "https://rubygems.org"\n\n')
            for dep in dependencies:
                f.write(f'gem "{dep["name"]}", "{dep["version"]}"\n')
        
        return str(gemfile_path)
    
    def _parse_manifest_for_fallback(self, manifest_path: str, compatible: str, log_snippet: str, result: Dict, runtime_type: str) -> List[Dict]:
        """Parse Gemfile for fallback results."""
        results = []
        try:
            with open(manifest_path, 'r') as f:
                for line in f:
                    if line.strip().startswith('gem '):
                        parts = line.split('"')
                        if len(parts) >= 4:
                            results.append(self._create_basic_fallback_result(parts[1], parts[3], compatible, log_snippet, result))
        except Exception as e:
            logger.warning(f"Failed to parse Gemfile for fallback: {e}")
        return results


class RuntimeAnalyzerManager:
    """Manager for runtime-specific analyzers."""
    
    def __init__(self, config_file: Optional[str] = None, use_containers: bool = None):
        from .runtime_config import RuntimeConfig
        from .execution_environment import ExecutionEnvironmentFactory
        
        self.config = RuntimeConfig(config_file)
        
        # Auto-detect environment: containers for local dev, native for production
        if use_containers is None:
            # Default to containers for local development (non-CodeBuild environments)
            import os
            use_containers = os.environ.get('CODEBUILD_BUILD_ID') is None
            logger.info(f"Auto-detected execution mode: {'container' if use_containers else 'native'}")
        
        self.execution_env = ExecutionEnvironmentFactory.create_environment(use_containers)
        self.analyzers = [
            JavaRuntimeAnalyzer(),    # Java first
            PythonRuntimeAnalyzer(),  # Python second
            NodeJSRuntimeAnalyzer(),  # Node.js third
            DotNetRuntimeAnalyzer(),  # .NET fourth
            RubyRuntimeAnalyzer()     # Ruby last
        ]
    
    def get_applicable_analyzers(self, components: List[Any]) -> List[RuntimeAnalyzer]:
        """Get analyzers that can process the given components."""
        applicable = []
        
        for analyzer in self.analyzers:
            if analyzer.can_analyze_components(components):
                applicable.append(analyzer)
        
        return applicable
    
    def generate_manifests_only(self, components: List[Any], output_dir: str, sbom_data: Optional[Dict[str, Any]] = None, **kwargs) -> Dict[str, Any]:
        """Generate runtime manifests without performing actual analysis (for --extract-manifests mode)."""
        logger.info(f"Generating runtime manifests for {len(components)} components")
        
        results = {}
        applicable_analyzers = self.get_applicable_analyzers(components)
        
        logger.info(f"Found {len(applicable_analyzers)} applicable analyzers: {[a.get_runtime_type() for a in applicable_analyzers]}")
        
        if not applicable_analyzers:
            logger.warning("No applicable runtime analyzers found for components")
            return {'message': 'No applicable runtime analyzers found'}
        
        # Create output directory
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        
        for analyzer in applicable_analyzers:
            runtime_type = analyzer.get_runtime_type()
            logger.info(f"Generating {runtime_type} manifest")
            
            try:
                # Extract runtime-specific dependencies
                dependencies = analyzer.extract_dependencies(components)
                logger.info(f"Extracted {len(dependencies)} {runtime_type} dependencies")
                
                if not dependencies:
                    logger.warning(f"No {runtime_type} dependencies found, skipping")
                    continue
                
                # Create runtime-specific subdirectory
                runtime_dir = Path(output_dir) / runtime_type
                runtime_dir.mkdir(exist_ok=True)
                
                # Generate manifest file with SBOM name prefix
                sbom_name = kwargs.get('sbom_name')
                manifest_path = analyzer.generate_manifest_file(dependencies, str(runtime_dir), sbom_name)
                logger.info(f"Generated {runtime_type} manifest: {manifest_path}")
                
                results[runtime_type] = {
                    'analyzer': runtime_type,
                    'dependencies_count': len(dependencies),
                    'manifest_path': manifest_path
                }
                
            except Exception as e:
                logger.error(f"Exception generating {runtime_type} manifest: {str(e)}")
                results[runtime_type] = {
                    'analyzer': runtime_type,
                    'error': str(e)
                }
        
        logger.info(f"Manifest generation completed for {len(results)} runtimes: {list(results.keys())}")
        return results
    
    def analyze_components_by_runtime(self, components: List[Any], output_dir: str, sbom_data: Optional[Dict[str, Any]] = None, **kwargs) -> Dict[str, Any]:
        """Analyze components using appropriate runtime analyzers."""
        logger.info(f"Starting runtime analysis for {len(components)} components")
        logger.debug(f"Output directory: {output_dir}")
        logger.debug(f"SBOM data provided: {sbom_data is not None}")
        logger.debug(f"Additional kwargs: {list(kwargs.keys())}")
        
        results = {}
        applicable_analyzers = self.get_applicable_analyzers(components)
        
        logger.info(f"Found {len(applicable_analyzers)} applicable analyzers: {[a.get_runtime_type() for a in applicable_analyzers]}")
        
        if not applicable_analyzers:
            logger.warning("No applicable runtime analyzers found for components")
            # Log component types for debugging
            component_types = []
            for comp in components[:5]:  # Log first 5 components
                comp_type = getattr(comp, 'component_type', 'unknown')
                name = getattr(comp, 'name', 'unknown')
                purl = getattr(comp, 'purl', '') or getattr(comp, 'properties', {}).get('purl', '')
                component_types.append(f"{name} (type: {comp_type}, purl: {purl[:50]}...)")
            logger.debug(f"Sample components: {component_types}")
            return {'message': 'No applicable runtime analyzers found'}
        
        # Use detected OS from SBOM analyzer if provided, otherwise detect from SBOM data
        detected_versions = {}
        sbom_name = kwargs.get('sbom_name')
        detected_os_from_sbom = kwargs.get('detected_os')
        logger.debug(f"SBOM name: {sbom_name}")
        
        if detected_os_from_sbom:
            logger.info(f"Using OS detected by SBOM analyzer: {detected_os_from_sbom}")
            detected_versions['os_version'] = detected_os_from_sbom
            
            # Still detect runtime versions from SBOM data if available
            if sbom_data:
                logger.debug("Detecting runtime versions from SBOM data")
                runtime_versions = self.config.detect_versions_from_sbom(sbom_data)
                # Keep runtime versions but use passed OS version
                for key, value in runtime_versions.items():
                    if key != 'os_version' and value:
                        detected_versions[key] = value
                logger.info(f"Combined detected versions: {detected_versions}")
        elif sbom_data:
            logger.debug("Detecting versions from SBOM data")
            detected_versions = self.config.detect_versions_from_sbom(sbom_data)
            logger.info(f"Detected versions from SBOM: {detected_versions}")
        else:
            logger.debug("No SBOM data provided for version detection")
            detected_versions['os_version'] = None
        
        # Create output directory
        logger.debug(f"Creating output directory: {output_dir}")
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        logger.debug(f"Output directory created successfully")
        
        for analyzer in applicable_analyzers:
            runtime_type = analyzer.get_runtime_type()
            logger.info(f"Processing {runtime_type} runtime analyzer")
            
            try:
                # Extract runtime-specific dependencies
                logger.debug(f"Extracting {runtime_type} dependencies from {len(components)} components")
                dependencies = analyzer.extract_dependencies(components)
                logger.info(f"Extracted {len(dependencies)} {runtime_type} dependencies")
                
                if not dependencies:
                    logger.warning(f"No {runtime_type} dependencies found, skipping analyzer")
                    continue
                
                # Check runtime cache - separate cached from untested dependencies
                cached_results = []
                untested_dependencies = []
                analysis_cache = kwargs.get('analysis_cache')
                os_version_for_cache = self.config.get_os_version(
                    sbom_name, detected_versions.get('os_version')
                )
                
                if analysis_cache:
                    for dep in dependencies:
                        # Handle different dep formats: Python/Node use 'name', Java uses 'artifactId'
                        dep_name = dep.get('name') or dep.get('artifactId', '')
                        dep_version = dep.get('version', '')
                        cached = analysis_cache.get_runtime(
                            dep_name, dep_version, runtime_type, os_version_for_cache or ''
                        )
                        if cached:
                            cached_results.append(cached)
                        else:
                            untested_dependencies.append(dep)
                    
                    if cached_results:
                        logger.info(f"Runtime cache: {len(cached_results)} cached, {len(untested_dependencies)} to test for {runtime_type}")
                else:
                    untested_dependencies = dependencies
                
                # If all dependencies are cached, skip container run entirely
                if not untested_dependencies:
                    logger.info(f"All {len(dependencies)} {runtime_type} dependencies found in cache, skipping container run")
                    analysis_result = {
                        'components': cached_results,
                        'summary': {
                            'total_components': len(cached_results),
                            'compatible': sum(1 for c in cached_results if c.get('compatibility', {}).get('status') == 'compatible'),
                            'incompatible': sum(1 for c in cached_results if c.get('compatibility', {}).get('status') != 'compatible'),
                        }
                    }
                    # Save and continue to next runtime
                    runtime_dir = Path(output_dir) / runtime_type
                    runtime_dir.mkdir(exist_ok=True)
                    result_filename = f"{sbom_name}_{runtime_type}_analysis.json" if sbom_name else f"{runtime_type}_analysis.json"
                    result_path = runtime_dir / result_filename
                    with open(result_path, 'w') as f:
                        json.dump(analysis_result, f, indent=2)
                    
                    results[runtime_type] = {
                        'analyzer': runtime_type,
                        'dependencies_count': len(dependencies),
                        'manifest_path': '',
                        'result_path': str(result_path),
                        'analysis_result': analysis_result,
                        'from_cache': True
                    }
                    continue
                
                # Use untested dependencies for manifest generation
                deps_for_manifest = untested_dependencies
                
                # Log sample dependencies for debugging
                sample_deps = dependencies[:3]
                logger.debug(f"Sample {runtime_type} dependencies: {sample_deps}")
                
                # Create runtime-specific subdirectory
                runtime_dir = Path(output_dir) / runtime_type
                logger.debug(f"Creating runtime directory: {runtime_dir}")
                runtime_dir.mkdir(exist_ok=True)
                
                # Get configured runtime version with supported versions check
                supported_versions = self.config.COMPATIBLE_VERSIONS.get(runtime_type, [])
                runtime_version = self.config.get_runtime_version(
                    runtime_type, sbom_name, detected_versions.get(runtime_type), supported_versions
                )
                os_version = self.config.get_os_version(
                    sbom_name, detected_versions.get('os_version')
                )
                logger.info(f"{runtime_type} analysis config - Runtime: {runtime_version}, OS: {os_version}")
                
                # Generate manifest file with SBOM name prefix
                logger.debug(f"Generating {runtime_type} manifest file in {runtime_dir}")
                manifest_path = analyzer.generate_manifest_file(deps_for_manifest, str(runtime_dir), sbom_name)
                logger.info(f"Generated {runtime_type} manifest: {manifest_path}")
                
                # Check prerequisites for runtime (skip for container execution)
                logger.debug(f"Checking prerequisites for {runtime_type}")
                prereq_ok, missing_tools = self.execution_env.check_prerequisites(runtime_type)
                
                # Skip prerequisite check for container execution
                if hasattr(self.execution_env, 'container_tool'):
                    logger.debug(f"Container execution detected, skipping local prerequisite check for {runtime_type}")
                    prereq_ok = True
                    missing_tools = []
                
                if not prereq_ok:
                    logger.error(f"Missing prerequisites for {runtime_type}: {missing_tools}")
                    analysis_result = {
                        'error': f'Missing prerequisites for {runtime_type}: {missing_tools}',
                        'summary': {'total_components': 0, 'compatible': 0, 'incompatible': 0},
                        'components': []
                    }
                else:
                    logger.info(f"Prerequisites check passed for {runtime_type}")
                    # Analyze dependencies with version info and execution environment
                    analysis_kwargs = {
                        **kwargs,
                        'runtime_version': runtime_version,
                        'os_version': os_version,
                        'execution_env': self.execution_env,
                        'output_dir': output_dir,  # Pass output_dir to execution environment
                        'sbom_name': sbom_name  # Pass SBOM name for correct output filename
                    }
                    logger.debug(f"Starting {runtime_type} dependency analysis with kwargs: {list(analysis_kwargs.keys())}")
                    logger.info(f"Executing {runtime_type} analysis on manifest: {manifest_path}")
                    
                    analysis_result = analyzer.analyze_dependencies(manifest_path, **analysis_kwargs)
                    
                    # Log analysis result summary
                    if 'error' in analysis_result:
                        logger.error(f"{runtime_type} analysis failed: {analysis_result['error']}")
                    else:
                        summary = analysis_result.get('summary', {})
                        logger.info(f"{runtime_type} analysis completed - Total: {summary.get('total_components', 0)}, Compatible: {summary.get('compatible', 0)}, Incompatible: {summary.get('incompatible', 0)}")
                        
                        # Log execution result details if available
                        exec_result = analysis_result.get('execution_result', {})
                        if exec_result:
                            logger.debug(f"{runtime_type} execution result - Success: {exec_result.get('success', False)}, Environment: {exec_result.get('environment', 'unknown')}")
                            if exec_result.get('error'):
                                logger.warning(f"{runtime_type} execution error: {exec_result['error'][:200]}...")
                            if exec_result.get('output'):
                                logger.debug(f"{runtime_type} execution output (first 200 chars): {exec_result['output'][:200]}...")
                
                # Save enriched analysis result to disk (overwrites raw data with enriched data)
                # Cache new results and merge with cached results
                if analysis_cache and 'components' in analysis_result:
                    for comp in analysis_result['components']:
                        analysis_cache.put_runtime(
                            comp.get('name', ''), comp.get('version', ''),
                            runtime_type, os_version or '',
                            comp
                        )
                
                # Merge cached results back into analysis result
                if cached_results and 'components' in analysis_result:
                    analysis_result['components'].extend(cached_results)
                    # Update summary
                    all_comps = analysis_result['components']
                    analysis_result['summary'] = {
                        'total_components': len(all_comps),
                        'compatible': sum(1 for c in all_comps if c.get('compatibility', {}).get('status') == 'compatible'),
                        'incompatible': sum(1 for c in all_comps if c.get('compatibility', {}).get('status') != 'compatible'),
                    }
                    logger.info(f"{runtime_type} merged {len(cached_results)} cached + {len(all_comps) - len(cached_results)} new results")
                
                result_filename = f"{sbom_name}_{runtime_type}_analysis.json" if sbom_name else f"{runtime_type}_analysis.json"
                result_path = runtime_dir / result_filename
                
                logger.debug(f"Saving enriched {runtime_type} analysis result to: {result_path}")
                with open(result_path, 'w') as f:
                    json.dump(analysis_result, f, indent=2)
                logger.debug(f"Enriched analysis result saved successfully")
                
                results[runtime_type] = {
                    'analyzer': runtime_type,
                    'dependencies_count': len(dependencies),
                    'manifest_path': manifest_path,
                    'result_path': str(result_path),
                    'analysis_result': analysis_result,
                    'runtime_version': runtime_version,
                    'os_version': os_version,
                    'detected_versions': detected_versions.get(runtime_type),
                    'version_source': 'override' if sbom_name in self.config.config_data['sbom_overrides'] else 'detected' if detected_versions.get(runtime_type) else 'default'
                }
                
            except Exception as e:
                logger.error(f"Exception in {runtime_type} analyzer: {str(e)}")
                logger.exception(f"Full traceback for {runtime_type} analyzer error:")
                results[runtime_type] = {
                    'analyzer': runtime_type,
                    'error': str(e)
                }
        
        # Cleanup execution environment
        logger.debug("Cleaning up execution environment")
        try:
            # Check if cleanup should be skipped (for debugging)
            skip_cleanup = kwargs.get('skip_cleanup', False)
            self.execution_env.cleanup(skip_cleanup=skip_cleanup)
            if skip_cleanup:
                logger.info("Execution environment cleanup skipped for debugging")
            else:
                logger.debug("Execution environment cleanup completed")
        except Exception as e:
            logger.warning(f"Execution environment cleanup failed: {str(e)}")
        
        logger.info(f"Runtime analysis completed for {len(results)} runtimes: {list(results.keys())}")
        return results