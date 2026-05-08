#!/usr/bin/env python3
"""
Execution environment management for multi-runtime dependency analysis.
Supports both native tool execution and optional containerized isolation.
"""

import subprocess
import tempfile
import shutil
import os
import json
import logging
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from abc import ABC, abstractmethod

# Import centralized runtime configurations
from ..runtime_configs import (
    get_runtime_script_name,
    get_runtime_execution_config,
    get_runtime_default_version,
    get_base_image,
    get_container_config,
    get_package_manager_info
)

# Configure logger for execution environment
logger = logging.getLogger(__name__)


class ExecutionEnvironment(ABC):
    """Base class for execution environments."""
    
    @abstractmethod
    def check_prerequisites(self, runtime: str) -> Tuple[bool, List[str]]:
        """Check if prerequisites are available for runtime."""
        pass
    
    @abstractmethod
    def execute_analysis(self, runtime: str, manifest_path: str, **kwargs) -> Dict:
        """Execute dependency analysis in the environment."""
        pass
    
    @abstractmethod
    def cleanup(self):
        """Clean up environment resources."""
        pass
    
    @staticmethod
    def generate_output_filename(manifest_name: str, runtime: str, sbom_name: str = None) -> str:
        """Generate consistent output filename across all execution modes."""
        if sbom_name:
            base_name = sbom_name
        else:
            # Remove only the final extension (.json, .xml, etc.) not intermediate dots
            if '.' in manifest_name:
                base_name = manifest_name.rsplit('.', 1)[0]  # Remove only last .extension
            else:
                base_name = manifest_name
        
        return f'{base_name}_{runtime}_analysis.json'


class NativeExecutionEnvironment(ExecutionEnvironment):
    """Native tool execution environment for production/CodeBuild."""
    
    RUNTIME_PREREQUISITES = {
        'python': ['python3'],  # pip will be detected dynamically
        'nodejs': ['node', 'npm'],
        'dotnet': ['dotnet'],
        'ruby': ['ruby', 'gem', 'bundle'],
        'java': ['java', 'mvn']
    }
    

    
    def __init__(self):
        self.temp_dirs = []
    
    def check_prerequisites(self, runtime: str) -> Tuple[bool, List[str]]:
        """Check if native tools are available."""
        logger.debug(f"Checking prerequisites for {runtime} runtime")
        
        if runtime not in self.RUNTIME_PREREQUISITES:
            logger.error(f"Unknown runtime: {runtime}")
            return False, [f"Unknown runtime: {runtime}"]
        
        required_tools = self.RUNTIME_PREREQUISITES[runtime]
        logger.debug(f"Required tools for {runtime}: {required_tools}")
        
        missing_tools = []
        for tool in required_tools:
            try:
                logger.debug(f"Checking availability of {tool}")
                result = subprocess.run([tool, '--version'], 
                                     capture_output=True, check=True, timeout=10)
                if hasattr(result.stdout, 'decode'):
                    logger.debug(f"{tool} is available: {result.stdout.decode()[:100]}...")
                else:
                    stdout_str = str(result.stdout)
                    logger.debug(f"{tool} is available: {stdout_str[:100]}..." if len(stdout_str) > 100 else f"{tool} is available: {stdout_str}")
            except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired) as e:
                logger.warning(f"{tool} is not available: {str(e)}")
                missing_tools.append(tool)
        
        success = len(missing_tools) == 0
        logger.info(f"Prerequisites check for {runtime}: {'PASSED' if success else 'FAILED'} (missing: {missing_tools})")
        return success, missing_tools

    
    def _setup_runtime_analysis(self, runtime: str, manifest_path: str, work_dir: str, **kwargs) -> Tuple[str, str, str]:
        """Common setup for runtime analysis - returns (output_file_path, output_filename, manifest_name)."""
        script_name = get_runtime_script_name(runtime)
        tester_script = Path(__file__).parent / script_name
        work_tester = Path(work_dir) / script_name
        shutil.copy2(str(tester_script), str(work_tester))
        
        # Copy graviton_validator module
        graviton_validator_dir = Path(__file__).parent.parent
        work_graviton_validator = Path(work_dir) / 'graviton_validator'
        shutil.copytree(str(graviton_validator_dir), str(work_graviton_validator))
        logger.debug(f"Copied graviton_validator module to work directory")
        
        # Create output directory and file path using consistent filename generation
        manifest_name = os.path.basename(manifest_path)
        sbom_name = kwargs.get('sbom_name')
        
        output_dir = os.path.join(work_dir, runtime)
        os.makedirs(output_dir, exist_ok=True)
        output_filename = self.generate_output_filename(manifest_name, runtime, sbom_name)
        output_file_path = os.path.join(output_dir, output_filename)
        
        return output_file_path, output_filename, manifest_name
    
    def _handle_analysis_output(self, runtime: str, result: subprocess.CompletedProcess, output_file_path: str, output_filename: str, **kwargs) -> str:
        """Common output handling for runtime analysis - returns file content."""
        if os.path.exists(output_file_path):
            try:
                with open(output_file_path, 'r') as f:
                    file_output = f.read()
                logger.debug(f"NATIVE FILE MODE: Successfully read {runtime} output file: {output_file_path} ({len(file_output)} chars)")
                
                # Copy to permanent output directory if provided
                permanent_output_dir = kwargs.get('output_dir')
                if permanent_output_dir:
                    permanent_runtime_dir = os.path.join(permanent_output_dir, runtime)
                    os.makedirs(permanent_runtime_dir, exist_ok=True)
                    permanent_output_path = os.path.join(permanent_runtime_dir, output_filename)
                    shutil.copy2(output_file_path, permanent_output_path)
                    logger.debug(f"NATIVE FILE MODE: Copied {runtime} output file to: {permanent_output_path}")
                
                return file_output
            except Exception as e:
                logger.warning(f"NATIVE FILE MODE: Failed to read {runtime} output file {output_file_path}: {e}")
                return result.stdout
        else:
            logger.warning(f"NATIVE FILE MODE: {runtime} output file not found: {output_file_path}, using stdout")
            return result.stdout
    
    def execute_analysis(self, runtime: str, manifest_path: str, **kwargs) -> Dict:
        """Execute analysis using native tools with isolation."""
        logger.info(f"Starting native execution analysis for {runtime}")
        logger.debug(f"Manifest path: {manifest_path}")
        logger.debug(f"Execution kwargs: {list(kwargs.keys())}")
        
        # Create isolated temporary directory
        temp_dir = tempfile.mkdtemp(prefix=f'graviton_{runtime}_')
        self.temp_dirs.append(temp_dir)
        logger.debug(f"Created temporary directory: {temp_dir}")
        
        try:
            # Copy manifest to temp directory
            manifest_name = os.path.basename(manifest_path)
            temp_manifest = os.path.join(temp_dir, manifest_name)
            logger.debug(f"Copying manifest {manifest_path} to {temp_manifest}")
            shutil.copy2(manifest_path, temp_manifest)
            logger.debug(f"Manifest copied successfully")
            
            # Execute runtime-specific analysis
            logger.debug(f"Executing {runtime}-specific analysis")
            config = get_runtime_execution_config(runtime)
            if config:
                result = self._execute_runtime_analysis(runtime, temp_manifest, temp_dir, **kwargs)
            else:
                logger.error(f"Unsupported runtime: {runtime}")
                result = {'error': f'Unsupported runtime: {runtime}'}
            
            logger.info(f"Native {runtime} analysis completed - Success: {result.get('success', False)}")
            # Only log stderr as error if the process actually failed
            if result.get('error') and not result.get('success', False):
                logger.error(f"Native {runtime} analysis error: {result['error']}")
            elif result.get('stderr') and result.get('success', False):
                # Process succeeded but had stderr output - log as debug
                logger.debug(f"Native {runtime} analysis stderr (process succeeded): {result['stderr']}")
            
            return result
                
        except Exception as e:
            logger.error(f"Native execution analysis failed for {runtime}: {str(e)}")
            logger.exception(f"Full traceback for native {runtime} execution error:")
            return {'error': f'Analysis execution failed: {str(e)}'}
    
    def _execute_runtime_analysis(self, runtime: str, manifest_path: str, work_dir: str, **kwargs) -> Dict:
        """Execute runtime dependency analysis using unified approach."""
        config = get_runtime_execution_config(runtime)
        runtime_version = kwargs.get('runtime_version', config.get('default_version', get_runtime_default_version(runtime)))
        
        try:
            # Common setup
            output_file_path, output_filename, manifest_name = self._setup_runtime_analysis(runtime, manifest_path, work_dir, **kwargs)
            
            # Build command
            script_name = get_runtime_script_name(runtime)
            cmd = [sys.executable, script_name, manifest_name]
            
            # Add runtime-specific flags
            if runtime == 'java':
                if kwargs.get('deep_scan', False):
                    cmd.append('--deep-scan')
                if kwargs.get('runtime_test', False):
                    cmd.append('--runtime-test')
                if kwargs.get('verbose', False):
                    cmd.append('--verbose')
            
            cmd.extend(['-o', output_file_path])
            logger.debug(f"NATIVE FILE MODE: Executing {runtime} command: {' '.join(cmd)}")
            
            # Set environment variables
            env = os.environ.copy()
            if kwargs.get('verbose', False):
                if runtime == 'nodejs':
                    env['NODE_LOG_LEVEL'] = 'DEBUG'
                else:
                    env['DEBUG'] = '1'
            
            # Execute with runtime-specific timeout
            start_time = time.time()
            result = subprocess.run(cmd, capture_output=True, text=True, cwd=work_dir, timeout=config['timeout'], env=env)
            execution_time = round(time.time() - start_time, 2)
            
            logger.debug(f"{runtime} command completed - Return code: {result.returncode}, Execution time: {execution_time}s")
            
            # Determine success based on runtime-specific exit codes
            success_codes = config.get('success_codes', [0])
            success = result.returncode in success_codes
            
            # Common output handling
            file_output = self._handle_analysis_output(runtime, result, output_file_path, output_filename, **kwargs)
            
            # Build environment string
            if runtime == 'dotnet' and runtime_version:
                env_str = f'native_dotnet_{runtime_version}'
            elif runtime == 'dotnet':
                env_str = 'native_dotnet'
            else:
                env_str = f'{runtime}_{runtime_version}'
            
            return {
                'success': success,
                'output': file_output,
                'error': result.stderr if not success else None,
                'stderr': result.stderr,
                'environment': env_str,
                'command': ' '.join(cmd),
                'work_dir': work_dir,
                'execution_time': execution_time,
                'output_file_path': output_file_path
            }
            
        except subprocess.TimeoutExpired:
            return {'error': f'{runtime} analysis timed out after {config["timeout"]} seconds'}
        except Exception as e:
            logger.error(f"{runtime} analysis exception: {str(e)}")
            return {'error': f'{runtime} analysis failed: {str(e)}'}
    
    def cleanup(self, skip_cleanup=False):
        """Clean up temporary directories."""
        # Skip cleanup only if explicitly requested
        if skip_cleanup:
            logger.info(f"CLEANUP DISABLED: Preserving {len(self.temp_dirs)} temp directories for manual testing")
            for temp_dir in self.temp_dirs:
                logger.info(f"PRESERVED TEMP DIR: {temp_dir}")
            return
            
        logger.debug(f"Cleaning up {len(self.temp_dirs)} temporary directories")
        
        for temp_dir in self.temp_dirs:
            try:
                logger.debug(f"Removing temporary directory: {temp_dir}")
                shutil.rmtree(temp_dir)
            except Exception as e:
                logger.warning(f"Failed to remove temporary directory {temp_dir}: {e}")
        
        self.temp_dirs.clear()
        logger.debug("Temporary directory cleanup completed")


class ContainerExecutionEnvironment(ExecutionEnvironment):
    """Container-based execution environment for local development."""
    

    
    def __init__(self):
        self.created_images = []
        self.temp_dirs = []
        self.container_tool = 'docker'  # Default, will be detected
    
    def check_prerequisites(self, runtime: str) -> Tuple[bool, List[str]]:
        """Check if Docker or Podman is available."""
        container_tool = self._detect_container_tool()
        if container_tool:
            self.container_tool = container_tool
            return True, []
        return False, ['docker or podman']
    
    def _detect_container_tool(self) -> str:
        """Detect available container tool."""
        for tool in ['docker', 'podman']:
            try:
                subprocess.run([tool, '--version'], 
                             capture_output=True, check=True, timeout=10)
                return tool
            except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
                continue
        return None
    
    def execute_analysis(self, runtime: str, manifest_path: str, **kwargs) -> Dict:
        """Execute analysis in Docker container with dynamic OS-based construction."""
        logger.info(f"Starting container execution analysis for {runtime}")
        logger.debug(f"Container manifest path: {manifest_path}")
        logger.debug(f"Container execution kwargs: {list(kwargs.keys())}")
        logger.debug(f"DEBUG FILE COPY: output_dir in kwargs = {kwargs.get('output_dir')}")
        logger.debug(f"DEBUG FILE COPY: sbom_name in kwargs = {kwargs.get('sbom_name')}")
        
        # ECR Public is publicly accessible - no authentication needed
        logger.info(f"Using {self.container_tool} for container operations")
        
        try:
            runtime_version = kwargs.get('runtime_version', get_runtime_default_version(runtime))
            os_version = kwargs.get('os_version', 'amazon-linux-2023')
            logger.info(f"Container config - Runtime: {runtime} {runtime_version}, OS: {os_version}")
            
            # Create temporary directory for Docker context
            temp_dir = tempfile.mkdtemp(prefix=f'graviton_docker_{runtime}_')
            self.temp_dirs.append(temp_dir)
            logger.debug(f"Created Docker context directory: {temp_dir}")
            
            # Generate Dockerfile with detected OS
            logger.debug(f"Generating Dockerfile for {runtime} with OS {os_version}")
            dockerfile_content = self._generate_dockerfile(runtime, runtime_version, os_version)
            dockerfile_path = os.path.join(temp_dir, 'Dockerfile')
            logger.debug(f"Dockerfile content ({len(dockerfile_content)} chars): {dockerfile_content[:200]}...")
            
            with open(dockerfile_path, 'w') as f:
                f.write(dockerfile_content)
            logger.debug(f"Dockerfile written to: {dockerfile_path}")
            
            # Copy manifest to Docker context
            manifest_name = os.path.basename(manifest_path)
            temp_manifest = os.path.join(temp_dir, manifest_name)
            logger.debug(f"Copying manifest {manifest_path} to Docker context as {manifest_name}")
            shutil.copy2(manifest_path, temp_manifest)
            
            # Also copy with standard name for runtime compatibility
            if runtime == 'nodejs' and not manifest_name == 'package.json':
                standard_manifest = os.path.join(temp_dir, 'package.json')
                shutil.copy2(manifest_path, standard_manifest)
                logger.debug(f"Also copied manifest as package.json for Node.js compatibility")
            
            # Copy graviton_validator.py and entire module to Docker context
            self._copy_graviton_validator_module(temp_dir)
            
            # Copy standalone tester script to Docker context (for backward compatibility)
            self._copy_standalone_tester(runtime, temp_dir)
            
            # Log manifest contents for debugging
            try:
                with open(temp_manifest, 'r') as f:
                    manifest_content = f.read()
                    logger.debug(f"Container manifest content ({len(manifest_content)} chars): {manifest_content[:300]}...")
            except Exception as e:
                logger.warning(f"Could not read manifest content for logging: {e}")
            
            # Build Docker image with OS info
            os_tag = os_version.replace(':', '-').replace('.', '-')
            image_name = f'graviton-{runtime}-analysis:{runtime_version}-{os_tag}'
            self.created_images.append(image_name)
            logger.info(f"Building Docker image: {image_name}")
            
            build_cmd = [self.container_tool, 'build', '-t', image_name, '.']
            logger.debug(f"MANUAL TEST COMMAND: cd {temp_dir} && {' '.join(build_cmd)}")
            logger.debug(f"TEMP DIR PRESERVED FOR DEBUGGING: {temp_dir}")
            logger.debug(f"{self.container_tool.title()} build command: {' '.join(build_cmd)}")
            logger.debug(f"{self.container_tool.title()} build context: {temp_dir}")
            
            # Log all files for debugging and replication
            logger.debug(f"=== DEBUG INFO FOR {runtime.upper()} ANALYSIS ===")
            logger.debug(f"Temp directory: {temp_dir}")
            logger.debug(f"Volume mount: {temp_dir}:/workspace")
            
            # Log Dockerfile
            try:
                with open(os.path.join(temp_dir, 'Dockerfile'), 'r') as f:
                    dockerfile_content = f.read()
                    logger.debug(f"DOCKERFILE:\n{dockerfile_content}")
            except Exception as e:
                logger.warning(f"Could not read Dockerfile: {e}")
            
            # Log manifest file
            try:
                with open(temp_manifest, 'r') as f:
                    manifest_content = f.read()
                    logger.debug(f"MANIFEST FILE ({manifest_name}):\n{manifest_content}")
            except Exception as e:
                logger.warning(f"Could not read manifest: {e}")
            
            # Log expected output path
            sbom_name = kwargs.get('sbom_name')
            if sbom_name:
                expected_base = sbom_name
            else:
                expected_base = manifest_name.rsplit('.', 1)[0] if '.' in manifest_name else manifest_name
            expected_output = f"{temp_dir}/{runtime}/{expected_base}_{runtime}_analysis.json"
            logger.debug(f"EXPECTED OUTPUT FILE: {expected_output}")
            

            
            build_start = time.time()
            build_result = subprocess.run(
                build_cmd, capture_output=True, text=True, cwd=temp_dir, timeout=kwargs.get('container_timeout', 600)
            )
            build_elapsed = time.time() - build_start
            
            logger.debug(f"{self.container_tool.title()} build completed in {build_elapsed:.1f}s - Return code: {build_result.returncode}")
            if build_result.stdout:
                logger.debug(f"{self.container_tool.title()} build stdout ({len(build_result.stdout)} chars): {build_result.stdout[:500]}...")
            if build_result.stderr:
                logger.debug(f"{self.container_tool.title()} build stderr ({len(build_result.stderr)} chars): {build_result.stderr[:500]}...")
            
            if build_result.returncode != 0:
                logger.error(f"{self.container_tool.title()} build failed for {runtime}: {build_result.stderr[:200]}...")
                return {
                    'success': False,
                    'error': f'{self.container_tool.title()} build failed: {build_result.stderr}',
                    'environment': f'container_{runtime}_{runtime_version}'
                }
            
            logger.info(f"{self.container_tool.title()} image built successfully: {image_name}")
            
            # Run analysis in container with same structure as native execution
            sbom_name = kwargs.get('sbom_name')
            analysis_cmd = self._get_analysis_command(runtime, manifest_name, sbom_name)
            container_run_cmd = [
                self.container_tool, 'run', '--rm',
                '-v', f'{temp_dir}:/workspace',
                '-w', '/workspace',
                image_name,
                'sh', '-c', analysis_cmd
            ]
            
            logger.info(f"Running {runtime} analysis in container")
            logger.debug(f"BUILD COMMAND: cd {temp_dir} && {' '.join(build_cmd)}")
            logger.debug(f"RUN COMMAND: {' '.join(container_run_cmd)}")
            logger.debug(f"ANALYSIS COMMAND INSIDE CONTAINER: {analysis_cmd}")
            logger.debug(f"DEBUG FILE COPY: Manifest name passed to container = {manifest_name}")
            logger.debug(f"DEBUG FILE COPY: Expected container output filename = {manifest_name.rsplit('.', 1)[0] if '.' in manifest_name else manifest_name}_{runtime}_analysis.json")
            logger.debug(f"{self.container_tool.title()} run command: {' '.join(container_run_cmd)}")

            logger.debug(f"=== END DEBUG INFO ===")
            
            run_result = subprocess.run(
                container_run_cmd, capture_output=True, text=True, timeout=kwargs.get('container_timeout', 180)
            )
            
            logger.debug(f"Container analysis completed - Return code: {run_result.returncode}")
            logger.debug(f"Container stdout ({len(run_result.stdout)} chars): {run_result.stdout[:500]}...")
            logger.debug(f"Container stderr ({len(run_result.stderr)} chars): {run_result.stderr[:500]}...")
            
            # Check if output directory was created
            output_dir = os.path.join(temp_dir, runtime)
            if os.path.exists(output_dir):
                output_files = os.listdir(output_dir)
                logger.debug(f"Output directory contains {len(output_files)} files: {output_files}")
            else:
                logger.warning(f"Output directory not found: {output_dir}")
            
            # Handle runtime-specific exit codes
            if runtime == 'java':
                # Java package installer exit codes: 0=all compatible, 1=error, 2=some incompatible
                success = run_result.returncode in [0, 2]
            else:
                success = run_result.returncode == 0
            
            environment = f'container_{runtime}_{runtime_version}_{os_version.replace(":", "-")}'
            
            if success:
                logger.info(f"Container {runtime} analysis: SUCCESS")
            else:
                logger.error(f"Container {runtime} analysis: FAILED - {run_result.stderr[:200]}...")
                # Log error but continue execution
                logger.warning(f"Container {runtime} analysis failed, returning error result")
            
            # Read output file from mounted volume - match native mode structure
            # Use same filename logic as _get_analysis_command to ensure consistency
            sbom_name = kwargs.get('sbom_name')
            if sbom_name:
                base_name = sbom_name
            else:
                if '.' in manifest_name:
                    base_name = manifest_name.rsplit('.', 1)[0]  # Remove only last .extension
                else:
                    base_name = manifest_name
            
            output_filename = f'{base_name}_{runtime}_analysis.json'
            output_file_path = os.path.join(temp_dir, runtime, output_filename)
            logger.debug(f"DEBUG FILE COPY: Expected output filename = {output_filename}")
            logger.debug(f"DEBUG FILE COPY: Manifest name = {manifest_name}")
            logger.debug(f"DEBUG FILE COPY: SBOM name = {sbom_name}")
            logger.debug(f"DEBUG FILE COPY: Base name = {base_name}")
            
            # Check what files actually exist in the output directory
            if os.path.exists(os.path.join(temp_dir, runtime)):
                actual_files = os.listdir(os.path.join(temp_dir, runtime))
                logger.debug(f"DEBUG FILE COPY: Actual files in output dir = {actual_files}")
                for f in actual_files:
                    if f.endswith(f'_{runtime}_analysis.json'):
                        logger.debug(f"DEBUG FILE COPY: Found actual output file = {f}")
                        # Try to read the actual file if our expected one doesn't exist
                        if not os.path.exists(output_file_path):
                            actual_file_path = os.path.join(temp_dir, runtime, f)
                            logger.debug(f"DEBUG FILE COPY: Using actual file instead = {actual_file_path}")
                            output_file_path = actual_file_path
                            output_filename = f
            
            analysis_output = ''
            # Try to read output file regardless of success status (file might exist even on partial failure)
            if os.path.exists(output_file_path):
                try:
                    with open(output_file_path, 'r') as f:
                        analysis_output = f.read()
                    logger.debug(f"Successfully read output file: {output_file_path} ({len(analysis_output)} chars)")
                    
                    # Copy output file to permanent output directory if provided
                    permanent_output_dir = kwargs.get('output_dir')
                    logger.debug(f"DEBUG FILE COPY: permanent_output_dir = {permanent_output_dir}")
                    logger.debug(f"DEBUG FILE COPY: temp file exists = {os.path.exists(output_file_path)}")
                    logger.debug(f"DEBUG FILE COPY: temp file path = {output_file_path}")
                    if permanent_output_dir:
                        permanent_runtime_dir = os.path.join(permanent_output_dir, runtime)
                        os.makedirs(permanent_runtime_dir, exist_ok=True)
                        permanent_output_path = os.path.join(permanent_runtime_dir, output_filename)
                        logger.debug(f"DEBUG FILE COPY: Copying FROM {output_file_path} TO {permanent_output_path}")
                        logger.debug(f"DEBUG FILE COPY: Output filename being copied = {output_filename}")
                        shutil.copy2(output_file_path, permanent_output_path)
                        logger.debug(f"DEBUG FILE COPY: Copy completed - file exists = {os.path.exists(permanent_output_path)}")
                    else:
                        logger.debug(f"DEBUG FILE COPY: No output_dir provided, file will not be copied")
                        
                except Exception as e:
                    logger.warning(f"Failed to read output file {output_file_path}: {e}")
                    analysis_output = run_result.stdout  # Fallback to stdout
            else:
                logger.warning(f"Output file not found: {output_file_path}, using stdout")
                analysis_output = run_result.stdout
            
            return {
                'success': success,
                'output': analysis_output,
                'error': run_result.stderr,
                'environment': environment,
                'build_output': build_result.stdout,
                'image_name': image_name,
                'analysis_command': analysis_cmd,
                'output_file_path': output_file_path
            }
            
        except subprocess.TimeoutExpired as te:
            timed_out_cmd = ' '.join(te.cmd[:3]) if te.cmd else 'unknown'
            phase = 'build' if 'build' in timed_out_cmd else 'run'
            logger.error(f"Container {phase} timed out for {runtime} after {te.timeout} seconds (cmd: {timed_out_cmd})")
            return {
                'success': False,
                'error': f'Container {phase} timed out for {runtime} after {te.timeout}s',
                'environment': f'container_{runtime}_{kwargs.get("runtime_version", "unknown")}'
            }
        except Exception as e:
            logger.error(f"Container analysis exception for {runtime}: {str(e)}")
            logger.exception(f"Full container {runtime} analysis exception traceback:")
            return {
                'success': False,
                'error': f'Container analysis failed: {str(e)}',
                'environment': f'container_{runtime}_{kwargs.get("runtime_version", "unknown")}'
            }
    
    def _generate_dockerfile(self, runtime: str, runtime_version: str, os_version: str) -> str:
        """Generate Dockerfile with dynamic OS-based construction following design document."""
        # Extract OS name and version
        os_name, os_ver = self._parse_os_version(os_version)
        base_image = self._get_base_image(os_name, os_ver)
        
        # Generate OS-specific package manager commands
        pkg_mgr_update, pkg_mgr_install = self._get_package_commands(os_name)
        
        # Build Dockerfile based on detected OS and runtime
        # Note: Ruby uses its own base image, others use detected OS
        dockerfile_lines = [f"FROM {base_image}"]
        
        if runtime == 'python':
            if os_name in ['amazon-linux', 'amazon', 'centos', 'rhel', 'fedora']:
                dockerfile_lines.extend([
                    f"RUN {pkg_mgr_update}",
                    f"RUN {pkg_mgr_install} bash python3 python3-pip gcc gcc-c++ python3-devel make",
                    "RUN pip3 install openpyxl PyYAML defusedxml packaging psutil",
                    "WORKDIR /workspace"
                ])
            else:
                dockerfile_lines.extend([
                    f"RUN {pkg_mgr_update}",
                    f"RUN {pkg_mgr_install} bash python3 python3-pip gcc g++ python3-dev build-essential",
                    "RUN pip3 install openpyxl PyYAML defusedxml packaging psutil 'urllib3<2.0'",
                    "WORKDIR /workspace"
                ])
        elif runtime == 'nodejs':
            # Use official Node.js Alpine image to avoid GLIBC compatibility issues
            node_version = runtime_version if runtime_version != 'latest' else '20'
            dockerfile_lines = [f"FROM node:{node_version}-alpine"]
            dockerfile_lines.extend([
                "RUN apk update",
                "RUN apk add --no-cache bash gcc g++ make musl-dev python3-dev python3 py3-pip linux-headers libffi-dev openssl-dev curl",
                "RUN pip3 install --break-system-packages PyYAML defusedxml packaging psutil openpyxl 'urllib3<2.0'",
                "WORKDIR /workspace"
            ])
        elif runtime == 'dotnet':
            # Use official Microsoft .NET SDK image (Debian-based)
            dotnet_version = runtime_version if runtime_version != 'latest' else '8.0'
            dockerfile_lines = [f"FROM mcr.microsoft.com/dotnet/sdk:{dotnet_version}"]
            dockerfile_lines.extend([
                "RUN apt-get update",
                "RUN apt-get install -y bash python3 python3-pip",
                "RUN pip3 install --break-system-packages PyYAML defusedxml packaging psutil openpyxl 'urllib3<2.0'",
                "ENV DOTNET_CLI_TELEMETRY_OPTOUT=1",
                "ENV DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1",
                "WORKDIR /workspace"
            ])
        elif runtime == 'ruby':
            # Use Alpine Ruby image for faster builds and specific Ruby versions
            ruby_version = runtime_version if runtime_version != 'latest' else '3.2'
            dockerfile_lines = [f"FROM ruby:{ruby_version}-alpine"]
            dockerfile_lines.extend([
                "RUN apk update",
                "RUN apk add --no-cache bash gcc g++ make musl-dev python3-dev python3 py3-pip linux-headers libffi-dev openssl-dev curl",
                "RUN gem install bundler",
                "RUN pip3 install --break-system-packages PyYAML defusedxml packaging psutil openpyxl 'urllib3<2.0'",
                "WORKDIR /workspace"
            ])
        elif runtime == 'java':
            if os_name in ['amazon-linux', 'amazon', 'centos', 'rhel', 'fedora']:
                # RPM-based systems
                dockerfile_lines.extend([
                    f"RUN {pkg_mgr_update}",
                    f"RUN {pkg_mgr_install} bash java-{runtime_version}-amazon-corretto-devel maven python3 python3-pip",
                    "RUN pip3 install PyYAML defusedxml packaging psutil openpyxl 'requests<2.29' 'urllib3<2.0'",
                    "WORKDIR /workspace"
                ])
            else:
                # DEB-based systems
                dockerfile_lines.extend([
                    f"RUN {pkg_mgr_update}",
                    f"RUN {pkg_mgr_install} bash openjdk-{runtime_version}-jdk maven python3 python3-pip",
                    "RUN pip3 install PyYAML defusedxml packaging psutil openpyxl 'requests<2.29' 'urllib3<2.0'",
                    "WORKDIR /workspace"
                ])
        else:
            dockerfile_lines.extend(["WORKDIR /workspace"])
        
        return "\n".join(dockerfile_lines)
    
    def _parse_os_version(self, os_version: str) -> tuple:
        """Parse OS version string into name and version."""
        if ':' in os_version:
            os_name, os_ver = os_version.split(':', 1)
        elif os_version.startswith('amazon-linux-'):
            # Special handling for amazon-linux-2023 format
            os_name = 'amazon-linux'
            os_ver = os_version.replace('amazon-linux-', '')
        elif '-' in os_version:
            parts = os_version.split('-')
            os_name = parts[0]
            os_ver = '-'.join(parts[1:]) if len(parts) > 1 else 'latest'
        else:
            os_name = os_version
            os_ver = 'latest'
        
        return os_name.lower(), os_ver
    
    def _get_base_image(self, os_name: str, os_ver: str) -> str:
        """Get base image for OS - let Podman handle registry resolution."""
        if os_name in ['amazon-linux', 'amazon']:
            return f'amazonlinux:{os_ver}'
        elif os_name == 'ubuntu':
            return f'ubuntu:{os_ver}'
        elif os_name == 'debian':
            return f'debian:{os_ver}'
        elif os_name in ['rhel', 'centos']:
            return f'centos:{os_ver}'
        elif os_name == 'fedora':
            return f'fedora:{os_ver}'
        else:
            return 'amazonlinux:2023'  # Default to Amazon Linux 2023
    
    def _get_package_commands(self, os_name: str) -> tuple:
        """Get package manager commands for OS."""
        if os_name in ['ubuntu', 'debian']:
            return "apt-get update", "apt-get install -y"
        elif os_name in ['amazon-linux', 'amazon', 'centos', 'rhel', 'fedora']:
            return "yum update -y", "yum install -y"
        else:
            return "apt-get update", "apt-get install -y"  # Default to apt
    
    def _get_analysis_command(self, runtime: str, manifest_name: str, sbom_name: str = None) -> str:
        """Get analysis command for runtime-specific package installer scripts."""
        script_name = get_runtime_script_name(runtime)
        output_filename = self.generate_output_filename(manifest_name, runtime, sbom_name)
        
        logger.debug(f"Output File Location: ./{runtime}/{output_filename}")
        base_cmd = f'mkdir -p ./{runtime} && python3 graviton_validator/analysis/{script_name} "{manifest_name}"'
        if runtime == 'java':
            base_cmd += f' --runtime-test --deep-scan'
        base_cmd += f' -o "./{runtime}/{output_filename}"'
        
        return base_cmd
    

    

    
    def cleanup(self, skip_cleanup=False):
        """Clean up containers and images."""
        # Skip cleanup only if explicitly requested
        if skip_cleanup:
            logger.info(f"CLEANUP DISABLED: Preserving {len(self.temp_dirs)} temp directories and {len(self.created_images)} images for manual testing")
            for temp_dir in self.temp_dirs:
                logger.info(f"PRESERVED TEMP DIR: {temp_dir}")
            for image in self.created_images:
                logger.info(f"PRESERVED IMAGE: {image}")
            return
            
        logger.debug(f"Cleaning up {len(self.created_images)} Docker images and {len(self.temp_dirs)} temp directories")
        
        # Clean up Docker images
        for image in self.created_images:
            try:
                logger.debug(f"Removing {self.container_tool} image: {image}")
                result = subprocess.run([self.container_tool, 'rmi', '-f', image], 
                                     capture_output=True, timeout=30)
                if result.returncode == 0:
                    logger.debug(f"Successfully removed {self.container_tool} image: {image}")
                else:
                    logger.warning(f"Failed to remove {self.container_tool} image {image}: {result.stderr}")
            except Exception as e:
                logger.warning(f"Exception removing {self.container_tool} image {image}: {e}")
        
        # Clean up temp directories
        for temp_dir in self.temp_dirs:
            try:
                logger.debug(f"Removing temporary directory: {temp_dir}")
                shutil.rmtree(temp_dir)
            except Exception as e:
                logger.warning(f"Failed to remove temporary directory {temp_dir}: {e}")
        
        self.created_images.clear()
        self.temp_dirs.clear()
        logger.debug("Container cleanup completed")
    
    def _copy_graviton_validator_module(self, temp_dir: str):
        """Copy entire graviton_validator module and main script to Docker context."""
        try:
            # Copy graviton_validator.py (main script)
            main_script = Path(__file__).parent.parent.parent / 'graviton_validator.py'
            if main_script.exists():
                dest_main = os.path.join(temp_dir, 'graviton_validator.py')
                shutil.copy2(str(main_script), dest_main)
                logger.debug(f"Copied graviton_validator.py to Docker context")
            else:
                logger.warning(f"Main script not found: {main_script}")
            
            # Copy entire graviton_validator module
            module_dir = Path(__file__).parent.parent
            dest_module = os.path.join(temp_dir, 'graviton_validator')
            if module_dir.exists():
                shutil.copytree(str(module_dir), dest_module)
                logger.debug(f"Copied graviton_validator module to Docker context")
            else:
                logger.warning(f"Module directory not found: {module_dir}")
            
            # Copy knowledge_bases directory if it exists
            kb_dir = Path(__file__).parent.parent.parent / 'knowledge_bases'
            if kb_dir.exists():
                dest_kb = os.path.join(temp_dir, 'knowledge_bases')
                shutil.copytree(str(kb_dir), dest_kb)
                logger.debug(f"Copied knowledge_bases to Docker context")
            
            # Copy deny_lists directory if it exists
            deny_dir = Path(__file__).parent.parent.parent / 'deny_lists'
            if deny_dir.exists():
                dest_deny = os.path.join(temp_dir, 'deny_lists')
                shutil.copytree(str(deny_dir), dest_deny)
                logger.debug(f"Copied deny_lists to Docker context")
            
            # Copy schemas directory if it exists (needed for OS detection)
            schemas_dir = Path(__file__).parent.parent.parent / 'schemas'
            if schemas_dir.exists():
                dest_schemas = os.path.join(temp_dir, 'schemas')
                shutil.copytree(str(schemas_dir), dest_schemas)
                logger.debug(f"Copied schemas to Docker context")
                
        except Exception as e:
            logger.warning(f"Failed to copy graviton_validator module: {e}")
    
    def _copy_standalone_tester(self, runtime: str, temp_dir: str):
        """Copy standalone tester script to Docker context."""
        script_name = get_runtime_script_name(runtime)
        if script_name != f'{runtime}_package_installer.py':  # Only copy if script exists
            script_path = Path(__file__).parent / script_name
            
            if script_path.exists():
                dest_path = os.path.join(temp_dir, script_name)
                shutil.copy2(str(script_path), dest_path)
                logger.debug(f"Copied {script_name} to Docker context")
            else:
                logger.warning(f"Standalone tester script not found: {script_path}")


class ExecutionEnvironmentFactory:
    """Factory for creating execution environments."""
    
    @staticmethod
    def create_environment(use_containers: bool = False) -> ExecutionEnvironment:
        """Create appropriate execution environment."""
        if use_containers:
            return ContainerExecutionEnvironment()
        else:
            return NativeExecutionEnvironment()
    
    @staticmethod
    def detect_best_environment() -> ExecutionEnvironment:
        """Detect and return the best available execution environment."""
        return NativeExecutionEnvironment()