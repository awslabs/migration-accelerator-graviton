"""
Concrete implementation of compatibility analysis engine with OS-aware capabilities.
"""

import logging
import time
from typing import List, Optional, Dict, Tuple

from ..knowledge_base.base import KnowledgeBase
from ..models import (
    AnalysisResult, 
    ComponentResult, 
    CompatibilityResult,
    CompatibilityStatus,
    SoftwareComponent
)
from .base import CompatibilityAnalyzer, RecommendationGenerator
from .filters import ComponentFilter, ComponentCategory
from ..os_detection import OSDetector, OSConfigManager
from ..deny_list import DenyListLoader

logger = logging.getLogger(__name__)


class GravitonCompatibilityAnalyzer(CompatibilityAnalyzer):
    """
    Concrete implementation of compatibility analyzer for Graviton processors with OS-aware capabilities.
    """
    
    def __init__(self, knowledge_base: KnowledgeBase, 
                 recommendation_generator: Optional[RecommendationGenerator] = None, 
                 matching_config=None,
                 os_detector: Optional[OSDetector] = None,
                 os_config_manager: Optional[OSConfigManager] = None,
                 component_filter: Optional[ComponentFilter] = None,
                 deny_list_loader: Optional[DenyListLoader] = None,
                 runtime_analyzers: Optional[Dict] = None,
                 analysis_cache=None):
        """
        Initialize the compatibility analyzer with OS-aware capabilities.
        
        Args:
            knowledge_base: KnowledgeBase instance for compatibility lookups
            recommendation_generator: Optional RecommendationGenerator for upgrade suggestions
            matching_config: Optional matching configuration for intelligent matching
            os_detector: Optional OSDetector for OS identification
            os_config_manager: Optional OSConfigManager for OS compatibility data
            component_filter: Optional ComponentFilter for OS-aware filtering
            analysis_cache: Optional AnalysisCache for cross-SBOM result caching
        """
        self.knowledge_base = knowledge_base
        self.recommendation_generator = recommendation_generator or DefaultRecommendationGenerator(knowledge_base)
        self.matching_config = matching_config
        self.analysis_cache = analysis_cache
        
        # OS-aware components
        self.os_config_manager = os_config_manager or OSConfigManager()
        self.os_detector = os_detector or self.os_config_manager
        self.component_filter = component_filter or ComponentFilter(
            os_config_manager=self.os_config_manager
        )
        self.deny_list_loader = deny_list_loader
        
        # Initialize runtime analyzers
        if runtime_analyzers is None:
            self.runtime_analyzers = self._create_default_runtime_analyzers()
        else:
            self.runtime_analyzers = runtime_analyzers
        
        # Log available runtime analyzers
        if self.runtime_analyzers:
            runtime_types = list(self.runtime_analyzers.keys())
            logger.info(f"Initialized with runtime analyzers: {runtime_types}")
    
    def analyze_components(self, components: List[SoftwareComponent], detected_os: Optional[str] = None, sbom_file: Optional[str] = None) -> AnalysisResult:
        """
        Analyze a list of software components for Graviton compatibility with hierarchical optimization.
        
        Args:
            components: List of SoftwareComponent objects to analyze
            detected_os: Optional detected OS name for OS-aware analysis
            
        Returns:
            AnalysisResult containing the complete analysis with hierarchical optimization
        """
        start_time = time.time()
        component_results = []
        errors = []
        
        logger.info(f"Starting hierarchical analysis of {len(components)} components")
        if detected_os:
            logger.info(f"Detected OS: {detected_os}")
        
        # Group components by source package for hierarchical analysis
        source_groups, standalone_components = self._group_components_by_source(components)
        
        # Categorize components by OS compatibility
        categorized_components = self._categorize_components_by_os(components, detected_os)
        
        processed_count = 0
        total_components = len(components)
        
        # Process source package groups (parent + children)
        for source_package, group_components in source_groups.items():
            try:
                if processed_count % 10 == 0:
                    print(".", end="", flush=True)
                
                # Find parent component (one without parent_component set or matches source_package name)
                parent_component = None
                for c in group_components:
                    if not c.parent_component or c.name == source_package:
                        parent_component = c
                        break
                
                if not parent_component:
                    parent_component = group_components[0]  # Fallback
                
                logger.debug(f"Processing source group '{source_package}' with {len(group_components)} components")
                
                # Analyze parent component
                parent_category = categorized_components.get(parent_component.name, ComponentCategory.APPLICATION)
                parent_result = self.check_single_component(parent_component, detected_os, parent_category)
                component_results.append(parent_result)
                
                # Apply parent compatibility to all children
                for child_component in group_components:
                    if child_component.name != parent_component.name:
                        child_result = self._create_inherited_result(child_component, parent_result, parent_component.name)
                        component_results.append(child_result)
                
                processed_count += len(group_components)
                
            except Exception as e:
                error_msg = f"Error analyzing source group {source_package}: {str(e)}"
                logger.error(error_msg)
                errors.append(error_msg)
                
                # Create error results for all components in the group
                for component in group_components:
                    error_result = ComponentResult(
                        component=component,
                        compatibility=CompatibilityResult(
                            status=CompatibilityStatus.UNKNOWN,
                            current_version_supported=False,
                            minimum_supported_version=None,
                            recommended_version=None,
                            notes=f"Analysis failed: {str(e)}. Component compatibility could not be determined due to processing error."
                        )
                    )
                    component_results.append(error_result)
                processed_count += len(group_components)
        
        # Process standalone components (no hierarchical relationship)
        for i, component in enumerate(standalone_components):
            try:
                if processed_count % 10 == 0:
                    print(".", end="", flush=True)
                    logger.debug(f"Processing standalone component {processed_count+1}/{total_components}: {component.name}")
                
                component_category = categorized_components.get(component.name, ComponentCategory.APPLICATION)
                result = self.check_single_component(component, detected_os, component_category)
                component_results.append(result)
                processed_count += 1
                
            except Exception as e:
                error_msg = f"Error analyzing component {component.name}: {str(e)}"
                logger.error(error_msg)
                errors.append(error_msg)
                
                error_result = ComponentResult(
                    component=component,
                    compatibility=CompatibilityResult(
                        status=CompatibilityStatus.UNKNOWN,
                        current_version_supported=False,
                        minimum_supported_version=None,
                        recommended_version=None,
                        notes=f"Analysis failed: {str(e)}. Component compatibility could not be determined due to processing error."
                    )
                )
                component_results.append(error_result)
                processed_count += 1
        
        # Calculate statistics
        compatible_count = sum(1 for r in component_results 
                             if r.compatibility.status == CompatibilityStatus.COMPATIBLE)
        incompatible_count = sum(1 for r in component_results 
                               if r.compatibility.status == CompatibilityStatus.INCOMPATIBLE)
        needs_upgrade_count = sum(1 for r in component_results 
                                if r.compatibility.status == CompatibilityStatus.NEEDS_UPGRADE)
        needs_verification_count = sum(1 for r in component_results 
                                     if r.compatibility.status == CompatibilityStatus.NEEDS_VERIFICATION)
        needs_version_verification_count = sum(1 for r in component_results 
                                             if r.compatibility.status == CompatibilityStatus.NEEDS_VERSION_VERIFICATION)
        unknown_count = sum(1 for r in component_results 
                          if r.compatibility.status == CompatibilityStatus.UNKNOWN)
        
        processing_time = time.time() - start_time
        
        # Add newline after progress dots
        if len(components) > 0:
            print()  # New line after progress dots
        
        logger.info(f"Analysis complete: {compatible_count} compatible, "
                   f"{incompatible_count} incompatible, {needs_upgrade_count} needs upgrade, "
                   f"{needs_verification_count} needs verification, {needs_version_verification_count} needs version verification, "
                   f"{unknown_count} unknown ({processing_time:.2f}s)")
        
        return AnalysisResult(
            components=component_results,
            total_components=len(components),
            compatible_count=compatible_count,
            incompatible_count=incompatible_count,
            needs_upgrade_count=needs_upgrade_count,
            needs_verification_count=needs_verification_count,
            needs_version_verification_count=needs_version_verification_count,
            unknown_count=unknown_count,
            errors=errors,
            processing_time=processing_time,
            detected_os=detected_os,
            sbom_file=sbom_file
        )
    
    def check_single_component(self, component: SoftwareComponent, detected_os: Optional[str] = None, component_category: ComponentCategory = ComponentCategory.APPLICATION) -> ComponentResult:
        """
        Check compatibility for a single software component with OS awareness.
        """
        # Check cache first
        if self.analysis_cache:
            cached = self.analysis_cache.get(
                component.name, component.version or "", component.component_type, detected_os or ""
            )
            if cached:
                return ComponentResult(
                    component=component,
                    compatibility=CompatibilityResult(
                        status=CompatibilityStatus(cached["status"]),
                        current_version_supported=cached.get("current_version_supported", False),
                        minimum_supported_version=cached.get("minimum_supported_version"),
                        recommended_version=cached.get("recommended_version"),
                        notes=cached.get("notes", ""),
                        confidence_level=cached.get("confidence_level", 0.0)
                    ),
                    matched_name=cached.get("matched_name")
                )
        
        result = self._do_check_single_component(component, detected_os, component_category)
        
        # Store in cache
        if self.analysis_cache:
            status = result.compatibility.status
            status_str = status.value if hasattr(status, 'value') else str(status)
            self.analysis_cache.put(
                component.name, component.version or "", component.component_type,
                {
                    "status": status_str,
                    "current_version_supported": result.compatibility.current_version_supported,
                    "minimum_supported_version": result.compatibility.minimum_supported_version,
                    "recommended_version": result.compatibility.recommended_version,
                    "notes": result.compatibility.notes,
                    "confidence_level": result.compatibility.confidence_level,
                    "matched_name": result.matched_name
                },
                detected_os or ""
            )
        
        return result
    
    def _do_check_single_component(self, component: SoftwareComponent, detected_os: Optional[str] = None, component_category: ComponentCategory = ComponentCategory.APPLICATION) -> ComponentResult:
        """Internal implementation of single component check."""
        # Check deny list first
        if self.deny_list_loader and self.deny_list_loader.is_denied(component.name):
            deny_entry = self.deny_list_loader.get_deny_entry(component.name)
            return ComponentResult(
                component=component,
                compatibility=CompatibilityResult(
                    status=CompatibilityStatus.INCOMPATIBLE,
                    current_version_supported=False,
                    minimum_supported_version=deny_entry.minimum_supported_version,
                    recommended_version=None,
                    notes=f"Explicitly denied: {deny_entry.reason}" + 
                          (f". Alternative: {deny_entry.recommended_alternative}" if deny_entry.recommended_alternative else ""),
                    confidence_level=1.0
                )
            )
        
        # Handle system packages with OS-aware logic
        if component_category in [ComponentCategory.SYSTEM_COMPATIBLE, ComponentCategory.KERNEL_MODULE]:
            return self._handle_system_compatible_component(component, detected_os)
        elif component_category == ComponentCategory.SYSTEM_UNKNOWN:
            return self._handle_system_unknown_component(component, detected_os)
        
        # Check for runtime-specific analysis first
        component_dict = {
            "name": component.name,
            "version": component.version,
            "type": component.component_type,
            "properties": component.properties or {},
            "purl": component.properties.get('purl', '') if component.properties else ''
        }
        
        # Check knowledge base BEFORE runtime detection to prevent false positives
        # (e.g., node_exporter misclassified as Node.js package)
        kb_result = self.knowledge_base.get_compatibility(component.name, component.version or "")
        if kb_result.status != CompatibilityStatus.UNKNOWN:
            logger.debug(f"KB match found for {component.name}: {kb_result.status}")
            return ComponentResult(component=component, compatibility=kb_result)
        
        runtime_type = self.component_filter.detect_runtime_type(component_dict)
        if runtime_type and runtime_type in self.runtime_analyzers:
            logger.debug(f"Using {runtime_type} analyzer for component {component.name}")
            return self.runtime_analyzers[runtime_type].analyze_component(component)
        
        # Check for package:owner property (app_identifier specific)
        if detected_os and hasattr(component, 'properties') and component.properties:
            package_owner = component.properties.get('package:owner')
            if package_owner:
                package_name = self._extract_package_name(package_owner)
                logger.debug(f"Checking OS package compatibility for {package_name} on {detected_os}")
                
                if self._check_os_package_compatibility(package_name, detected_os):
                    logger.debug(f"OS package {package_name} found compatible")
                    return ComponentResult(
                        component=component,
                        compatibility=CompatibilityResult(
                            status=CompatibilityStatus.COMPATIBLE,
                            current_version_supported=True,
                            minimum_supported_version=None,
                            recommended_version=None,
                            notes=f"OS package '{package_name}' compatible with Graviton on {detected_os}. OS analysis: package_owner={package_owner}, extracted_name={package_name}",
                            confidence_level=0.9
                        )
                    )
                else:
                    logger.debug(f"OS package {package_name} not found in knowledge base")
        
        # For application components, use standard knowledge base lookup
        logger.debug(f"Performing knowledge base lookup for {component.name}@{component.version}")
        compatibility_result = self.knowledge_base.get_compatibility(
            component.name, 
            component.version or ""
        )
        logger.debug(f"Knowledge base lookup result for {component.name}: {compatibility_result.status}")
        
        matched_name = None
        
        # Intelligent matching for unknown components
        if (compatibility_result.status == CompatibilityStatus.UNKNOWN and 
            self.matching_config and getattr(self.matching_config, 'enable_fuzzy_matching', True)):
            
            # Quick performance check - skip very long names
            if len(component.name) > 50:
                logger.debug(f"Skipping intelligent matching for {component.name} (name too long: {len(component.name)} chars)")
                pass  # Skip expensive matching for very long names
            else:
                logger.debug(f"Attempting intelligent matching for {component.name}")
                potential_matches = self.knowledge_base.intelligent_match(component.name, self.matching_config)
                
                if potential_matches:
                    # Use the best match (first in the list)
                    best_match = potential_matches[0]
                    matched_name = best_match
                    logger.debug(f"Found intelligent match for {component.name}: {best_match}")
                    
                    # Get compatibility for the matched name
                    matched_compatibility = self.knowledge_base.get_compatibility(
                        best_match,
                        component.version or ""
                    )
                    
                    # Only use match if it provides better information
                    if matched_compatibility.status != CompatibilityStatus.UNKNOWN:
                        # Add note about intelligent matching
                        original_notes = matched_compatibility.notes or ""
                        match_note = f"Found via intelligent matching from '{component.name}' to '{best_match}'"
                        matched_compatibility.notes = f"{match_note}. {original_notes}".strip(". ")
                        
                        compatibility_result = matched_compatibility
                        logger.debug(f"Using matched compatibility result: {compatibility_result.status}")
                    else:
                        logger.debug(f"Matched component {best_match} also has UNKNOWN status")
                else:
                    logger.debug(f"No intelligent matches found for {component.name}")
        
        # Create component result
        component_result = ComponentResult(
            component=component,
            compatibility=compatibility_result,
            matched_name=matched_name
        )
        
        # Generate recommendations if available
        if self.recommendation_generator:
            component_result = self.recommendation_generator.generate_recommendations(component_result)
        
        return component_result
    
    def _group_components_by_source(self, components: List[SoftwareComponent]) -> Tuple[Dict[str, List[SoftwareComponent]], List[SoftwareComponent]]:
        """
        Group components by source package for hierarchical analysis.
        
        Args:
            components: List of all components
            
        Returns:
            Tuple of (source_groups, standalone_components)
        """
        source_groups = {}
        standalone_components = []
        
        # First pass: identify all components that belong to source groups
        components_with_source = set()
        for component in components:
            if component.source_package:
                components_with_source.add(component.name)
                components_with_source.add(component.source_package)
            elif component.child_components:
                # Parent component with children
                components_with_source.add(component.name)
                components_with_source.update(component.child_components)
        
        # Second pass: group components
        for component in components:
            if component.source_package:
                # Child component - group by source package
                if component.source_package not in source_groups:
                    source_groups[component.source_package] = []
                source_groups[component.source_package].append(component)
            elif component.child_components:
                # Parent component - group by its own name
                if component.name not in source_groups:
                    source_groups[component.name] = []
                source_groups[component.name].append(component)
            elif component.name in components_with_source:
                # Component is part of a hierarchy but not properly linked
                # Find the appropriate group
                group_found = False
                for group_name, group_components in source_groups.items():
                    if any(c.name == component.name or component.name in c.child_components for c in group_components):
                        source_groups[group_name].append(component)
                        group_found = True
                        break
                if not group_found:
                    standalone_components.append(component)
            else:
                # Truly standalone component
                standalone_components.append(component)
        
        return source_groups, standalone_components
    
    def _create_inherited_result(self, child_component: SoftwareComponent, parent_result: ComponentResult, parent_name: str) -> ComponentResult:
        """
        Create a compatibility result for a child component by inheriting from parent.
        
        Args:
            child_component: Child component to create result for
            parent_result: Parent component's analysis result
            parent_name: Name of the parent component
            
        Returns:
            ComponentResult with inherited compatibility
        """
        # Copy parent's compatibility result
        inherited_compatibility = CompatibilityResult(
            status=parent_result.compatibility.status,
            current_version_supported=parent_result.compatibility.current_version_supported,
            minimum_supported_version=parent_result.compatibility.minimum_supported_version,
            recommended_version=parent_result.compatibility.recommended_version,
            notes=f"Inherited from source package '{parent_name}'. {parent_result.compatibility.notes or ''}".strip(),
            confidence_level=parent_result.compatibility.confidence_level * 0.95  # Slightly lower confidence for inherited
        )
        
        return ComponentResult(
            component=child_component,
            compatibility=inherited_compatibility,
            matched_name=parent_result.matched_name
        )
    
    def _categorize_components_by_os(self, components: List[SoftwareComponent], detected_os: Optional[str]) -> Dict[str, ComponentCategory]:
        """
        Categorize components based on OS compatibility.
        
        Args:
            components: List of components to categorize
            detected_os: Detected OS name
            
        Returns:
            Dictionary mapping component names to categories
        """
        categorized = {}
        
        for component in components:
            component_dict = {
                "name": component.name,
                "version": component.version,
                "type": component.component_type,
                "properties": component.properties
            }
            
            category = self.component_filter.categorize_component(component_dict, detected_os)
            categorized[component.name] = category
            
            logger.debug(f"Categorized {component.name} as {category.value}")
        
        return categorized
    
    def _handle_system_compatible_component(self, component: SoftwareComponent, detected_os: Optional[str]) -> ComponentResult:
        """
        Handle system-compatible components (OS packages from Graviton-compatible OS).
        
        Args:
            component: SoftwareComponent to analyze
            detected_os: Detected OS name
            
        Returns:
            ComponentResult with compatible status
        """
        logger.debug(f"Analyzing system-compatible component {component.name} on OS: {detected_os}")
        
        # Check if the detected OS is actually Graviton-compatible
        if detected_os and self.os_config_manager.is_os_graviton_compatible(detected_os):
            os_info = self.os_config_manager.get_os_info(detected_os)
            logger.debug(f"OS {detected_os} is Graviton-compatible. OS info: {os_info}")
            
            notes = f"System package from Graviton-compatible OS ({detected_os})"
            if os_info:
                lse_support = os_info.get("lse_support")
                if lse_support:
                    notes += f". LSE support: {lse_support}"
            
            os_analysis = f"OS analysis: graviton_compatible=True, detected_os={detected_os}, lse_support={os_info.get('lse_support') if os_info else 'unknown'}"
            notes += f". {os_analysis}"
            
            compatibility_result = CompatibilityResult(
                status=CompatibilityStatus.COMPATIBLE,
                current_version_supported=True,
                minimum_supported_version=None,
                recommended_version=None,
                notes=notes,
                confidence_level=0.95
            )
        else:
            # OS is not Graviton-compatible or unknown
            logger.debug(f"OS {detected_os} is not Graviton-compatible or unknown")
            
            notes = "System package from unknown or non-Graviton-compatible OS"
            if detected_os:
                notes += f" ({detected_os})"
                is_supported = detected_os in self.os_config_manager.get_supported_os_list()
                logger.debug(f"OS {detected_os} in supported list: {is_supported}")
            
            os_analysis = f"OS analysis: graviton_compatible=False, detected_os={detected_os}, in_supported_list={detected_os in self.os_config_manager.get_supported_os_list() if detected_os else False}"
            notes += f". {os_analysis}"
            
            compatibility_result = CompatibilityResult(
                status=CompatibilityStatus.UNKNOWN,
                current_version_supported=False,
                minimum_supported_version=None,
                recommended_version=None,
                notes=notes,
                confidence_level=0.3
            )
        
        return ComponentResult(
            component=component,
            compatibility=compatibility_result
        )
    
    def _handle_system_unknown_component(self, component: SoftwareComponent, detected_os: Optional[str]) -> ComponentResult:
        """
        Handle system-unknown components (OS packages from unknown/unsupported OS).
        
        Args:
            component: SoftwareComponent to analyze
            detected_os: Detected OS name
            
        Returns:
            ComponentResult with unknown status
        """
        logger.debug(f"Analyzing system-unknown component {component.name} on OS: {detected_os}")
        
        notes = "System package from unknown or unsupported OS"
        if detected_os:
            notes += f" ({detected_os})"
            is_supported = detected_os in self.os_config_manager.get_supported_os_list()
            logger.debug(f"OS {detected_os} in supported list: {is_supported}")
            
            if is_supported:
                notes += ". OS is supported but package compatibility unknown"
            else:
                notes += ". OS not in Graviton compatibility database"
        
        os_analysis = f"OS analysis: system_unknown=True, detected_os={detected_os}, in_supported_list={detected_os in self.os_config_manager.get_supported_os_list() if detected_os else False}"
        notes += f". {os_analysis}"
        
        compatibility_result = CompatibilityResult(
            status=CompatibilityStatus.UNKNOWN,
            current_version_supported=False,
            minimum_supported_version=None,
            recommended_version=None,
            notes=notes,
            confidence_level=0.3
        )
        
        return ComponentResult(
            component=component,
            compatibility=compatibility_result
        )
    
    def _extract_package_name(self, package_owner: str) -> str:
        """
        Extract base package name from package:owner value.
        
        Args:
            package_owner: Value from package:owner property (e.g., "amazon-ssm-agent-3.3.2299.0-1.amzn2023.aarch64")
            
        Returns:
            Base package name (e.g., "amazon-ssm-agent")
        """
        # Remove architecture suffix first
        base = package_owner.rsplit('.', 1)[0] if '.' in package_owner else package_owner
        
        # Split by '-' and find where version starts
        parts = base.split('-')
        package_parts = []
        
        for part in parts:
            # If part starts with a digit, it's likely a version
            if part and part[0].isdigit():
                break
            package_parts.append(part)
        
        return '-'.join(package_parts) if package_parts else parts[0]
    
    def _check_os_package_compatibility(self, package_name: str, detected_os: str) -> bool:
        """
        Check if package exists in OS-specific knowledge base.
        
        Args:
            package_name: Base package name to check
            detected_os: Detected OS name
            
        Returns:
            True if package is found and compatible in OS KB
        """
        try:
            # Check if package exists in knowledge base
            # For OS packages, use a default version if none provided
            logger.debug(f"Checking OS package {package_name} in knowledge base")
            compatibility_result = self.knowledge_base.get_compatibility(package_name, "0.0.1")
            logger.debug(f"OS package {package_name} KB result: {compatibility_result.status}")
            
            # If found and compatible, return True
            if compatibility_result.status == CompatibilityStatus.COMPATIBLE:
                return True
            
            # Disable intelligent matching for OS packages to improve performance
            # TODO: Re-enable with better performance optimizations if needed
            # potential_matches = self.knowledge_base.intelligent_match(package_name, self.matching_config)
            # if potential_matches:
            #     for match in potential_matches:
            #         match_result = self.knowledge_base.get_compatibility(match, "0.0.1")
            #         if match_result.status == CompatibilityStatus.COMPATIBLE:
            #             return True
            
            return False
        except Exception as e:
            logger.debug(f"Error checking OS package compatibility for '{package_name}': {e}")
            return False
    
    def _create_default_runtime_analyzers(self) -> Dict:
        """
        Create default runtime analyzers with knowledge base access.
        
        Returns:
            Dictionary of runtime analyzers by type
        """
        analyzers = {}
        
        # Java analyzer with knowledge base
        try:
            from .java_runtime_analyzer import JavaRuntimeCompatibilityAnalyzer
            analyzers['java'] = JavaRuntimeCompatibilityAnalyzer(knowledge_base=self.knowledge_base)
            logger.info("Java runtime analyzer initialized with knowledge base")
        except ImportError as e:
            logger.warning(f"Java runtime analyzer not available: {e}")
        
        # Python analyzer
        try:
            from .python_runtime_analyzer import PythonRuntimeAnalyzer
            analyzers['python'] = PythonRuntimeAnalyzer()
            logger.info("Python runtime analyzer initialized")
        except ImportError as e:
            logger.warning(f"Python runtime analyzer not available: {e}")
        
        # NodeJS analyzer
        try:
            from .nodejs_runtime_analyzer import NodeJSRuntimeAnalyzer
            analyzers['nodejs'] = NodeJSRuntimeAnalyzer()
            logger.info("NodeJS runtime analyzer initialized")
        except ImportError as e:
            logger.warning(f"NodeJS runtime analyzer not available: {e}")
        
        # .NET analyzer
        try:
            from .dotnet_runtime_analyzer import DotNetRuntimeAnalyzer
            analyzers['dotnet'] = DotNetRuntimeAnalyzer()
            logger.info(".NET runtime analyzer initialized")
        except ImportError as e:
            logger.warning(f".NET runtime analyzer not available: {e}")
        
        # Ruby analyzer
        try:
            from .ruby_runtime_analyzer import RubyRuntimeAnalyzer
            analyzers['ruby'] = RubyRuntimeAnalyzer()
            logger.info("Ruby runtime analyzer initialized")
        except ImportError as e:
            logger.warning(f"Ruby runtime analyzer not available: {e}")
        
        return analyzers


class DefaultRecommendationGenerator(RecommendationGenerator):
    """
    Default implementation of recommendation generator.
    """
    
    def __init__(self, knowledge_base: KnowledgeBase):
        """
        Initialize the recommendation generator.
        
        Args:
            knowledge_base: KnowledgeBase instance for compatibility lookups
        """
        self.knowledge_base = knowledge_base
    
    def generate_recommendations(self, component_result: ComponentResult) -> ComponentResult:
        """
        Generate upgrade recommendations for a component analysis result.
        
        Args:
            component_result: ComponentResult to generate recommendations for
            
        Returns:
            Updated ComponentResult with recommendations
        """
        compatibility = component_result.compatibility
        component = component_result.component
        
        # If already compatible, no recommendations needed
        if compatibility.status == CompatibilityStatus.COMPATIBLE:
            return component_result
        
        # If incompatible or needs upgrade, try to find upgrade path
        if compatibility.status in [CompatibilityStatus.INCOMPATIBLE, CompatibilityStatus.NEEDS_UPGRADE]:
            software_name = component_result.matched_name or component.name
            
            # Find compatible versions
            compatible_versions = self.knowledge_base.find_compatible_versions(software_name)
            
            if compatible_versions:
                # Update compatibility result with upgrade path information
                upgrade_notes = self._generate_upgrade_notes(
                    component, 
                    compatible_versions,
                    compatibility.minimum_supported_version,
                    compatibility.recommended_version
                )
                
                # Add upgrade path information to notes (prevent duplication)
                original_notes = compatibility.notes or ""
                if upgrade_notes and upgrade_notes not in original_notes:
                    compatibility.notes = f"{original_notes} {upgrade_notes}".strip()
            else:
                # No upgrade path available (prevent duplication)
                no_upgrade_note = "No compatible versions found in knowledge base"
                original_notes = compatibility.notes or ""
                if no_upgrade_note not in original_notes:
                    compatibility.notes = f"{original_notes} {no_upgrade_note}".strip()
        
        # For unknown status, provide general guidance with ISV analysis details
        elif compatibility.status == CompatibilityStatus.UNKNOWN:
            original_notes = compatibility.notes or ""
            
            # Prevent duplication by checking if recommendation text is already present
            unknown_note = "Compatibility unknown - consider testing with Graviton instances or checking with software vendor"
            isv_analysis = f"ISV analysis: kb_lookup=UNKNOWN, intelligent_matching={'used' if component_result.matched_name else 'not_used'}, matched_name={component_result.matched_name or 'none'}"
            
            # Only add recommendation text if not already present
            if "Compatibility unknown - consider testing" not in original_notes and "ISV analysis:" not in original_notes:
                compatibility.notes = f"{original_notes} {unknown_note}. {isv_analysis}".strip()
            # If only ISV analysis is missing, add just that
            elif "ISV analysis:" not in original_notes:
                compatibility.notes = f"{original_notes}. {isv_analysis}".strip()
            # If text is already complete, don't modify
        
        return component_result
    
    def _generate_upgrade_notes(self, 
                              component: SoftwareComponent, 
                              compatible_versions: List,
                              minimum_version: Optional[str],
                              recommended_version: Optional[str]) -> str:
        """
        Generate upgrade recommendation notes.
        
        Args:
            component: The software component
            compatible_versions: List of compatible version information
            minimum_version: Minimum supported version
            recommended_version: Recommended version
            
        Returns:
            String with upgrade recommendations
        """
        notes = []
        
        if minimum_version:
            if component.version:
                notes.append(f"Upgrade from v{component.version} to at least v{minimum_version}")
            else:
                notes.append(f"Ensure version is at least v{minimum_version}")
        
        if recommended_version and recommended_version != minimum_version:
            notes.append(f"Recommended version: v{recommended_version}")
        
        if compatible_versions:
            version_count = len(compatible_versions)
            notes.append(f"{version_count} compatible version range(s) available")
        
        return ". ".join(notes) + "." if notes else ""


def create_analyzer(knowledge_base: KnowledgeBase, 
                   recommendation_generator: Optional[RecommendationGenerator] = None,
                   matching_config=None,
                   deny_list_loader: Optional[DenyListLoader] = None,
                   analysis_cache=None) -> CompatibilityAnalyzer:
    """
    Factory function to create a compatibility analyzer with OS-aware capabilities.
    
    Args:
        knowledge_base: KnowledgeBase instance
        recommendation_generator: Optional custom RecommendationGenerator
        matching_config: Optional matching configuration for intelligent matching
        analysis_cache: Optional AnalysisCache for cross-SBOM result caching
        
    Returns:
        CompatibilityAnalyzer instance with OS detection capabilities
    """
    # Initialize OS-aware components
    os_config_manager = OSConfigManager()
    os_detector = os_config_manager  # OSDetector is now just a re-export of OSConfigManager
    component_filter = ComponentFilter(os_config_manager=os_config_manager)
    
    return GravitonCompatibilityAnalyzer(
        knowledge_base=knowledge_base, 
        recommendation_generator=recommendation_generator, 
        matching_config=matching_config,
        os_detector=os_detector,
        os_config_manager=os_config_manager,
        component_filter=component_filter,
        deny_list_loader=deny_list_loader,
        analysis_cache=analysis_cache
    )