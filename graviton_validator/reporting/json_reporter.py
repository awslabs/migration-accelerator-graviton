"""
JSON report generator for Graviton compatibility analysis results.
"""

import json
from datetime import datetime
from typing import Dict, List, Optional, Any

from .base import ReportGenerator
from ..models import AnalysisResult, ComponentResult, CompatibilityStatus


class JSONReporter(ReportGenerator):
    """
    JSON report generator that serves as the foundation for all other report formats.
    Generates structured JSON output with compatibility analysis results.
    """
    
    def __init__(self, include_metadata: bool = True, pretty_print: bool = True):
        """
        Initialize JSON reporter.
        
        Args:
            include_metadata: Whether to include metadata like timestamps
            pretty_print: Whether to format JSON with indentation
        """
        self.include_metadata = include_metadata
        self.pretty_print = pretty_print
        self._os_config = None  # Lazy-loaded OS config manager
    
    def generate_report(self, analysis_result: AnalysisResult, output_path: Optional[str] = None) -> str:
        """
        Generate JSON report from analysis results.
        
        Args:
            analysis_result: AnalysisResult to generate report from
            output_path: Optional path to write report to file
            
        Returns:
            JSON report content as string
        """
        report_data = self._build_report_structure(analysis_result)
        
        # Convert to JSON string
        if self.pretty_print:
            json_content = json.dumps(report_data, indent=2, ensure_ascii=False)
        else:
            json_content = json.dumps(report_data, ensure_ascii=False)
        
        # Write to file if path provided
        if output_path:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(json_content)
        
        return json_content
    
    def get_format_name(self) -> str:
        """Get the name of the report format."""
        return "json"
    
    def _build_report_structure(self, analysis_result: AnalysisResult) -> Dict[str, Any]:
        """
        Build the complete report data structure.
        
        Args:
            analysis_result: Analysis results to structure
            
        Returns:
            Dictionary containing structured report data
        """
        report = {
            "summary": self._build_summary(analysis_result),
            "components": self._build_components_list(analysis_result.components),
            "statistics": self._build_statistics(analysis_result),
            "errors": analysis_result.errors
        }
        
        if self.include_metadata:
            report["metadata"] = self._build_metadata(analysis_result)
        
        return report
    
    def _build_summary(self, analysis_result: AnalysisResult) -> Dict[str, Any]:
        """Build summary section of the report with OS-aware information."""
        total = analysis_result.total_components
        compatible = analysis_result.compatible_count
        incompatible = analysis_result.incompatible_count
        unknown = analysis_result.unknown_count
        
        # Calculate needs_verification, needs_version_verification and needs_upgrade counts from components
        needs_verification = sum(1 for comp in analysis_result.components 
                               if self._get_status_value(comp.compatibility.status) == "needs_verification")
        needs_version_verification = sum(1 for comp in analysis_result.components 
                                       if self._get_status_value(comp.compatibility.status) == "needs_version_verification")
        needs_upgrade = sum(1 for comp in analysis_result.components 
                          if self._get_status_value(comp.compatibility.status) == "needs_upgrade")
        
        summary = {
            "total_components": total,
            "compatible": compatible,
            "incompatible": incompatible,
            "needs_upgrade": needs_upgrade,
            "needs_verification": needs_verification,
            "needs_version_verification": needs_version_verification,
            "unknown": unknown,
            "compatibility_rate": round((compatible / total * 100) if total > 0 else 0, 2),
            "has_issues": incompatible > 0 or unknown > 0 or needs_verification > 0 or needs_version_verification > 0,
            "processing_time_seconds": round(analysis_result.processing_time, 3)
        }
        
        # Add OS-aware summary
        os_summary = self._build_os_summary(analysis_result)
        if os_summary:
            summary["os_summary"] = os_summary
        
        return summary
    
    def _build_components_list(self, components: List[ComponentResult]) -> List[Dict[str, Any]]:
        """Build components section of the report."""
        components_data = []
        
        for comp_result in components:
            component_type = comp_result.component.component_type
            
            component_data = {
                "name": comp_result.component.name,
                "version": comp_result.component.version,
                "type": component_type,
                "source_sbom": comp_result.component.source_sbom,
                "compatibility": {
                    "status": self._get_status_value(comp_result.compatibility.status),
                    "current_version_supported": comp_result.compatibility.current_version_supported,
                    "minimum_supported_version": comp_result.compatibility.minimum_supported_version,
                    "recommended_version": comp_result.compatibility.recommended_version,
                    "notes": comp_result.compatibility.notes,
                    "confidence_level": comp_result.compatibility.confidence_level
                }
            }
            
            # Add matched name if intelligent matching was used
            if comp_result.matched_name and comp_result.matched_name != comp_result.component.name:
                component_data["matched_name"] = comp_result.matched_name
            
            # Add component properties if they exist
            if comp_result.component.properties:
                component_data["properties"] = comp_result.component.properties
            
            components_data.append(component_data)
        
        return components_data
    
    def _build_statistics(self, analysis_result: AnalysisResult) -> Dict[str, Any]:
        """Build statistics section of the report."""
        components = analysis_result.components
        
        # Group by status
        status_breakdown = {
            "compatible": [],
            "incompatible": [],
            "needs_upgrade": [],
            "needs_verification": [],
            "needs_version_verification": [],
            "unknown": []
        }
        
        # Group by source SBOM
        sbom_breakdown = {}
        
        # Track upgrade recommendations
        upgrade_available = 0
        no_upgrade_path = 0
        
        for comp_result in components:
            status = self._get_status_value(comp_result.compatibility.status)
            # Ensure status exists in breakdown dictionary
            if status not in status_breakdown:
                status_breakdown[status] = []
            status_breakdown[status].append(comp_result.component.name)
            
            # Track SBOM sources with OS info
            sbom = comp_result.component.source_sbom
            if sbom not in sbom_breakdown:
                sbom_breakdown[sbom] = {"compatible": 0, "incompatible": 0, "needs_upgrade": 0, "needs_verification": 0, "needs_version_verification": 0, "unknown": 0, "detected_os": "N/A"}
            # Ensure status exists in SBOM breakdown
            if status not in sbom_breakdown[sbom]:
                sbom_breakdown[sbom][status] = 0
            sbom_breakdown[sbom][status] += 1
            
            # Set detected OS for this SBOM from component properties or analysis result
            if sbom_breakdown[sbom]["detected_os"] == "N/A":
                # Try to get OS from component properties first
                comp_os = comp_result.component.properties.get("sbom_detected_os") if comp_result.component.properties else None
                if comp_os:
                    sbom_breakdown[sbom]["detected_os"] = comp_os
                elif analysis_result.detected_os:
                    sbom_breakdown[sbom]["detected_os"] = analysis_result.detected_os
            
            # Set OS support status if not already set
            if "os_support_status" not in sbom_breakdown[sbom]:
                detected_os = sbom_breakdown[sbom]["detected_os"]
                if detected_os != "N/A":
                    # Check OS compatibility using OS config manager
                    try:
                        # Use lazy-loaded OS config manager to avoid repeated instantiation
                        if self._os_config is None:
                            from ..os_detection import OSConfigManager
                            self._os_config = OSConfigManager()
                        
                        # Handle OS names with versions (e.g., ubuntu-20.04)
                        if '-' in detected_os and not detected_os.startswith('amazon-linux'):
                            base_os, version = detected_os.split('-', 1)
                            is_supported = self._os_config.is_os_graviton_compatible(base_os, version)
                        else:
                            is_supported = self._os_config.is_os_graviton_compatible(detected_os)
                        
                        sbom_breakdown[sbom]["os_support_status"] = "Supported" if is_supported else "Not Supported"
                    except Exception:
                        sbom_breakdown[sbom]["os_support_status"] = "Unknown"
                else:
                    sbom_breakdown[sbom]["os_support_status"] = "Unknown"
            
            # Track upgrade paths
            if status in ["incompatible", "needs_upgrade", "needs_verification", "needs_version_verification"]:
                if comp_result.compatibility.recommended_version:
                    upgrade_available += 1
                else:
                    no_upgrade_path += 1
        
        return {
            "status_breakdown": {
                status: {
                    "count": len(components_list),
                    "components": components_list
                } for status, components_list in status_breakdown.items() if components_list
            },
            "sbom_breakdown": sbom_breakdown,
            "upgrade_recommendations": {
                "upgrade_available": upgrade_available,
                "no_upgrade_path": no_upgrade_path
            }
        }
    
    def _build_metadata(self, analysis_result: AnalysisResult) -> Dict[str, Any]:
        """Build metadata section of the report."""
        metadata = {
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "generator": "Graviton Compatibility Validator",
            "version": self._get_tool_version(),
            "report_format": self.get_format_name()
        }
        
        # Add OS and SBOM file info if available
        if analysis_result.detected_os:
            metadata["detected_os"] = analysis_result.detected_os
        if analysis_result.sbom_file:
            metadata["sbom_file"] = analysis_result.sbom_file
            
        return metadata
    
    def _get_status_value(self, status) -> str:
        """Safely get status value, handling both enum and string types.
        
        Args:
            status: CompatibilityStatus enum or string
            
        Returns:
            Status value as string
        """
        try:
            if hasattr(status, 'value'):
                return status.value
            elif isinstance(status, str):
                return status
            else:
                # Log the issue for debugging
                import logging
                logger = logging.getLogger(__name__)
                logger.error(f"Unexpected status type: {type(status)}, value: {status}")
                return str(status)
        except Exception as e:
            import logging
            logger = logging.getLogger(__name__)
            logger.error(f"Error getting status value: {e}, status type: {type(status)}, status: {status}")
            return "unknown"
    
    def _get_tool_version(self) -> str:
        """Get the tool version from the centralized version module."""
        try:
            from ..version import get_version
            return get_version()
        except ImportError:
            return "0.0.1"  # Fallback version
    
    def get_structured_data(self, analysis_result: AnalysisResult) -> Dict[str, Any]:
        """
        Get structured data without converting to JSON string.
        Used by other reporters that need the data structure.
        
        Args:
            analysis_result: Analysis results to structure
            
        Returns:
            Dictionary containing structured report data
        """
        return self._build_report_structure(analysis_result)
    
    def _build_os_summary(self, analysis_result: AnalysisResult) -> Optional[Dict[str, Any]]:
        """Build OS-aware summary from component properties."""
        components = analysis_result.components
        if not components:
            return None
        
        # Extract OS information from component properties
        detected_os = None
        system_packages = 0
        application_packages = 0
        os_compatible = False
        
        for comp_result in components:
            props = comp_result.component.properties or {}
            
            # Get detected OS (use first one found)
            if not detected_os and "detected_os" in props:
                detected_os = props["detected_os"]
            
            # Count system vs application packages
            if props.get("os_system_package") == "true":
                system_packages += 1
            else:
                application_packages += 1
            
            # Check OS compatibility
            if props.get("os_graviton_compatible") == "true":
                os_compatible = True
        
        if not detected_os:
            return None
        
        return {
            "detected_os": detected_os,
            "system_packages": system_packages,
            "application_packages": application_packages,
            "os_compatible": os_compatible,
            "system_package_percentage": round((system_packages / len(components) * 100) if components else 0, 1)
        }