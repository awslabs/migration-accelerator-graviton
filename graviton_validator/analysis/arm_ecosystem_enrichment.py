"""
ARM Ecosystem Enrichment module.

Queries the ARM MCP server's knowledge base to enrich components that have
Unknown or Needs Verification status after the primary analysis.
Only targets OS/system-level packages (not language-level dependencies which
are handled by runtime testing).
"""

import logging
import re
from typing import Dict, List, Optional, Tuple

from graviton_validator.models import (
    AnalysisResult, CompatibilityResult, CompatibilityStatus, ComponentResult
)
from graviton_validator.analysis.arm_mcp_client import ArmMcpClient

logger = logging.getLogger(__name__)

# Distance threshold for considering a knowledge base result relevant
RELEVANCE_THRESHOLD = 0.85

# Component types that are language-level dependencies (skip these)
LANGUAGE_PACKAGE_TYPES = {"pip", "npm", "maven", "gem", "nuget", "pypi", "golang"}


def _is_language_package(result: ComponentResult) -> bool:
    """Check if a component is a language-level dependency (handled by runtime testing)."""
    props = result.component.properties or {}
    pkg_type = props.get("package:type", "").lower()
    if pkg_type in LANGUAGE_PACKAGE_TYPES:
        return True
    # Also check component_type field
    comp_type = (result.component.component_type or "").lower()
    if comp_type in LANGUAGE_PACKAGE_TYPES:
        return True
    return False


def _parse_arm_snippet(snippet: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """
    Parse an Arm Ecosystem Dashboard snippet to extract compatibility info.
    
    Returns: (status_text, min_version, recommended_version)
    """
    if not snippet:
        return None, None, None

    status_text = None
    min_version = None
    recommended_version = None

    # Check for "works on Arm" pattern
    if "works on Arm" in snippet.lower() or "works on arm linux" in snippet.lower():
        status_text = "compatible"

    # Extract "starting from version X.Y.Z"
    m = re.search(r'starting from version\s+([\d][\w.\-]+)', snippet, re.IGNORECASE)
    if m:
        min_version = m.group(1)

    # Extract "recommends version X.Y.Z and above"
    m = re.search(r'recommends?\s+version\s+([\d][\w.\-]+)\s+and above', snippet, re.IGNORECASE)
    if m:
        recommended_version = m.group(1)

    # "from <month> <year>" without version
    if not min_version:
        m = re.search(r'from\s+\w+\s+\d{4}', snippet, re.IGNORECASE)
        if m and status_text == "compatible":
            pass  # Compatible but no specific version

    return status_text, min_version, recommended_version


def enrich_with_arm_ecosystem(analysis_result: AnalysisResult) -> AnalysisResult:
    """
    Enrich analysis results by querying the ARM MCP server for components
    with Unknown or Needs Verification status.
    
    Modifies the analysis_result in place and returns it.
    Skips language-level packages (handled by runtime testing).
    Gracefully skips if no container runtime is available.
    """
    # Collect unique components that need enrichment
    candidates: Dict[str, List[ComponentResult]] = {}
    for cr in analysis_result.components:
        if cr.compatibility.status not in (CompatibilityStatus.UNKNOWN, CompatibilityStatus.NEEDS_VERIFICATION):
            continue
        if _is_language_package(cr):
            continue
        if cr.component.component_type in ("container", "container-image"):
            continue
        name = cr.component.name.lower()
        if name not in candidates:
            candidates[name] = []
        candidates[name].append(cr)

    if not candidates:
        logger.info("No components need ARM ecosystem enrichment")
        return analysis_result

    logger.info(f"ARM ecosystem enrichment: {len(candidates)} unique components to check")

    # Connect to ARM MCP server
    client = ArmMcpClient()
    if not client.connect():
        logger.warning("Skipping ARM ecosystem enrichment - no container runtime available")
        return analysis_result

    try:
        enriched_count = 0
        for name, component_results in candidates.items():
            query = f"{name} arm64 aarch64"
            results = client.knowledge_base_search(query)

            if not results:
                continue

            # Find best relevant result
            best = None
            for r in results:
                dist = r.get("distance", 1.0)
                if dist < RELEVANCE_THRESHOLD:
                    if best is None or dist < best.get("distance", 1.0):
                        best = r

            if not best:
                continue

            snippet = best.get("snippet", "")
            title = best.get("title", "")
            url = best.get("url", "")
            status_text, min_version, rec_version = _parse_arm_snippet(snippet)

            if not status_text:
                continue

            # Update all component results with this name
            for cr in component_results:
                arm_note = f"ARM Ecosystem Dashboard: {snippet[:150].strip()}"
                if url:
                    arm_note += f" (source: {url})"

                existing_notes = cr.compatibility.notes or ""
                cr.compatibility.notes = f"{existing_notes}. {arm_note}".strip(". ")

                if status_text == "compatible":
                    cr.compatibility.status = CompatibilityStatus.COMPATIBLE
                    cr.compatibility.current_version_supported = True
                    if min_version:
                        cr.compatibility.minimum_supported_version = min_version
                    if rec_version:
                        cr.compatibility.recommended_version = rec_version

                enriched_count += 1

        # Recount statistics
        if enriched_count > 0:
            analysis_result.compatible_count = sum(
                1 for r in analysis_result.components
                if r.compatibility.status == CompatibilityStatus.COMPATIBLE)
            analysis_result.unknown_count = sum(
                1 for r in analysis_result.components
                if r.compatibility.status == CompatibilityStatus.UNKNOWN)
            analysis_result.needs_verification_count = sum(
                1 for r in analysis_result.components
                if r.compatibility.status == CompatibilityStatus.NEEDS_VERIFICATION)

        logger.info(f"ARM ecosystem enrichment complete: {enriched_count} components updated")

    finally:
        client.close()

    return analysis_result
