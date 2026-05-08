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

# Module-level cache for ARM MCP results across multiple SBOMs in a single run
_arm_mcp_cache: Dict[str, Optional[Dict]] = {}

# Singleton MCP client - started once, reused across all SBOMs
_mcp_client: Optional[ArmMcpClient] = None
_mcp_init_attempted: bool = False


def _get_mcp_client() -> Optional[ArmMcpClient]:
    """Get or create singleton MCP client."""
    global _mcp_client, _mcp_init_attempted
    if _mcp_init_attempted:
        return _mcp_client
    _mcp_init_attempted = True
    client = ArmMcpClient()
    if client.connect():
        _mcp_client = client
    return _mcp_client


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

    # Get singleton MCP client (starts container only on first call)
    client = _get_mcp_client()
    if not client:
        logger.warning("Skipping ARM ecosystem enrichment - no container runtime available")
        return analysis_result

    try:
        enriched_count = 0
        cache_hits = 0
        for name, component_results in candidates.items():
            # Check cache first
            if name in _arm_mcp_cache:
                cache_hits += 1
                cached = _arm_mcp_cache[name]
                if cached is None:
                    continue
                status_text, min_version, rec_version, arm_note = cached["status"], cached["min_ver"], cached["rec_ver"], cached["note"]
            else:
                query = f"{name} arm64 aarch64"
                results = client.knowledge_base_search(query)

                if not results:
                    _arm_mcp_cache[name] = None
                    continue

                # Find best relevant result
                best = None
                for r in results:
                    dist = r.get("distance", 1.0)
                    if dist is None:
                        dist = 1.0
                    if dist < RELEVANCE_THRESHOLD:
                        if best is None or dist < (best.get("distance") or 1.0):
                            best = r

                if not best:
                    _arm_mcp_cache[name] = None
                    continue

                snippet = best.get("snippet", "")
                url = best.get("url", "")
                status_text, min_version, rec_version = _parse_arm_snippet(snippet)

                if not status_text:
                    _arm_mcp_cache[name] = None
                    continue

                arm_note = f"ARM Ecosystem Dashboard: {snippet[:150].strip()}"
                if url:
                    arm_note += f" (source: {url})"

                _arm_mcp_cache[name] = {"status": status_text, "min_ver": min_version, "rec_ver": rec_version, "note": arm_note}

            # Update all component results with this name
            for cr in component_results:
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

        if cache_hits:
            logger.info(f"ARM ecosystem cache: {cache_hits} hits, {len(candidates) - cache_hits} queries")

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
        pass  # Singleton client stays alive for reuse across SBOMs

    return analysis_result
