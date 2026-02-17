"""
Container image ARM64 architecture checker.

Queries Docker Registry HTTP API v2 to check if container images
have ARM64/aarch64 manifests available. No external dependencies
beyond requests (already used by the tool).
"""

import logging
import re
from typing import Dict, List, Optional

import requests

logger = logging.getLogger(__name__)

# Cache for image arch lookups within a single run
_arch_cache: Dict[str, Dict] = {}


def _parse_image_ref(image: str) -> tuple:
    """Parse image reference into (registry, repository, tag)."""
    tag = "latest"
    if ":" in image and not image.rsplit(":", 1)[-1].startswith("/"):
        image, tag = image.rsplit(":", 1)

    # Default to Docker Hub
    if "/" not in image:
        return "registry-1.docker.io", f"library/{image}", tag
    parts = image.split("/", 1)
    if "." in parts[0] or ":" in parts[0]:
        return parts[0], parts[1], tag
    return "registry-1.docker.io", image, tag


def _get_docker_hub_token(repository: str) -> Optional[str]:
    """Get anonymous auth token for Docker Hub."""
    try:
        resp = requests.get(
            "https://auth.docker.io/token",
            params={"service": "registry.docker.io", "scope": f"repository:{repository}:pull"},
            timeout=10,
        )
        if resp.ok:
            return resp.json().get("token")
    except Exception as e:
        logger.debug(f"Failed to get Docker Hub token: {e}")
    return None


def check_image_arm64(image: str) -> Dict:
    """
    Check if a container image has ARM64 architecture support.
    
    Returns dict with:
        image: original image reference
        arm64: True/False/None (None if check failed)
        architectures: list of available architectures
        error: error message if check failed
    """
    if image in _arch_cache:
        return _arch_cache[image]

    registry, repository, tag = _parse_image_ref(image)
    result = {"image": image, "arm64": None, "architectures": [], "error": None}

    try:
        # Get auth token (Docker Hub)
        headers = {
            "Accept": "application/vnd.oci.image.index.v1+json, "
                      "application/vnd.docker.distribution.manifest.list.v2+json"
        }
        if "docker.io" in registry:
            token = _get_docker_hub_token(repository)
            if token:
                headers["Authorization"] = f"Bearer {token}"
            url = f"https://registry-1.docker.io/v2/{repository}/manifests/{tag}"
        else:
            url = f"https://{registry}/v2/{repository}/manifests/{tag}"

        resp = requests.get(url, headers=headers, timeout=15)

        if not resp.ok:
            result["error"] = f"Registry returned {resp.status_code}"
            _arch_cache[image] = result
            return result

        data = resp.json()
        media_type = data.get("mediaType", "")

        # Manifest list / OCI index
        if "manifest.list" in media_type or "image.index" in media_type:
            archs = []
            for manifest in data.get("manifests", []):
                platform = manifest.get("platform", {})
                arch = platform.get("architecture", "")
                if arch:
                    archs.append(arch)
            result["architectures"] = sorted(set(archs))
            result["arm64"] = "arm64" in archs or "aarch64" in archs
        else:
            # Single-arch manifest - check config
            result["error"] = "Single-arch manifest, cannot determine multi-arch support"
            result["arm64"] = None

    except Exception as e:
        result["error"] = str(e)
        logger.debug(f"Failed to check image {image}: {e}")

    _arch_cache[image] = result
    return result


def check_container_components(components: list) -> List[Dict]:
    """
    Check ARM64 support for all container-type components in a component list.
    
    Args:
        components: list of ComponentResult objects
        
    Returns:
        List of check results for container images
    """
    results = []
    seen_images = set()

    for cr in components:
        if cr.component.component_type not in ("container", "container-image"):
            continue
        props = cr.component.properties or {}
        for key in ("container:image", "container:base-image"):
            image = props.get(key, "")
            if image and image != "unknown" and image not in seen_images:
                seen_images.add(image)
                logger.info(f"Checking ARM64 support for container image: {image}")
                result = check_image_arm64(image)
                result["source"] = key
                results.append(result)

                # Update component notes
                if result["arm64"] is True:
                    note = f"Container image '{image}' supports ARM64"
                elif result["arm64"] is False:
                    note = f"Container image '{image}' does NOT support ARM64 (available: {', '.join(result['architectures'])})"
                else:
                    note = f"Could not verify ARM64 support for '{image}': {result.get('error', 'unknown error')}"

                existing = cr.compatibility.notes or ""
                cr.compatibility.notes = f"{existing}. {note}".strip(". ")

    if results:
        arm64_ok = sum(1 for r in results if r["arm64"] is True)
        arm64_no = sum(1 for r in results if r["arm64"] is False)
        logger.info(f"Container image check: {arm64_ok} support ARM64, {arm64_no} do not, "
                    f"{len(results) - arm64_ok - arm64_no} unknown")

    return results
