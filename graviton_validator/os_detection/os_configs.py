"""
OS Configuration Manager for loading and accessing OS compatibility data.
"""

import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)


class OSConfigManager:
    """Manages OS compatibility configuration data."""
    
    # Class-level cache to prevent repeated loading
    _cached_data = {}
    _cached_paths = set()
    
    def __init__(self, config_path: Optional[str] = None):
        """Initialize with optional custom config path."""
        self.config_path = config_path or self._get_default_config_path()
        self._os_data = None
        self._load_config()
    
    def _get_default_config_path(self) -> str:
        """Get default path to OS compatibility JSON file."""
        current_dir = Path(__file__).parent.parent.parent
        return str(current_dir / "schemas" / "graviton_os_compatibility.json")
    
    def _load_config(self) -> None:
        """Load OS compatibility data from JSON file with caching."""
        # Check if data is already cached for this path
        if self.config_path in self._cached_data:
            self._os_data = self._cached_data[self.config_path]
            return
        
        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                self._os_data = json.load(f)
            
            # Cache the loaded data
            self._cached_data[self.config_path] = self._os_data
            
            # Only log once per path
            if self.config_path not in self._cached_paths:
                logger.debug(f"Loaded OS compatibility data from {self.config_path}")
                self._cached_paths.add(self.config_path)
                
        except FileNotFoundError:
            logger.error(f"OS compatibility file not found: {self.config_path}")
            self._os_data = {"supported_operating_systems": {}, "detection_rules": {}}
            self._cached_data[self.config_path] = self._os_data
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in OS compatibility file: {e}")
            self._os_data = {"supported_operating_systems": {}, "detection_rules": {}}
            self._cached_data[self.config_path] = self._os_data
    
    def get_supported_os_list(self) -> List[str]:
        """Return list of all supported OS names."""
        return list(self._os_data.get("supported_operating_systems", {}).keys())
    
    def is_os_graviton_compatible(self, os_name: str, version: Optional[str] = None) -> bool:
        """Check if OS and version are Graviton compatible."""
        os_info = self._find_os_entry(os_name)
        if not os_info:
            return False
        
        if not os_info.get("graviton_compatible", False):
            return False
        
        if version and os_info.get("supported_versions"):
            # Simple version check - can be enhanced for complex version ranges
            supported_versions = os_info["supported_versions"]
            if "all" in supported_versions:
                return True
            # Basic version matching - can be enhanced
            for supported_version in supported_versions:
                if supported_version.startswith(">="):
                    min_version = supported_version.replace(">=", "")
                    if version >= min_version:  # Simple string comparison
                        return True
                elif version == supported_version or version.startswith(supported_version):
                    return True
            return False
        
        return True
    
    def get_detection_patterns(self, os_name: str) -> Dict[str, List[str]]:
        """Get detection patterns for specific OS."""
        os_info = self._os_data.get("supported_operating_systems", {}).get(os_name, {})
        return {
            "package_patterns": os_info.get("package_patterns", []),
            "vendor_names": os_info.get("vendor_names", []),
            "purl_distros": os_info.get("purl_distros", [])
        }
    
    def get_all_detection_rules(self) -> Dict[str, Any]:
        """Get all detection rules from the configuration."""
        return self._os_data.get("detection_rules", {})
    
    def _find_os_entry(self, os_name: str) -> Optional[Dict[str, Any]]:
        """Find OS entry by exact match or longest prefix match."""
        supported_os = self._os_data.get("supported_operating_systems", {})
        entry = supported_os.get(os_name)
        if not entry:
            for key in sorted(supported_os.keys(), key=len, reverse=True):
                if os_name.startswith(key):
                    return supported_os[key]
        return entry

    def get_os_info(self, os_name: str) -> Optional[Dict[str, Any]]:
        """Get complete OS information."""
        return self._find_os_entry(os_name)
    
    def reload_config(self) -> None:
        """Reload configuration from file, clearing cache."""
        # Clear cache for this path to force reload
        if self.config_path in self._cached_data:
            del self._cached_data[self.config_path]
        if self.config_path in self._cached_paths:
            self._cached_paths.remove(self.config_path)
        self._load_config()
    
    @classmethod
    def clear_cache(cls) -> None:
        """Clear all cached OS configuration data."""
        cls._cached_data.clear()
        cls._cached_paths.clear()
    
    def detect_os_from_sbom_data(self, sbom_data: Dict[str, Any]) -> Optional[str]:
        """Detect OS from SBOM data using format-specific methods."""
        # For Syft SBOMs, check distro field first (most reliable)
        if "distro" in sbom_data:
            detected = self._detect_os_from_syft_distro(sbom_data["distro"])
            if detected:
                return detected
        
        # For CycloneDX SBOMs, check for operating-system components
        if "bomFormat" in sbom_data and "CycloneDX" in str(sbom_data.get("bomFormat", "")):
            detected = self._detect_os_from_cyclonedx(sbom_data)
            if detected:
                return detected
        
        # Generic metadata-based detection
        return self._detect_os_from_metadata(sbom_data)
    
    def detect_os_from_components(self, components: List[Dict[str, Any]]) -> Optional[str]:
        """Detect OS from component patterns."""
        os_votes = {}
        
        for component in components[:100]:  # Sample first 100 components for performance
            detected_os = self._detect_os_from_component(component)
            if detected_os:
                os_votes[detected_os] = os_votes.get(detected_os, 0) + 1
        
        # Return OS with most votes
        if os_votes:
            return max(os_votes, key=os_votes.get)
        
        return None
    
    def detect_os_from_purl(self, purl_string: str) -> Optional[str]:
        """Extract OS from Package URL (PURL)."""
        try:
            if not purl_string.startswith("pkg:"):
                return None
            
            # Extract qualifiers which often contain distro info
            parts = purl_string.split("?")
            if len(parts) > 1:
                qualifiers = parts[1].split("#")[0]
                
                for qualifier in qualifiers.split("&"):
                    if "=" in qualifier:
                        key, value = qualifier.split("=", 1)
                        if key == "distro":
                            return self._map_purl_distro_to_os(value)
            
            # Check the type part for OS hints
            purl_type = purl_string.split("/")[0].replace("pkg:", "")
            return self._map_purl_type_to_os(purl_type)
            
        except Exception:
            return None
    
    def _detect_os_from_metadata(self, sbom_data: Dict[str, Any]) -> Optional[str]:
        """Generic metadata-based OS detection."""
        metadata = sbom_data.get("metadata", {})
        os_candidates = []
        
        # Check document name/title
        for field in ["name", "title"]:
            text = metadata.get(field, "")
            if text:
                detected = self._detect_os_from_text(text)
                if detected:
                    os_candidates.append(detected)
        
        # Check tools for OS hints
        tools = metadata.get("tools", [])
        for tool in tools:
            if isinstance(tool, dict):
                tool_name = tool.get("name", "")
                detected = self._detect_os_from_text(tool_name)
                if detected:
                    os_candidates.append(detected)
        
        return self._get_best_os_candidate(os_candidates)
    
    def _detect_os_from_syft_distro(self, distro: Dict[str, Any]) -> Optional[str]:
        """Detect OS from Syft distro field."""
        if not isinstance(distro, dict):
            return None
        
        distro_id = distro.get("id", "").lower()
        version = distro.get("version", "") or distro.get("versionID", "")
        
        if distro_id == "amzn":
            if version == "2023":
                return "amazon-linux-2023"
            elif version == "2":
                return "amazon-linux-2"
            else:
                # Default to amazon-linux-2023 for unknown versions (current default)
                return "amazon-linux-2023"
        elif distro_id == "ubuntu":
            return f"ubuntu-{version}" if version else "ubuntu"
        elif distro_id in ["rhel", "redhat"]:
            return f"rhel-{version}" if version else "rhel"
        elif distro_id == "centos":
            return f"centos-{version}" if version else "centos"
        elif distro_id == "debian":
            return f"debian-{version}" if version else "debian"
        elif distro_id == "alpine":
            return f"alpine-{version}" if version else "alpine"
        
        # Fallback to pretty name
        pretty_name = distro.get("prettyName", "")
        if pretty_name:
            return self._detect_os_from_text(pretty_name)
        
        return None
    
    def _detect_os_from_cyclonedx(self, sbom_data: Dict[str, Any]) -> Optional[str]:
        """Detect OS from CycloneDX operating-system components."""
        metadata = sbom_data.get("metadata", {})
        
        # Check metadata.component
        component = metadata.get("component", {})
        if component.get("type") == "operating-system":
            detected = self._extract_os_from_cyclonedx_component(component)
            if detected:
                return detected
        
        # Check metadata.system.os
        system = metadata.get("system", {})
        os_info = system.get("os", {})
        if os_info:
            name = os_info.get("name", "").lower()
            version = os_info.get("version", "")
            
            if "ubuntu" in name:
                return f"ubuntu-{version}" if version else "ubuntu"
            elif "amazon" in name:
                if version == "2023":
                    return "amazon-linux-2023"
                elif version == "2":
                    return "amazon-linux-2"
                else:
                    # Default to amazon-linux-2023 for unknown versions
                    return "amazon-linux-2023"
            elif "rhel" in name or "red hat" in name:
                return f"rhel-{version}" if version else "rhel"
        
        # Check main components array
        components = sbom_data.get("components", [])
        for component in components:
            if component.get("type") == "operating-system":
                detected = self._extract_os_from_cyclonedx_component(component)
                if detected:
                    return detected
        
        return None
    
    def _extract_os_from_cyclonedx_component(self, component: Dict[str, Any]) -> Optional[str]:
        """Extract OS info from CycloneDX operating-system component."""
        name = component.get("name", "").lower()
        version = component.get("version", "")
        
        # Check syft distro properties
        properties = component.get("properties", [])
        distro_id = None
        version_id = None
        
        for prop in properties:
            if isinstance(prop, dict):
                prop_name = prop.get("name", "")
                if prop_name == "syft:distro:id":
                    distro_id = prop.get("value", "")
                elif prop_name == "syft:distro:versionID":
                    version_id = prop.get("value", "")
        
        # Use distro properties if available
        if distro_id:
            if distro_id == "amzn":
                if version_id == "2023":
                    return "amazon-linux-2023"
                elif version_id == "2":
                    return "amazon-linux-2"
                else:
                    # Default to amazon-linux-2023 for unknown versions
                    return "amazon-linux-2023"
            elif distro_id == "ubuntu":
                return f"ubuntu-{version_id}" if version_id else "ubuntu"
            elif distro_id in ["rhel", "redhat"]:
                return f"rhel-{version_id}" if version_id else "rhel"
            elif distro_id == "centos":
                return f"centos-{version_id}" if version_id else "centos"
            elif distro_id == "debian":
                return f"debian-{version_id}" if version_id else "debian"
            elif distro_id == "alpine":
                return f"alpine-{version_id}" if version_id else "alpine"
        
        # Fallback to name analysis
        if "ubuntu" in name:
            return f"ubuntu-{version}" if version else "ubuntu"
        elif "amazon" in name or "amzn" in name:
            if version == "2023":
                return "amazon-linux-2023"
            elif version == "2":
                return "amazon-linux-2"
            else:
                # Default to amazon-linux-2023 for unknown versions
                return "amazon-linux-2023"
        elif "rhel" in name or "red hat" in name:
            return f"rhel-{version}" if version else "rhel"
        elif "centos" in name:
            return f"centos-{version}" if version else "centos"
        elif "debian" in name:
            return f"debian-{version}" if version else "debian"
        elif "alpine" in name:
            return f"alpine-{version}" if version else "alpine"
        
        return None
    
    def _detect_os_from_component(self, component: Dict[str, Any]) -> Optional[str]:
        """Detect OS from a single component."""
        # Check version patterns
        version = component.get("version", "")
        if version:
            detected = self._detect_os_from_version_pattern(version)
            if detected:
                return detected
        
        # Check PURL
        purl = component.get("purl", "")
        if purl:
            detected = self.detect_os_from_purl(purl)
            if detected:
                return detected
        
        # Check metadata vendor
        metadata = component.get("metadata", {})
        if isinstance(metadata, dict):
            vendor = metadata.get("vendor", "")
            if vendor:
                detected = self._detect_os_from_vendor(vendor)
                if detected:
                    return detected
        
        return None
    
    def _detect_os_from_version_pattern(self, version: str) -> Optional[str]:
        """Detect OS from version pattern."""
        version_lower = version.lower()
        detection_rules = self.get_all_detection_rules()
        package_patterns = detection_rules.get("package_patterns", {})
        
        for os_name, patterns in package_patterns.items():
            for pattern in patterns:
                if pattern.lower() in version_lower:
                    return os_name
        
        return None
    
    def _detect_os_from_vendor(self, vendor: str) -> Optional[str]:
        """Detect OS from vendor name."""
        vendor_lower = vendor.lower()
        detection_rules = self.get_all_detection_rules()
        vendor_patterns = detection_rules.get("vendor_patterns", {})
        
        for vendor_name, os_list in vendor_patterns.items():
            if vendor_name.lower() in vendor_lower:
                return os_list[0] if os_list else None
        
        return None
    
    def _detect_os_from_text(self, text: str) -> Optional[str]:
        """Detect OS from arbitrary text."""
        text_lower = text.lower()
        detection_rules = self.get_all_detection_rules()
        os_keywords = detection_rules.get("os_keywords", {})
        
        for keyword, os_name in os_keywords.items():
            if keyword in text_lower:
                return os_name
        
        return None
    
    def _map_purl_distro_to_os(self, distro: str) -> Optional[str]:
        """Map PURL distro field to OS name."""
        detection_rules = self.get_all_detection_rules()
        purl_distro_patterns = detection_rules.get("purl_distro_patterns", {})
        return purl_distro_patterns.get(distro)
    
    def _map_purl_type_to_os(self, purl_type: str) -> Optional[str]:
        """Map PURL type to OS."""
        type_mappings = {
            "rpm": None,
            "deb": "ubuntu",
            "apk": "alpine",
            "freebsd": "freebsd"
        }
        return type_mappings.get(purl_type)
    
    def _get_best_os_candidate(self, candidates: List[str]) -> Optional[str]:
        """Get best OS candidate from list."""
        if not candidates:
            return None
        
        vote_count = {}
        for candidate in candidates:
            vote_count[candidate] = vote_count.get(candidate, 0) + 1
        
        return max(vote_count, key=vote_count.get)