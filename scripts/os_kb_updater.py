#!/usr/bin/env python3
"""
Automated OS Knowledge Base Updater

Intelligently updates OS knowledge bases based on:
1. Last update timestamp (updates if older than threshold)
2. OS versions present in input SBOM
3. New OS versions not yet in knowledge base
"""

import json
import subprocess
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Set
import concurrent.futures
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class OSKBMetadata:
    """Manages metadata for OS knowledge base files"""
    
    def __init__(self, metadata_file: Path):
        self.metadata_file = metadata_file
        self.metadata = self._load_metadata()
    
    def _load_metadata(self) -> Dict:
        """Load metadata from JSON file"""
        if self.metadata_file.exists():
            try:
                with open(self.metadata_file, 'r') as f:
                    return json.load(f)
            except json.JSONDecodeError:
                logger.warning(f"Invalid metadata file, creating new one")
        return {"os_knowledge_bases": {}}
    
    def save_metadata(self):
        """Save metadata to JSON file"""
        self.metadata_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self.metadata_file, 'w') as f:
            json.dump(self.metadata, f, indent=2)
    
    def get_last_update(self, os_name: str, os_version: str) -> Optional[datetime]:
        """Get last update timestamp for an OS KB"""
        key = f"{os_name}-{os_version}"
        timestamp_str = self.metadata.get("os_knowledge_bases", {}).get(key, {}).get("last_updated")
        if timestamp_str:
            return datetime.fromisoformat(timestamp_str)
        return None
    
    def set_last_update(self, os_name: str, os_version: str, timestamp: Optional[datetime] = None):
        """Set last update timestamp for an OS KB"""
        if timestamp is None:
            timestamp = datetime.now()
        
        key = f"{os_name}-{os_version}"
        if "os_knowledge_bases" not in self.metadata:
            self.metadata["os_knowledge_bases"] = {}
        
        self.metadata["os_knowledge_bases"][key] = {
            "os_name": os_name,
            "os_version": os_version,
            "last_updated": timestamp.isoformat(),
            "kb_file": f"{key}-graviton-packages.json"
        }
        self.save_metadata()
    
    def needs_update(self, os_name: str, os_version: str, max_age_days: int = 7) -> bool:
        """Check if OS KB needs update based on age"""
        last_update = self.get_last_update(os_name, os_version)
        if last_update is None:
            return True  # Never updated
        
        age = datetime.now() - last_update
        return age > timedelta(days=max_age_days)


class OSDetectorFromSBOM:
    """Detect OS information from SBOM files"""
    
    # Mapping of common OS identifiers to standardized names
    OS_MAPPINGS = {
        "ubuntu": "ubuntu",
        "debian": "debian",
        "amzn": "amazonlinux",
        "amazon": "amazonlinux",
        "amazonlinux": "amazonlinux",
        "centos": "centos",
        "rhel": "rhel",
        "alpine": "alpine",
        "almalinux": "almalinux",
        "rocky": "rocky"
    }
    
    def detect_os_from_sbom(self, sbom_file: Path) -> List[Dict[str, str]]:
        """
        Detect OS versions from SBOM file
        
        Returns:
            List of dicts with 'os_name' and 'os_version' keys
        """
        try:
            with open(sbom_file, 'r') as f:
                sbom_data = json.load(f)
        except (json.JSONDecodeError, FileNotFoundError) as e:
            logger.error(f"Failed to read SBOM {sbom_file}: {e}")
            return []
        
        detected_os = []
        
        # Method 1: Check Syft distro field
        if "distro" in sbom_data:
            os_info = self._parse_syft_distro(sbom_data["distro"])
            if os_info:
                detected_os.append(os_info)
        
        # Method 2: Check CycloneDX metadata
        if "metadata" in sbom_data:
            os_info = self._parse_cyclonedx_metadata(sbom_data["metadata"])
            if os_info:
                detected_os.append(os_info)
        
        # Method 3: Analyze components for OS packages
        if "components" in sbom_data:
            os_info = self._detect_from_components(sbom_data["components"])
            if os_info:
                detected_os.extend(os_info)
        
        # Method 4: Check artifacts (Syft format)
        if "artifacts" in sbom_data:
            os_info = self._detect_from_artifacts(sbom_data["artifacts"])
            if os_info:
                detected_os.extend(os_info)
        
        # Deduplicate
        unique_os = []
        seen = set()
        for os_info in detected_os:
            key = f"{os_info['os_name']}-{os_info['os_version']}"
            if key not in seen:
                seen.add(key)
                unique_os.append(os_info)
        
        return unique_os
    
    def _parse_syft_distro(self, distro: Dict) -> Optional[Dict[str, str]]:
        """Parse Syft distro field"""
        name = distro.get("name", "").lower()
        version = distro.get("version", "")
        
        if not name or not version:
            return None
        
        os_name = self.OS_MAPPINGS.get(name, name)
        return {"os_name": os_name, "os_version": version}
    
    def _parse_cyclonedx_metadata(self, metadata: Dict) -> Optional[Dict[str, str]]:
        """Parse CycloneDX metadata for OS info"""
        # Check component metadata
        component = metadata.get("component", {})
        if component.get("type") == "operating-system":
            name = component.get("name", "").lower()
            version = component.get("version", "")
            if name and version:
                os_name = self.OS_MAPPINGS.get(name, name)
                return {"os_name": os_name, "os_version": version}
        return None
    
    def _detect_from_components(self, components: List[Dict]) -> List[Dict[str, str]]:
        """Detect OS from component PURLs"""
        detected = []
        for component in components[:50]:  # Sample first 50
            purl = component.get("purl", "")
            if purl and "distro=" in purl:
                os_info = self._parse_purl_distro(purl)
                if os_info:
                    detected.append(os_info)
        return detected
    
    def _detect_from_artifacts(self, artifacts: List[Dict]) -> List[Dict[str, str]]:
        """Detect OS from Syft artifacts"""
        detected = []
        for artifact in artifacts[:50]:  # Sample first 50
            purl = artifact.get("purl", "")
            if purl and "distro=" in purl:
                os_info = self._parse_purl_distro(purl)
                if os_info:
                    detected.append(os_info)
        return detected
    
    def _parse_purl_distro(self, purl: str) -> Optional[Dict[str, str]]:
        """Parse distro info from PURL"""
        try:
            # Extract distro from qualifiers: pkg:deb/debian/pkg?distro=bullseye
            if "distro=" not in purl:
                return None
            
            distro_part = purl.split("distro=")[1].split("&")[0].split("#")[0]
            
            # Map distro codenames to versions
            distro_version_map = {
                "bullseye": ("debian", "11"),
                "bookworm": ("debian", "12"),
                "buster": ("debian", "10"),
                "focal": ("ubuntu", "20.04"),
                "jammy": ("ubuntu", "22.04"),
                "noble": ("ubuntu", "24.04"),
                "bionic": ("ubuntu", "18.04"),
            }
            
            if distro_part in distro_version_map:
                os_name, os_version = distro_version_map[distro_part]
                return {"os_name": os_name, "os_version": os_version}
            
            # Try to extract from PURL type
            purl_type = purl.split("/")[0].replace("pkg:", "")
            if purl_type == "deb":
                # Try to get OS from namespace
                parts = purl.split("/")
                if len(parts) >= 2:
                    namespace = parts[1]
                    if namespace in self.OS_MAPPINGS:
                        return {"os_name": self.OS_MAPPINGS[namespace], "os_version": distro_part}
        except Exception:
            pass
        
        return None


class OSKBUpdater:
    """Main updater class"""
    
    def __init__(self, kb_dir: Path, scripts_dir: Path, max_age_days: int = 7):
        self.kb_dir = kb_dir
        self.scripts_dir = scripts_dir
        self.max_age_days = max_age_days
        self.metadata = OSKBMetadata(kb_dir / ".os_kb_metadata.json")
        self.detector = OSDetectorFromSBOM()
        self.generate_script = scripts_dir / "generate_docker_kb.sh"
        
        if not self.generate_script.exists():
            raise FileNotFoundError(f"Generate script not found: {self.generate_script}")
    
    def get_required_os_from_sbom(self, sbom_file: Path) -> List[Dict[str, str]]:
        """Get list of OS versions required based on SBOM"""
        return self.detector.detect_os_from_sbom(sbom_file)
    
    def update_os_kb(self, os_name: str, os_version: str) -> bool:
        """Update a single OS knowledge base"""
        logger.info(f"Updating KB for {os_name} {os_version}...")
        
        try:
            # Run generate_docker_kb.sh
            result = subprocess.run(
                [str(self.generate_script), os_name, os_version],
                cwd=self.scripts_dir,
                capture_output=True,
                text=True,
                timeout=600  # 10 minute timeout
            )
            
            if result.returncode == 0:
                logger.info(f"✅ Successfully updated {os_name} {os_version}")
                self.metadata.set_last_update(os_name, os_version)
                return True
            else:
                logger.error(f"❌ Failed to update {os_name} {os_version}: {result.stderr}")
                return False
        
        except subprocess.TimeoutExpired:
            logger.error(f"❌ Timeout updating {os_name} {os_version}")
            return False
        except Exception as e:
            logger.error(f"❌ Error updating {os_name} {os_version}: {e}")
            return False
    
    def update_required_os(self, sbom_file: Path, force: bool = False, parallel: bool = True) -> Dict[str, bool]:
        """
        Update OS KBs required by SBOM
        
        Args:
            sbom_file: Path to SBOM file
            force: Force update even if not stale
            parallel: Update multiple OS in parallel
        
        Returns:
            Dict mapping "os_name-os_version" to success status
        """
        required_os = self.get_required_os_from_sbom(sbom_file)
        
        if not required_os:
            logger.warning(f"No OS detected in SBOM: {sbom_file}")
            return {}
        
        logger.info(f"Detected OS in SBOM: {[f'{o['os_name']} {o['os_version']}' for o in required_os]}")
        
        # Filter OS that need updates
        to_update = []
        for os_info in required_os:
            os_name = os_info["os_name"]
            os_version = os_info["os_version"]
            
            if force or self.metadata.needs_update(os_name, os_version, self.max_age_days):
                to_update.append((os_name, os_version))
                logger.info(f"  → {os_name} {os_version} needs update")
            else:
                logger.info(f"  → {os_name} {os_version} is up-to-date")
        
        if not to_update:
            logger.info("All required OS KBs are up-to-date")
            return {}
        
        # Update OS KBs
        results = {}
        
        if parallel and len(to_update) > 1:
            logger.info(f"Updating {len(to_update)} OS KBs in parallel...")
            with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
                future_to_os = {
                    executor.submit(self.update_os_kb, os_name, os_version): (os_name, os_version)
                    for os_name, os_version in to_update
                }
                
                for future in concurrent.futures.as_completed(future_to_os):
                    os_name, os_version = future_to_os[future]
                    key = f"{os_name}-{os_version}"
                    try:
                        results[key] = future.result()
                    except Exception as e:
                        logger.error(f"Exception updating {key}: {e}")
                        results[key] = False
        else:
            for os_name, os_version in to_update:
                key = f"{os_name}-{os_version}"
                results[key] = self.update_os_kb(os_name, os_version)
        
        # Log summary
        if results:
            success_count = sum(1 for v in results.values() if v)
            total_count = len(results)
            if success_count == total_count:
                logger.info(f"✅ Successfully updated {success_count}/{total_count} OS knowledge base(s)")
            else:
                logger.warning(f"⚠️ Updated {success_count}/{total_count} OS knowledge base(s)")
                failed = [k for k, v in results.items() if not v]
                logger.warning(f"Failed: {', '.join(failed)}")
        
        return results
    
    def list_stale_os_kbs(self) -> List[Dict[str, str]]:
        """List all OS KBs that are stale"""
        stale = []
        for key, info in self.metadata.metadata.get("os_knowledge_bases", {}).items():
            os_name = info["os_name"]
            os_version = info["os_version"]
            if self.metadata.needs_update(os_name, os_version, self.max_age_days):
                stale.append({"os_name": os_name, "os_version": os_version, "key": key})
        return stale


def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Automated OS Knowledge Base Updater",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Update OS KBs required by SBOM (only if stale)
  %(prog)s --sbom app.sbom.json
  
  # Force update regardless of age
  %(prog)s --sbom app.sbom.json --force
  
  # Update specific OS
  %(prog)s --os ubuntu --version 22.04
  
  # List stale OS KBs
  %(prog)s --list-stale
  
  # Update all stale OS KBs
  %(prog)s --update-all-stale
        """
    )
    
    parser.add_argument('--sbom', type=Path, help='SBOM file to analyze for required OS')
    parser.add_argument('--os', help='OS name to update (e.g., ubuntu, debian)')
    parser.add_argument('--version', help='OS version to update (e.g., 22.04, 11)')
    parser.add_argument('--force', action='store_true', help='Force update even if not stale')
    parser.add_argument('--max-age-days', type=int, default=7, help='Max age in days before update (default: 7)')
    parser.add_argument('--list-stale', action='store_true', help='List all stale OS KBs')
    parser.add_argument('--update-all-stale', action='store_true', help='Update all stale OS KBs')
    parser.add_argument('--no-parallel', action='store_true', help='Disable parallel updates')
    
    args = parser.parse_args()
    
    # Setup paths
    script_dir = Path(__file__).parent
    kb_dir = script_dir.parent / "knowledge_bases" / "os_knowledge_bases"
    
    updater = OSKBUpdater(kb_dir, script_dir, args.max_age_days)
    
    # List stale
    if args.list_stale:
        stale = updater.list_stale_os_kbs()
        if stale:
            print(f"Stale OS KBs (older than {args.max_age_days} days):")
            for os_info in stale:
                print(f"  - {os_info['os_name']} {os_info['os_version']}")
        else:
            print("No stale OS KBs found")
        return 0
    
    # Update all stale
    if args.update_all_stale:
        stale = updater.list_stale_os_kbs()
        if not stale:
            print("No stale OS KBs to update")
            return 0
        
        print(f"Updating {len(stale)} stale OS KBs...")
        results = {}
        for os_info in stale:
            key = f"{os_info['os_name']}-{os_info['os_version']}"
            results[key] = updater.update_os_kb(os_info['os_name'], os_info['os_version'])
        
        success = sum(1 for v in results.values() if v)
        print(f"\nResults: {success}/{len(results)} successful")
        return 0 if success == len(results) else 1
    
    # Update from SBOM
    if args.sbom:
        if not args.sbom.exists():
            print(f"Error: SBOM file not found: {args.sbom}")
            return 1
        
        results = updater.update_required_os(args.sbom, args.force, not args.no_parallel)
        
        if results:
            success = sum(1 for v in results.values() if v)
            print(f"\nResults: {success}/{len(results)} successful")
            return 0 if success == len(results) else 1
        else:
            print("No updates needed")
            return 0
    
    # Update specific OS
    if args.os and args.version:
        success = updater.update_os_kb(args.os, args.version)
        return 0 if success else 1
    
    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
