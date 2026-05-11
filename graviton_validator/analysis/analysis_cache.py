"""
Component analysis cache for avoiding redundant analysis across multiple SBOMs.

In-memory cache that stores results by (name, version, type, detected_os) key
so identical components found in different SBOM files are only analyzed once
within a single run.
"""

import logging
import hashlib
from typing import Dict, Optional

logger = logging.getLogger(__name__)


class AnalysisCache:
    """In-memory cache for component analysis results within a single run."""
    
    def __init__(self):
        self._cache: Dict[str, Dict] = {}
        self._hits = 0
        self._misses = 0
    
    def _make_key(self, name: str, version: str, component_type: str, detected_os: str = "") -> str:
        """Create a cache key from component attributes. MD5 is used only for key hashing, not for security."""
        raw = f"{name}|{version}|{component_type}|{detected_os}"
        return hashlib.md5(raw.encode()).hexdigest()  # nosec B324
    
    def get(self, name: str, version: str, component_type: str, detected_os: str = "") -> Optional[Dict]:
        """Look up cached result. Returns None on miss."""
        key = self._make_key(name, version, component_type, detected_os)
        result = self._cache.get(key)
        if result:
            self._hits += 1
        else:
            self._misses += 1
        return result
    
    def put(self, name: str, version: str, component_type: str, result: Dict, detected_os: str = ""):
        """Store analysis result in cache."""
        key = self._make_key(name, version, component_type, detected_os)
        self._cache[key] = result
    
    def get_runtime(self, name: str, version: str, runtime: str, os_version: str) -> Optional[Dict]:
        """Look up cached runtime test result."""
        return self.get(name, version, f"runtime_{runtime}", os_version)
    
    def put_runtime(self, name: str, version: str, runtime: str, os_version: str, result: Dict):
        """Store runtime test result in cache."""
        self.put(name, version, f"runtime_{runtime}", result, os_version)
    
    def log_stats(self):
        """Log cache performance statistics."""
        total = self._hits + self._misses
        if total > 0:
            hit_rate = round(self._hits / total * 100, 1)
            logger.info(f"Analysis cache: {self._hits} hits, {self._misses} misses, "
                       f"{hit_rate}% hit rate, {len(self._cache)} entries cached")
