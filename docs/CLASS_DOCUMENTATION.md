# Graviton Migration Accelerator - Complete Class Documentation

## Table of Contents
1. [Core Data Models](#core-data-models)
2. [Configuration Classes](#configuration-classes)
3. [SBOM Parsers](#sbom-parsers)
4. [Analysis Engine Classes](#analysis-engine-classes)
5. [Runtime Analysis Classes](#runtime-analysis-classes)
6. [Knowledge Base Classes](#knowledge-base-classes)
7. [Filtering & Detection Classes](#filtering--detection-classes)
8. [Execution Environment Classes](#execution-environment-classes)
9. [Reporting Classes](#reporting-classes)
10. [Utility & Support Classes](#utility--support-classes)

---

## Core Data Models

### CompatibilityStatus (Enum)
**Location**: `graviton_validator/models.py`
**Purpose**: Enumeration of possible compatibility statuses for components

```python
class CompatibilityStatus(Enum):
    COMPATIBLE = "compatible"
    INCOMPATIBLE = "incompatible"
    NEEDS_UPGRADE = "needs_upgrade"
    NEEDS_VERIFICATION = "needs_verification"
    NEEDS_VERSION_VERIFICATION = "needs_version_verification"
    UNKNOWN = "unknown"
```

**Usage**: Used throughout the system to represent the compatibility state of software components with Graviton processors.

### SoftwareComponent (dataclass)
**Location**: `graviton_validator/models.py`
**Purpose**: Represents a software component extracted from an SBOM

**Fields**:
- `name: str` - Component name (required)
- `version: Optional[str]` - Component version
- `component_type: str` - Type (library, application, etc.)
- `source_sbom: str` - Source SBOM file path
- `properties: Dict[str, str]` - Additional metadata (PURL, package owner, etc.)
- `parent_component: Optional[str]` - Parent component name for hierarchical analysis
- `child_components: List[str]` - Child component names (auto-initialized as empty list)
- `source_package: Optional[str]` - Source package name for Debian/Ubuntu

**Key Methods**:
- `__post_init__()` - Initializes child_components as empty list if None

**Usage**: Primary data structure for representing software components throughout the analysis pipeline.

### CompatibilityResult (dataclass)
**Location**: `graviton_validator/models.py`
**Purpose**: Result of compatibility analysis for a software component

**Fields**:
- `status: CompatibilityStatus` - Compatibility status
- `current_version_supported: bool` - Whether current version is supported
- `minimum_supported_version: Optional[str]` - Minimum version that works
- `recommended_version: Optional[str]` - Recommended version to use
- `notes: Optional[str]` - Additional information and analysis details
- `confidence_level: float = 1.0` - Confidence in the analysis (for intelligent matching)

**Usage**: Contains the complete compatibility assessment for a single component.

### ComponentResult (dataclass)
**Location**: `graviton_validator/models.py`
**Purpose**: Analysis result for a single component combining component info and compatibility

**Fields**:
- `component: SoftwareComponent` - The analyzed component
- `compatibility: CompatibilityResult` - Compatibility analysis result
- `matched_name: Optional[str] = None` - Name used if intelligent matching was applied

**Usage**: Wrapper that combines component data with its analysis results.

### AnalysisResult (dataclass)
**Location**: `graviton_validator/models.py`
**Purpose**: Complete analysis result for all components in an SBOM

**Fields**:
- `components: List[ComponentResult]` - Individual component results
- `total_components: int` - Total number of components analyzed
- `compatible_count: int` - Number of compatible components
- `incompatible_count: int` - Number of incompatible components
- `needs_upgrade_count: int` - Components needing version upgrade
- `needs_verification_count: int` - Components requiring manual verification
- `needs_version_verification_count: int` - Components with missing version info
- `unknown_count: int` - Components with unknown compatibility
- `errors: List[str]` - Analysis errors encountered
- `processing_time: float` - Total analysis time in seconds
- `detected_os: Optional[str] = None` - Detected operating system
- `sbom_file: Optional[str] = None` - Source SBOM file path

**Usage**: Top-level container for complete SBOM analysis results, used for reporting and statistics.

### VersionInfo (dataclass)
**Location**: `graviton_validator/models.py`
**Purpose**: Represents version information for a software component

**Fields**:
- `version: str` - Version string
- `status: CompatibilityStatus` - Compatibility status for this version
- `notes: Optional[str] = None` - Additional notes about this version

**Usage**: Used in knowledge base entries to represent version-specific compatibility information.

---

## Configuration Classes

### Config (dataclass)
**Location**: `graviton_validator/config.py`
**Purpose**: Main configuration class that aggregates all configuration sections

**Fields**:
- `knowledge_base: KnowledgeBaseConfig` - Knowledge base settings
- `cache: CacheConfig` - Caching configuration
- `output: OutputConfig` - Output formatting settings
- `matching: MatchingConfig` - Intelligent matching configuration
- `filtering: FilteringConfig` - Component filtering settings
- `logging: LoggingConfig` - Logging configuration

**Usage**: Central configuration object loaded from YAML files or defaults, passed throughout the application.

### MatchingConfig (dataclass)
**Location**: `graviton_validator/config.py`
**Purpose**: Configuration for intelligent matching algorithms

**Fields**:
- `intelligent_matching: bool = True` - Enable intelligent matching
- `similarity_threshold: float = 0.8` - Minimum similarity for matches
- `enable_fuzzy_matching: bool = True` - Enable fuzzy string matching
- `enable_alias_matching: bool = True` - Enable alias resolution
- `custom_aliases: Dict[str, str]` - User-defined aliases
- `name_mappings: Dict[str, str]` - Additional name mappings
- `matching_strategies: List[str]` - List of strategies to use
- `strategy_weights: Dict[str, float]` - Weights for different strategies
- `enable_substring_matching: bool = True` - Enable substring matching
- `enable_normalized_matching: bool = True` - Enable normalized name matching
- `max_matches: int = 5` - Maximum matches to return
- `min_confidence_threshold: float = 0.5` - Minimum confidence for matches

**Usage**: Controls behavior of intelligent matching system for unknown components.

### FilteringConfig (dataclass)
**Location**: `graviton_validator/config.py`
**Purpose**: Configuration for component filtering

**Fields**:
- `exclude_system_packages: bool = True` - Filter out system packages
- `custom_kernel_patterns: List[str]` - Custom kernel module patterns
- `custom_system_patterns: List[str]` - Custom system package patterns
- `custom_exclusions: List[str]` - Custom exclusion patterns
- `kernel_module_patterns: List[str]` - Kernel module detection patterns
- `system_library_patterns: List[str]` - System library patterns
- `os_utility_patterns: List[str]` - OS utility patterns
- `development_patterns: List[str]` - Development package patterns
- `test_patterns: List[str]` - Test package patterns
- `validate_patterns: bool = True` - Validate regex patterns
- `pattern_validation_timeout: float = 1.0` - Pattern validation timeout

**Usage**: Controls which components are filtered out during analysis based on regex patterns.

### CacheConfig (dataclass)
**Location**: `graviton_validator/config.py`
**Purpose**: Configuration for caching system

**Fields**:
- `enabled: bool = True` - Enable caching
- `cache_dir: str = ".cache"` - Cache directory path
- `max_age_days: int = 30` - Maximum cache entry age
- `rate_limiting: bool = True` - Enable rate limiting
- `rate_limits: Dict[str, Dict[str, int]]` - Per-runtime rate limits

**Usage**: Controls caching behavior for API calls and expensive operations.

### LoggingConfig (dataclass)
**Location**: `graviton_validator/config.py`
**Purpose**: Configuration for logging system

**Fields**:
- `level: str = "INFO"` - Default logging level
- `log_file: Optional[str] = None` - Log file path
- `verbose: bool = False` - Enable verbose logging

**Usage**: Controls logging behavior throughout the application.

---

## SBOM Parsers

### SBOMParser (ABC)
**Location**: `graviton_validator/parsers/base.py`
**Purpose**: Abstract base class for SBOM parsers

**Abstract Methods**:
- `parse(sbom_data: dict, sbom_file: str) -> List[SoftwareComponent]` - Parse SBOM data
- `_parse_components(sbom_data: dict, sbom_file: str) -> List[SoftwareComponent]` - Extract components
- `_extract_component_info(component_data: dict) -> dict` - Extract component information

**Usage**: Base class that defines the interface for all SBOM format parsers.

### CycloneDXParser (SBOMParser)
**Location**: `graviton_validator/parsers/cyclonedx.py`
**Purpose**: Parser for CycloneDX SBOM format

**Key Methods**:
- `parse(sbom_data: dict, sbom_file: str) -> List[SoftwareComponent]` - Main parsing entry point
- `_parse_components(sbom_data: dict, sbom_file: str) -> List[SoftwareComponent]` - Extract components from CycloneDX structure
- `_extract_component_info(component: dict) -> dict` - Extract component details
- `_extract_properties(component: dict) -> dict` - Extract component properties
- `_detect_hierarchical_relationships(components: List[dict]) -> Tuple[Dict, Dict]` - Detect parent-child relationships

**Parsing Logic**:
1. Validates CycloneDX format (checks for `bomFormat` field)
2. Extracts components from `components` array
3. Processes component properties including PURL
4. Detects hierarchical relationships between components
5. Handles both flat and nested component structures

**Usage**: Handles CycloneDX format SBOMs, the most common format used by the tool.

### SPDXParser (SBOMParser)
**Location**: `graviton_validator/parsers/spdx.py`
**Purpose**: Parser for SPDX SBOM format

**Key Methods**:
- `parse(sbom_data: dict, sbom_file: str) -> List[SoftwareComponent]` - Main parsing entry point
- `_parse_components(sbom_data: dict, sbom_file: str) -> List[SoftwareComponent]` - Extract SPDX packages
- `_extract_component_info(package: dict) -> dict` - Extract package information
- `_parse_relationships(sbom_data: dict) -> Dict[str, List[str]]` - Parse SPDX relationships

**Parsing Logic**:
1. Validates SPDX format (checks for `spdxVersion` field)
2. Extracts packages from `packages` array
3. Processes SPDX-specific fields like `downloadLocation`, `filesAnalyzed`
4. Parses relationships to understand dependencies
5. Handles SPDX license information

**Usage**: Handles SPDX format SBOMs, commonly used in enterprise environments.

### SyftParser (SBOMParser)
**Location**: `graviton_validator/parsers/syft.py`
**Purpose**: Parser for Syft-generated SBOM format

**Key Methods**:
- `parse(sbom_data: dict, sbom_file: str) -> List[SoftwareComponent]` - Main parsing entry point
- `_parse_components(sbom_data: dict, sbom_file: str) -> List[SoftwareComponent]` - Extract Syft artifacts
- `_extract_component_info(artifact: dict) -> dict` - Extract artifact information
- `_extract_metadata_properties(metadata: dict) -> dict` - Extract metadata properties

**Parsing Logic**:
1. Validates Syft format (checks for `artifacts` and `descriptor` fields)
2. Extracts artifacts from `artifacts` array
3. Processes Syft-specific metadata
4. Handles different artifact types (packages, files, etc.)
5. Extracts location and metadata information

**Usage**: Handles Syft-generated SBOMs, popular in container scanning scenarios.

### SBOMParserFactory
**Location**: `graviton_validator/parsers/factory.py`
**Purpose**: Factory class for creating appropriate SBOM parsers

**Key Methods**:
- `create_parser(sbom_format: str) -> SBOMParser` - Create parser for specific format
- `detect_format(sbom_data: dict) -> str` - Auto-detect SBOM format
- `get_supported_formats() -> List[str]` - Get list of supported formats

**Format Detection Logic**:
1. CycloneDX: Checks for `bomFormat` containing "CycloneDX"
2. Syft: Checks for `artifacts`, `artifactRelationships`, `descriptor`, `source`
3. SPDX: Checks for `spdxversion`, `relationships`, `packages`

**Usage**: Central factory for creating format-specific parsers based on SBOM content.

---

## Analysis Engine Classes

### CompatibilityAnalyzer (ABC)
**Location**: `graviton_validator/analysis/base.py`
**Purpose**: Abstract base class for compatibility analysis

**Abstract Methods**:
- `analyze_components(components: List[SoftwareComponent]) -> AnalysisResult` - Analyze component list
- `check_single_component(component: SoftwareComponent) -> ComponentResult` - Analyze single component

**Usage**: Defines the interface for compatibility analysis engines.

### GravitonCompatibilityAnalyzer (CompatibilityAnalyzer)
**Location**: `graviton_validator/analysis/compatibility_analyzer.py`
**Purpose**: Main compatibility analyzer for Graviton processors with OS-aware capabilities

**Constructor Parameters**:
- `knowledge_base: KnowledgeBase` - Knowledge base for compatibility lookups
- `recommendation_generator: Optional[RecommendationGenerator]` - Upgrade recommendation generator
- `matching_config` - Intelligent matching configuration
- `os_detector: Optional[OSDetector]` - OS detection service
- `os_config_manager: Optional[OSConfigManager]` - OS configuration manager
- `component_filter: Optional[ComponentFilter]` - Component filtering service
- `deny_list_loader: Optional[DenyListLoader]` - Deny list service
- `runtime_analyzers: Optional[Dict]` - Runtime-specific analyzers

**Key Methods**:
- `analyze_components(components, detected_os, sbom_file) -> AnalysisResult` - Main analysis orchestration
- `check_single_component(component, detected_os, component_category) -> ComponentResult` - Single component analysis
- `_group_components_by_source(components) -> Tuple[Dict, List]` - Group for hierarchical analysis
- `_categorize_components_by_os(components, detected_os) -> Dict` - Categorize by OS compatibility
- `_handle_system_compatible_component(component, detected_os) -> ComponentResult` - Handle system packages
- `_create_inherited_result(child_component, parent_result, parent_name) -> ComponentResult` - Create inherited results

**Analysis Flow**:
1. **Hierarchical Grouping**: Groups components by source package for optimization
2. **OS Categorization**: Categorizes components based on OS compatibility
3. **Deny List Check**: Checks components against deny lists first
4. **System Component Handling**: Special handling for OS packages
5. **Runtime Analysis**: Uses runtime-specific analyzers when applicable
6. **Knowledge Base Lookup**: Searches compatibility database
7. **Intelligent Matching**: Attempts fuzzy matching for unknown components
8. **Recommendation Generation**: Generates upgrade recommendations

**Performance Optimizations**:
- Hierarchical analysis: Parent compatibility inherited by children
- Progress tracking: Shows progress dots for large component sets
- Intelligent matching limits: Skips expensive matching for very long names (>50 chars)

**Usage**: Core analysis engine that orchestrates all compatibility checking logic.

### DefaultRecommendationGenerator (RecommendationGenerator)
**Location**: `graviton_validator/analysis/compatibility_analyzer.py`
**Purpose**: Default implementation of recommendation generator

**Constructor Parameters**:
- `knowledge_base: KnowledgeBase` - Knowledge base for version lookups

**Key Methods**:
- `generate_recommendations(component_result: ComponentResult) -> ComponentResult` - Generate recommendations
- `_generate_upgrade_notes(component, compatible_versions, minimum_version, recommended_version) -> str` - Create upgrade notes

**Recommendation Logic**:
1. **Compatible Components**: No recommendations needed
2. **Incompatible/Needs Upgrade**: Find compatible versions and create upgrade path
3. **Unknown Components**: Provide general guidance and ISV analysis details

**Usage**: Generates actionable recommendations for component compatibility issues.

---

## Runtime Analysis Classes

### RuntimeAnalyzer (ABC)
**Location**: `graviton_validator/analysis/manifest_generators.py`
**Purpose**: Abstract base class for runtime-specific analyzers

**Class Constants**:
- `RUNTIME_CONFIGS` - Configuration mapping for all supported runtimes

**Abstract Methods**:
- `get_runtime_type() -> str` - Return runtime identifier
- `extract_dependencies(components: List[Any]) -> List[Dict[str, Any]]` - Extract runtime dependencies
- `generate_manifest_file(dependencies, output_dir, sbom_name) -> str` - Generate manifest file
- `_parse_manifest_for_fallback(manifest_path, compatible, log_snippet, result, runtime_type) -> List[Dict]` - Parse for fallback results

**Common Methods**:
- `can_analyze_components(components: List[Any]) -> bool` - Check if analyzer applies
- `analyze_dependencies(manifest_path: str, **kwargs) -> Dict[str, Any]` - Unified dependency analysis
- `_extract_simple_dependencies(components, purl_prefix, dep_type) -> List[Dict]` - Common extraction logic
- `_create_basic_fallback_result(name, version, compatible, log_snippet, result, **extra_fields) -> Dict` - Create fallback results
- `_create_fallback_results(manifest_path, result, config, runtime_type) -> List[Dict]` - Create fallback when detailed analysis fails
- `_load_results_from_file(runtime_type, **kwargs) -> Optional[List[Dict]]` - Load results from file

**Usage**: Base class for all runtime-specific analyzers (Java, Python, Node.js, .NET, Ruby).

### JavaRuntimeAnalyzer (RuntimeAnalyzer)
**Location**: `graviton_validator/analysis/manifest_generators.py`
**Purpose**: Java/Maven runtime analyzer

**Key Methods**:
- `get_runtime_type() -> str` - Returns "java"
- `extract_dependencies(components) -> List[Dict]` - Extract Maven dependencies from SBOM
- `generate_manifest_file(dependencies, output_dir, sbom_name) -> str` - Generate pom.xml
- `_parse_manifest_for_fallback(manifest_path, compatible, log_snippet, result, runtime_type) -> List[Dict]` - Parse pom.xml for fallback

**Dependency Extraction Logic**:
1. Identifies Java components by type (`jar`, `maven`, `java-archive`) or PURL (`pkg:maven/`)
2. Extracts groupId and artifactId from PURL or component name
3. Handles version information from PURL or component version
4. Deduplicates based on (groupId, artifactId, version) tuple

**Manifest Generation**:
- Creates Maven pom.xml with all extracted dependencies
- Uses standard Maven project structure
- Sets compile scope for all dependencies

**Usage**: Handles Java/Maven dependency analysis and manifest generation.

### PythonRuntimeAnalyzer (RuntimeAnalyzer)
**Location**: `graviton_validator/analysis/manifest_generators.py`
**Purpose**: Python/pip runtime analyzer

**Key Methods**:
- `get_runtime_type() -> str` - Returns "python"
- `extract_dependencies(components) -> List[Dict]` - Extract Python dependencies
- `generate_manifest_file(dependencies, output_dir, sbom_name) -> str` - Generate requirements.txt
- `_parse_manifest_for_fallback(manifest_path, compatible, log_snippet, result, runtime_type) -> List[Dict]` - Parse requirements.txt

**Dependency Extraction Logic**:
- Identifies Python components by PURL prefix `pkg:pypi/`
- Extracts package name and version
- Uses simple name-version mapping

**Manifest Generation**:
- Creates requirements.txt with `package==version` format
- One dependency per line

**Usage**: Handles Python/pip dependency analysis and requirements.txt generation.

### NodeJSRuntimeAnalyzer (RuntimeAnalyzer)
**Location**: `graviton_validator/analysis/manifest_generators.py`
**Purpose**: Node.js/npm runtime analyzer

**Key Methods**:
- `get_runtime_type() -> str` - Returns "nodejs"
- `extract_dependencies(components) -> List[Dict]` - Extract npm dependencies
- `generate_manifest_file(dependencies, output_dir, sbom_name) -> str` - Generate package.json
- `_parse_manifest_for_fallback(manifest_path, compatible, log_snippet, result, runtime_type) -> List[Dict]` - Parse package.json

**Dependency Extraction Logic**:
- Identifies Node.js components by PURL prefix `pkg:npm/`
- Extracts package name and version

**Manifest Generation**:
- Creates package.json with standard npm structure
- Includes all dependencies in `dependencies` section
- Sets basic package metadata

**Fallback Analysis**:
- Detects native build indicators (gyp, node-gyp, binding.gyp, compile)
- Adds native build detection to result properties

**Usage**: Handles Node.js/npm dependency analysis and package.json generation.

### DotNetRuntimeAnalyzer (RuntimeAnalyzer)
**Location**: `graviton_validator/analysis/manifest_generators.py`
**Purpose**: .NET/NuGet runtime analyzer

**Key Methods**:
- `get_runtime_type() -> str` - Returns "dotnet"
- `extract_dependencies(components) -> List[Dict]` - Extract NuGet dependencies
- `generate_manifest_file(dependencies, output_dir, sbom_name) -> str` - Generate .csproj
- `_parse_manifest_for_fallback(manifest_path, compatible, log_snippet, result, runtime_type) -> List[Dict]` - Parse .csproj

**Dependency Extraction Logic**:
- Identifies .NET components by PURL prefix `pkg:nuget/`
- Extracts package name and version

**Manifest Generation**:
- Creates .csproj file with .NET 6.0 target framework
- Sets RuntimeIdentifier to linux-arm64
- Includes all dependencies as PackageReference elements

**Usage**: Handles .NET/NuGet dependency analysis and .csproj generation.

### RubyRuntimeAnalyzer (RuntimeAnalyzer)
**Location**: `graviton_validator/analysis/manifest_generators.py`
**Purpose**: Ruby/Gem runtime analyzer

**Key Methods**:
- `get_runtime_type() -> str` - Returns "ruby"
- `extract_dependencies(components) -> List[Dict]` - Extract gem dependencies
- `generate_manifest_file(dependencies, output_dir, sbom_name) -> str` - Generate Gemfile
- `_parse_manifest_for_fallback(manifest_path, compatible, log_snippet, result, runtime_type) -> List[Dict]` - Parse Gemfile

**Dependency Extraction Logic**:
- Identifies Ruby components by PURL prefix `pkg:gem/`
- Extracts gem name and version

**Manifest Generation**:
- Creates Gemfile with RubyGems source
- Includes all dependencies with exact version specifications

**Usage**: Handles Ruby/gem dependency analysis and Gemfile generation.

### RuntimeAnalyzerManager
**Location**: `graviton_validator/analysis/manifest_generators.py`
**Purpose**: Manager for runtime-specific analyzers

**Constructor Parameters**:
- `config_file: Optional[str]` - Runtime configuration file
- `use_containers: bool` - Whether to use container execution

**Key Methods**:
- `get_applicable_analyzers(components) -> List[RuntimeAnalyzer]` - Get analyzers for components
- `generate_manifests_only(components, output_dir, sbom_data, **kwargs) -> Dict` - Generate manifests without analysis
- `analyze_components_by_runtime(components, output_dir, sbom_data, **kwargs) -> Dict` - Full runtime analysis

**Initialization Logic**:
1. Loads runtime configuration (versions, timeouts)
2. Auto-detects execution environment (container vs native based on CODEBUILD_BUILD_ID)
3. Initializes all runtime analyzers
4. Sets up execution environment factory

**Analysis Flow**:
1. **Version Detection**: Detects runtime versions from SBOM metadata
2. **Analyzer Selection**: Identifies applicable analyzers for components
3. **Manifest Generation**: Creates runtime-specific manifest files
4. **Prerequisite Check**: Verifies required tools are available
5. **Analysis Execution**: Runs dependency analysis using execution environment
6. **Result Processing**: Loads and validates analysis results
7. **Result Storage**: Saves enriched results to disk

**Usage**: Central coordinator for all runtime analysis activities.

---

## Knowledge Base Classes

### KnowledgeBase (ABC)
**Location**: `graviton_validator/knowledge_base/base.py`
**Purpose**: Abstract base class for knowledge base implementations

**Abstract Methods**:
- `get_compatibility(software_name: str, version: str) -> CompatibilityResult` - Get compatibility info
- `find_software(software_name: str) -> Optional[Any]` - Find software entry
- `find_compatible_versions(software_name: str) -> List[Any]` - Find compatible versions
- `intelligent_match(software_name: str, config) -> List[str]` - Intelligent matching

**Usage**: Defines interface for knowledge base implementations.

### JSONKnowledgeBase (KnowledgeBase)
**Location**: `graviton_validator/knowledge_base/data_structures.py`
**Purpose**: JSON-based knowledge base implementation

**Constructor Parameters**:
- `compatibility_records: Dict[str, CompatibilityRecord]` - Main compatibility database
- `software_aliases: Dict[str, str]` - Name alias mappings
- `intelligent_matcher: Optional[IntelligentMatcher]` - Intelligent matching service
- `version_comparator: Optional[VersionComparator]` - Version comparison service

**Key Methods**:
- `get_compatibility(software_name: str, version: str) -> CompatibilityResult` - Main compatibility lookup
- `find_software(software_name: str) -> Optional[CompatibilityRecord]` - Find software entry
- `find_compatible_versions(software_name: str) -> List[VersionInfo]` - Get compatible versions
- `intelligent_match(software_name: str, config) -> List[str]` - Perform intelligent matching
- `_resolve_alias(software_name: str) -> str` - Resolve software name aliases
- `_check_version_compatibility(record: CompatibilityRecord, version: str) -> CompatibilityResult` - Check version compatibility

**Lookup Logic**:
1. **Direct Lookup**: Searches for exact software name match
2. **Alias Resolution**: Checks software aliases for alternative names
3. **Version Checking**: Compares requested version against compatible versions
4. **Status Determination**: Returns appropriate compatibility status

**Usage**: Main knowledge base implementation used throughout the system.

### CompatibilityRecord (dataclass)
**Location**: `graviton_validator/knowledge_base/data_structures.py`
**Purpose**: Represents compatibility information for a software package

**Fields**:
- `name: str` - Software package name
- `compatible_versions: List[VersionInfo]` - List of compatible versions
- `incompatible_versions: List[VersionInfo]` - List of incompatible versions
- `notes: Optional[str]` - General notes about the software
- `aliases: Optional[List[str]]` - Alternative names for the software
- `minimum_supported_version: Optional[str]` - Minimum version that works
- `recommended_version: Optional[str]` - Recommended version to use
- `last_updated: Optional[str]` - Last update timestamp

**Usage**: Core data structure for storing compatibility information in knowledge base.

### KnowledgeBaseLoader
**Location**: `graviton_validator/knowledge_base/loader.py`
**Purpose**: Loads and manages knowledge base files

**Key Methods**:
- `load_single(file_path: str) -> JSONKnowledgeBase` - Load single KB file
- `load_multiple(file_paths: List[str]) -> JSONKnowledgeBase` - Load and merge multiple KB files
- `_merge_knowledge_bases(knowledge_bases: List[JSONKnowledgeBase]) -> JSONKnowledgeBase` - Merge KB entries
- `_validate_knowledge_base_structure(data: dict, file_path: str)` - Validate KB file structure

**Loading Logic**:
1. **File Validation**: Validates JSON structure and required fields
2. **Data Parsing**: Converts JSON data to CompatibilityRecord objects
3. **Alias Processing**: Builds alias mapping for alternative names
4. **Merging**: Combines multiple KB files with conflict resolution
5. **Service Integration**: Integrates intelligent matcher and version comparator

**Usage**: Central service for loading knowledge base data from JSON files.

### FuzzyMatcher (IntelligentMatcher)
**Location**: `graviton_validator/knowledge_base/intelligent_matcher.py`
**Purpose**: Intelligent matching service using fuzzy string matching

**Constructor Parameters**:
- `knowledge_base_entries: Dict[str, Any]` - Available software entries for matching

**Key Methods**:
- `find_matches(query: str, config) -> List[str]` - Find potential matches
- `_calculate_similarity(query: str, candidate: str, config) -> float` - Calculate similarity score
- `_levenshtein_similarity(s1: str, s2: str) -> float` - Levenshtein distance similarity
- `_jaro_winkler_similarity(s1: str, s2: str) -> float` - Jaro-Winkler similarity
- `_substring_similarity(query: str, candidate: str) -> float` - Substring matching similarity
- `_normalized_similarity(query: str, candidate: str) -> float` - Normalized name similarity

**Matching Strategies**:
1. **Levenshtein Distance**: Character-level edit distance
2. **Jaro-Winkler**: String similarity with prefix weighting
3. **Substring Matching**: Partial string containment
4. **Normalized Matching**: Case-insensitive, punctuation-normalized matching

**Scoring Logic**:
- Combines multiple similarity metrics with configurable weights
- Filters results by minimum confidence threshold
- Returns top matches sorted by confidence score

**Usage**: Provides intelligent matching for unknown software components.

### SemanticVersionComparator (VersionComparator)
**Location**: `graviton_validator/knowledge_base/version_comparator.py`
**Purpose**: Semantic version comparison service

**Key Methods**:
- `compare_versions(version1: str, version2: str) -> int` - Compare two versions
- `is_version_in_range(version: str, min_version: str, max_version: str) -> bool` - Check version range
- `parse_version(version_str: str) -> Tuple[int, ...]` - Parse version string
- `_normalize_version(version: str) -> str` - Normalize version format

**Comparison Logic**:
1. **Version Parsing**: Splits version into numeric components
2. **Component Comparison**: Compares each version component numerically
3. **Range Checking**: Validates version falls within specified range
4. **Format Handling**: Handles various version formats (x.y.z, x.y, etc.)

**Usage**: Provides version comparison capabilities for compatibility checking.

---

## Filtering & Detection Classes

### ComponentCategory (Enum)
**Location**: `graviton_validator/analysis/filters.py`
**Purpose**: Enumeration of component categories for filtering

```python
class ComponentCategory(Enum):
    SYSTEM_COMPATIBLE = "system_compatible"
    SYSTEM_UNKNOWN = "system_unknown"
    KERNEL_MODULE = "kernel_module"
    APPLICATION = "application"
```

**Usage**: Used to categorize components for different handling strategies.

### ComponentFilter
**Location**: `graviton_validator/analysis/filters.py`
**Purpose**: Filters and categorizes components based on OS and type

**Constructor Parameters**:
- `os_config_manager: Optional[OSConfigManager]` - OS configuration service
- `config: Optional[FilterConfig]` - Filtering configuration

**Key Methods**:
- `categorize_component(component: dict, detected_os: str, os_kb: Any = None) -> ComponentCategory` - Categorize component
- `detect_runtime_type(component: dict) -> Optional[str]` - Detect runtime type
- `_is_kernel_module(component_name: str) -> bool` - Check if kernel module
- `_is_system_library(component_name: str) -> bool` - Check if system library
- `_is_os_utility(component_name: str) -> bool` - Check if OS utility
- `_matches_patterns(name: str, patterns: List[str]) -> bool` - Check pattern matching

**Categorization Logic**:
1. **Kernel Module Check**: Matches against kernel module patterns
2. **System Library Check**: Matches against system library patterns
3. **OS Utility Check**: Matches against OS utility patterns
4. **OS Compatibility**: Determines if OS supports Graviton
5. **Default Category**: Returns APPLICATION for unmatched components

**Runtime Detection**:
- Analyzes component PURL and properties
- Identifies Java, Python, Node.js, .NET, Ruby components
- Returns runtime type for specialized analysis

**Usage**: Central filtering service for component categorization and runtime detection.

### OSConfigManager
**Location**: `graviton_validator/os_detection/os_configs.py`
**Purpose**: Manages OS configuration and Graviton compatibility information

**Key Methods**:
- `detect_os_from_sbom_data(sbom_data: dict) -> Optional[str]` - Detect OS from SBOM
- `is_os_graviton_compatible(os_name: str) -> bool` - Check Graviton compatibility
- `get_os_info(os_name: str) -> Optional[dict]` - Get OS information
- `get_supported_os_list() -> List[str]` - Get supported OS list
- `_extract_os_from_metadata(metadata: dict) -> Optional[str]` - Extract OS from metadata
- `_extract_os_from_components(components: List[dict]) -> Optional[str]` - Extract OS from components

**OS Detection Logic**:
1. **Metadata Analysis**: Checks SBOM metadata for OS information
2. **Component Analysis**: Analyzes component names for OS indicators
3. **Pattern Matching**: Uses regex patterns to identify OS distributions
4. **Version Extraction**: Extracts OS version information

**Supported Operating Systems**:
- Amazon Linux 2, Amazon Linux 2023
- Ubuntu 18.04, 20.04, 22.04, 24.04
- Debian 10, 11, 12
- CentOS 8
- Alpine 3.17.10, 3.18.12

**Usage**: Provides OS detection and compatibility checking throughout the system.

---

## Execution Environment Classes

### ExecutionEnvironment (ABC)
**Location**: `graviton_validator/analysis/execution_environment.py`
**Purpose**: Abstract base class for execution environments

**Abstract Methods**:
- `check_prerequisites(runtime: str) -> Tuple[bool, List[str]]` - Check prerequisites
- `execute_analysis(runtime: str, manifest_path: str, **kwargs) -> Dict` - Execute analysis
- `cleanup(skip_cleanup: bool = False)` - Cleanup resources

**Usage**: Defines interface for different execution environments (native vs container).

### NativeExecutionEnvironment (ExecutionEnvironment)
**Location**: `graviton_validator/analysis/execution_environment.py`
**Purpose**: Native execution environment using local tools

**Key Methods**:
- `check_prerequisites(runtime: str) -> Tuple[bool, List[str]]` - Check local tools
- `execute_analysis(runtime: str, manifest_path: str, **kwargs) -> Dict` - Execute using local tools
- `cleanup(skip_cleanup: bool = False)` - Clean up temporary directories
- `_execute_runtime_analysis(runtime, manifest_path, work_dir, **kwargs) -> Dict` - Execute runtime analysis
- `_setup_runtime_analysis(runtime, manifest_path, work_dir, **kwargs) -> Tuple` - Setup analysis environment
- `_handle_analysis_output(runtime, result, output_file_path, output_filename, **kwargs) -> str` - Handle output

**Execution Logic**:
1. **Isolation**: Creates temporary directory for each analysis
2. **Manifest Copy**: Copies manifest to isolated environment
3. **Command Building**: Builds runtime-specific command
4. **Environment Setup**: Sets debug environment variables if verbose
5. **Execution**: Runs command with timeout and captures output
6. **Result Processing**: Processes output file or stdout
7. **Cleanup**: Removes temporary directories

**Environment Variables**:
- Sets `NODE_LOG_LEVEL=DEBUG` for Node.js when verbose
- Sets `DEBUG=1` for Python, Java, .NET, Ruby when verbose

**Usage**: Used in AWS CodeBuild and local environments with native tools.

### ContainerExecutionEnvironment (ExecutionEnvironment)
**Location**: `graviton_validator/analysis/execution_environment.py`
**Purpose**: Container-based execution environment for local development

**Key Methods**:
- `check_prerequisites(runtime: str) -> Tuple[bool, List[str]]` - Check Docker/Podman
- `execute_analysis(runtime: str, manifest_path: str, **kwargs) -> Dict` - Execute in container
- `cleanup(skip_cleanup: bool = False)` - Clean up containers and images
- `_detect_container_tool() -> str` - Detect available container tool
- `_build_runtime_image(runtime: str, os_version: str, runtime_version: str) -> str` - Build container image
- `_execute_in_container(runtime, manifest_path, image_name, **kwargs) -> Dict` - Execute analysis in container

**Container Logic**:
1. **Tool Detection**: Detects Docker or Podman availability
2. **Image Building**: Builds runtime-specific container images
3. **Volume Mounting**: Mounts manifest and output directories
4. **Execution**: Runs analysis inside container
5. **Result Extraction**: Extracts results from container
6. **Cleanup**: Removes containers and images

**Image Building**:
- Uses OS-specific base images (Amazon Linux, Ubuntu, etc.)
- Installs runtime-specific tools and dependencies
- Configures ARM64 architecture simulation if needed

**Usage**: Used for local development and testing with container isolation.

### ExecutionEnvironmentFactory
**Location**: `graviton_validator/analysis/execution_environment.py`
**Purpose**: Factory for creating execution environments

**Key Methods**:
- `create_environment(use_containers: bool = None) -> ExecutionEnvironment` - Create appropriate environment

**Selection Logic**:
- Checks `CODEBUILD_BUILD_ID` environment variable
- Uses native environment in AWS CodeBuild
- Uses container environment for local development
- Allows explicit override via parameter

**Usage**: Central factory for execution environment creation.

---

## Reporting Classes

### ReportGenerator (ABC)
**Location**: `graviton_validator/reporting/base.py`
**Purpose**: Abstract base class for report generators

**Abstract Methods**:
- `generate_report(analysis_result: AnalysisResult) -> str` - Generate report content

**Usage**: Defines interface for all report format generators.

### JSONReporter (ReportGenerator)
**Location**: `graviton_validator/reporting/json_reporter.py`
**Purpose**: Generates JSON format reports

**Key Methods**:
- `generate_report(analysis_result: AnalysisResult) -> str` - Generate JSON report
- `_create_metadata(analysis_result: AnalysisResult) -> dict` - Create metadata section
- `_create_summary(analysis_result: AnalysisResult) -> dict` - Create summary section
- `_create_statistics(analysis_result: AnalysisResult) -> dict` - Create statistics section
- `_serialize_component_result(component_result: ComponentResult) -> dict` - Serialize component

**JSON Structure**:
```json
{
  "metadata": {
    "tool_version": "version",
    "analysis_timestamp": "ISO timestamp",
    "sbom_files": ["file1.json"],
    "detected_os": "os_name",
    "analysis_mode": "mode"
  },
  "summary": {
    "total_components": 100,
    "compatible": 80,
    "incompatible": 10,
    "needs_upgrade": 5,
    "needs_verification": 3,
    "unknown": 2,
    "compatibility_rate": 80.0,
    "has_issues": true
  },
  "components": [...],
  "statistics": {...},
  "errors": [...]
}
```

**Usage**: Generates machine-readable JSON reports for programmatic processing.

### ExcelReporter (ReportGenerator)
**Location**: `graviton_validator/reporting/excel_reporter.py`
**Purpose**: Generates Excel format reports with multiple worksheets

**Key Methods**:
- `generate_report(analysis_result: AnalysisResult, output_path: str)` - Generate Excel file
- `_create_summary_sheet(workbook, analysis_result)` - Create summary worksheet
- `_create_components_sheet(workbook, analysis_result)` - Create components worksheet
- `_create_issues_sheet(workbook, analysis_result)` - Create issues worksheet
- `_create_statistics_sheet(workbook, analysis_result)` - Create statistics worksheet
- `_apply_formatting(worksheet, analysis_result)` - Apply conditional formatting

**Excel Structure**:
1. **Summary Sheet**: High-level statistics and charts
2. **Components Sheet**: Detailed component analysis results
3. **Issues Sheet**: Incompatible and problematic components
4. **Statistics Sheet**: Detailed breakdowns and metrics

**Formatting**:
- Color-coded compatibility status (green=compatible, red=incompatible, etc.)
- Conditional formatting for easy visual identification
- Charts and graphs for summary data
- Filters and sorting for data exploration

**Usage**: Generates business-friendly Excel reports for stakeholder review.

### MarkdownReporter (ReportGenerator)
**Location**: `graviton_validator/reporting/markdown_reporter.py`
**Purpose**: Generates Markdown format reports for documentation

**Key Methods**:
- `generate_report(analysis_result: AnalysisResult) -> str` - Generate Markdown report
- `_generate_summary_section(analysis_result: AnalysisResult) -> str` - Generate summary
- `_generate_components_section(analysis_result: AnalysisResult) -> str` - Generate components table
- `_generate_issues_section(analysis_result: AnalysisResult) -> str` - Generate issues section
- `_generate_recommendations_section(analysis_result: AnalysisResult) -> str` - Generate recommendations

**Markdown Structure**:
```markdown
# Graviton Compatibility Analysis Report

## Executive Summary
- Total Components: 100
- Compatible: 80 (80%)
- Issues Found: 20

## Compatibility Overview
| Status | Count | Percentage |
|--------|-------|------------|
| Compatible | 80 | 80% |
| Incompatible | 10 | 10% |

## Detailed Analysis Results
[Component table with details]

## Issues Requiring Attention
[List of problematic components]

## Recommendations
[Upgrade suggestions and next steps]
```

**Usage**: Generates documentation-friendly Markdown reports for technical teams.

### HumanReadableReporter (ReportGenerator)
**Location**: `graviton_validator/reporting/text_reporter.py`
**Purpose**: Generates human-readable text reports for console output

**Constructor Parameters**:
- `detailed: bool = False` - Include detailed component information

**Key Methods**:
- `generate_report(analysis_result: AnalysisResult) -> str` - Generate text report
- `_generate_summary(analysis_result: AnalysisResult) -> str` - Generate summary section
- `_generate_detailed_results(analysis_result: AnalysisResult) -> str` - Generate detailed results
- `_format_component_result(component_result: ComponentResult) -> str` - Format single component

**Text Format**:
```
Graviton Compatibility Analysis Report
=====================================

Summary:
  Total Components: 100
  Compatible: 80 (80.0%)
  Incompatible: 10 (10.0%)
  Needs Upgrade: 5 (5.0%)
  Unknown: 5 (5.0%)

Issues Found: 20 components require attention

[Detailed component list if --verbose-output flag used]
```

**Usage**: Generates console-friendly text reports for command-line usage.

---

## Utility & Support Classes

### RuntimeResultValidator
**Location**: `graviton_validator/validation/runtime_result_validator.py`
**Purpose**: Validates runtime analysis results for schema compliance

**Key Methods**:
- `validate_single(result: dict) -> dict` - Validate single result
- `validate_batch(results: List[dict]) -> List[dict]` - Validate batch of results
- `_validate_required_fields(result: dict) -> dict` - Check required fields
- `_normalize_status(status: str) -> str` - Normalize status values
- `_ensure_compatibility_structure(result: dict) -> dict` - Ensure compatibility structure

**Validation Rules**:
1. **Required Fields**: Ensures name, version, compatibility fields exist
2. **Status Normalization**: Normalizes status values to standard set
3. **Structure Validation**: Ensures proper nested structure
4. **Type Checking**: Validates field types and formats

**Usage**: Ensures runtime analysis results conform to expected schema.

### PrerequisiteChecker
**Location**: `graviton_validator/prerequisites.py`
**Purpose**: Checks for required tools and dependencies

**Key Methods**:
- `check_all_prerequisites(args) -> Tuple[bool, List[str]]` - Check all prerequisites
- `check_runtime_prerequisites(runtime: str) -> Tuple[bool, List[str]]` - Check runtime tools
- `check_basic_tools() -> Tuple[bool, List[str]]` - Check basic tools
- `get_installation_instructions(missing_tools: List[str]) -> str` - Get installation help

**Prerequisite Categories**:
1. **Basic Tools**: Python 3, pip, curl, jq
2. **Runtime Tools**: Maven, npm, dotnet, ruby, bundler
3. **Container Tools**: Docker or Podman (for container mode)
4. **Optional Tools**: Additional tools for enhanced features

**Usage**: Validates environment before running analysis to prevent failures.

### PatternValidator
**Location**: `graviton_validator/pattern_validator.py`
**Purpose**: Validates regex patterns in configuration

**Key Methods**:
- `validate_filtering_config(config: FilteringConfig) -> List[str]` - Validate filtering patterns
- `validate_pattern(pattern: str, timeout: float = 1.0) -> bool` - Validate single pattern
- `_test_pattern_performance(pattern: str, timeout: float) -> bool` - Test pattern performance

**Validation Logic**:
1. **Syntax Validation**: Checks regex syntax correctness
2. **Performance Testing**: Tests pattern against sample strings
3. **Timeout Protection**: Prevents catastrophic backtracking
4. **Error Collection**: Collects all validation errors

**Usage**: Ensures regex patterns in configuration are valid and performant.

### DenyListLoader
**Location**: `graviton_validator/deny_list/loader.py`
**Purpose**: Loads and manages deny list entries

**Key Methods**:
- `load_from_file(file_path: str)` - Load deny list from file
- `load_from_directory(directory_path: str)` - Load all deny lists from directory
- `is_denied(package_name: str) -> bool` - Check if package is denied
- `get_deny_entry(package_name: str) -> Optional[DenyListEntry]` - Get deny entry details

**Loading Logic**:
1. **File Validation**: Validates JSON structure
2. **Entry Processing**: Converts to DenyListEntry objects
3. **Merging**: Combines multiple deny list files
4. **Indexing**: Creates fast lookup index by package name

**Usage**: Manages packages that are explicitly incompatible with Graviton.

### DenyListEntry (dataclass)
**Location**: `graviton_validator/deny_list/models.py`
**Purpose**: Represents a deny list entry

**Fields**:
- `package_name: str` - Package name to deny
- `reason: str` - Reason for incompatibility
- `minimum_supported_version: Optional[str]` - First compatible version if any
- `recommended_alternative: Optional[str]` - Suggested replacement

**Usage**: Data structure for deny list entries with incompatibility details.

---

This completes the comprehensive class documentation covering all major classes in the Graviton Migration Accelerator tool. Each class is documented with its purpose, key methods, implementation details, and usage patterns.