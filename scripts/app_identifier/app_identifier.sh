#!/bin/bash

# Application Identifier for Graviton Migration
# Generates CycloneDX SBOM files for AWS Graviton migration assessment
# See README.md for detailed documentation

# Configuration variables
readonly DEFAULT_TIMEOUT=5
readonly MAX_RETRIES=3
readonly RETRY_DELAY=2
readonly CYCLONE_DX_VERSION="1.5"
readonly SPEC_VERSION="1.5"
readonly KERNEL_PROCESSES=('kthread' 'rcu_[^[:space:]]*' 'slub_[^[:space:]]*' 'netns' 'kworker/' 'mm_[^[:space:]]*' 'ksoftirqd/' 'migration/' 'cpuhp/[0-9]+' 'kdevtmpfs' 'kauditd' 'khungtaskd' 'oom_reaper' 'writeback' 'kcompactd[0-9]*' 'khugepaged' 'kintegrityd' 'kblockd' 'kswapd[0-9]*' 'watchdogd' 'irq/[^[:space:]]*')
readonly FILESYSTEM_PROCESSES=('xfsalloc' 'xfs[-_][^[:space:]]*' 'jfsIO' 'jfsCommit' 'jfsSync' 'ext4-[^[:space:]]*' 'bio[_-][^[:space:]]*')
readonly NETWORK_PROCESSES=('inet_[^[:space:]]*' 'nvme[^[:space:]]*' 'addrconf' 'kstrp' 'mld' 'ena[^[:space:]]*' 'rpciod' 'xprtiod' 'ipv6_addrconf' 'dhclient' 'tls-strp')
readonly SYSTEM_SERVICES=('systemd(-[^[:space:]]*)?' 'dbus-[^[:space:]]*' 'sshd:' 'sd-pam' 'login' 'getty' 'agetty' 'cron' 'atd' 'rsyslogd' 'systemd-[^[:space:]]*' 'auditd' 'lsmd' 'rngd' 'acpid' 'gssproxy' 'chronyd' 'sudo' 'su' 'awk' 'sed' 'cut' 'sort' 'uniq' 'head' 'tail' 'wc' 'tr' 'find' 'xargs')
readonly UTILITY_PROCESSES=('ps -eo' 'grep' '\[.*\]' 'bash$' 'sh$' 'sudo$' 'sleep' 'true' 'false')

# Version patterns for matching
readonly VERSION_PATTERNS=(
    '--version[=\ ]([0-9]+\.[0-9]+\.[0-9]+)'
    '-v[=\ ]([0-9]+\.[0-9]+\.[0-9]+)'
    'version[=\ ]([0-9]+\.[0-9]+\.[0-9]+)'
    'v([0-9]+\.[0-9]+\.[0-9]+)'
    '([0-9]+\.[0-9]+\.[0-9]+)'
    '([0-9]+\.[0-9]+)'
)

# Package managers and their version commands
declare -A PACKAGE_MANAGERS=(
    ["rpm"]="rpm -qa --qf '%{NAME} %{VERSION}\n'"
    ["dpkg"]="dpkg-query -W -f='\${Package} \${Version}\n'"
)

# Global log level configuration
LOG_LEVEL=${DEFAULT_LOG_LEVEL:-INFO}

# Function to generate default output filename
get_default_output_file() {
    local instance_id=""
    local hostname="$(hostname)"
    local timestamp="$(date +%Y%m%d-%H%M%S)"
    local token=""
    
    # Try to get EC2 instance ID using IMDSv2 first, then fallback to IMDSv1
    token=$(curl -s -f -m 2 -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" 2>/dev/null)
    
    if [[ -n "$token" ]]; then
        instance_id=$(curl -s -f -m 2 -H "X-aws-ec2-metadata-token: $token" "http://169.254.169.254/latest/meta-data/instance-id" 2>/dev/null)
    else
        instance_id=$(curl -s -f -m 2 "http://169.254.169.254/latest/meta-data/instance-id" 2>/dev/null)
    fi
    
    if [[ -n "$instance_id" ]]; then
        echo "${hostname}-${instance_id}-${timestamp}.sbom.json"
    else
        echo "${hostname}-${timestamp}.sbom.json"
    fi
}

# Function to display usage information
show_usage() {
    local default_file=$(get_default_output_file)
    cat << EOF
Application Identifier for Graviton Migration Accelerator (SBOM Output)

Usage: $(basename "$0") [output_file]
  output_file: Path to save results (default: $default_file)

Environment variables:
  DEFAULT_LOG_LEVEL: Set logging verbosity (DEBUG, INFO, WARNING, ERROR) - default: INFO

Example:
  $(basename "$0")
  DEFAULT_LOG_LEVEL=DEBUG $(basename "$0") ./custom_output.sbom.json
EOF
}

# Logging function
log() {
    local level="$1"
    local message="$2"
    local timestamp="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    
    local -A log_priorities=(
        ["DEBUG"]=1
        ["INFO"]=2
        ["WARNING"]=3
        ["ERROR"]=4
    )
    
    local current_priority=${log_priorities[$LOG_LEVEL]}
    local message_priority=${log_priorities[$level]}
    
    if [[ -n "$message_priority" && "$message_priority" -ge "$current_priority" ]]; then
        #printf '%s {"level":"%s","timestamp":"%s","script":"%s","message":"%s"}\n' \
        #    "$timestamp" "$level" "$timestamp" "${0##*/}" "$message" >&2
        echo "$timestamp - $level - $message" >&2
    fi
}

trap 'log "ERROR" "Script interrupted"; exit 1' INT TERM

# Create secure temporary file
create_secure_temp() {
    local prefix="app_identifier_"
    local temp_dir
    local temp_file

    if [[ -d "/dev/shm" && -w "/dev/shm" ]]; then
        temp_dir="/dev/shm"
    else
        temp_dir="/tmp"
    fi

    temp_file=$(mktemp "${temp_dir}/${prefix}XXXXXX") || {
        log "ERROR" "Failed to create temporary file"
        return 1
    }

    chmod 600 "$temp_file" || {
        log "ERROR" "Failed to set permissions on temporary file"
        rm -f "$temp_file"
        return 1
    }

    echo "$temp_file"
}

# Check required commands
log "DEBUG" "Checking prerequisites"
readonly REQUIRED_COMMANDS=("jq" "awk" "grep" "timeout" "free" "lscpu" "ps" "hostname" "curl" "ip" "nproc")
readonly UUID_COMMANDS=("uuidgen" "uuid")
readonly OPTIONAL_COMMANDS=("rpm" "dpkg" "apk" "pacman")

# Check required commands
for cmd in "${REQUIRED_COMMANDS[@]}"; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        log "ERROR" "Required command not found: $cmd"
        exit 1
    else
        log "DEBUG" "Found required command: $cmd at $(command -v "$cmd")"
    fi
done

# Check for at least one package manager
pkg_manager_found=false
for cmd in "${OPTIONAL_COMMANDS[@]}"; do
    if command -v "$cmd" >/dev/null 2>&1; then
        pkg_manager_found=true
        log "DEBUG" "Found package manager: $cmd at $(command -v "$cmd")"
        break
    else
        log "DEBUG" "Package manager not found: $cmd"
    fi
done

if [[ "$pkg_manager_found" == "false" ]]; then
    log "WARNING" "No supported package manager found (rpm/dpkg/apk/pacman). Package information will be limited."
fi

# Check for UUID generation command
uuid_cmd_found=false
for cmd in "${UUID_COMMANDS[@]}"; do
    if command -v "$cmd" >/dev/null 2>&1; then
        uuid_cmd_found=true
        log "DEBUG" "Found UUID command: $cmd at $(command -v "$cmd")"
        break
    else
        log "DEBUG" "UUID command not found: $cmd"
    fi
done

if [[ "$uuid_cmd_found" == "false" ]]; then
    log "ERROR" "No UUID generation command found (uuidgen/uuid)"
    exit 1
fi

# Check required files/directories
if [[ ! -r "/proc/meminfo" ]]; then
    log "ERROR" "Cannot read /proc/meminfo - required for memory information"
    exit 1
fi

if [[ ! -r "/proc" ]]; then
    log "ERROR" "Cannot access /proc filesystem - required for process information"
    exit 1
fi

log "DEBUG" "All prerequisites satisfied"

# Function to generate UUID across distributions
generate_uuid() {
    if command -v uuidgen >/dev/null 2>&1; then
        log "DEBUG" "Using uuidgen for UUID generation"
        uuidgen | tr '[:upper:]' '[:lower:]'
    elif command -v uuid >/dev/null 2>&1; then
        log "DEBUG" "Using uuid command for UUID generation"
        uuid -v4 | tr '[:upper:]' '[:lower:]'
    else
        # Fallback: generate pseudo-UUID using /proc/sys/kernel/random/uuid if available
        if [[ -r /proc/sys/kernel/random/uuid ]]; then
            log "DEBUG" "Using /proc/sys/kernel/random/uuid for UUID generation"
            cat /proc/sys/kernel/random/uuid
        else
            # Last resort: generate using date and random
            log "DEBUG" "Using fallback random UUID generation"
            printf '%08x-%04x-%04x-%04x-%012x\n' \
                $((RANDOM * RANDOM)) \
                $((RANDOM % 65536)) \
                $((RANDOM % 65536)) \
                $((RANDOM % 65536)) \
                $((RANDOM * RANDOM * RANDOM))
        fi
    fi
}

# Function to build exclude pattern
build_exclude_pattern() {
    local patterns=()
    
    # Add all process patterns with proper grouping
    patterns+=("${KERNEL_PROCESSES[@]}")
    patterns+=("${FILESYSTEM_PROCESSES[@]}")
    patterns+=("${NETWORK_PROCESSES[@]}")
    patterns+=("${SYSTEM_SERVICES[@]}")
    patterns+=("${UTILITY_PROCESSES[@]}")
    
    # Join patterns with | and wrap in parentheses
    # IFS is set in subshell scope only, does not affect global scope
    # nosemgrep
    local exclude_pattern=$(IFS='|'; echo "${patterns[*]}" | sed 's/\[\-/[-/g')
    echo "$exclude_pattern"
}

# Function to detect package manager
detect_package_manager() {
    log "DEBUG" "Detecting package manager"
    
    # Check for Alpine Linux (apk)
    if command -v apk &> /dev/null; then
        echo "alpine"
    # Check for Arch Linux (pacman)
    elif command -v pacman &> /dev/null; then
        echo "arch"
    # Check for RPM-based systems (RHEL, CentOS, Fedora, Amazon Linux)
    elif command -v rpm &> /dev/null; then
        # Check if it's openSUSE/SLES
        if [[ -f /etc/os-release ]] && grep -qi "suse" /etc/os-release; then
            echo "suse"
        else
            echo "rpm"
        fi
    # Check for Debian-based systems (Ubuntu, Debian)
    elif command -v dpkg &> /dev/null; then
        echo "debian"
    else
        echo "unknown"
    fi
}

# Function to get installed packages
get_installed_packages() {
    local package_manager="$1"
    local temp_file="$2"
    local retry_count=0
    
    log "DEBUG" "Getting installed packages using $package_manager"
    
    while ((retry_count < MAX_RETRIES)); do
        case "$package_manager" in
            "rpm"|"suse")
                log "DEBUG" "Attempting RPM package query (attempt $((retry_count + 1)))"
                if rpm -qa --queryformat '%{NAME}\t%{VERSION}\t%{VENDOR}\t%{SUMMARY}\n' > "$temp_file" 2>/dev/null; then
                    local pkg_count=$(wc -l < "$temp_file")
                    log "DEBUG" "RPM query successful, found $pkg_count packages"
                    break
                fi
                ;;
            "debian")
                log "DEBUG" "Attempting DPKG package query (attempt $((retry_count + 1)))"
                if dpkg-query -W -f='${Package}\t${Version}\t${Maintainer}\t${Description}\n' > "$temp_file" 2>/dev/null; then
                    local pkg_count=$(wc -l < "$temp_file")
                    log "DEBUG" "DPKG query successful, found $pkg_count packages"
                    break
                fi
                ;;
            "alpine")
                log "DEBUG" "Attempting APK package query (attempt $((retry_count + 1)))"
                if apk info -v 2>/dev/null | awk '
                    function join(arr,start,end,sep) {
                        result=arr[start]
                        for(i=start+1;i<=end;i++) 
                            result=result sep arr[i]
                        return result
                    }
                    {
                        split($1,a,"-")
                        ver=a[length(a)]
                        delete a[length(a)]
                        name=join(a,1,length(a),"-")
                        print name "\t" ver "\tAlpine\tAlpine package"
                    }' > "$temp_file"; then
                    local pkg_count=$(wc -l < "$temp_file")
                    log "DEBUG" "APK query successful, found $pkg_count packages"
                    break
                fi
                ;;
            "arch")
                log "DEBUG" "Attempting Pacman package query (attempt $((retry_count + 1)))"
                if pacman -Q 2>/dev/null | awk '{print $1 "\t" $2 "\tArch Linux\tArch package"}' > "$temp_file"; then
                    local pkg_count=$(wc -l < "$temp_file")
                    log "DEBUG" "Pacman query successful, found $pkg_count packages"
                    break
                fi
                ;;
        esac
        
        ((retry_count++))
        log "WARNING" "Package query failed, retry $retry_count of $MAX_RETRIES for $package_manager"
        sleep "$RETRY_DELAY"
    done
    
    if [[ ! -s "$temp_file" ]]; then
        log "ERROR" "Failed to get package list after $MAX_RETRIES attempts using $package_manager"
        return 1
    fi
}

# Function to get running processes
get_running_processes() {
    local temp_file="$1"
    
    log "DEBUG" "Getting running processes"
    readonly EXCLUDE_PATTERN=$(build_exclude_pattern)
    log "DEBUG" "EXCLUDE_PATTERN: $EXCLUDE_PATTERN"
    ps -eo user,pid,comm,args --no-headers | grep -vE "${EXCLUDE_PATTERN}" | \
        awk '{printf "%s\t%s\t%s\t%s\n", $1, $2, $3, substr($0, index($0,$4))}' > "$temp_file"
    
    if [[ ! -s "$temp_file" ]]; then
        log "ERROR" "Failed to get process list"
        return 1
    fi
}

# Function to extract version from command or binary
get_version_from_name() {
    local input="$1"
    local version=""

    # Try each version pattern and validate
    for pattern in "${VERSION_PATTERNS[@]}"; do
        if [[ "$input" =~ $pattern ]]; then
            local candidate="${BASH_REMATCH[1]}"
            
            # Skip if candidate is part of an IP address in the input
            if [[ "$input" =~ [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+ ]] && [[ "${BASH_REMATCH[0]}" == *"$candidate"* ]]; then
                log "DEBUG" "Skipping version '$candidate' - part of IP address ${BASH_REMATCH[0]}"
                continue
            fi
            
            version="$candidate"
            log "DEBUG" "Extracted version '$version' from '$input'"
            break
        fi
    done

    echo "$version"
}

# Function to get version from package
get_version_from_package() {
    local process_name="$1"
    local package_list="$2"
    
    log "DEBUG" "Searching for package version for process: $process_name"
    
    # Try exact match first with word boundaries
    local version=$(grep -P "^${process_name}\t" "$package_list" | cut -f2)
    if [[ -n "$version" ]]; then
        log "DEBUG" "Found exact package match for $process_name: version $version"
        echo "$version"
        return 0
    fi
    
    # Try partial match with word boundaries
    local pkg_info=$(grep -iP "\b${process_name}\b" "$package_list" | head -1)
    if [[ -n "$pkg_info" ]]; then
        version=$(echo "$pkg_info" | cut -f2)
        local pkg_name=$(echo "$pkg_info" | cut -f1)
        log "DEBUG" "Found partial package match: $pkg_name for process $process_name: version $version"
        echo "$version"
        return 0
    fi
    
    # Try fuzzy match as last resort
    pkg_info=$(grep -i "$process_name" "$package_list" | head -1)
    if [[ -n "$pkg_info" ]]; then
        version=$(echo "$pkg_info" | cut -f2)
        local pkg_name=$(echo "$pkg_info" | cut -f1)
        log "DEBUG" "Found fuzzy package match: $pkg_name for process $process_name: version $version"
        echo "$version"
        return 0
    fi
    
    return 1
}

# Function to generate SBOM-compatible output
generate_sbom_output() {
    local output_file="$1"
    local running_apps=("${!2}")
    local installed_pkgs=("${!3}")
    local system_info="$4"
    local errors="$5"
    
    log "INFO" "Generating SBOM-compatible output"
    
    local serial_number="urn:uuid:$(generate_uuid)"
    local timestamp="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    
    local hostname=$(echo "$system_info" | jq -r '.hostname')
    local os_name=$(echo "$system_info" | jq -r '.os.name')
    local os_version=$(echo "$system_info" | jq -r '.os.version')
    local architecture=$(echo "$system_info" | jq -r '.architecture')
    
    # Create temporary file for components to avoid "Argument list too long" error
    local components_file=$(mktemp)
    echo '[]' > "$components_file"
    
    # Add installed packages as components
    for pkg in "${installed_pkgs[@]}"; do
        local name=$(echo "$pkg" | jq -r '.name')
        local version=$(echo "$pkg" | jq -r '.version')
        local vendor=$(echo "$pkg" | jq -r '.vendor // "Unknown"')
        local description=$(echo "$pkg" | jq -r '.description // ""')
        
        jq --argjson component "$(jq -n \
            --arg type "library" \
            --arg bom_ref "${name}@${version}" \
            --arg name "$name" \
            --arg version "$version" \
            --arg vendor "$vendor" \
            --arg description "$description" \
            '{
                "type": $type,
                "bom-ref": $bom_ref,
                "name": $name,
                "version": $version,
                "supplier": {
                    "name": $vendor
                },
                "description": $description,
                "scope": "required",
                "properties": [
                    {
                        "name": "package:type",
                        "value": "system-package"
                    }
                ]
            }')" '. += [$component]' "$components_file" > "${components_file}.tmp" && mv "${components_file}.tmp" "$components_file"
    done
    
    # Add running applications as components
    for app in "${running_apps[@]}"; do
        local name=$(echo "$app" | jq -r '.name')
        local version=$(echo "$app" | jq -r '.version // "unknown"')
        local pid=$(echo "$app" | jq -r '.pid')
        local user=$(echo "$app" | jq -r '.user')
        local command=$(echo "$app" | jq -r '.command')
        local version_source=$(echo "$app" | jq -r '.version_source')
        local package_owner=$(echo "$app" | jq -r '.package_owner // ""')
        
        # Add version detection method to description only if version was detected
        local description="Running application: $command"
        if [[ "$version" != "unknown" && "$version_source" != "none" ]]; then
            description="Running application: $command (version detected via $version_source)"
        fi
        if [[ -n "$package_owner" ]]; then
            description="$description [Package: $package_owner]"
        fi
        
        # Create component with conditional package owner property
        if [[ -n "$package_owner" ]]; then
            jq --argjson component "$(jq -n \
                --arg type "application" \
                --arg bom_ref "${name}@${version}:${pid}" \
                --arg name "$name" \
                --arg version "$version" \
                --arg description "$description" \
                --arg pid "$pid" \
                --arg user "$user" \
                --arg version_source "$version_source" \
                --arg package_owner "$package_owner" \
                '{
                    "type": $type,
                    "bom-ref": $bom_ref,
                    "name": $name,
                    "version": $version,
                    "description": $description,
                    "scope": "required",
                    "properties": [
                        {
                            "name": "process:pid",
                            "value": $pid
                        },
                        {
                            "name": "process:user",
                            "value": $user
                        },
                        {
                            "name": "version:source",
                            "value": $version_source
                        },
                        {
                            "name": "package:owner",
                            "value": $package_owner
                        }
                    ]
                }')" '. += [$component]' "$components_file" > "${components_file}.tmp" && mv "${components_file}.tmp" "$components_file"
        else
            jq --argjson component "$(jq -n \
                --arg type "application" \
                --arg bom_ref "${name}@${version}:${pid}" \
                --arg name "$name" \
                --arg version "$version" \
                --arg description "$description" \
                --arg pid "$pid" \
                --arg user "$user" \
                --arg version_source "$version_source" \
                '{
                    "type": $type,
                    "bom-ref": $bom_ref,
                    "name": $name,
                    "version": $version,
                    "description": $description,
                    "scope": "required",
                    "properties": [
                        {
                            "name": "process:pid",
                            "value": $pid
                        },
                        {
                            "name": "process:user",
                            "value": $user
                        },
                        {
                            "name": "version:source",
                            "value": $version_source
                        }
                    ]
                }')" '. += [$component]' "$components_file" > "${components_file}.tmp" && mv "${components_file}.tmp" "$components_file"
        fi
    done
    
    # Generate final SBOM
    jq -n \
        --arg bomFormat "CycloneDX" \
        --arg specVersion "$SPEC_VERSION" \
        --arg serialNumber "$serial_number" \
        --arg timestamp "$timestamp" \
        --arg hostname "$hostname" \
        --arg os_name "$os_name" \
        --arg os_version "$os_version" \
        --arg architecture "$architecture" \
        --slurpfile components "$components_file" \
        --argjson system_info "$system_info" \
        --arg errors "$errors" \
        '{
            "bomFormat": $bomFormat,
            "specVersion": $specVersion,
            "serialNumber": $serialNumber,
            "version": 1,
            "metadata": {
                "timestamp": $timestamp,
                "tools": [
                    {
                        "vendor": "AWS",
                        "name": "graviton-migration-accelerator",
                        "version": "1.0.0"
                    }
                ],
                "component": {
                    "type": "operating-system",
                    "name": ($os_name + " (" + $hostname + ")"),
                    "version": $os_version,
                    "description": ("System: " + $os_name + " " + $os_version + " on " + $architecture)
                },
                "system": $system_info
            },
            "components": $components[0],
            "properties": [
                {
                    "name": "scan:errors",
                    "value": $errors
                }
            ]
        }' > "$output_file"
    
    # Clean up temporary file
    rm -f "$components_file"
}

# Function to find which package owns an executable file
get_package_owner() {
    local executable="$1"
    local package_manager="$2"
    
    log "DEBUG" "Finding package owner for: $executable"
    
    # Skip if executable path is not absolute or doesn't exist
    if [[ ! "$executable" =~ ^/ ]] || [[ ! -e "$executable" ]]; then
        log "DEBUG" "Executable not found or not absolute path: $executable"
        return 1
    fi
    
    local owner_info=""
    
    case "$package_manager" in
        "rpm")
            # Use rpm -qf to find package owner
            if owner_info=$(rpm -qf "$executable" 2>/dev/null); then
                log "DEBUG" "RPM package owner found: $owner_info"
                echo "$owner_info"
                return 0
            fi
            ;;
        "debian")
            # Use dpkg -S to find package owner
            if owner_info=$(dpkg -S "$executable" 2>/dev/null | cut -d: -f1); then
                log "DEBUG" "DEB package owner found: $owner_info"
                echo "$owner_info"
                return 0
            fi
            ;;
        "alpine")
            # Use apk info --who-owns to find package owner
            if owner_info=$(apk info --who-owns "$executable" 2>/dev/null | grep -o '^[^[:space:]]*'); then
                log "DEBUG" "APK package owner found: $owner_info"
                echo "$owner_info"
                return 0
            fi
            ;;
        "arch")
            # Use pacman -Qo to find package owner
            if owner_info=$(pacman -Qo "$executable" 2>/dev/null | awk '{print $5}'); then
                log "DEBUG" "Pacman package owner found: $owner_info"
                echo "$owner_info"
                return 0
            fi
            ;;
        "suse")
            # Use rpm -qf for openSUSE (uses RPM but different detection)
            if owner_info=$(rpm -qf "$executable" 2>/dev/null); then
                log "DEBUG" "SUSE RPM package owner found: $owner_info"
                echo "$owner_info"
                return 0
            fi
            ;;
    esac
    
    log "DEBUG" "No package owner found for: $executable"
    return 1
}

# Function to get version from binary
get_version_from_binary() {
    local pid="$1"
    local comm="$2"
    
    local executable=""
    
    # Try to get full executable path from /proc/PID/exe
    if [[ -r "/proc/$pid/exe" ]]; then
        executable=$(readlink -f "/proc/$pid/exe" 2>/dev/null)
        if [[ -n "$executable" && -x "$executable" ]]; then
            log "DEBUG" "Using full executable path: $executable"
        else
            executable="$comm"
            log "DEBUG" "Failed to get full path, using comm: $executable"
        fi
    else
        executable="$comm"
        log "DEBUG" "No permission to read /proc/$pid/exe, using comm: $executable"
    fi
    
    log "DEBUG" "Attempting to get version from binary: $executable"
    local version_args=("--version" "-v" "-V" "version")
    
    for arg in "${version_args[@]}"; do
        log "DEBUG" "Trying $executable $arg"
        
        local output
        # Use command substitution with error redirection and timeout
        if output=$(timeout 3 "$executable" "$arg" 2>&1) && [[ -n "$output" ]]; then
            # Look for X.Y.Z pattern first
            version=$(echo "$output" | grep -Po '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
            if [[ -n $version ]]; then
                log "DEBUG" "Found version $version from $executable $arg (X.Y.Z pattern)"
                echo "$version"
                return 0
            fi
            
            # Look for X.Y pattern
            version=$(echo "$output" | grep -Po '[0-9]+\.[0-9]+(?!\.[0-9])' | head -1)
            if [[ -n $version ]]; then
                log "DEBUG" "Found version $version from $executable $arg (X.Y pattern)"
                echo "$version"
                return 0
            fi
        fi
    done
    
    return 1
}

# Function to get version information and package ownership
get_version_info() {
    local name="$1"
    local pid="$2"
    local command="$3"
    local package_list="$4"
    local package_manager="$5"
    
    local version=""
    local source=""
    local package_owner=""
    local executable=""
    
    log "DEBUG" "Starting version detection for '$name'"
    
    # Get executable path for package ownership lookup
    if [[ -r "/proc/$pid/exe" ]]; then
        executable=$(readlink -f "/proc/$pid/exe" 2>/dev/null)
        if [[ -n "$executable" && -e "$executable" ]]; then
            log "DEBUG" "Found executable path: $executable"
            # Try to find package owner
            package_owner=$(get_package_owner "$executable" "$package_manager")
            if [[ -n "$package_owner" ]]; then
                log "DEBUG" "Found package owner: $package_owner"
            fi
        fi
    fi
    
    # Method 1: Try binary version (most reliable)
    version=$(get_version_from_binary "$pid" "$name")
    if [[ -n "$version" ]]; then
        source="binary"
        log "DEBUG" "Found version $version from binary"
        echo "$version:$source:$package_owner"
        return 0
    fi

    # Method 2: Check package information (system verified)
    version=$(get_version_from_package "$name" "$package_list")
    if [[ -n "$version" ]]; then
        source="package"
        log "DEBUG" "Found version $version from package information"
        echo "$version:$source:$package_owner"
        return 0
    fi
    
    # Method 3: Extract from command line (fallback, prone to false positives)
    version=$(get_version_from_name "$command")
    if [[ -n "$version" ]]; then
        source="command_line"
        log "DEBUG" "Found version $version from command line"
        echo "$version:$source:$package_owner"
        return 0
    fi
    
    log "DEBUG" "No version found for '$name'"
    echo "unknown:none:$package_owner"
}

# Function to create and manage package index for efficient lookups
create_package_index() {
    local pkg_list="$1"
    local index_file="$2"
    local temp_index="${index_file}.tmp"
    
    log "DEBUG" "Starting package index creation from: $pkg_list"

    # Validate input file
    if [[ ! -f "$pkg_list" ]]; then
        log "ERROR" "Package list file not found: $pkg_list"
        return 1
    fi

    if [[ ! -s "$pkg_list" ]]; then
        log "ERROR" "Package list file is empty: $pkg_list"
        return 1
    fi

    log "DEBUG" "Validating package list file format"
    # Check if file has the expected format (tab-separated)
    if ! grep -q $'\t' "$pkg_list"; then
        log "ERROR" "Package list file does not have the expected tab-separated format"
        return 1
    fi

    # Create temporary index
    log "DEBUG" "Creating temporary index file: $temp_index"
    {
        # Process the package list and create the index
        # Format: name<tab>version<tab>normalized_name
        awk -F'\t' '
        BEGIN {
            OFS="\t"
        }
        function normalize(str) {
            # Convert to lowercase and remove special characters
            gsub(/[^a-zA-Z0-9]/, "", str)
            return tolower(str)
        }
        {
            if (NF >= 2) {
                normalized = normalize($1)
                if (length(normalized) > 0) {
                    print $1, $2, normalized
                }
            }
        }' "$pkg_list" > "$temp_index"
    } 2> >(while read -r line; do log "ERROR" "awk error: $line"; done)

    # Verify temporary index was created successfully
    if [[ ! -s "$temp_index" ]]; then
        log "ERROR" "Failed to create temporary index file"
        rm -f "$temp_index"
        return 1
    fi

    # Sort the index for faster lookups
    log "DEBUG" "Sorting package index"
    if ! sort -k3,3 -k1,1 "$temp_index" > "$index_file"; then
        log "ERROR" "Failed to sort package index"
        rm -f "$temp_index" "$index_file"
        return 1
    fi

    # Clean up temporary file
    rm -f "$temp_index"

    # Verify final index
    local index_count=$(wc -l < "$index_file")
    log "DEBUG" "Created package index with $index_count entries"

    return 0
}

# Function to search the index
search_package_index() {
    local search_term="$1"
    local index_file="$2"

    if [[ ! -f "$index_file" ]]; then
        log "ERROR" "Index file not found: $index_file"
        return 1
    fi

    local normalized_term=$(echo "$search_term" | tr -cd '[:alnum:]' | tr '[:upper:]' '[:lower:]')
    
    log "DEBUG" "Searching index for: $search_term (normalized: $normalized_term)"
    
    # Look for exact matches first
    local exact_match=$(grep -m 1 "^[^\t]*\t[^\t]*\t${normalized_term}$" "$index_file")
    if [[ -n "$exact_match" ]]; then
        log "DEBUG" "Found exact match: $exact_match"
        echo "$exact_match"
        return 0
    fi
    
    # Look for partial matches
    local partial_matches=$(grep -m 5 "$normalized_term" "$index_file")
    if [[ -n "$partial_matches" ]]; then
        log "DEBUG" "Found partial matches:"
        echo "$partial_matches" | while read -r match; do
            log "DEBUG" "  $match"
        done
        echo "$partial_matches"
        return 0
    fi
    
    log "DEBUG" "No matches found for: $search_term"
    return 1
}

validate_version() {
    local version="$1"
    local valid_pattern='^[0-9]+\.[0-9]+(\.[0-9]+)?([-.][a-zA-Z0-9]+)?$'
    
    if [[ "$version" =~ $valid_pattern ]]; then
        return 0
    fi
    return 1
}

# =============================================================================
# Container Discovery Functions
# =============================================================================

# Runtime manifest files to scan for inside container filesystems
readonly CONTAINER_MANIFEST_NAMES=(
    "requirements.txt" "Pipfile" "pyproject.toml"
    "package.json"
    "pom.xml" "build.gradle"
    "Gemfile" "*.gemspec"
    "*.csproj" "packages.config"
)

# Detect available container runtime (read-only check)
detect_container_runtime() {
    for rt in crictl docker podman nerdctl; do
        if command -v "$rt" >/dev/null 2>&1; then
            log "DEBUG" "Found container runtime: $rt"
            echo "$rt"
            return 0
        fi
    done
    log "DEBUG" "No container runtime found"
    return 1
}

# List running containers. Outputs: container_id<tab>container_name<tab>image_name
list_running_containers() {
    local runtime="$1"
    log "DEBUG" "Listing running containers via $runtime"

    case "$runtime" in
        crictl)
            crictl ps -o json 2>/dev/null | jq -r '
                .containers[]? |
                "\(.id)\t\(.metadata.name // .id[:12])\t\(.image.image // .imageRef)"
            ' 2>/dev/null
            ;;
        docker|podman|nerdctl)
            "$runtime" ps --format '{{.ID}}\t{{.Names}}\t{{.Image}}' --no-trunc 2>/dev/null
            ;;
    esac
}

# Get the merged/root filesystem path for a container (read-only inspect)
get_container_rootfs() {
    local runtime="$1"
    local container_id="$2"

    case "$runtime" in
        crictl)
            crictl inspect "$container_id" 2>/dev/null | jq -r '.info.runtimeSpec.root.path // empty' 2>/dev/null
            ;;
        docker|podman|nerdctl)
            "$runtime" inspect "$container_id" --format '{{.GraphDriver.Data.MergedDir}}' 2>/dev/null
            ;;
    esac
}

# Attempt to detect base image from OCI labels or layer history
detect_base_image() {
    local runtime="$1"
    local container_id="$2"

    case "$runtime" in
        crictl)
            # Try OCI annotation
            crictl inspect "$container_id" 2>/dev/null | jq -r '
                .info.config.Labels["org.opencontainers.image.base.name"] //
                .info.config.image // empty
            ' 2>/dev/null
            ;;
        docker|podman|nerdctl)
            # Try OCI label first, then image history comment
            local base
            base=$("$runtime" inspect "$container_id" 2>/dev/null | jq -r '
                .[0].Config.Labels["org.opencontainers.image.base.name"] // empty
            ' 2>/dev/null)
            if [[ -z "$base" ]]; then
                local image
                image=$("$runtime" inspect "$container_id" --format '{{.Image}}' 2>/dev/null)
                if [[ -n "$image" ]]; then
                    base=$("$runtime" history "$image" --format '{{.CreatedBy}}' --no-trunc 2>/dev/null | \
                        grep -oP '(?<=FROM )\S+' | tail -1)
                fi
            fi
            echo "$base"
            ;;
    esac
}

# Read OS package database directly from container overlay filesystem
# Outputs tab-separated: name<tab>version<tab>vendor<tab>description
read_container_packages() {
    local rootfs="$1"

    # Debian/Ubuntu - dpkg
    if [[ -f "${rootfs}/var/lib/dpkg/status" ]]; then
        log "DEBUG" "Reading dpkg status from container filesystem"
        awk '/^Package:/{name=$2} /^Version:/{ver=$2} /^Maintainer:/{maint=$2} /^Description:/{desc=substr($0,14)} /^$/{if(name!="" && ver!="") print name"\t"ver"\t"maint"\t"desc; name="";ver="";maint="";desc=""}' \
            "${rootfs}/var/lib/dpkg/status" 2>/dev/null
        return
    fi

    # RHEL/Amazon Linux - rpm
    local rpmdb=""
    for candidate in "${rootfs}/var/lib/rpm" "${rootfs}/usr/lib/sysimage/rpm"; do
        if [[ -d "$candidate" ]]; then
            rpmdb="$candidate"
            break
        fi
    done
    if [[ -n "$rpmdb" ]]; then
        log "DEBUG" "Reading rpm db from container filesystem"
        rpm --dbpath "$rpmdb" -qa --queryformat '%{NAME}\t%{VERSION}\t%{VENDOR}\t%{SUMMARY}\n' 2>/dev/null
        return
    fi

    # Alpine - apk
    if [[ -f "${rootfs}/lib/apk/db/installed" ]]; then
        log "DEBUG" "Reading apk db from container filesystem"
        awk '/^P:/{name=$0; sub(/^P:/,"",name)} /^V:/{ver=$0; sub(/^V:/,"",ver)} /^$/{if(name!="" && ver!="") print name"\t"ver"\tAlpine\tAlpine package"; name="";ver=""}' \
            "${rootfs}/lib/apk/db/installed" 2>/dev/null
        return
    fi

    log "DEBUG" "No recognized package DB found in container filesystem"
}

# Find runtime manifest files in container filesystem
find_container_manifests() {
    local rootfs="$1"
    local find_args=()

    for name in "${CONTAINER_MANIFEST_NAMES[@]}"; do
        if [[ ${#find_args[@]} -gt 0 ]]; then
            find_args+=("-o")
        fi
        find_args+=("-name" "$name")
    done

    find "$rootfs" -maxdepth 10 \( "${find_args[@]}" \) -not -path "*/node_modules/*" -not -path "*/.venv/*" -not -path "*/site-packages/pip/*" 2>/dev/null
}

# Generate a CycloneDX SBOM for a single container
generate_container_sbom() {
    local output_file="$1"
    local container_name="$2"
    local image_name="$3"
    local base_image="$4"
    local system_info="$5"
    local rootfs="$6"

    local serial_number="urn:uuid:$(generate_uuid)"
    local timestamp="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    local hostname=$(echo "$system_info" | jq -r '.hostname')
    local instance_id=$(echo "$system_info" | jq -r '.ec2.instance_id // empty')

    # Collect packages
    local components_file=$(mktemp)
    echo '[]' > "$components_file"

    # OS-level packages from container filesystem
    local pkg_count=0
    while IFS=$'\t' read -r name version vendor description; do
        [[ -z "$name" || -z "$version" ]] && continue
        jq --argjson c "$(jq -n \
            --arg name "$name" --arg version "$version" \
            --arg vendor "${vendor:-Unknown}" --arg desc "${description:-}" \
            '{type:"library","bom-ref":($name+"@"+$version),name:$name,version:$version,supplier:{name:$vendor},description:$desc,properties:[{name:"package:type",value:"container-os-package"}]}'
        )" '. += [$c]' "$components_file" > "${components_file}.tmp" && mv "${components_file}.tmp" "$components_file"
        ((pkg_count++))
    done < <(read_container_packages "$rootfs")
    log "DEBUG" "Found $pkg_count OS packages in container $container_name"

    # Runtime manifest files - add as components with file content reference
    local manifest_count=0
    while IFS= read -r manifest_path; do
        [[ -z "$manifest_path" ]] && continue
        local rel_path="${manifest_path#${rootfs}}"
        local manifest_name=$(basename "$manifest_path")
        jq --argjson c "$(jq -n \
            --arg name "$manifest_name" --arg path "$rel_path" \
            '{type:"file","bom-ref":("manifest:"+$path),name:$name,version:"",description:("Runtime manifest: "+$path),properties:[{name:"package:type",value:"container-manifest"},{name:"manifest:path",value:$path}]}'
        )" '. += [$c]' "$components_file" > "${components_file}.tmp" && mv "${components_file}.tmp" "$components_file"
        ((manifest_count++))
    done < <(find_container_manifests "$rootfs")
    log "DEBUG" "Found $manifest_count manifest files in container $container_name"

    # Build SBOM
    jq -n \
        --arg bomFormat "CycloneDX" \
        --arg specVersion "$SPEC_VERSION" \
        --arg serialNumber "$serial_number" \
        --arg timestamp "$timestamp" \
        --arg container_name "$container_name" \
        --arg image_name "$image_name" \
        --arg base_image "${base_image:-unknown}" \
        --arg hostname "$hostname" \
        --arg instance_id "${instance_id:-}" \
        --slurpfile components "$components_file" \
        '{
            bomFormat: $bomFormat,
            specVersion: $specVersion,
            serialNumber: $serialNumber,
            version: 1,
            metadata: {
                timestamp: $timestamp,
                tools: [{vendor:"AWS",name:"graviton-migration-accelerator",version:"1.0.0"}],
                component: {
                    type: "container",
                    name: $container_name,
                    version: $image_name,
                    description: ("Container: " + $container_name + " Image: " + $image_name)
                },
                properties: [
                    {name:"container:image", value:$image_name},
                    {name:"container:base-image", value:$base_image},
                    {name:"container:name", value:$container_name},
                    {name:"instance:hostname", value:$hostname},
                    {name:"instance:id", value:$instance_id}
                ]
            },
            components: $components[0]
        }' > "$output_file"

    rm -f "$components_file"
    log "INFO" "Generated container SBOM: $output_file ($pkg_count packages, $manifest_count manifests)"
}

# =============================================================================
# End Container Discovery Functions
# =============================================================================

# Post-generation container discovery: appends container components to existing host SBOM
discover_containers_post() {
    local host_sbom="$1"
    local output_dir="$2"
    local system_info="$3"

    # Detect runtime
    local runtime
    if ! runtime=$(detect_container_runtime); then
        log "INFO" "No container runtime detected - skipping container discovery"
        return 0
    fi
    log "INFO" "Detected container runtime: $runtime"

    local is_root=false
    [[ $(id -u) -eq 0 ]] && is_root=true

    if [[ "$is_root" != "true" ]]; then
        log "WARNING" "Not running as root - container filesystem inspection will be skipped (container image references will still be added to host SBOM)"
    fi

    local container_count=0
    local seen_images=""

    while IFS=$'\t' read -r cid cname cimage; do
        [[ -z "$cid" ]] && continue
        ((container_count++))
        log "INFO" "Discovered container: $cname (image: $cimage)"

        # Detect base image
        local base_image
        base_image=$(detect_base_image "$runtime" "$cid")

        # Append container component to host SBOM
        local tmp_sbom="${host_sbom}.tmp"
        jq --arg name "$cname" --arg image "$cimage" --arg base "${base_image:-unknown}" \
            '.components += [{
                type: "container",
                "bom-ref": ("container:" + $name),
                name: $name,
                version: $image,
                description: ("Container image: " + $image),
                properties: [
                    {name: "container:image", value: $image},
                    {name: "container:base-image", value: $base},
                    {name: "package:type", value: "container-image"}
                ]
            }]' "$host_sbom" > "$tmp_sbom" && mv "$tmp_sbom" "$host_sbom"

        # Generate per-container SBOM only if root and image not already processed
        if [[ "$is_root" == "true" ]]; then
            if echo "$seen_images" | grep -qF "$cimage"; then
                log "DEBUG" "Skipping duplicate image: $cimage (already scanned)"
                continue
            fi
            seen_images="${seen_images}${cimage}\n"

            local rootfs
            rootfs=$(get_container_rootfs "$runtime" "$cid")
            if [[ -n "$rootfs" && -d "$rootfs" ]]; then
                local safe_name=$(echo "${cname}_${cimage}" | tr '/:' '_')
                local instance_id=$(echo "$system_info" | jq -r '.ec2.instance_id // "unknown"')
                local container_sbom="${output_dir}/sbom_container_${instance_id}_${safe_name}.json"
                generate_container_sbom "$container_sbom" "$cname" "$cimage" "$base_image" "$system_info" "$rootfs"
            else
                log "WARNING" "Could not access rootfs for container $cname ($cid)"
            fi
        fi
    done < <(list_running_containers "$runtime")

    if [[ $container_count -eq 0 ]]; then
        log "INFO" "No running containers found"
    else
        log "INFO" "Discovered $container_count running containers"
    fi
}

# Function to check available memory
check_memory() {
    local available_mem
    # Try different methods to get available memory
    if available_mem=$(free -m 2>/dev/null | awk '/^Mem:/{if(NF>=7) print $7; else if(NF>=4) print $4; else print $2}'); then
        if [[ -n "$available_mem" ]] && ((available_mem < 100)); then
            log "WARNING" "Low memory available: ${available_mem}MB"
            return 1
        fi
    else
        log "DEBUG" "Could not determine available memory, continuing"
    fi
    return 0
}

# Function to validate JSON output
validate_json() {
    local file="$1"
    local schema_check=0
    
    # Check if file exists and is not empty
    if [[ ! -s "$file" ]]; then
        log "ERROR" "JSON file is empty or does not exist: $file"
        return 1
    fi
    
    # Check if it's valid JSON
    if ! jq empty "$file" 2>/dev/null; then
        log "ERROR" "Invalid JSON format in file: $file"
        return 1
    fi
    
    # Check for required fields (SBOM format)
    if ! jq -e '.bomFormat and .metadata.component and .components' "$file" >/dev/null 2>&1; then
        log "ERROR" "Missing required fields in SBOM output"
        return 1
    fi
    
    log "DEBUG" "JSON validation successful"
    return 0
}

# Function to get OS information
get_os_info() {
    log "DEBUG" "Getting OS information"
    local os_name=""
    local os_version=""
    local os_id=""
    local pretty_name=""

    if [ -f /etc/os-release ]; then
        log "DEBUG" "Using /etc/os-release for OS information"
        . /etc/os-release
        os_name=$NAME
        os_version=$VERSION_ID
        os_id=$ID
        pretty_name=$PRETTY_NAME
    else
        log "DEBUG" "No /etc/os-release found, trying alternative methods"
        if [ -f /etc/lsb-release ]; then
            log "DEBUG" "Using /etc/lsb-release for OS information"
            . /etc/lsb-release
            os_name=$DISTRIB_ID
            os_version=$DISTRIB_RELEASE
        elif [ -f /etc/debian_version ]; then
            log "DEBUG" "Using /etc/debian_version for OS information"
            os_name="Debian"
            os_version=$(cat /etc/debian_version)
        elif [ -f /etc/redhat-release ]; then
            log "DEBUG" "Using /etc/redhat-release for OS information"
            os_name=$(cat /etc/redhat-release | cut -d ' ' -f 1)
            os_version=$(cat /etc/redhat-release | sed 's/.*release \([^ ]*\).*/\1/')
        elif [ -f /etc/centos-release ]; then
            log "DEBUG" "Using /etc/centos-release for OS information"
            os_name=$(cat /etc/centos-release | cut -d ' ' -f 1)
            os_version=$(cat /etc/centos-release | sed 's/.*release \([^ ]*\).*/\1/')
        elif [ -f /etc/SuSE-release ]; then
            log "DEBUG" "Using /etc/SuSE-release for OS information"
            os_name="SuSE"
            os_version=$(cat /etc/SuSE-release | tr "\n" ' ' | sed 's/.*= *\([0-9]*\).*/\1/')
        fi
    fi

    if [ -z "$os_name" ]; then
        log "WARNING" "Could not determine OS from release files, using uname"
        os_name=$(uname -s)
        os_version=$(uname -r)
    fi

    log "DEBUG" "OS identified as: $os_name $os_version"
    
    echo "OS Name: $os_name"
    echo "OS Version: $os_version"
    echo "OS ID: $os_id"
    echo "Pretty Name: $pretty_name"
}

# Function to check if running on EC2 instance
is_ec2_instance() {
    log "DEBUG" "Checking if running on EC2 instance"
    
    local token
    token=$(curl -s -f -m 5 -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" 2>/dev/null)
    
    if [[ -n "$token" ]]; then
        log "DEBUG" "Successfully obtained IMDSv2 token, this is an EC2 instance"
        return 0
    fi
    
    if curl -s -f -m 5 http://169.254.169.254/latest/meta-data/ >/dev/null 2>&1; then
        log "DEBUG" "Successfully accessed IMDSv1, this is an EC2 instance"
        return 0
    fi
    
    log "DEBUG" "Not running on EC2 instance"
    return 1
}

# Function to get EC2 metadata
get_ec2_metadata() {
    local path="$1"
    local result=""
    local token=""
    
    token=$(curl -s -f -m 5 -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" 2>/dev/null)
    
    if [[ -n "$token" ]]; then
        result=$(curl -s -f -m 5 -H "X-aws-ec2-metadata-token: $token" "http://169.254.169.254/latest/meta-data/$path" 2>/dev/null)
    else
        result=$(curl -s -f -m 5 "http://169.254.169.254/latest/meta-data/$path" 2>/dev/null)
    fi
    
    echo "$result"
}

# Function to get system information
get_system_info() {
    log "DEBUG" "Collecting system information"
    
    log "DEBUG" "Getting CPU information"
    local lscpu="$(lscpu)"
    log "DEBUG" "lscpu output available, $(echo "$lscpu" | wc -l) lines"
    
    local thread_per_core=$(echo "$lscpu" | grep -i 'thread.*per core' | awk '{print $NF}' | xargs)
    local total_vcpus=$(nproc --all)
    
    log "DEBUG" "Raw thread_per_core value: '$thread_per_core'"
    log "DEBUG" "Total vCPUs detected: $total_vcpus"
    
    # Handle missing thread_per_core (default to 2)
    if [[ -z "$thread_per_core" ]] || [[ "$thread_per_core" == "0" ]]; then
        thread_per_core=2
        log "DEBUG" "Thread per core not found or zero, defaulting to 2"
    else
        log "DEBUG" "Thread per core detected: $thread_per_core"
    fi
    
    local calculated_cores=$(( total_vcpus / thread_per_core ))
    log "DEBUG" "Calculated cores: $calculated_cores (vCPUs: $total_vcpus / threads_per_core: $thread_per_core)"
    
    log "DEBUG" "Getting memory information"
    local total_memory=$(grep 'MemTotal' /proc/meminfo | awk -F':' '{print $2}' | xargs)
    log "DEBUG" "Total memory detected: $total_memory KB"
    
    log "DEBUG" "Getting network information"
    local ip_addresses
    # Try modern ip command with JSON support first
    if ip_addresses=$(ip -4 --json addr show 2>/dev/null | jq 'map(.addr_info[] | select(.scope != "host") | "\(.label):\(.local)") | join(";")' 2>/dev/null | xargs); then
        log "DEBUG" "Using ip --json for network information"
        log "DEBUG" "Network interfaces found: $ip_addresses"
    else
        # Fallback for older systems without --json support
        log "DEBUG" "ip --json not supported, using fallback method for network information"
        ip_addresses=$(ip -4 addr show 2>/dev/null | awk '/inet / && !/127\.0\.0\.1/ {gsub(/\/.*/, "", $2); print $NF ":" $2}' | paste -sd ';' -)
        log "DEBUG" "Network interfaces found (fallback): $ip_addresses"
    fi
    
    # Check if running on EC2
    local instance_id=""
    local region=""
    local availability_zone=""
    local instance_type=""
    
    if is_ec2_instance; then
        log "INFO" "Running on EC2 instance, collecting EC2 metadata"
        instance_id=$(get_ec2_metadata "instance-id")
        availability_zone=$(get_ec2_metadata "placement/availability-zone")
        instance_type=$(get_ec2_metadata "instance-type")
        
        if [[ -n "$availability_zone" ]]; then
            region=${availability_zone::-1}
        fi
        
        log "DEBUG" "EC2 Instance ID: $instance_id"
        log "DEBUG" "EC2 Region: $region"
        log "DEBUG" "EC2 Instance Type: $instance_type"
    fi

    # Debug cache information
    log "DEBUG" "NUMA nodes: $(echo "$lscpu" | grep -i 'numa.*node' | awk -F: '{print $NF}' | xargs)"
    log "DEBUG" "L1d cache: $(echo "$lscpu" | grep -i 'l1d.*cache' | awk -F: '{print $NF}' | xargs)"
    log "DEBUG" "L1i cache: $(echo "$lscpu" | grep -i 'l1i.*cache' | awk -F: '{print $NF}' | xargs)"
    log "DEBUG" "L2 cache: $(echo "$lscpu" | grep -i 'l2.*cache' | awk -F: '{print $NF}' | xargs)"
    log "DEBUG" "L3 cache: $(echo "$lscpu" | grep -i 'l3.*cache' | awk -F: '{print $NF}' | xargs)"

    # Output system information
    jq -n \
        --arg hostname "$(hostname)" \
        --arg ip_addresses "$ip_addresses" \
        --arg architecture "$(uname -m)" \
        --arg os_name "$(get_os_info | grep 'OS Name:' | awk -F: '{print $NF}' | xargs)" \
        --arg os_version "$(get_os_info | grep 'OS Version:' | awk -F: '{print $NF}' | xargs)" \
        --arg total_cores "$calculated_cores" \
        --arg total_vcpus "$total_vcpus" \
        --arg total_memory "$total_memory" \
        --arg numa_nodes "$(echo "$lscpu" | grep -i 'numa.*node' | awk -F: '{print $NF}' | xargs)" \
        --arg l1d_cache "$(echo "$lscpu" | grep -i 'l1d.*cache' | awk -F: '{print $NF}' | xargs)" \
        --arg l1i_cache "$(echo "$lscpu" | grep -i 'l1i.*cache' | awk -F: '{print $NF}' | xargs)" \
        --arg l2_cache "$(echo "$lscpu" | grep -i 'l2.*cache' | awk -F: '{print $NF}' | xargs)" \
        --arg l3_cache "$(echo "$lscpu" | grep -i 'l3.*cache' | awk -F: '{print $NF}' | xargs)" \
        --arg instance_id "${instance_id:-}" \
        --arg region "${region:-}" \
        --arg availability_zone "${availability_zone:-}" \
        --arg instance_type "${instance_type:-}" \
        '{
            "hostname": $hostname,
            "ip_addresses": $ip_addresses,
            "architecture": $architecture,
            "os": {
                "name": $os_name,
                "version": $os_version
            },
            "cpu": {
                "total_cores": $total_cores,
                "total_vcpus": $total_vcpus,
                "numa_nodes": $numa_nodes,
                "cache": {
                    "l1d": $l1d_cache,
                    "l1i": $l1i_cache,
                    "l2": $l2_cache,
                    "l3": $l3_cache
                }
            },
            "memory": {
                "total_kb": $total_memory
            }
        } + if $instance_id != "" then {
            "ec2": {
                "instance_id": $instance_id,
                "region": $region,
                "availability_zone": $availability_zone,
                "instance_type": $instance_type
            }
        } else {} end'
}

identify_applications() {
    # Set up cleanup trap
    trap 'log "DEBUG" "Cleaning up temporary directory: $temp_dir"; rm -rf "$temp_dir"' EXIT INT TERM

    local output_file="${1:-$DEFAULT_OUTPUT_FILE}"
    local temp_dir=""
    
    log "DEBUG" "Starting application identification process"

    # Check available memory before starting
    if ! check_memory; then
        log "ERROR" "Insufficient memory available to process applications"
        return 1
    fi
    
    # Validate output directory
    local output_dir=$(dirname "$output_file")
    if [[ ! -w "$output_dir" ]]; then
        log "ERROR" "Output directory '$output_dir' is not writable"
        return 1
    fi
    
    # Create temporary directory with error handling
    temp_dir=$(mktemp -d) || {
        log "ERROR" "Failed to create temporary directory"
        return 1
    }
    log "DEBUG" "Created temporary directory: $temp_dir"
    
    # Create temporary files
    local pkg_list="${temp_dir}/packages.txt"
    local proc_list="${temp_dir}/processes.txt"
    local pkg_index="${temp_dir}/package_index.txt"
    
    log "DEBUG" "Created temporary files: pkg_list=$pkg_list, proc_list=$proc_list, pkg_index=$pkg_index"
    
    # Detect package manager
    local package_manager=$(detect_package_manager)
    log "DEBUG" "Detected package manager: $package_manager"
    
    if [[ "$package_manager" == "unknown" ]]; then
        log "WARNING" "No supported package manager found, package information will be limited"
    else
        log "DEBUG" "Getting installed packages using $package_manager"
        if ! get_installed_packages "$package_manager" "$pkg_list"; then
            log "ERROR" "Failed to get installed packages"
            return 1
        fi
        log "DEBUG" "Successfully retrieved installed packages"

        log "DEBUG" "Creating package index"
        if ! create_package_index "$pkg_list" "$pkg_index"; then
            log "ERROR" "Failed to create package index"
            return 1
        fi
    fi

    # Get running processes
    log "DEBUG" "Getting running processes"
    if ! get_running_processes "$proc_list"; then
        log "ERROR" "Failed to get running processes"
        return 1
    fi
    local process_count=$(wc -l < "$proc_list")
    log "DEBUG" "Found $process_count running processes"

    # Process data and create JSON output
    log "INFO" "Generating application report"
    
    local running_apps=()
    local installed_pkgs=()
    local processed=0
    local errors=0

    # Process running applications with progress tracking
    while IFS=$'\t' read -r user pid comm args; do
        ((processed++))
        if ((processed % 10 == 0)); then
            log "DEBUG" "Processing progress: $processed/$process_count"
        fi

        if [[ -n "$comm" ]]; then
            log "DEBUG" "Processing application: $comm (PID: $pid)"
            
            local version_info
            if ! version_info=$(get_version_info "$comm" "$pid" "$args" "$pkg_index" "$package_manager"); then
                log "WARNING" "Failed to get version info for $comm"
                ((errors++))
                continue
            fi
            
            # Parse the enhanced version info (version:source:package_owner)
            local version="${version_info%%:*}"
            local temp="${version_info#*:}"
            local source="${temp%%:*}"
            local package_owner="${temp#*:}"

            # Validate version if found
            if [[ "$version" != "unknown" ]] && ! validate_version "$version"; then
                log "WARNING" "Invalid version format: $version for $comm"
                version="unknown"
                source="invalid"
            fi
            
            log "DEBUG" "Creating JSON entry for $comm (version: $version, source: $source, package: $package_owner)"
            
            local entry
            if ! entry=$(jq -n \
                --arg name "$comm" \
                --arg version "$version" \
                --arg user "$user" \
                --arg pid "$pid" \
                --arg command "$args" \
                --arg source "$source" \
                --arg package_owner "${package_owner:-}" \
                '{name: $name, version: $version, user: $user, pid: $pid, command: $command, version_source: $source, package_owner: $package_owner}'); then
                
                log "WARNING" "Failed to create JSON entry for $comm"
                ((errors++))
                continue
            fi
            
            running_apps+=("$entry")
            log "DEBUG" "Successfully added entry for $comm"
        fi
    done < "$proc_list"

    log "DEBUG" "Processed $processed applications with $errors errors"

    # Process installed packages
    log "DEBUG" "Processing installed packages"
    while IFS=$'\t' read -r name version vendor description; do
        if [[ -n "$name" && -n "$version" ]]; then
            local entry
            if ! entry=$(jq -n \
                --arg name "$name" \
                --arg version "$version" \
                --arg vendor "${vendor:-Unknown}" \
                --arg description "${description:-No description}" \
                '{name: $name, version: $version, vendor: $vendor, description: $description}'); then
                
                log "WARNING" "Failed to create JSON entry for package $name"
                ((errors++))
                continue
            fi
            
            installed_pkgs+=("$entry")
        fi
    done < "$pkg_list"

    log "INFO" "Getting system information"
    local system_info=$(get_system_info)

    # Generate SBOM output (creates components_file internally)
    log "INFO" "Writing SBOM results to $output_file"
    if ! generate_sbom_output "$output_file" running_apps[@] installed_pkgs[@] "$system_info" "$errors"; then
        log "ERROR" "Failed to write SBOM output to $output_file"
        return 1
    fi

    # Run container discovery - adds container components to host SBOM and generates per-container SBOMs
    local output_dir=$(dirname "$output_file")
    log "INFO" "Starting container discovery"
    discover_containers_post "$output_file" "$output_dir" "$system_info"

    # Validate the generated JSON
    if ! validate_json "$output_file"; then
        log "ERROR" "Generated JSON failed validation"
        return 1
    fi

    log "INFO" "Report generated successfully with $errors errors"
    log "DEBUG" "Found ${#running_apps[@]} running applications and ${#installed_pkgs[@]} installed packages"
    return 0
}

# Main execution
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    # Check for help flag
    if [[ "$1" == "-h" || "$1" == "--help" ]]; then
        show_usage
        exit 0
    fi

    # Process command line arguments
    DEFAULT_OUTPUT_FILE="$(get_default_output_file)"
    output_file="${1:-$DEFAULT_OUTPUT_FILE}"

    # Log script start
    log "INFO" "Starting application identification with LOG_LEVEL=$LOG_LEVEL"
    log "INFO" "SBOM output will be saved to: $output_file"

    # Run the main function
    if identify_applications "$output_file"; then
        log "INFO" "Application identification completed successfully"
        exit 0
    else
        log "ERROR" "Application identification failed"
        exit 1
    fi
fi
