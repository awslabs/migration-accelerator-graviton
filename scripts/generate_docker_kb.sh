#!/bin/bash
# Generate OS knowledge base using Docker containers
# Usage: ./generate_docker_kb.sh <os> <version>

set -e

if [ $# -ne 2 ]; then
    echo "Usage: $0 <os> <version>"
    echo "Examples:"
    echo "  $0 amazonlinux 2"
    echo "  $0 ubuntu 22.04"
    echo "  $0 centos 8"
    echo "  $0 alpine 3.18"
    exit 1
fi

# Check if Docker is installed
if ! command -v docker >/dev/null 2>&1; then
    echo "Error: Docker is not installed or not in PATH"
    echo "Please install Docker first: https://docs.docker.com/get-docker/"
    exit 1
fi

# Check if Docker daemon is running
if ! docker info >/dev/null 2>&1; then
    echo "Error: Docker daemon is not running"
    echo "Please start Docker daemon first"
    exit 1
fi

OS="$1"
VERSION="$2"
CONTAINER_NAME="graviton-kb-${OS}-${VERSION}-$(date +%s)"
OUTPUT_DIR="./os_packages"

# Map OS names to Docker images and special handling
case "$OS" in
    "amazonlinux")
        IMAGE="amazonlinux:${VERSION}"
        SPECIAL_SETUP=""
        ;;
    "ubuntu")
        IMAGE="ubuntu:${VERSION}"
        SPECIAL_SETUP=""
        ;;
    "centos")
        if [ "$VERSION" = "8" ]; then
            IMAGE="quay.io/centos/centos:stream8"
            SPECIAL_SETUP="RUN sed -i 's/mirrorlist/#mirrorlist/g' /etc/yum.repos.d/CentOS-* && sed -i 's|#baseurl=http://mirror.centos.org|baseurl=http://vault.centos.org|g' /etc/yum.repos.d/CentOS-*"
        else
            IMAGE="centos:${VERSION}"
            SPECIAL_SETUP=""
        fi
        ;;
    "rhel")
        IMAGE="registry.access.redhat.com/rhel${VERSION}/rhel:latest"
        SPECIAL_SETUP=""
        ;;
    "alpine")
        IMAGE="alpine:${VERSION}"
        SPECIAL_SETUP="RUN apk update && apk add --no-cache bash"
        ;;
    "debian")
        if [ "$VERSION" = "10" ]; then
            IMAGE="debian:${VERSION}"
            SPECIAL_SETUP="RUN sed -i 's|http://deb.debian.org/debian|http://archive.debian.org/debian|g' /etc/apt/sources.list && sed -i '/security/d' /etc/apt/sources.list && echo 'Acquire::Check-Valid-Until false;' > /etc/apt/apt.conf.d/99no-check-valid-until"
        else
            IMAGE="debian:${VERSION}"
            SPECIAL_SETUP=""
        fi
        ;;
    *)
        echo "Unsupported OS: $OS"
        exit 1
        ;;
esac

echo "Generating knowledge base for $OS $VERSION using $IMAGE"
mkdir -p "$OUTPUT_DIR"

# Create Dockerfile
cat > Dockerfile.tmp << EOF
FROM $IMAGE

# Special setup for problematic OS versions
$SPECIAL_SETUP

# Install Python and required tools including find
RUN if command -v yum >/dev/null 2>&1; then \\
        yum update -y && yum install -y python3 gawk findutils; \\
    elif command -v apt-get >/dev/null 2>&1; then \\
        apt-get update && apt-get install -y python3 gawk findutils; \\
    elif command -v apk >/dev/null 2>&1; then \\
        apk update && apk add python3 gawk findutils; \\
    fi

WORKDIR /scripts
COPY dump_os_packages.sh convert_os_packages.py ./
RUN chmod +x *.sh *.py

# Run both scripts using bash
RUN bash ./dump_os_packages.sh && \\
    JSONL_FILE=\$(ls os_packages/*.jsonl | head -1) && \\
    python3 convert_os_packages.py "\$JSONL_FILE" "${OS}-${VERSION}"
EOF

# Build container
echo "Building Docker image..."
docker build --platform linux/arm64 -f Dockerfile.tmp -t "$CONTAINER_NAME" .

# Extract the generated JSON file
echo "Extracting knowledge base..."
docker create --name "${CONTAINER_NAME}-extract" "$CONTAINER_NAME"

# Create temp directory and copy files there first
TEMP_DIR="/tmp/graviton-kb-$$"
mkdir -p "$TEMP_DIR"
docker cp "${CONTAINER_NAME}-extract:/scripts/os_packages/." "$TEMP_DIR/"

# Find JSON file in temp directory and copy to output
JSON_FILE=$(find "$TEMP_DIR" -name "*.json" -type f | head -1)
if [ -n "$JSON_FILE" ]; then
    # Use the detected OS name from dump_os_packages.sh instead of command line params
if [ -f "$TEMP_DIR"/*-available.jsonl ]; then
    DETECTED_OS=$(basename "$TEMP_DIR"/*-available.jsonl | sed 's/-[^-]*-available\.jsonl$//')
    FINAL_FILE="$OUTPUT_DIR/${DETECTED_OS}-graviton-packages.json"
else
    FINAL_FILE="$OUTPUT_DIR/${OS}-${VERSION}-graviton-packages.json"
fi
    cp "$JSON_FILE" "$FINAL_FILE"
    echo "Knowledge base generated: $FINAL_FILE"
    echo "Packages: $(python3 -c "import json; print(len(json.load(open('$FINAL_FILE'))['software_compatibility']))")"
else
    echo "Error: No JSON file generated"
    exit 1
fi

# Cleanup temp directory
rm -rf "$TEMP_DIR"

# Cleanup
docker rm -f "${CONTAINER_NAME}-extract" 2>/dev/null || true
docker rmi "$CONTAINER_NAME" 2>/dev/null || true
rm -f Dockerfile.tmp

echo "$FINAL_FILE"