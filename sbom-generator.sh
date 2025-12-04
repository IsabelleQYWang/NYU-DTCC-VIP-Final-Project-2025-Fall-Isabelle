#!/bin/bash

# Dynamic SBOM Generator with Runtime Dependencies
# Generates SBOM using Syft and augments it with dynamically linked libraries

set -e

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Default values
OUTPUT_FORMAT="json"
SBOM_TOOL="syft"
TEMP_DIR="/tmp/sbom_$$"
STRACE_TIMEOUT=30

# Usage function
usage() {
    cat << EOF
Usage: $0 [OPTIONS] TARGET

Generate SBOM with dynamic runtime dependencies.

OPTIONS:
    -t, --target TARGET         Target to analyze (binary, directory, or container image)
    -o, --output FILE          Output file (default: sbom-enhanced.json)
    -f, --format FORMAT        SBOM format: json, spdx, cyclonedx (default: json)
    -e, --execute              Execute the binary to capture runtime deps (for binaries only)
    -a, --args ARGS           Arguments to pass when executing binary
    --timeout SECONDS         Timeout for strace execution (default: 30)
    -h, --help                Show this help message

EXAMPLES:
    $0 -t /usr/bin/myapp -e
    $0 -t ./myproject -o project-sbom.json
    $0 -t alpine:latest -o container-sbom.json
    $0 -t /usr/bin/curl -e -a "https://example.com" --timeout 10

EOF
    exit 1
}

# Logging functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Detect OS
detect_os() {
    if [[ "$OSTYPE" == "darwin"* ]]; then
        OS_TYPE="macos"
    elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
        OS_TYPE="linux"
    else
        OS_TYPE="unknown"
    fi
}

# Check dependencies
check_dependencies() {
    local missing=()
    
    if ! command -v syft &> /dev/null; then
        missing+=("syft")
    fi
    
    if [ "$OS_TYPE" = "macos" ]; then
        # macOS uses dtruss instead of strace
        if ! command -v dtruss &> /dev/null && ! [ -f /usr/bin/dtruss ]; then
            log_warn "dtruss not found (requires SIP disabled or running as root)"
            log_info "Will use ldd/otool for static analysis only"
        fi
    else
        if ! command -v strace &> /dev/null; then
            missing+=("strace")
        fi
    fi
    
    if ! command -v jq &> /dev/null; then
        missing+=("jq")
    fi
    
    if [ ${#missing[@]} -gt 0 ]; then
        log_error "Missing required dependencies: ${missing[*]}"
        log_info "Install them with:"
        for dep in "${missing[@]}"; do
            case $dep in
                syft)
                    if [ "$OS_TYPE" = "macos" ]; then
                        echo "  brew install syft"
                    else
                        echo "  curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sudo sh -s -- -b /usr/local/bin"
                    fi
                    ;;
                strace)
                    echo "  apt-get install strace  # Debian/Ubuntu"
                    echo "  yum install strace      # RHEL/CentOS"
                    ;;
                jq)
                    if [ "$OS_TYPE" = "macos" ]; then
                        echo "  brew install jq"
                    else
                        echo "  apt-get install jq      # Debian/Ubuntu"
                        echo "  yum install jq          # RHEL/CentOS"
                    fi
                    ;;
            esac
        done
        exit 1
    fi
}

# Generate base SBOM using Syft
generate_base_sbom() {
    local target=$1
    local output=$2
    
    log_info "Generating base SBOM for: $target"
    
    case $OUTPUT_FORMAT in
        json)
            syft "$target" -o json > "$output"
            ;;
        spdx)
            syft "$target" -o spdx-json > "$output"
            ;;
        cyclonedx)
            syft "$target" -o cyclonedx-json > "$output"
            ;;
        *)
            log_error "Unsupported format: $OUTPUT_FORMAT"
            exit 1
            ;;
    esac
    
    log_info "Base SBOM generated: $output"
}

# Extract dynamic libraries using ldd (Linux) or otool (macOS)
extract_static_libs() {
    local binary=$1
    local output=$2
    
    if [ ! -x "$binary" ]; then
        log_warn "Binary not executable or not found: $binary"
        echo "[]" > "$output"
        return
    fi
    
    if [ "$OS_TYPE" = "macos" ]; then
        log_info "Extracting linked libraries with otool..."
        
        otool -L "$binary" 2>/dev/null | tail -n +2 | awk '{print $1}' | while read -r lib; do
            if [ -f "$lib" ]; then
                local libname=$(basename "$lib")
                local libpath="$lib"
                local version=$(get_lib_version "$lib")
                
                cat << EOF
{
  "name": "$libname",
  "path": "$libpath",
  "version": "$version",
  "type": "dynamic-library",
  "source": "otool"
}
EOF
            fi
        done | jq -s '.' > "$output"
    else
        log_info "Extracting static linked libraries with ldd..."
        
        ldd "$binary" 2>/dev/null | grep "=>" | awk '{print $3}' | while read -r lib; do
            if [ -f "$lib" ]; then
                local libname=$(basename "$lib")
                local libpath=$(readlink -f "$lib")
                local version=$(get_lib_version "$lib")
                
                cat << EOF
{
  "name": "$libname",
  "path": "$libpath",
  "version": "$version",
  "type": "dynamic-library",
  "source": "ldd"
}
EOF
            fi
        done | jq -s '.' > "$output"
    fi
}

# Capture dynamic libraries using strace (Linux) or dtruss (macOS)
capture_runtime_libs() {
    local binary=$1
    local args=$2
    local output=$3
    
    if [ "$OS_TYPE" = "macos" ]; then
        log_info "Capturing runtime dependencies with dtruss (requires sudo)..."
        log_info "Executing: $binary $args (timeout: ${STRACE_TIMEOUT}s)"
        
        local trace_log="${TEMP_DIR}/dtruss.log"
        
        # dtruss requires sudo on macOS
        if [ "$EUID" -ne 0 ]; then
            log_warn "dtruss requires root privileges. Trying with sudo..."
            timeout "$STRACE_TIMEOUT" sudo dtruss -t open "$binary" $args &> "$trace_log" || true
        else
            timeout "$STRACE_TIMEOUT" dtruss -t open "$binary" $args &> "$trace_log" || true
        fi
        
        # Parse dtruss output for .dylib files
        grep -E '\.(dylib|so)' "$trace_log" | \
            grep -v "err = " | \
            sed -E 's/.*"([^"]+\.(dylib|so)[^"]*)".*/\1/' | \
            sort -u | while read -r lib; do
            
            if [ -f "$lib" ]; then
                local libname=$(basename "$lib")
                local libpath="$lib"
                local version=$(get_lib_version "$lib")
                
                cat << EOF
{
  "name": "$libname",
  "path": "$libpath",
  "version": "$version",
  "type": "dynamic-library",
  "source": "dtruss"
}
EOF
            fi
        done | jq -s '.' > "$output"
    else
        log_info "Capturing runtime dependencies with strace..."
        log_info "Executing: $binary $args (timeout: ${STRACE_TIMEOUT}s)"
        
        local strace_log="${TEMP_DIR}/strace.log"
        
        # Run strace to capture library loads
        timeout "$STRACE_TIMEOUT" strace -f -e trace=openat,open -o "$strace_log" "$binary" $args &>/dev/null || true
        
        # Parse strace output for .so files
        grep -E '\.so[.0-9]*"' "$strace_log" | \
            grep -v ENOENT | \
            sed -E 's/.*"([^"]+\.so[^"]*)".*$/\1/' | \
            sort -u | while read -r lib; do
            
            if [ -f "$lib" ]; then
                local libname=$(basename "$lib")
                local libpath=$(readlink -f "$lib")
                local version=$(get_lib_version "$lib")
                
                cat << EOF
{
  "name": "$libname",
  "path": "$libpath",
  "version": "$version",
  "type": "dynamic-library",
  "source": "strace"
}
EOF
            fi
        done | jq -s '.' > "$output"
    fi
    
    log_info "Found $(jq 'length' "$output") runtime libraries"
}

# Get library version
get_lib_version() {
    local lib=$1
    
    if [ "$OS_TYPE" = "macos" ]; then
        # Try to extract version from dylib filename
        if [[ $lib =~ \.([0-9]+\.[0-9]+\.[0-9]+)\.dylib ]]; then
            echo "${BASH_REMATCH[1]}"
        elif [[ $lib =~ \.([0-9]+)\.dylib ]]; then
            echo "${BASH_REMATCH[1]}"
        else
            echo "unknown"
        fi
    else
        # Try to extract version from filename
        if [[ $lib =~ \.so\.([0-9.]+) ]]; then
            echo "${BASH_REMATCH[1]}"
        elif [[ $lib =~ -([0-9.]+)\.so ]]; then
            echo "${BASH_REMATCH[1]}"
        else
            # Try readelf to get version
            if command -v readelf &> /dev/null; then
                readelf -V "$lib" 2>/dev/null | grep -A1 "Version needs:" | tail -1 | awk '{print $4}' | tr -d '()'
            else
                echo "unknown"
            fi
        fi
    fi
}

# Merge libraries into SBOM
merge_libs_to_sbom() {
    local sbom=$1
    local libs=$2
    local output=$3
    
    log_info "Merging dynamic libraries into SBOM..."
    
    local capture_method="ldd"
    if [ "$OS_TYPE" = "macos" ]; then
        capture_method="otool+dtruss"
    else
        capture_method="ldd+strace"
    fi
    
    # Create enhanced SBOM with dynamic dependencies
    jq --argjson libs "$(cat "$libs")" --arg method "$capture_method" '
    . + {
        "dynamicDependencies": {
            "libraries": $libs,
            "captureMethod": $method,
            "captureTimestamp": (now | strftime("%Y-%m-%dT%H:%M:%SZ"))
        }
    }
    ' "$sbom" > "$output"
    
    log_info "Enhanced SBOM created: $output"
}

# Generate summary report
generate_report() {
    local sbom=$1
    
    log_info "=== SBOM Summary ==="
    
    local pkg_count=$(jq '.artifacts | length' "$sbom" 2>/dev/null || echo "0")
    local dyn_count=$(jq '.dynamicDependencies.libraries | length' "$sbom" 2>/dev/null || echo "0")
    
    echo "Total Packages: $pkg_count"
    echo "Dynamic Libraries: $dyn_count"
    
    if [ "$dyn_count" -gt 0 ]; then
        echo ""
        echo "Dynamic Libraries:"
        jq -r '.dynamicDependencies.libraries[] | "  - \(.name) (\(.version)) - \(.path)"' "$sbom"
    fi
}

# Main function
main() {
    local target=""
    local output="sbom-enhanced.json"
    local execute=false
    local exec_args=""
    
    # Detect OS
    detect_os
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -t|--target)
                target="$2"
                shift 2
                ;;
            -o|--output)
                output="$2"
                shift 2
                ;;
            -f|--format)
                OUTPUT_FORMAT="$2"
                shift 2
                ;;
            -e|--execute)
                execute=true
                shift
                ;;
            -a|--args)
                exec_args="$2"
                shift 2
                ;;
            --timeout)
                STRACE_TIMEOUT="$2"
                shift 2
                ;;
            -h|--help)
                usage
                ;;
            *)
                if [ -z "$target" ]; then
                    target="$1"
                    shift
                else
                    log_error "Unknown option: $1"
                    usage
                fi
                ;;
        esac
    done
    
    if [ -z "$target" ]; then
        log_error "No target specified"
        usage
    fi
    
    # Check dependencies
    check_dependencies
    
    # Create temp directory
    mkdir -p "$TEMP_DIR"
    trap "rm -rf $TEMP_DIR" EXIT
    
    local base_sbom="${TEMP_DIR}/base-sbom.json"
    local static_libs="${TEMP_DIR}/static-libs.json"
    local runtime_libs="${TEMP_DIR}/runtime-libs.json"
    local all_libs="${TEMP_DIR}/all-libs.json"
    
    log_info "Running on: $OS_TYPE"
    
    # Generate base SBOM
    generate_base_sbom "$target" "$base_sbom"
    
    # If target is an executable binary, capture libraries
    if [ -f "$target" ] && [ -x "$target" ]; then
        # Extract static libraries
        extract_static_libs "$target" "$static_libs"
        
        # Capture runtime libraries if requested
        if [ "$execute" = true ]; then
            capture_runtime_libs "$target" "$exec_args" "$runtime_libs"
            # Merge both static and runtime libs
            jq -s '.[0] + .[1] | unique_by(.path)' "$static_libs" "$runtime_libs" > "$all_libs"
        else
            cp "$static_libs" "$all_libs"
        fi
        
        # Merge into SBOM
        merge_libs_to_sbom "$base_sbom" "$all_libs" "$output"
    else
        # For non-executables, just copy the base SBOM
        log_warn "Target is not an executable binary, skipping dynamic library capture"
        cp "$base_sbom" "$output"
    fi
    
    # Generate report
    generate_report "$output"
    
    log_info "Complete! Enhanced SBOM saved to: $output"
}

# Run main function
main "$@"
