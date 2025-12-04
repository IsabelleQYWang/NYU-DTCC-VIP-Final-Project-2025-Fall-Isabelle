# NYU DTCC VIP Final Project 2025 Fall - Isabelle Wang

## Automated SBOM Generator with Dynamic Dependency Capture

A comprehensive tool that automatically generates Software Bill of Materials (SBOMs) and captures dynamic linked dependencies at both compile-time and runtime.

### Project Overview

Traditional SBOM generators only capture statically declared dependencies. This tool extends SBOM generation by:
1. Generating base SBOMs using Syft
2. Capturing statically linked libraries using `otool` (macOS) or `ldd` (Linux)
3. Capturing runtime-loaded libraries using `dtruss` (macOS) or `strace` (Linux)
4. Merging all dependencies into an enhanced SBOM

### Features

- ✅ Cross-platform support (Linux and macOS)
- ✅ Multiple SBOM format outputs (JSON, SPDX, CycloneDX)
- ✅ Static library analysis
- ✅ Runtime library tracing
- ✅ Automatic version detection
- ✅ Enhanced SBOM output with dynamic dependencies section

### Requirements

**macOS:**
```bash
brew install syft jq
```

**Linux:**
```bash
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sudo sh -s -- -b /usr/local/bin
sudo apt-get install strace jq  # Debian/Ubuntu
```

### Installation

1. Clone the repository:
```bash
git clone https://github.com/YOUR_USERNAME/NYU-DTCC-VIP-Final-Project-2025-Fall-Isabelle-Wang.git
cd NYU-DTCC-VIP-Final-Project-2025-Fall-Isabelle-Wang
```

2. Make the script executable:
```bash
chmod +x sbom-generator.sh
```

### Usage

#### Basic Usage
```bash
# Analyze a binary
./sbom-generator.sh -t /bin/ls -o ls-sbom.json

# Analyze with runtime tracing (requires sudo)
sudo ./sbom-generator.sh -t /usr/bin/curl -e -a "https://example.com" -o curl-sbom.json
```

### Command Line Options
```
Usage: ./sbom-generator.sh [OPTIONS] TARGET

OPTIONS:
    -t, --target TARGET    Target to analyze
    -o, --output FILE     Output file
    -f, --format FORMAT   SBOM format: json, spdx, cyclonedx
    -e, --execute         Execute binary to capture runtime deps
    -a, --args ARGS       Arguments for execution
    --timeout SECONDS     Timeout for tracing (default: 30)
    -h, --help           Show help
```

### Examples
```bash
# Example 1: Basic analysis
./sbom-generator.sh -t /bin/ls -o examples/ls-sbom.json

# Example 2: With runtime tracing
sudo ./sbom-generator.sh -t /bin/curl -e -a "https://google.com" -o curl-sbom.json

# Example 3: View results
cat examples/ls-sbom.json | jq '.dynamicDependencies.libraries'
```
  
NYU DTCC VIP Program  
Fall 2025
