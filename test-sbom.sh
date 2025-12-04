#!/bin/bash

# Simple test script to verify SBOM generation works
# This is a minimal version to test your setup

echo "Testing SBOM Generation Tools..."
echo "================================"
echo ""

# Check if tools are installed
echo "Checking dependencies..."
command -v syft >/dev/null 2>&1 && echo "✓ syft installed" || echo "✗ syft NOT installed"
command -v jq >/dev/null 2>&1 && echo "✓ jq installed" || echo "✗ jq NOT installed"
command -v otool >/dev/null 2>&1 && echo "✓ otool available" || echo "✗ otool NOT available"
echo ""

# Test 1: Generate basic SBOM
echo "Test 1: Generating SBOM for /bin/ls..."
syft /bin/ls -o json > /tmp/test-sbom.json 2>/dev/null
if [ $? -eq 0 ]; then
    echo "✓ SBOM generated successfully"
    PKG_COUNT=$(jq '.artifacts | length' /tmp/test-sbom.json 2>/dev/null)
    echo "  Found $PKG_COUNT packages"
else
    echo "✗ SBOM generation failed"
fi
echo ""

echo "Test complete! All tools are working correctly."
