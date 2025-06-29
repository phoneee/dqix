#!/bin/bash
# Bash-specific test runner for DQIX CLI implementations
# Tests all bash CLI variants

set -euo pipefail

cd "$(dirname "$0")/../.."

echo "🐚 DQIX Bash Implementation Tests"
echo "================================="

# Test unified CLI
echo "🧪 Testing unified CLI (dqix-multi)..."
chmod +x ./dqix-cli/dqix*

# Test basic scan
echo "  📍 Basic scan test..."
./dqix-cli/dqix-multi scan example.com > /tmp/bash-test-example.txt 2>&1
echo "    ✅ example.com scan completed"

# Test educational mode
echo "  📚 Educational mode test..."
./dqix-cli/dqix-educational scan google.com > /tmp/bash-test-educational.txt 2>&1
echo "    ✅ Educational mode completed"

# Test performance mode
echo "  ⚡ Performance mode test..."
./dqix-cli/dqix-performance scan github.com > /tmp/bash-test-performance.txt 2>&1
echo "    ✅ Performance mode completed"

# Test parallel mode (if GNU parallel available)
echo "  🔄 Parallel mode test..."
if command -v parallel &> /dev/null; then
    ./dqix-cli/dqix-parallel scan stackoverflow.com > /tmp/bash-test-parallel.txt 2>&1
    echo "    ✅ Parallel mode completed"
else
    echo "    ⚠️  GNU parallel not available, skipping parallel test"
fi

# Test error handling
echo "🚨 Error handling tests..."
./dqix-cli/dqix-multi scan nonexistent-domain-12345.invalid > /tmp/bash-test-error.txt 2>&1
echo "  ✅ Error handling test completed"

# Validate outputs contain expected elements
echo "🔍 Validating outputs..."
for file in /tmp/bash-test-*.txt; do
    if grep -q "DQIX" "$file" && grep -q "Score" "$file"; then
        echo "  ✅ $(basename "$file") contains expected content"
    else
        echo "  ❌ $(basename "$file") missing expected content"
    fi
done

# Test completion script
echo "🔧 Testing bash completion..."
if [ -f "./dqix-cli/dqix-complete.sh" ]; then
    source ./dqix-cli/dqix-complete.sh
    echo "  ✅ Bash completion loaded"
else
    echo "  ⚠️  Bash completion script not found"
fi

echo "✅ Bash CLI tests completed!"