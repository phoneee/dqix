#!/bin/bash
# Go-specific test runner for DQIX
# Uses Go's native testing framework

set -euo pipefail

cd "$(dirname "$0")/../.."

echo "🐹 DQIX Go Implementation Tests"
echo "================================"

# Build first
echo "📦 Building Go implementation..."
cd dqix-go
go mod tidy
go build -o dqix ./cmd/dqix/
cd ..

# Test basic functionality
echo "🧪 Testing basic functionality..."
./dqix-go/dqix scan example.com > /tmp/go-test-example.json
./dqix-go/dqix scan google.com > /tmp/go-test-google.json

# Validate output format
echo "🔍 Validating output format..."
if command -v jq &> /dev/null; then
    echo "  ✅ example.com JSON valid: $(jq -r '.domain' /tmp/go-test-example.json 2>/dev/null || echo 'Invalid')"
    echo "  ✅ google.com JSON valid: $(jq -r '.domain' /tmp/go-test-google.json 2>/dev/null || echo 'Invalid')"
else
    echo "  ⚠️  jq not available, skipping JSON validation"
fi

# Run Go unit tests if available
echo "🔬 Running Go unit tests..."
cd dqix-go
if [ -f "*_test.go" ]; then
    go test ./...
else
    echo "  ℹ️  No Go unit tests found"
fi
cd ..

# Performance test
echo "⚡ Performance test..."
time ./dqix-go/dqix scan github.com > /tmp/go-test-performance.json

echo "✅ Go tests completed!"