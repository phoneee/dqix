#!/bin/bash
# DQIX Pre-commit Cleanup Hook
# Automatically cleans unnecessary files before commit
# Version: 2.0.0

set -e

echo "🔍 Pre-commit cleanup starting..."

# Get the project root directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_ROOT"

# Run the development cleanup
./scripts/clean-dev.sh

# Additional pre-commit specific checks
echo
echo "🔎 Pre-commit validation:"
echo "========================"

# Check for sensitive files that shouldn't be committed
SENSITIVE_PATTERNS=(
    "*.key"
    "*.pem"
    "*.p12"
    "*.pfx"
    "*.jks"
    "*.env"
    "*secret*"
    "*password*"
    "*token*"
    "*.credentials"
)

echo "🔐 Checking for sensitive files..."
SENSITIVE_FOUND=false
for pattern in "${SENSITIVE_PATTERNS[@]}"; do
    if find . -name "$pattern" -type f 2>/dev/null | grep -q .; then
        echo "⚠️  WARNING: Found potential sensitive files matching '$pattern'"
        find . -name "$pattern" -type f 2>/dev/null | head -5
        SENSITIVE_FOUND=true
    fi
done

if [ "$SENSITIVE_FOUND" = true ]; then
    echo "❌ Sensitive files detected. Please review before committing."
    echo "   Add them to .gitignore if they should not be tracked."
else
    echo "✅ No sensitive files detected"
fi

# Check for large files (> 50MB)
echo
echo "📏 Checking for large files..."
LARGE_FILES=$(find . -type f -size +50M 2>/dev/null | grep -v ".git/" || true)
if [ -n "$LARGE_FILES" ]; then
    echo "⚠️  WARNING: Large files found (>50MB):"
    echo "$LARGE_FILES"
    echo "   Consider using Git LFS for large files."
else
    echo "✅ No large files detected"
fi

# Check for binary files that might be build artifacts
echo
echo "🔧 Checking for potential build artifacts..."
BINARY_PATTERNS=(
    "*.exe"
    "*.dll"
    "*.so"
    "*.dylib"
    "*.wasm"
    "*.o"
    "*.obj"
    "*.a"
    "*.lib"
)

BUILD_ARTIFACTS_FOUND=false
for pattern in "${BINARY_PATTERNS[@]}"; do
    # Exclude known legitimate binary files
    if find . -name "$pattern" -type f \
        ! -path "./.git/*" \
        ! -path "./node_modules/*" \
        ! -path "./target/*" \
        ! -path "./dist-newstyle/*" \
        ! -path "./__pycache__/*" \
        2>/dev/null | grep -q .; then
        echo "⚠️  Found potential build artifacts: $pattern"
        find . -name "$pattern" -type f \
            ! -path "./.git/*" \
            ! -path "./node_modules/*" \
            ! -path "./target/*" \
            ! -path "./dist-newstyle/*" \
            ! -path "./__pycache__/*" \
            2>/dev/null | head -3
        BUILD_ARTIFACTS_FOUND=true
    fi
done

if [ "$BUILD_ARTIFACTS_FOUND" = false ]; then
    echo "✅ No build artifacts detected"
fi

# Validate critical configuration files exist
echo
echo "📋 Validating critical files..."
CRITICAL_FILES=(
    ".gitignore"
    "README.md"
    "shared-config.yaml"
    "TEST_DOMAINS.yaml"
)

for file in "${CRITICAL_FILES[@]}"; do
    if [ -f "$file" ]; then
        echo "✅ $file exists"
    else
        echo "❌ $file missing"
    fi
done

# Final git status check
echo
echo "📊 Final repository status:"
echo "=========================="
if command -v git &> /dev/null; then
    # Check if there are any files that would be ignored by .gitignore but are already tracked
    TRACKED_IGNORED=$(git ls-files -i --exclude-standard 2>/dev/null || true)
    if [ -n "$TRACKED_IGNORED" ]; then
        echo "⚠️  WARNING: Tracked files that should be ignored:"
        echo "$TRACKED_IGNORED" | head -10
        echo "   Consider removing these files from tracking: git rm --cached <file>"
    else
        echo "✅ No tracked files violating .gitignore"
    fi
    
    # Show current status
    echo
    echo "Current git status:"
    git status --short | head -15
    
    TOTAL_CHANGES=$(git status --porcelain | wc -l)
    if [ "$TOTAL_CHANGES" -gt 15 ]; then
        echo "... and $(( TOTAL_CHANGES - 15 )) more changes"
    fi
    
    echo
    echo "Repository ready for commit! 🚀"
else
    echo "Git not available"
fi

echo
echo "✨ Pre-commit cleanup completed successfully!"