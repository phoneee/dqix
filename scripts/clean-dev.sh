#!/bin/bash
# DQIX Development Cleanup Script
# Removes all unnecessary files before testing/committing
# Version: 2.0.0

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo "🧹 DQIX Development Cleanup"
echo "=========================="
echo "Project Root: $PROJECT_ROOT"
echo

cd "$PROJECT_ROOT"

# Function to show cleanup progress
cleanup_step() {
    echo "🔄 $1..."
}

cleanup_done() {
    echo "✅ $1"
}

# Python cleanup
cleanup_step "Cleaning Python artifacts"
find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
find . -type f -name "*.pyc" -delete 2>/dev/null || true
find . -type f -name "*.pyo" -delete 2>/dev/null || true
find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
find . -type d -name ".mypy_cache" -exec rm -rf {} + 2>/dev/null || true
find . -type d -name ".ruff_cache" -exec rm -rf {} + 2>/dev/null || true
find . -type f -name ".coverage" -delete 2>/dev/null || true
find . -type d -name "htmlcov" -exec rm -rf {} + 2>/dev/null || true
cleanup_done "Python artifacts cleaned"

# Go cleanup
cleanup_step "Cleaning Go artifacts"
find . -type f -name "dqix-go" -delete 2>/dev/null || true
find . -type f -name "dqix-go-*" -delete 2>/dev/null || true
find . -type f -name "*.exe" -delete 2>/dev/null || true
find . -type f -name "go.work" -delete 2>/dev/null || true
find . -type f -name "go.work.sum" -delete 2>/dev/null || true
cleanup_done "Go artifacts cleaned"

# Rust cleanup
cleanup_step "Cleaning Rust artifacts"
find . -type d -name "target" -path "*/dqix-rust/*" -exec rm -rf {} + 2>/dev/null || true
find . -type f -name "Cargo.lock" -delete 2>/dev/null || true
find . -type f -name "*.rs.bk" -delete 2>/dev/null || true
cleanup_done "Rust artifacts cleaned"

# Haskell cleanup
cleanup_step "Cleaning Haskell artifacts"
find . -type d -name "dist-newstyle" -exec rm -rf {} + 2>/dev/null || true
find . -type d -name ".stack-work" -exec rm -rf {} + 2>/dev/null || true
find . -type f -name "*.hi" -delete 2>/dev/null || true
find . -type f -name "*.o" -delete 2>/dev/null || true
find . -type f -name "*.dyn_hi" -delete 2>/dev/null || true
find . -type f -name "*.dyn_o" -delete 2>/dev/null || true
cleanup_done "Haskell artifacts cleaned"

# C++/Emscripten cleanup
cleanup_step "Cleaning C++/Emscripten artifacts"
find . -type f -name "*.wasm" -delete 2>/dev/null || true
find . -type f -name "*.js.map" -delete 2>/dev/null || true
find . -type d -name "emscripten-cache" -exec rm -rf {} + 2>/dev/null || true
find . -type d -name "cmake-build-*" -exec rm -rf {} + 2>/dev/null || true
find . -type f -name "*.obj" -delete 2>/dev/null || true
find . -type f -name "*.a" -delete 2>/dev/null || true
find . -type f -name "*.lib" -delete 2>/dev/null || true
cleanup_done "C++/Emscripten artifacts cleaned"

# DQIX specific cleanup
cleanup_step "Cleaning DQIX generated files"
find . -type f -name "dqix_export_*.json" -delete 2>/dev/null || true
find . -type f -name "dqix_export_*.report" -delete 2>/dev/null || true
find . -type f -name "dqix_report_*.html" -delete 2>/dev/null || true
find . -type f -name "dqix_report_*.pdf" -delete 2>/dev/null || true
find . -type f -name "dqix_report_*.json" -delete 2>/dev/null || true
find . -type d -name ".dqix_assessments" -exec rm -rf {} + 2>/dev/null || true
find . -type d -name "assessments" -exec rm -rf {} + 2>/dev/null || true
find . -type d -name "bulk_assessments" -exec rm -rf {} + 2>/dev/null || true
find . -type d -name "visualizations" -exec rm -rf {} + 2>/dev/null || true
cleanup_done "DQIX generated files cleaned"

# Temporary files cleanup
cleanup_step "Cleaning temporary files"
find . -type f -name "*.tmp" -delete 2>/dev/null || true
find . -type f -name "*.temp" -delete 2>/dev/null || true
find . -type f -name "*.log" -delete 2>/dev/null || true
find . -type d -name "temp" -exec rm -rf {} + 2>/dev/null || true
find . -type d -name "tmp" -exec rm -rf {} + 2>/dev/null || true
find . -type d -name ".build" -exec rm -rf {} + 2>/dev/null || true
find . -type f -name "Dockerfile.tmp" -delete 2>/dev/null || true
cleanup_done "Temporary files cleaned"

# Generated documentation cleanup
cleanup_step "Cleaning generated documentation"
find . -type f -name "*_SUMMARY.md" -delete 2>/dev/null || true
find . -type f -name "*_ANALYSIS.md" -delete 2>/dev/null || true
find . -type f -name "*_IMPLEMENTATION_*.md" -delete 2>/dev/null || true
find . -type f -name "*_ENHANCEMENT_*.md" -delete 2>/dev/null || true
find . -type f -name "*_ARCHITECTURE*.md" -delete 2>/dev/null || true
find . -type f -name "*_PRODUCTION_*.md" -delete 2>/dev/null || true
cleanup_done "Generated documentation cleaned"

# Infrastructure temp files cleanup
cleanup_step "Cleaning infrastructure temporary files"
find . -type f -name "cloudflare-worker-*.js" -delete 2>/dev/null || true
find . -type f -name "dns-zone-*.txt" -delete 2>/dev/null || true
find . -type f -name "nginx-*.conf" -delete 2>/dev/null || true
find . -type f -name "verify-*.sh" -delete 2>/dev/null || true
find . -type f -name "deploy_*.py" -delete 2>/dev/null || true
find . -type f -name "create_*.py" -delete 2>/dev/null || true
find . -type f -name "perfect_security_*.md" -delete 2>/dev/null || true
cleanup_done "Infrastructure temporary files cleaned"

# OS specific cleanup
cleanup_step "Cleaning OS specific files"
find . -type f -name ".DS_Store" -delete 2>/dev/null || true
find . -type f -name ".DS_Store?" -delete 2>/dev/null || true
find . -type f -name "._*" -delete 2>/dev/null || true
find . -type f -name ".Spotlight-V100" -delete 2>/dev/null || true
find . -type f -name ".Trashes" -delete 2>/dev/null || true
find . -type f -name "ehthumbs.db" -delete 2>/dev/null || true
find . -type f -name "Thumbs.db" -delete 2>/dev/null || true
cleanup_done "OS specific files cleaned"

# IDE cleanup
cleanup_step "Cleaning IDE files"
find . -type f -name "*.swp" -delete 2>/dev/null || true
find . -type f -name "*.swo" -delete 2>/dev/null || true
find . -type f -name "*~" -delete 2>/dev/null || true
cleanup_done "IDE files cleaned"

# Empty directories cleanup
cleanup_step "Removing empty directories"
find . -type d -empty -delete 2>/dev/null || true
cleanup_done "Empty directories removed"

echo
echo "🎉 Development cleanup completed!"
echo "Repository is ready for testing and committing."

# Show current status
echo
echo "📊 Current repository status:"
echo "=============================="
if command -v git &> /dev/null; then
    echo "Git status:"
    git status --porcelain | head -20
    if [ $(git status --porcelain | wc -l) -gt 20 ]; then
        echo "... and $(( $(git status --porcelain | wc -l) - 20 )) more files"
    fi
else
    echo "Git not available - showing directory size:"
    du -sh . 2>/dev/null || echo "Unable to calculate directory size"
fi