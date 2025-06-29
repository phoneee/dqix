#!/bin/bash
# DQIX Redundant Scripts Cleanup
# Safely archives redundant scripts that have been combined into dqix_unified_tools.sh

set -eo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ARCHIVE_DIR="${SCRIPT_DIR}/archived_redundant_scripts"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}🗂️  DQIX Redundant Scripts Cleanup${NC}"
echo "=================================================="

# Create archive directory
mkdir -p "$ARCHIVE_DIR"
echo -e "${BLUE}📁 Created archive directory: $ARCHIVE_DIR${NC}"

# Function to safely move files
safe_move() {
    local file="$1"
    local description="$2"
    
    if [[ -f "$file" ]]; then
        echo -e "${YELLOW}📦 Archiving: $file ($description)${NC}"
        mv "$file" "$ARCHIVE_DIR/"
        echo -e "${GREEN}✅ Archived: $(basename "$file")${NC}"
    else
        echo -e "${RED}⚠️  Not found: $file${NC}"
    fi
}

# Function to safely move directories
safe_move_dir() {
    local dir="$1"
    local description="$2"
    
    if [[ -d "$dir" ]]; then
        echo -e "${YELLOW}📦 Archiving directory: $dir ($description)${NC}"
        mv "$dir" "$ARCHIVE_DIR/"
        echo -e "${GREEN}✅ Archived: $(basename "$dir")${NC}"
    else
        echo -e "${RED}⚠️  Not found: $dir${NC}"
    fi
}

echo
echo -e "${BLUE}🔄 Archiving redundant test scripts...${NC}"

# Test runners (replaced by unified tool)
safe_move "test_all_implementations.sh" "Universal test runner (complex version)"
safe_move "test_all_implementations_simple.sh" "Universal test runner (simple version)"
safe_move "tests/runners/run-bash-tests.sh" "Bash-specific test runner"
safe_move "tests/runners/run-go-tests.sh" "Go-specific test runner"
safe_move "tests/runners/universal-test-runner.py" "Python universal test runner"
safe_move "tests/quick_test.sh" "Quick test script"

echo
echo -e "${BLUE}🌐 Archiving redundant domain testing scripts...${NC}"

# Domain testing scripts (replaced by unified tool)
safe_move "scripts/quick_domain_test.py" "Quick domain testing"
safe_move "scripts/test_domains.py" "Domain testing suite"
safe_move "scripts/comprehensive_domain_analyzer.py" "Comprehensive domain analysis"

echo
echo -e "${BLUE}🔧 Archiving redundant setup scripts...${NC}"

# Setup scripts (replaced by unified tool)
safe_move "scripts/setup-git-hooks.sh" "Git hooks setup"
safe_move "scripts/setup-commit-hooks.sh" "Commit hooks setup"
safe_move "scripts/clean-dev.sh" "Development cleanup"
safe_move "scripts/pre-commit-clean.sh" "Pre-commit cleanup"

echo
echo -e "${BLUE}📋 Creating archive manifest...${NC}"

# Create manifest of archived files
cat > "$ARCHIVE_DIR/ARCHIVE_MANIFEST.md" << EOF
# DQIX Archived Redundant Scripts

**Archive Date:** $(date)
**Reason:** Functionality consolidated into \`dqix_unified_tools.sh\`

## Archived Files

### Test Scripts
$(ls -la "$ARCHIVE_DIR"/*test* 2>/dev/null | awk '{print "- " $9 " (" $5 " bytes)"}' || echo "- None")

### Domain Scripts  
$(ls -la "$ARCHIVE_DIR"/*domain* 2>/dev/null | awk '{print "- " $9 " (" $5 " bytes)"}' || echo "- None")

### Setup Scripts
$(ls -la "$ARCHIVE_DIR"/*setup* "$ARCHIVE_DIR"/*clean* "$ARCHIVE_DIR"/*commit* 2>/dev/null | awk '{print "- " $9 " (" $5 " bytes)"}' || echo "- None")

### Runner Scripts
$(ls -la "$ARCHIVE_DIR"/run-* 2>/dev/null | awk '{print "- " $9 " (" $5 " bytes)"}' || echo "- None")

## Replacement

All functionality from these scripts is now available through:

\`\`\`bash
./dqix_unified_tools.sh <command> [options]
\`\`\`

### Command Mapping

| Old Script | New Command |
|------------|-------------|
| test_all_implementations*.sh | \`./dqix_unified_tools.sh test\` |
| scripts/*domain*.py | \`./dqix_unified_tools.sh domain\` |
| scripts/setup-*.sh | \`./dqix_unified_tools.sh setup\` |
| scripts/clean-*.sh | \`./dqix_unified_tools.sh clean\` |
| tests/runners/run-*.sh | \`./dqix_unified_tools.sh test --languages <lang>\` |

## Recovery

To restore any archived script:
\`\`\`bash
cp archived_redundant_scripts/<script_name> ./
\`\`\`

## Safe Deletion

After verifying the unified tool works correctly, this entire archive directory can be safely deleted.
EOF

echo
echo -e "${BLUE}📊 Generating cleanup summary...${NC}"

# Count archived files
archived_count=$(find "$ARCHIVE_DIR" -type f ! -name "ARCHIVE_MANIFEST.md" | wc -l)
total_size=$(du -sh "$ARCHIVE_DIR" | cut -f1)

echo
echo -e "${GREEN}✅ Cleanup Summary${NC}"
echo "=================================================="
echo -e "${BLUE}Archived Files:${NC} $archived_count"
echo -e "${BLUE}Archive Size:${NC} $total_size"
echo -e "${BLUE}Archive Location:${NC} $ARCHIVE_DIR"
echo
echo -e "${GREEN}🎉 Cleanup completed successfully!${NC}"
echo
echo -e "${YELLOW}Next Steps:${NC}"
echo "1. Test the unified tool: ./dqix_unified_tools.sh test --languages bash go --quick"
echo "2. Verify all functionality works as expected"
echo "3. Update documentation to reference new unified interface"
echo "4. After verification, optionally delete archive: rm -rf $ARCHIVE_DIR"
echo
echo -e "${BLUE}📖 See REDUNDANT_SCRIPTS_ANALYSIS.md for detailed migration guide${NC}"