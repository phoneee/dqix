#!/usr/bin/env bash
#
# Comprehensive sector testing for DQIX
#

set -euo pipefail

# Colors
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
RESET='\033[0m'

echo -e "${BLUE}🌐 DQIX Comprehensive Sector Testing${RESET}"
echo "===================================="

# Test categories
CATEGORIES=(
    "Thai Financial:thai_financial:3"
    "Thai Insurance:thai_insurance:3"
    "Thai Public:thai_public_sector:3"
    "Asian Finance:asian:2"
    "EU Finance:european_union:2"
    "US Finance:united_states:2"
    "International:international:2"
    "Telecom:telecommunications:2"
    "Tech Giants:technology:3"
)

# Create results directory
RESULTS_DIR="sector_test_results_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$RESULTS_DIR"

echo -e "\n${YELLOW}Testing sectors with both Python and Bash implementations${RESET}"

# Test each category
for category_spec in "${CATEGORIES[@]}"; do
    IFS=':' read -r display_name sector limit <<< "$category_spec"
    
    echo -e "\n${GREEN}Testing $display_name...${RESET}"
    
    output_file="$RESULTS_DIR/${sector}_test.md"
    
    python scripts/test_domains.py \
        --sectors "$sector" \
        --implementations python bash \
        --limit "$limit" \
        --output "$output_file" 2>&1 | grep -E "(Testing|Score:|ERROR)" || true
    
    echo -e "  📄 Report saved: $output_file"
done

# Generate combined report
echo -e "\n${BLUE}Generating combined report...${RESET}"

cat > "$RESULTS_DIR/COMBINED_REPORT.md" << EOF
# DQIX Combined Sector Test Report

Generated: $(date)

## Test Summary

This report combines testing results across multiple sectors and regions.

### Sectors Tested:
EOF

for category_spec in "${CATEGORIES[@]}"; do
    IFS=':' read -r display_name sector limit <<< "$category_spec"
    echo "- **$display_name** ($limit domains per category)" >> "$RESULTS_DIR/COMBINED_REPORT.md"
done

echo -e "\n## Individual Sector Reports\n" >> "$RESULTS_DIR/COMBINED_REPORT.md"

# Append all individual reports
for category_spec in "${CATEGORIES[@]}"; do
    IFS=':' read -r display_name sector limit <<< "$category_spec"
    echo -e "\n---\n" >> "$RESULTS_DIR/COMBINED_REPORT.md"
    echo "### $display_name" >> "$RESULTS_DIR/COMBINED_REPORT.md"
    if [ -f "$RESULTS_DIR/${sector}_test.md" ]; then
        tail -n +5 "$RESULTS_DIR/${sector}_test.md" >> "$RESULTS_DIR/COMBINED_REPORT.md"
    fi
done

# Generate statistics
echo -e "\n## Overall Statistics\n" >> "$RESULTS_DIR/COMBINED_REPORT.md"

# Count total domains tested
total_domains=$(find "$RESULTS_DIR" -name "*.json" -exec grep -o '"domain":' {} \; | wc -l)
echo "- Total domains tested: $total_domains" >> "$RESULTS_DIR/COMBINED_REPORT.md"

echo -e "\n${GREEN}✅ Testing complete!${RESET}"
echo -e "📁 Results saved in: $RESULTS_DIR"
echo -e "📊 Combined report: $RESULTS_DIR/COMBINED_REPORT.md"

# Create a quick summary
echo -e "\n${YELLOW}Quick Summary:${RESET}"
echo "=============="

# Find top performers
echo -e "\n${GREEN}Top 5 Domains by Score:${RESET}"
find "$RESULTS_DIR" -name "*.json" -exec jq -r '
    .[] | 
    to_entries[] | 
    .value.domains[]? | 
    select(.overall_score != null) | 
    "\(.overall_score)%|\(.grade)|\(.domain_info.domain)|\(.domain_info.name)"
' {} \; 2>/dev/null | sort -t'|' -k1 -nr | head -5 | while IFS='|' read -r score grade domain name; do
    printf "  %-20s %-30s %s %s\n" "$domain" "$name" "$score" "$grade"
done

# Find domains with issues
echo -e "\n${RED}Domains with Issues:${RESET}"
find "$RESULTS_DIR" -name "*.json" -exec jq -r '
    .[] | 
    to_entries[] | 
    .value.domains[]? | 
    select(.error != null) | 
    "\(.domain_info.domain)|\(.error)"
' {} \; 2>/dev/null | head -5 | while IFS='|' read -r domain error; do
    printf "  %-30s %s\n" "$domain" "${error:0:50}..."
done