#!/usr/bin/env bash
# DQIX Output Library - Unified output formatting for all modes

# Color definitions
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'  
readonly YELLOW='\033[0;33m'
readonly BLUE='\033[0;34m'
readonly MAGENTA='\033[0;35m'
readonly CYAN='\033[0;36m'
readonly WHITE='\033[0;37m'
readonly BOLD='\033[1m'
readonly NC='\033[0m' # No Color

# Output Formatting Functions
format_assessment_output() {
    local domain="$1"
    local score="$2"
    local mode="$3"
    local tls_result="$4"
    local dns_result="$5"
    local https_result="$6"
    local headers_result="$7"
    
    case "$mode" in
        "educational")
            format_educational_output "$domain" "$score" "$tls_result" "$dns_result" "$https_result" "$headers_result"
            ;;
        "performance")
            format_performance_output "$domain" "$score" "$tls_result" "$dns_result" "$https_result" "$headers_result"
            ;;
        "parallel")
            format_parallel_output "$domain" "$score" "$tls_result" "$dns_result" "$https_result" "$headers_result"
            ;;
        "comprehensive")
            format_comprehensive_output "$domain" "$score" "$tls_result" "$dns_result" "$https_result" "$headers_result"
            ;;
        *)
            format_standard_output "$domain" "$score" "$tls_result" "$dns_result" "$https_result" "$headers_result"
            ;;
    esac
}

format_standard_output() {
    local domain="$1" score="$2" tls="$3" dns="$4" https="$5" headers="$6"
    
    echo -e "${BOLD}${BLUE}🔍 DQIX Assessment: $domain${NC}"
    echo -e "Overall Score: ${GREEN}${score}${NC}"
    echo ""
    echo -e "🔐 TLS Security: ${GREEN}$tls${NC}"
    echo -e "🌍 DNS Security: ${GREEN}$dns${NC}"
    echo -e "🌐 HTTPS Config: ${GREEN}$https${NC}"
    echo -e "🛡️  Security Headers: ${GREEN}$headers${NC}"
}

format_educational_output() {
    local domain="$1" score="$2" tls="$3" dns="$4" https="$5" headers="$6"
    
    echo -e "${BOLD}${BLUE}📚 DQIX Educational Assessment: $domain${NC}"
    echo -e "Overall Score: ${GREEN}${score}${NC}"
    echo ""
    echo -e "${BOLD}🔐 TLS/SSL Security (Score: $tls)${NC}"
    echo "   This measures the encryption strength and certificate validity"
    echo "   - Certificate chain validation"
    echo "   - Protocol version (TLS 1.2/1.3 preferred)"
    echo "   - Cipher suite strength"
    echo ""
    echo -e "${BOLD}🌍 DNS Security (Score: $dns)${NC}"
    echo "   This evaluates DNS configuration and security features"
    echo "   - DNSSEC validation"
    echo "   - SPF, DKIM, DMARC records"
    echo "   - CAA records for certificate authority authorization"
    echo ""
    echo -e "${BOLD}🌐 HTTPS Configuration (Score: $https)${NC}"
    echo "   This checks HTTPS accessibility and configuration"
    echo "   - HTTPS availability and redirects"
    echo "   - HSTS (HTTP Strict Transport Security)"
    echo "   - HTTP/2 support"
    echo ""
    echo -e "${BOLD}🛡️  Security Headers (Score: $headers)${NC}"
    echo "   This analyzes HTTP security headers"
    echo "   - Content Security Policy (CSP)"
    echo "   - X-Frame-Options (clickjacking protection)"
    echo "   - X-Content-Type-Options"
    echo "   - Referrer-Policy"
}

format_performance_output() {
    local domain="$1" score="$2" tls="$3" dns="$4" https="$5" headers="$6"
    
    echo -e "${CYAN}⚡ $domain: $score (TLS:$tls DNS:$dns HTTPS:$https HDR:$headers)${NC}"
}

format_parallel_output() {
    local domain="$1" score="$2" tls="$3" dns="$4" https="$5" headers="$6"
    
    echo -e "${MAGENTA}[$(date '+%H:%M:%S')] $domain: $score${NC}"
}

format_comprehensive_output() {
    local domain="$1" score="$2" tls="$3" dns="$4" https="$5" headers="$6"
    
    echo -e "${BOLD}${CYAN}🔍 DQIX Comprehensive Assessment${NC}"
    echo -e "${BOLD}Domain: $domain${NC}"
    echo -e "${BOLD}Timestamp: $(date)${NC}"
    echo ""
    echo -e "${BOLD}=== SECURITY OVERVIEW ===${NC}"
    echo -e "Overall Score: ${GREEN}${score}${NC}"
    
    local grade=$(calculate_grade "$score")
    echo -e "Security Grade: ${GREEN}$grade${NC}"
    echo ""
    echo -e "${BOLD}=== DETAILED ANALYSIS ===${NC}"
    echo -e "🔐 TLS/SSL Security:     ${GREEN}$tls${NC}"
    echo -e "🌍 DNS Security:         ${GREEN}$dns${NC}"  
    echo -e "🌐 HTTPS Configuration:  ${GREEN}$https${NC}"
    echo -e "🛡️  Security Headers:     ${GREEN}$headers${NC}"
}

# Utility Functions
calculate_grade() {
    local score="$1"
    
    if (( $(echo "$score >= 0.95" | bc -l) )); then
        echo "A+"
    elif (( $(echo "$score >= 0.85" | bc -l) )); then
        echo "A"
    elif (( $(echo "$score >= 0.75" | bc -l) )); then
        echo "B"
    elif (( $(echo "$score >= 0.65" | bc -l) )); then
        echo "C"
    elif (( $(echo "$score >= 0.55" | bc -l) )); then
        echo "D"
    else
        echo "F"
    fi
}

# JSON Output Functions
format_json_output() {
    local domain="$1" score="$2" tls="$3" dns="$4" https="$5" headers="$6"
    
    cat <<EOF
{
  "domain": "$domain",
  "overall_score": $score,
  "grade": "$(calculate_grade "$score")",
  "timestamp": "$(date -Iseconds)",
  "probe_results": [
    {
      "probe_id": "tls",
      "score": $tls,
      "status": "completed"
    },
    {
      "probe_id": "dns", 
      "score": $dns,
      "status": "completed"
    },
    {
      "probe_id": "https",
      "score": $https,
      "status": "completed"
    },
    {
      "probe_id": "security_headers",
      "score": $headers,
      "status": "completed"
    }
  ]
}
EOF
}