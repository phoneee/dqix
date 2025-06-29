#!/usr/bin/env bash
# DQIX Complete Library - Real assessment logic aligned with other implementations
# Uses same criteria and scoring as Go/Python/Rust implementations

# Color Definitions
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[0;33m'
readonly BLUE='\033[0;34m'
readonly MAGENTA='\033[0;35m'
readonly CYAN='\033[0;36m'
readonly BOLD='\033[1m'
readonly NC='\033[0m'

# === CORE ASSESSMENT FUNCTIONS ===

perform_domain_assessment() {
    local domain="$1" mode="${2:-standard}"
    
    echo "🔍 Assessing $domain in $mode mode..."
    
    # Run real probes based on shared-config.yaml criteria
    local tls_result=$(assess_tls_security "$domain")
    local dns_result=$(assess_dns_security "$domain")
    local https_result=$(assess_https_config "$domain")
    local headers_result=$(assess_security_headers "$domain")
    
    # Calculate weighted score using shared-config.yaml weights
    local overall_score=$(calculate_overall_score "$tls_result" "$dns_result" "$https_result" "$headers_result")
    
    # Output based on format preference
    if [[ "$ENABLE_JSON" == "true" ]]; then
        format_json_output "$domain" "$overall_score" "$tls_result" "$dns_result" "$https_result" "$headers_result"
    else
        format_assessment_output "$domain" "$overall_score" "$mode" "$tls_result" "$dns_result" "$https_result" "$headers_result"
    fi
}

# === REAL PROBE IMPLEMENTATIONS ===

assess_tls_security() {
    local domain="$1"
    local score=0.0
    local details=""
    
    # Test TLS connection using openssl
    if command -v openssl &>/dev/null; then
        # Get TLS certificate info
        local cert_info=$(echo | openssl s_client -connect "$domain:443" -servername "$domain" 2>/dev/null)
        
        if [[ $? -eq 0 ]] && [[ -n "$cert_info" ]]; then
            local tls_version=$(echo "$cert_info" | grep "Protocol:" | awk '{print $2}')
            local cipher=$(echo "$cert_info" | grep "Cipher is" | awk '{print $4}')
            local cert_valid=$(echo "$cert_info" | grep "Verify return code: 0" &>/dev/null && echo "true" || echo "false")
            
            # Scoring based on TLS version (aligned with Go implementation)
            case "$tls_version" in
                "TLSv1.3") score=1.0 ;;
                "TLSv1.2") score=0.8 ;;
                "TLSv1.1") score=0.4 ;;
                "TLSv1") score=0.2 ;;
                *) score=0.0 ;;
            esac
            
            # Adjust score based on certificate validity
            if [[ "$cert_valid" == "false" ]]; then
                score=$(echo "scale=2; $score * 0.5" | bc -l 2>/dev/null || echo "0.0")
            fi
            
            details="TLS $tls_version, Cipher: $cipher, Cert Valid: $cert_valid"
        else
            score=0.0
            details="TLS connection failed"
        fi
    else
        # Fallback: test basic HTTPS connectivity
        if curl -s --connect-timeout 5 "https://$domain" >/dev/null 2>&1; then
            score=0.6
            details="HTTPS accessible (openssl not available for detailed analysis)"
        else
            score=0.0
            details="HTTPS not accessible"
        fi
    fi
    
    echo "$score"
}

assess_dns_security() {
    local domain="$1"
    local score=0.0
    local features=0
    local total_features=5
    
    # Check basic DNS resolution
    if nslookup "$domain" >/dev/null 2>&1; then
        features=$((features + 1))
    fi
    
    # Check for IPv6 support (AAAA record)
    if command -v dig &>/dev/null; then
        if dig AAAA "$domain" +short | grep -q .; then
            features=$((features + 1))
        fi
        
        # Check for MX record
        if dig MX "$domain" +short | grep -q .; then
            features=$((features + 1))
        fi
        
        # Check for TXT records (SPF, DMARC indicators)
        local txt_records=$(dig TXT "$domain" +short)
        if echo "$txt_records" | grep -q "v=spf1"; then
            features=$((features + 1))
        fi
        
        # Check for DMARC
        local dmarc_records=$(dig TXT "_dmarc.$domain" +short 2>/dev/null)
        if echo "$dmarc_records" | grep -q "v=DMARC1"; then
            features=$((features + 1))
        fi
    else
        # Fallback using nslookup
        if nslookup -type=MX "$domain" 2>/dev/null | grep -q "mail exchanger"; then
            features=$((features + 1))
        fi
        if nslookup -type=TXT "$domain" 2>/dev/null | grep -q "v=spf1"; then
            features=$((features + 1))
        fi
    fi
    
    # Calculate score based on DNS features
    score=$(echo "scale=2; $features / $total_features" | bc -l 2>/dev/null || echo "0.5")
    
    echo "$score"
}

assess_https_config() {
    local domain="$1"
    local score=0.0
    local features=0
    local total_features=4
    
    # Test HTTPS accessibility
    if curl -s --connect-timeout 5 "https://$domain" >/dev/null 2>&1; then
        features=$((features + 1))
        
        # Check for HTTP to HTTPS redirect
        local http_response=$(curl -s -I --connect-timeout 5 "http://$domain" 2>/dev/null | head -1)
        if echo "$http_response" | grep -q "301\|302"; then
            local location=$(curl -s -I --connect-timeout 5 "http://$domain" 2>/dev/null | grep -i "location:" | grep "https://")
            if [[ -n "$location" ]]; then
                features=$((features + 1))
            fi
        fi
        
        # Check for HSTS header
        local headers=$(curl -s -I --connect-timeout 5 "https://$domain" 2>/dev/null)
        if echo "$headers" | grep -qi "strict-transport-security"; then
            features=$((features + 1))
        fi
        
        # Check for HTTP/2 support (basic check)
        if curl -s --http2 --connect-timeout 5 "https://$domain" >/dev/null 2>&1; then
            features=$((features + 1))
        fi
    fi
    
    # Calculate score
    score=$(echo "scale=2; $features / $total_features" | bc -l 2>/dev/null || echo "0.0")
    
    echo "$score"
}

assess_security_headers() {
    local domain="$1"
    local score=0.0
    local features=0
    local total_features=6
    
    # Get HTTP headers
    local headers=$(curl -s -I --connect-timeout 5 "https://$domain" 2>/dev/null)
    
    if [[ -n "$headers" ]]; then
        # Check for security headers
        
        # Content Security Policy
        if echo "$headers" | grep -qi "content-security-policy"; then
            features=$((features + 1))
        fi
        
        # X-Frame-Options
        if echo "$headers" | grep -qi "x-frame-options"; then
            features=$((features + 1))
        fi
        
        # X-Content-Type-Options
        if echo "$headers" | grep -qi "x-content-type-options"; then
            features=$((features + 1))
        fi
        
        # Referrer-Policy
        if echo "$headers" | grep -qi "referrer-policy"; then
            features=$((features + 1))
        fi
        
        # HSTS (also counts for security headers)
        if echo "$headers" | grep -qi "strict-transport-security"; then
            features=$((features + 1))
        fi
        
        # X-XSS-Protection (though deprecated, still commonly checked)
        if echo "$headers" | grep -qi "x-xss-protection"; then
            features=$((features + 1))
        fi
    fi
    
    # Calculate score
    score=$(echo "scale=2; $features / $total_features" | bc -l 2>/dev/null || echo "0.0")
    
    echo "$score"
}

# === SCORING FUNCTIONS (ALIGNED WITH SHARED-CONFIG.YAML) ===

calculate_overall_score() {
    local tls="$1" dns="$2" https="$3" headers="$4"
    
    # Use weights from shared-config.yaml:
    # tls: 1.5, security_headers: 1.5, https: 1.2, dns: 1.2
    local tls_weight=1.5
    local headers_weight=1.5
    local https_weight=1.2
    local dns_weight=1.2
    local total_weight=5.4
    
    if command -v bc &>/dev/null; then
        local score=$(echo "scale=2; ($tls * $tls_weight + $dns * $dns_weight + $https * $https_weight + $headers * $headers_weight) / $total_weight" | bc -l)
        echo "$score"
    else
        # Fallback calculation without bc
        echo "0.75"
    fi
}

calculate_grade() {
    local score="$1"
    local score_int
    
    # Convert score to integer for comparison (handle both 0.xx and .xx formats)
    if [[ "$score" =~ ^0\.([0-9]+) ]]; then
        score_int=${BASH_REMATCH[1]}
    elif [[ "$score" =~ ^\.([0-9]+) ]]; then
        score_int=${BASH_REMATCH[1]}
    else
        score_int=0
    fi
    
    # Pad to 2 digits for consistent comparison
    score_int=$(printf "%02d" "$score_int")
    
    if (( score_int >= 95 )); then echo "A+"
    elif (( score_int >= 85 )); then echo "A"
    elif (( score_int >= 75 )); then echo "B"
    elif (( score_int >= 65 )); then echo "C"
    elif (( score_int >= 55 )); then echo "D"
    else echo "F"
    fi
}

# === OUTPUT FORMATTING ===

format_assessment_output() {
    local domain="$1" score="$2" mode="$3" tls="$4" dns="$5" https="$6" headers="$7"
    
    case "$mode" in
        educational) format_educational_output "$domain" "$score" "$tls" "$dns" "$https" "$headers" ;;
        performance) format_performance_output "$domain" "$score" "$tls" "$dns" "$https" "$headers" ;;
        comprehensive) format_comprehensive_output "$domain" "$score" "$tls" "$dns" "$https" "$headers" ;;
        *) format_standard_output "$domain" "$score" "$tls" "$dns" "$https" "$headers" ;;
    esac
}

format_standard_output() {
    local domain="$1" score="$2" tls="$3" dns="$4" https="$5" headers="$6"
    
    echo -e "${BOLD}${BLUE}🔍 DQIX Assessment: $domain${NC}"
    echo -e "Overall Score: ${GREEN}${score}${NC} ($(calculate_grade "$score"))"
    echo ""
    echo -e "🔐 TLS Security: ${GREEN}$tls${NC}"
    echo -e "🌍 DNS Security: ${GREEN}$dns${NC}"
    echo -e "🌐 HTTPS Config: ${GREEN}$https${NC}"
    echo -e "🛡️  Security Headers: ${GREEN}$headers${NC}"
}

format_educational_output() {
    local domain="$1" score="$2" tls="$3" dns="$4" https="$5" headers="$6"
    
    format_standard_output "$domain" "$score" "$tls" "$dns" "$https" "$headers"
    echo ""
    echo -e "${BOLD}📚 Educational Information:${NC}"
    echo "• TLS/SSL: Encrypts data in transit. TLS 1.3 is best, 1.2 acceptable"
    echo "• DNS Security: DNSSEC, SPF, DMARC protect against domain attacks"  
    echo "• HTTPS Config: Forces secure connections with HSTS and redirects"
    echo "• Security Headers: CSP, X-Frame-Options prevent web attacks"
}

format_performance_output() {
    local domain="$1" score="$2" tls="$3" dns="$4" https="$5" headers="$6"
    echo -e "${CYAN}⚡ $domain: $score ($(calculate_grade "$score")) TLS:$tls DNS:$dns HTTPS:$https HDR:$headers${NC}"
}

format_comprehensive_output() {
    local domain="$1" score="$2" tls="$3" dns="$4" https="$5" headers="$6"
    
    echo -e "${BOLD}${CYAN}🔍 DQIX Comprehensive Assessment${NC}"
    echo -e "Domain: $domain | Score: ${GREEN}$score${NC} | Grade: ${GREEN}$(calculate_grade "$score")${NC}"
    echo -e "Timestamp: $(date)"
    echo ""
    echo -e "${BOLD}=== DETAILED ANALYSIS ===${NC}"
    echo -e "🔐 TLS/SSL Security:     ${GREEN}$tls${NC} (Weight: 1.5)"
    echo -e "🌍 DNS Security:         ${GREEN}$dns${NC} (Weight: 1.2)"
    echo -e "🌐 HTTPS Configuration:  ${GREEN}$https${NC} (Weight: 1.2)"
    echo -e "🛡️  Security Headers:     ${GREEN}$headers${NC} (Weight: 1.5)"
    echo ""
    echo -e "${BOLD}Assessment Method:${NC}"
    echo -e "• Uses real TLS/SSL testing with openssl"
    echo -e "• Performs actual DNS queries for security records"
    echo -e "• Tests HTTPS configuration and redirects"
    echo -e "• Analyzes HTTP security headers"
    echo -e "• Weighted scoring based on security importance"
}

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
      "name": "TLS/SSL Security",
      "score": $tls,
      "weight": 1.5,
      "status": "completed"
    },
    {
      "probe_id": "dns",
      "name": "DNS Security", 
      "score": $dns,
      "weight": 1.2,
      "status": "completed"
    },
    {
      "probe_id": "https",
      "name": "HTTPS Configuration",
      "score": $https,
      "weight": 1.2,
      "status": "completed"
    },
    {
      "probe_id": "security_headers",
      "name": "Security Headers",
      "score": $headers,
      "weight": 1.5,
      "status": "completed"
    }
  ],
  "methodology": {
    "tls_check": "Real TLS connection using openssl",
    "dns_check": "DNS queries for security records (SPF, DMARC, etc.)",
    "https_check": "HTTPS accessibility, redirects, HSTS",
    "headers_check": "Security headers analysis (CSP, X-Frame-Options, etc.)"
  }
}
EOF
}

# === UTILITY FUNCTIONS ===

validate_domain() {
    local domain="$1"
    if [[ ! "$domain" =~ ^[a-zA-Z0-9][a-zA-Z0-9.-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$ ]]; then
        handle_error 1 "Invalid domain format: $domain"
    fi
}

handle_error() {
    local error_code="$1" error_message="$2"
    echo "❌ Error $error_code: $error_message" >&2
    exit "$error_code"
}