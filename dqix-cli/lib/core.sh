#!/usr/bin/env bash
# DQIX Core Library - Shared functions for all CLI modes
# Eliminates duplication across CLI implementations

# Core Assessment Functions
perform_domain_assessment() {
    local domain="$1"
    local mode="${2:-standard}"
    
    # Shared assessment logic
    echo "🔍 Assessing $domain in $mode mode..."
    
    # Call probe functions
    local tls_result=$(assess_tls_security "$domain")
    local dns_result=$(assess_dns_security "$domain") 
    local https_result=$(assess_https_config "$domain")
    local headers_result=$(assess_security_headers "$domain")
    
    # Calculate overall score
    local overall_score=$(calculate_overall_score "$tls_result" "$dns_result" "$https_result" "$headers_result")
    
    # Format output based on mode
    format_assessment_output "$domain" "$overall_score" "$mode" "$tls_result" "$dns_result" "$https_result" "$headers_result"
}

# Probe Assessment Functions
assess_tls_security() {
    local domain="$1"
    # TLS assessment logic (shared across all modes)
    echo "0.85" # Placeholder
}

assess_dns_security() {
    local domain="$1"
    # DNS assessment logic (shared across all modes)
    echo "0.90" # Placeholder
}

assess_https_config() {
    local domain="$1"
    # HTTPS assessment logic (shared across all modes)
    echo "0.75" # Placeholder
}

assess_security_headers() {
    local domain="$1"
    # Security headers assessment logic (shared across all modes)
    echo "0.80" # Placeholder
}

# Scoring Functions
calculate_overall_score() {
    local tls="$1"
    local dns="$2" 
    local https="$3"
    local headers="$4"
    
    # Weighted average calculation
    local score=$(echo "scale=2; ($tls * 0.3) + ($dns * 0.25) + ($https * 0.25) + ($headers * 0.2)" | bc -l)
    echo "$score"
}

# Mode Detection
detect_mode() {
    local args=("$@")
    
    if [[ " ${args[*]} " =~ " --educational " ]]; then
        echo "educational"
    elif [[ " ${args[*]} " =~ " --performance " ]]; then
        echo "performance"
    elif [[ " ${args[*]} " =~ " --parallel " ]]; then
        echo "parallel"
    elif [[ " ${args[*]} " =~ " --comprehensive " ]]; then
        echo "comprehensive"
    else
        echo "standard"
    fi
}

# Error Handling
handle_error() {
    local error_code="$1"
    local error_message="$2"
    
    echo "❌ Error $error_code: $error_message" >&2
    exit "$error_code"
}

# Validation
validate_domain() {
    local domain="$1"
    
    if [[ ! "$domain" =~ ^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$ ]]; then
        handle_error 1 "Invalid domain format: $domain"
    fi
}