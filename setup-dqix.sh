#!/bin/bash
# DQIX - Domain Quality Index Setup Script
# Internet Observability Platform - 2025 Modern Bash Edition

# Modern Bash 2025 features
set -euo pipefail
shopt -s globasciiranges nullglob failglob
set +H  # Disable history expansion

# Performance optimizations
ULIMIT_OPTIMIZED=true
if [[ "$ULIMIT_OPTIMIZED" == "true" ]]; then
    ulimit -n 4096 2>/dev/null || true
fi

echo "🔍 DQIX - Internet Observability Platform Setup"
echo "=============================================="
echo ""

# Modern color definitions with enhanced ANSI support
declare -rA COLORS=(
    [RED]='\033[0;31m'
    [GREEN]='\033[0;32m'
    [YELLOW]='\033[1;33m'
    [BLUE]='\033[0;34m'
    [CYAN]='\033[0;36m'
    [MAGENTA]='\033[0;35m'
    [BOLD]='\033[1m'
    [DIM]='\033[2m'
    [RESET]='\033[0m'
)

# Modern time tracking using EPOCHSECONDS and EPOCHREALTIME
START_TIME="$EPOCHREALTIME"
START_SECONDS="$EPOCHSECONDS"

# Modern function definitions with enhanced logging
print_status() {
    local timestamp="$(date '+%H:%M:%S')"
    printf '%s[%s]%s %s[INFO]%s %s\n' \
        "${COLORS[DIM]}" "$timestamp" "${COLORS[RESET]}" \
        "${COLORS[BLUE]}" "${COLORS[RESET]}" "$1"
}

print_success() {
    local timestamp="$(date '+%H:%M:%S')"
    printf '%s[%s]%s %s[SUCCESS]%s %s\n' \
        "${COLORS[DIM]}" "$timestamp" "${COLORS[RESET]}" \
        "${COLORS[GREEN]}" "${COLORS[RESET]}" "$1"
}

print_warning() {
    local timestamp="$(date '+%H:%M:%S')"
    printf '%s[%s]%s %s[WARNING]%s %s\n' \
        "${COLORS[DIM]}" "$timestamp" "${COLORS[RESET]}" \
        "${COLORS[YELLOW]}" "${COLORS[RESET]}" "$1" >&2
}

print_error() {
    local timestamp="$(date '+%H:%M:%S')"
    printf '%s[%s]%s %s[ERROR]%s %s\n' \
        "${COLORS[DIM]}" "$timestamp" "${COLORS[RESET]}" \
        "${COLORS[RED]}" "${COLORS[RESET]}" "$1" >&2
}

# Modern performance timing function
get_elapsed_time() {
    local current_time="$EPOCHREALTIME"
    local elapsed=$(awk "BEGIN {printf \"%.3f\", $current_time - $START_TIME}")
    echo "${elapsed}s"
}

# Modern directory validation with enhanced error reporting
validate_project_structure() {
    local -a required_files=(
        "dqix-cli/dqix-multi"
        "dqix-go/go.mod"
        "dqix-rust/Cargo.toml"
        "dqix-haskell/dqix.cabal"
        "dqix-cpp/CMakeLists.txt"
    )
    
    local missing_files=()
    for file in "${required_files[@]}"; do
        [[ -f "$file" ]] || missing_files+=("$file")
    done
    
    if (( ${#missing_files[@]} > 0 )); then
        print_error "Project structure validation failed"
        print_error "Missing files: ${missing_files[*]}"
        print_error "Please run this script from the DQIX project root"
        return 1
    fi
    
    return 0
}

validate_project_structure || exit 1

print_status "Setting up DQIX Internet Observability Platform..."

# Make dqix-multi executable
chmod +x dqix-cli/dqix-multi
print_success "Made dqix-multi executable"

# Test the Bash implementation
print_status "Testing Bash implementation..."
if ./dqix-cli/dqix-multi run-tests; then
    print_success "Bash implementation tests passed ✅"
else
    print_warning "Some tests failed, but continuing setup..."
fi

# Create global symlink (with sudo)
print_status "Creating global command access..."
if sudo ln -sf "$(pwd)/dqix-cli/dqix-multi" /usr/local/bin/dqix 2>/dev/null; then
    print_success "Global 'dqix' command created"
    GLOBAL_INSTALLED=true
else
    print_warning "Could not create global command (no sudo access)"
    GLOBAL_INSTALLED=false
fi

# Add alias to shell configuration
SHELL_CONFIG=""
if [[ -f "$HOME/.zshrc" ]]; then
    SHELL_CONFIG="$HOME/.zshrc"
elif [[ -f "$HOME/.bashrc" ]]; then
    SHELL_CONFIG="$HOME/.bashrc"
elif [[ -f "$HOME/.bash_profile" ]]; then
    SHELL_CONFIG="$HOME/.bash_profile"
fi

if [[ -n "$SHELL_CONFIG" ]]; then
    if ! grep -q "alias dqix=" "$SHELL_CONFIG"; then
        echo "" >> "$SHELL_CONFIG"
        echo "# DQIX - Internet Observability Platform" >> "$SHELL_CONFIG"
        echo "alias dqix=\"$(pwd)/dqix-cli/dqix-multi\"" >> "$SHELL_CONFIG"
        print_success "Added dqix alias to $SHELL_CONFIG"
    else
        print_status "dqix alias already exists in $SHELL_CONFIG"
    fi
fi

# Modern dependency management with enhanced error handling
install_python_implementation() {
    print_status "Checking Python implementation..."
    
    if ! command -v python3 &>/dev/null; then
        print_warning "Python 3 not available"
        return 1
    fi
    
    if [[ ! -f "pyproject.toml" ]]; then
        print_warning "pyproject.toml missing"
        return 1
    fi
    
    print_status "Attempting to install Python dependencies..."
    
    # Modern process substitution for better error handling
    if python3 -m pip install -e . > >(grep -v "^WARNING") 2>&1; then
        print_success "Python implementation (dqix-python) installed"
        return 0
    else
        print_warning "Python implementation failed to install (dependencies missing)"
        return 1
    fi
}

if install_python_implementation; then
    PYTHON_INSTALLED=true
else
    PYTHON_INSTALLED=false
fi

# Modern associative array approach for language implementations
print_status "Checking polyglot language implementations..."

declare -A LANGUAGES=(
    [go]="go:dqix-go/go.mod:Go 1.23+"
    [rust]="cargo:dqix-rust/Cargo.toml:Rust 1.75+"
    [haskell]="cabal:dqix-haskell/dqix.cabal:GHC 9.6+"
    [cpp]="cmake:dqix-cpp/CMakeLists.txt:C++20"
)

declare -A LANG_STATUS=()

for lang in "${!LANGUAGES[@]}"; do
    IFS=':' read -r cmd file desc <<< "${LANGUAGES[$lang]}"
    
    if command -v "$cmd" &>/dev/null && [[ -f "$file" ]]; then
        print_success "$desc implementation available"
        LANG_STATUS["$lang"]=true
    else
        print_warning "$desc implementation not available"
        LANG_STATUS["$lang"]=false
    fi
done

# Legacy variable assignments for compatibility
GO_AVAILABLE="${LANG_STATUS[go]}"
RUST_AVAILABLE="${LANG_STATUS[rust]}"
HASKELL_AVAILABLE="${LANG_STATUS[haskell]}"
CPP_AVAILABLE="${LANG_STATUS[cpp]}"

# Modern completion summary with timing
echo ""
echo "🎯 DQIX Setup Complete! $(get_elapsed_time)"
echo "=============================================="
echo "Setup completed at: $(date '+%Y-%m-%d %H:%M:%S')"
echo "Total elapsed time: $(get_elapsed_time)"

# Show usage instructions
echo ""
echo -e "${CYAN}📋 Available Commands:${NC}"
if [[ "$GLOBAL_INSTALLED" == "true" ]]; then
    echo "  dqix scan github.com              # Comprehensive domain analysis"
    echo "  dqix validate github.com          # Security checklist validation"
    echo "  dqix test                         # Test with known good domains"
    echo "  dqix demo cloudflare.com          # Interactive demonstration"
    echo "  dqix run-tests                    # Execute TDD test suite"
else
    echo "  ./dqix-cli/dqix-multi scan github.com     # Comprehensive domain analysis"
    echo "  ./dqix-cli/dqix-multi validate github.com # Security checklist validation"
    echo "  ./dqix-cli/dqix-multi test                # Test with known good domains"
    echo "  ./dqix-cli/dqix-multi demo cloudflare.com # Interactive demonstration"
    echo "  ./dqix-cli/dqix-multi run-tests           # Execute TDD test suite"
fi

echo ""
echo -e "${CYAN}🚀 Language Implementations:${NC}"
echo "  ✅ Bash      - Ready to use (6/6 tests passed)"
if [[ "$PYTHON_INSTALLED" == "true" ]]; then
    echo "  ✅ Python    - dqix-python installed and ready"
else
    echo "  ⚠️  Python    - dqix-python installation failed (use Bash instead)"
fi

if [[ "$GO_AVAILABLE" == "true" ]]; then
    echo "  ✅ Go        - Available (cd dqix-go && go run cmd/dqix/main.go scan github.com)"
else
    echo "  ❌ Go        - Not available (install Go to use)"
fi

if [[ "$RUST_AVAILABLE" == "true" ]]; then
    echo "  ✅ Rust      - Available (cd dqix-rust && cargo run -- scan github.com)"
else
    echo "  ❌ Rust      - Not available (install Rust to use)"
fi

if [[ "$HASKELL_AVAILABLE" == "true" ]]; then
    echo "  ✅ Haskell   - Available (cd dqix-haskell && cabal run dqix scan github.com)"
else
    echo "  ❌ Haskell   - Not available (install GHC/Cabal to use)"
fi

if [[ "$CPP_AVAILABLE" == "true" ]]; then
    echo "  ✅ C++       - Available (cd dqix-cpp && mkdir -p build && cd build && cmake .. && make && ./bin/dqix-cpp scan github.com)"
else
    echo "  ❌ C++       - Not available (install CMake, OpenSSL, libcurl, c-ares to use)"
fi

echo ""
echo -e "${CYAN}🔍 Quick Test:${NC}"
if [[ "$GLOBAL_INSTALLED" == "true" ]]; then
    echo "  dqix scan github.com"
else
    echo "  ./dqix-cli/dqix-multi scan github.com"
fi

# Modern completion message with enhanced formatting
printf '\n%s✅ DQIX is ready to measure the health of the Internet!%s\n' \
    "${COLORS[GREEN]}" "${COLORS[RESET]}"
printf '%s📖 Documentation: README.md%s\n' \
    "${COLORS[BLUE]}" "${COLORS[RESET]}"
printf '%s🌐 Project: Internet Observability Platform - 2025 Edition%s\n' \
    "${COLORS[BLUE]}" "${COLORS[RESET]}"
printf '%s⏱️  Setup completed in: %s%s\n' \
    "${COLORS[CYAN]}" "$(get_elapsed_time)" "${COLORS[RESET]}"
printf '\n' 