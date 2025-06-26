#!/bin/bash

# DQIX Sub-Repository Creation Script
# Helps split the polyglot monorepo into specialized repositories

set -e

echo "🚀 DQIX Sub-Repository Creation Tool"
echo "===================================="
echo ""

# Configuration
ORG_NAME="dqix-org"
BASE_REPO="dqix"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Helper functions
log_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

log_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

log_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

log_error() {
    echo -e "${RED}❌ $1${NC}"
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    if ! command -v git &> /dev/null; then
        log_error "Git is required but not installed"
        exit 1
    fi
    
    if ! command -v gh &> /dev/null; then
        log_warning "GitHub CLI not found. You'll need to create repositories manually"
    fi
    
    log_success "Prerequisites checked"
}

# Create language-specific repository
create_language_repo() {
    local lang=$1
    local source_dir=$2
    local repo_name="${BASE_REPO}-${lang}"
    
    log_info "Creating $repo_name repository..."
    
    # Create temporary directory
    local temp_dir="temp_${repo_name}"
    mkdir -p "$temp_dir"
    
    # Copy language-specific files
    if [ -d "$source_dir" ]; then
        cp -r "$source_dir"/* "$temp_dir/"
    else
        log_error "Source directory $source_dir not found"
        return 1
    fi
    
    # Copy shared files
    cp README.md "$temp_dir/" 2>/dev/null || true
    cp LICENSE "$temp_dir/" 2>/dev/null || true
    cp .gitignore "$temp_dir/" 2>/dev/null || true
    
    # Create language-specific README
    cat > "$temp_dir/README.md" << EOF
# DQIX-${lang^} - Domain Quality Index

${lang^} implementation of the DQIX (Domain Quality Index) project.

## Quick Start

\`\`\`bash
# Build and install
EOF
    
    case $lang in
        "python")
            echo "pip install dqix" >> "$temp_dir/README.md"
            ;;
        "go")
            echo "go install github.com/$ORG_NAME/$repo_name@latest" >> "$temp_dir/README.md"
            ;;
        "rust")
            echo "cargo install dqix" >> "$temp_dir/README.md"
            ;;
    esac
    
    cat >> "$temp_dir/README.md" << EOF

# Usage
dqix assess example.com
\`\`\`

## Documentation

See the main [DQIX documentation](https://github.com/$ORG_NAME/$BASE_REPO) for complete usage instructions.

## Contributing

This repository is part of the larger DQIX project. Please see the main repository for contribution guidelines.

## License

MIT License - see LICENSE file for details.
EOF
    
    # Initialize git repository
    cd "$temp_dir"
    git init
    git add .
    git commit -m "Initial ${lang^} implementation"
    
    # Create remote repository if GitHub CLI is available
    if command -v gh &> /dev/null; then
        log_info "Creating GitHub repository..."
        gh repo create "$ORG_NAME/$repo_name" --public --description "DQIX ${lang^} implementation"
        git remote add origin "https://github.com/$ORG_NAME/$repo_name.git"
        git branch -M main
        git push -u origin main
    else
        log_warning "GitHub CLI not available. Create repository manually:"
        log_info "1. Create repository: https://github.com/new"
        log_info "2. Repository name: $repo_name"
        log_info "3. Add remote: git remote add origin https://github.com/$ORG_NAME/$repo_name.git"
        log_info "4. Push: git push -u origin main"
    fi
    
    cd ..
    rm -rf "$temp_dir"
    
    log_success "$repo_name repository created"
}

# Create specialized repositories
create_specialized_repo() {
    local name=$1
    local source_dir=$2
    local description=$3
    local repo_name="${BASE_REPO}-${name}"
    
    log_info "Creating $repo_name repository..."
    
    # Similar logic to create_language_repo but for specialized components
    local temp_dir="temp_${repo_name}"
    mkdir -p "$temp_dir"
    
    if [ -d "$source_dir" ]; then
        cp -r "$source_dir"/* "$temp_dir/"
    fi
    
    # Copy shared files
    cp README.md "$temp_dir/" 2>/dev/null || true
    cp LICENSE "$temp_dir/" 2>/dev/null || true
    cp .gitignore "$temp_dir/" 2>/dev/null || true
    
    # Create specialized README
    cat > "$temp_dir/README.md" << EOF
# DQIX-${name^} - $description

Part of the DQIX (Domain Quality Index) project.

## Purpose

$description

## Documentation

See the main [DQIX documentation](https://github.com/$ORG_NAME/$BASE_REPO) for complete information.

## License

MIT License - see LICENSE file for details.
EOF
    
    cd "$temp_dir"
    git init
    git add .
    git commit -m "Initial $name repository"
    
    if command -v gh &> /dev/null; then
        gh repo create "$ORG_NAME/$repo_name" --public --description "$description"
        git remote add origin "https://github.com/$ORG_NAME/$repo_name.git"
        git branch -M main
        git push -u origin main
    fi
    
    cd ..
    rm -rf "$temp_dir"
    
    log_success "$repo_name repository created"
}

# Main menu
show_menu() {
    echo ""
    echo "📋 Choose what to create:"
    echo "1. Language-specific repositories"
    echo "2. Specialized component repositories"
    echo "3. All repositories"
    echo "4. Exit"
    echo ""
}

# Create language repositories
create_language_repos() {
    log_info "Creating language-specific repositories..."
    
    create_language_repo "python" "dqix"
    create_language_repo "go" "dqix-go"
    create_language_repo "rust" "dqix-rust"
    
    log_success "All language repositories created"
}

# Create specialized repositories
create_specialized_repos() {
    log_info "Creating specialized repositories..."
    
    create_specialized_repo "benchmarks" "benchmarks" "Cross-language benchmarking and performance analysis"
    create_specialized_repo "dsl" "dsl" "Domain-Specific Language definitions for probe configuration"
    create_specialized_repo "docs" "docs" "Comprehensive documentation and guides"
    create_specialized_repo "deploy" "kubernetes" "Deployment manifests and infrastructure configuration"
    
    log_success "All specialized repositories created"
}

# Main execution
main() {
    check_prerequisites
    
    while true; do
        show_menu
        read -p "Enter your choice (1-4): " choice
        
        case $choice in
            1)
                create_language_repos
                ;;
            2)
                create_specialized_repos
                ;;
            3)
                create_language_repos
                create_specialized_repos
                ;;
            4)
                log_info "Exiting..."
                exit 0
                ;;
            *)
                log_error "Invalid choice. Please enter 1-4."
                ;;
        esac
    done
}

# Run if executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi 