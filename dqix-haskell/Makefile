# DQIX Internet Observability Platform - Haskell Implementation
# Functional Programming with TDD

.PHONY: all build test clean install run demo benchmark docs format lint

# Default target
all: build test

# Build the project
build:
	@echo "🔨 Building DQIX Haskell implementation..."
	cabal build

# Install dependencies
deps:
	@echo "📦 Installing dependencies..."
	cabal update
	cabal install --only-dependencies

# Run tests
test:
	@echo "🧪 Running test suite..."
	cabal test --test-show-details=streaming

# Run property-based tests
test-quick:
	@echo "🎲 Running QuickCheck property tests..."
	cabal exec -- ghci -e ":l Test" -e "quickCheck prop_ValidDomainRoundTrip"

# Run benchmarks
benchmark:
	@echo "⚡ Running benchmarks..."
	cabal bench

# Clean build artifacts
clean:
	@echo "🧹 Cleaning build artifacts..."
	cabal clean
	rm -rf dist-newstyle/

# Install the executable
install:
	@echo "📦 Installing DQIX..."
	cabal install

# Run the main program
run:
	@echo "🚀 Running DQIX..."
	cabal exec dqix

# Run demo
demo:
	@echo "🎯 Running DQIX demo..."
	cabal exec dqix demo github.com

# Run scan command
scan:
	@echo "🔍 Running DQIX scan..."
	cabal exec dqix scan github.com

# Run validation
validate:
	@echo "✅ Running DQIX validation..."
	cabal exec dqix validate github.com

# Run comprehensive test
test-comprehensive:
	@echo "🔬 Running comprehensive tests..."
	cabal exec dqix test

# Generate documentation
docs:
	@echo "📚 Generating documentation..."
	cabal haddock --haddock-all

# Format code
format:
	@echo "💅 Formatting Haskell code..."
	find . -name "*.hs" -exec stylish-haskell -i {} \;

# Lint code
lint:
	@echo "🔍 Linting Haskell code..."
	hlint .

# Development setup
setup:
	@echo "🛠️ Setting up development environment..."
	cabal update
	cabal install --only-dependencies
	cabal install stylish-haskell hlint

# Interactive development
repl:
	@echo "🎮 Starting GHCi REPL..."
	cabal repl

# Quick functional tests
test-functions:
	@echo "⚡ Testing core functions..."
	cabal exec -- ghci -e ":l Main" -e "validateDomain \"github.com\""
	cabal exec -- ghci -e ":l Main" -e "calculateTlsScore [(\"protocol_version\", \"TLS 1.3\")]"

# Test with real domains
test-domains:
	@echo "🌐 Testing with real domains..."
	cabal exec dqix scan github.com
	cabal exec dqix scan google.com
	cabal exec dqix scan cloudflare.com

# Profile performance
profile:
	@echo "📊 Profiling performance..."
	cabal configure --enable-profiling
	cabal build
	cabal exec dqix scan github.com -- +RTS -p

# Create distribution
dist:
	@echo "📦 Creating distribution..."
	cabal sdist

# Continuous integration
ci: deps build test lint docs
	@echo "✅ CI pipeline completed successfully"

# Development workflow
dev: clean setup build test
	@echo "🚀 Development environment ready"

# Help
help:
	@echo "DQIX Haskell Implementation - Available Commands:"
	@echo ""
	@echo "Build Commands:"
	@echo "  make build          - Build the project"
	@echo "  make deps           - Install dependencies"
	@echo "  make install        - Install executable"
	@echo "  make clean          - Clean build artifacts"
	@echo ""
	@echo "Test Commands:"
	@echo "  make test           - Run full test suite"
	@echo "  make test-quick     - Run QuickCheck tests"
	@echo "  make test-functions - Test core functions"
	@echo "  make test-domains   - Test with real domains"
	@echo ""
	@echo "Run Commands:"
	@echo "  make run            - Run main program"
	@echo "  make demo           - Run demo"
	@echo "  make scan           - Run scan command"
	@echo "  make validate       - Run validation"
	@echo ""
	@echo "Development Commands:"
	@echo "  make setup          - Setup development environment"
	@echo "  make repl           - Start GHCi REPL"
	@echo "  make format         - Format code"
	@echo "  make lint           - Lint code"
	@echo "  make docs           - Generate documentation"
	@echo ""
	@echo "Advanced Commands:"
	@echo "  make benchmark      - Run benchmarks"
	@echo "  make profile        - Profile performance"
	@echo "  make ci             - Run CI pipeline"
	@echo "  make dist           - Create distribution" 