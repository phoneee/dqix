# Modern Makefile for DQIX Development
# Requires: uv, Python 3.9+

.PHONY: help install install-dev test test-cov test-integration lint format type-check security docs clean build publish pre-commit benchmark
.DEFAULT_GOAL := help

# Configuration
PYTHON_VERSION := 3.12
PROJECT_NAME := dqix
SRC_DIR := dqix
TESTS_DIR := tests
DOCS_DIR := docs

# Colors for terminal output
CYAN := \033[36m
GREEN := \033[32m
YELLOW := \033[33m
RED := \033[31m
RESET := \033[0m

help: ## Show this help message
	@echo "$(CYAN)DQIX Development Commands$(RESET)"
	@echo ""
	@awk 'BEGIN {FS = ":.*##"} /^[a-zA-Z_-]+:.*##/ {printf "$(GREEN)%-20s$(RESET) %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# Installation Commands
install: ## Install project dependencies
	@echo "$(CYAN)Installing DQIX...$(RESET)"
	uv sync

install-dev: ## Install development dependencies
	@echo "$(CYAN)Installing DQIX with development dependencies...$(RESET)"
	uv sync --all-extras --dev
	uv run pre-commit install

# Testing Commands
test: ## Run tests
	@echo "$(CYAN)Running tests...$(RESET)"
	uv run pytest -v

test-unit: ## Run unit tests only
	@echo "$(CYAN)Running unit tests...$(RESET)"
	uv run pytest tests/unit/ -v -m "unit"

test-integration: ## Run integration tests
	@echo "$(CYAN)Running integration tests...$(RESET)"
	uv run pytest tests/integration/ -v -m "integration"

test-cov: ## Run tests with coverage
	@echo "$(CYAN)Running tests with coverage...$(RESET)"
	uv run pytest \
		--cov=$(SRC_DIR) \
		--cov-report=html \
		--cov-report=term-missing \
		--cov-report=xml

test-parallel: ## Run tests in parallel
	@echo "$(CYAN)Running tests in parallel...$(RESET)"
	uv run pytest -n auto

test-watch: ## Run tests in watch mode
	@echo "$(CYAN)Running tests in watch mode...$(RESET)"
	uv run ptw --runner "pytest -v"

benchmark: ## Run performance benchmarks
	@echo "$(CYAN)Running benchmarks...$(RESET)"
	uv run pytest tests/ -k "benchmark" --benchmark-json=benchmark.json

# Code Quality Commands
lint: ## Run linting
	@echo "$(CYAN)Running Ruff linter...$(RESET)"
	uv run ruff check .

lint-fix: ## Run linting with auto-fix
	@echo "$(CYAN)Running Ruff linter with auto-fix...$(RESET)"
	uv run ruff check --fix .

format: ## Format code
	@echo "$(CYAN)Formatting code with Ruff...$(RESET)"
	uv run ruff format .

format-check: ## Check code formatting
	@echo "$(CYAN)Checking code formatting...$(RESET)"
	uv run ruff format --check .

type-check: ## Run type checking
	@echo "$(CYAN)Running MyPy type checker...$(RESET)"
	uv run mypy $(SRC_DIR)

type-check-strict: ## Run strict type checking
	@echo "$(CYAN)Running strict MyPy type checking...$(RESET)"
	uv run mypy $(SRC_DIR) --strict

# Security Commands
security: ## Run security checks
	@echo "$(CYAN)Running security checks...$(RESET)"
	uv run bandit -r $(SRC_DIR)/
	uv run safety check

security-full: ## Run comprehensive security scan
	@echo "$(CYAN)Running comprehensive security scan...$(RESET)"
	uv run bandit -r $(SRC_DIR)/ -f json -o bandit-report.json
	uv run safety check --json --output safety-report.json

# Quality Gate (run all checks)
quality: lint format-check type-check security test ## Run all quality checks
	@echo "$(GREEN)All quality checks passed!$(RESET)"

# Pre-commit Commands
pre-commit: ## Run pre-commit hooks on all files
	@echo "$(CYAN)Running pre-commit hooks...$(RESET)"
	uv run pre-commit run --all-files

pre-commit-update: ## Update pre-commit hooks
	@echo "$(CYAN)Updating pre-commit hooks...$(RESET)"
	uv run pre-commit autoupdate

# Documentation Commands
docs: ## Build documentation
	@echo "$(CYAN)Building documentation...$(RESET)"
	cd $(DOCS_DIR) && uv run sphinx-build -W -b html . _build/html

docs-live: ## Build documentation with live reload
	@echo "$(CYAN)Building documentation with live reload...$(RESET)"
	cd $(DOCS_DIR) && uv run sphinx-autobuild . _build/html --host 0.0.0.0 --port 8000

docs-clean: ## Clean documentation build
	@echo "$(CYAN)Cleaning documentation build...$(RESET)"
	rm -rf $(DOCS_DIR)/_build/

# Build and Release Commands
build: ## Build package
	@echo "$(CYAN)Building package...$(RESET)"
	uv build

build-check: ## Check build artifacts
	@echo "$(CYAN)Checking build artifacts...$(RESET)"
	uv run python -m pip install twine
	uv run twine check dist/*

publish-test: ## Publish to TestPyPI
	@echo "$(YELLOW)Publishing to TestPyPI...$(RESET)"
	uv run twine upload --repository testpypi dist/*

publish: ## Publish to PyPI (production)
	@echo "$(RED)Publishing to PyPI...$(RESET)"
	@read -p "Are you sure you want to publish to PyPI? [y/N] " confirm && [ "$$confirm" = "y" ]
	uv run twine upload dist/*

# Development Environment Commands
dev-setup: ## Set up development environment
	@echo "$(CYAN)Setting up development environment...$(RESET)"
	uv python install $(PYTHON_VERSION)
	$(MAKE) install-dev
	@echo "$(GREEN)Development environment ready!$(RESET)"

dev-reset: ## Reset development environment
	@echo "$(CYAN)Resetting development environment...$(RESET)"
	rm -rf .venv/
	rm -rf .pytest_cache/
	rm -rf .mypy_cache/
	rm -rf .ruff_cache/
	rm -rf .coverage
	rm -rf htmlcov/
	rm -rf dist/
	rm -rf build/
	rm -rf *.egg-info/
	$(MAKE) dev-setup

# Cleaning Commands
clean: ## Clean build artifacts and cache
	@echo "$(CYAN)Cleaning build artifacts...$(RESET)"
	rm -rf .pytest_cache/
	rm -rf .mypy_cache/
	rm -rf .ruff_cache/
	rm -rf .coverage
	rm -rf htmlcov/
	rm -rf coverage.xml
	rm -rf pytest-results.xml
	rm -rf dist/
	rm -rf build/
	rm -rf *.egg-info/
	find . -type d -name __pycache__ -delete
	find . -type f -name "*.pyc" -delete

clean-all: clean docs-clean ## Clean everything including docs

# Dependency Management
deps-update: ## Update dependencies
	@echo "$(CYAN)Updating dependencies...$(RESET)"
	uv sync --upgrade

deps-audit: ## Audit dependencies for vulnerabilities
	@echo "$(CYAN)Auditing dependencies...$(RESET)"
	uv run safety check
	uv run pip-audit

# Database Commands (if needed for testing)
db-setup: ## Set up test database
	@echo "$(CYAN)Setting up test database...$(RESET)"
	# Add database setup commands here if needed

# Docker Commands (if using containers)
docker-build: ## Build Docker image
	@echo "$(CYAN)Building Docker image...$(RESET)"
	docker build -t $(PROJECT_NAME):latest .

docker-test: ## Run tests in Docker
	@echo "$(CYAN)Running tests in Docker...$(RESET)"
	docker run --rm $(PROJECT_NAME):latest make test

# Performance and Profiling
profile: ## Profile code performance
	@echo "$(CYAN)Profiling code performance...$(RESET)"
	uv run python -m cProfile -o profile.stats -m $(SRC_DIR).cli.main --help
	uv run python -c "import pstats; pstats.Stats('profile.stats').sort_stats('cumulative').print_stats(20)"

# Git Hooks
install-hooks: ## Install git hooks
	@echo "$(CYAN)Installing git hooks...$(RESET)"
	uv run pre-commit install --hook-type pre-commit
	uv run pre-commit install --hook-type pre-push
	uv run pre-commit install --hook-type commit-msg

# CI/CD Local Testing
ci-test: ## Simulate CI/CD pipeline locally
	@echo "$(CYAN)Simulating CI/CD pipeline...$(RESET)"
	$(MAKE) quality
	$(MAKE) test-cov
	$(MAKE) build
	$(MAKE) build-check
	@echo "$(GREEN)CI/CD simulation completed successfully!$(RESET)"

# Information Commands
info: ## Show project information
	@echo "$(CYAN)Project Information$(RESET)"
	@echo "Name: $(PROJECT_NAME)"
	@echo "Python: $(shell uv run python --version)"
	@echo "UV: $(shell uv --version)"
	@echo "Git: $(shell git --version 2>/dev/null || echo 'Not installed')"
	@echo "Source: $(SRC_DIR)/"
	@echo "Tests: $(TESTS_DIR)/"
	@echo "Docs: $(DOCS_DIR)/"

# Quick development shortcuts
dev: install-dev ## Alias for install-dev
check: quality ## Alias for quality
fix: lint-fix format ## Fix linting and formatting issues
quick-test: test-unit ## Run quick unit tests only 