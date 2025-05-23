# Contributing to DQIX

Thank you for your interest in contributing to DQIX! This document provides guidelines and instructions for contributing.

## Code of Conduct

By participating in this project, you agree to maintain a respectful and inclusive environment for everyone.

## How to Contribute

### Reporting Bugs

1. Check if the bug has already been reported in the Issues section
2. If not, create a new issue with:
   - A clear, descriptive title
   - Steps to reproduce the bug
   - Expected behavior
   - Actual behavior
   - Environment details (OS, Python version, etc.)
   - Any relevant logs or error messages

### Suggesting Features

1. Check if the feature has already been suggested in the Issues section
2. If not, create a new issue with:
   - A clear, descriptive title
   - Detailed description of the feature
   - Use cases and benefits
   - Any implementation ideas you might have

### Pull Requests

1. Fork the repository
2. Create a new branch for your feature/fix
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Update documentation if necessary
7. Submit a pull request

### Development Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/phoneee/domain-quality-index.git
   cd domain-quality-index
   ```

2. Create and activate a virtual environment:
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

3. Install development dependencies:
   ```bash
   pip install -e ".[dev]"
   ```

4. Install pre-commit hooks (optional but recommended):
   ```bash
   pre-commit install
   ```

### Code Style

- Follow PEP 8 guidelines
- Use type hints
- Write docstrings for all public functions and classes
- Keep functions focused and small
- Write meaningful commit messages

### Testing

- Write tests for new functionality
- Ensure all tests pass before submitting a PR
- Run tests with:
  ```bash
  pytest
  ```

### Documentation

- Update README.md if necessary
- Add docstrings for new functions/classes
- Update any relevant documentation in the docs directory

## Questions?

Feel free to open an issue for any questions about contributing. 