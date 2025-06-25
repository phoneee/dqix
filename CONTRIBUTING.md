# Contributing to DQIX

Thank you for your interest in contributing to DQIX! This document provides guidelines and instructions for contributing.

## Quick Start

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Make your changes
4. Run tests: `pytest`
5. Submit a pull request

## Development Setup

```bash
# Clone repository
git clone https://github.com/yourusername/dqix.git
cd dqix

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # Linux/macOS
# or
.venv\Scripts\activate  # Windows

# Install development dependencies
pip install -e ".[dev]"
```

## Code Style

- Follow [PEP 8](https://peps.python.org/pep-0008/) guidelines
- Use [Black](https://black.readthedocs.io/) for code formatting
- Use [isort](https://pycqa.github.io/isort/) for import sorting
- Use [mypy](https://mypy.readthedocs.io/) for type checking
- Use [ruff](https://beta.ruff.rs/) for linting

```bash
# Format code
black .
isort .

# Type checking
mypy .

# Linting
ruff check .
```

## Testing

- Write tests for new features
- Ensure all tests pass: `pytest`
- Maintain test coverage: `pytest --cov=dqix`

## Pull Request Process

1. Update documentation for new features
2. Add tests for new functionality
3. Ensure all tests pass
4. Update the changelog
5. Submit PR with clear description

## Code Review

- Be respectful and constructive
- Focus on code quality and maintainability
- Consider performance implications
- Check for security issues

## Questions?

Feel free to open an issue for any questions or concerns.

## Adding a New Probe

1. Create a new file in `dqix/probes/` (e.g., `my_probe.py`)
2. Implement the probe class:
   ```python
   from dqix.probes.base import Probe

   class MyProbe(Probe):
       name = "my_probe"
       description = "What this probe checks"

       def run(self, domain: str) -> float:
           # Return score between 0.0 and 1.0
           return 1.0
   ```
3. Add tests in `dqix/tests/test_my_probe.py`
4. Update presets in `dqix/presets/` if needed

## Commit Messages

We follow [Conventional Commits](https://www.conventionalcommits.org/):

- `