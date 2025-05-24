# Contributing to DQIX

Thanks for your interest in improving DQIX! This document provides guidelines and instructions for contributing.

## Development Setup

1. Fork & clone the repository:
   ```bash
   git clone https://github.com/YOUR_USERNAME/domain-quality-index.git
   cd domain-quality-index
   ```

2. Create a virtual environment and install dev dependencies:
   ```bash
   # Using uv (recommended)
   uv venv
   source .venv/bin/activate  # or .venv/Scripts/activate on Windows
   uv pip install -e .[dev]

   # Or using venv
   python -m venv .venv
   source .venv/bin/activate  # or .venv/Scripts/activate on Windows
   pip install -e .[dev]
   ```

3. Run tests to verify setup:
   ```bash
   pytest -q
   ```

## Code Style

DQIX uses:
- [Ruff](https://github.com/astral-sh/ruff) for linting
- [MyPy](https://mypy.readthedocs.io/) for type checking
- [Black](https://black.readthedocs.io/) for code formatting

Run all checks:
```bash
ruff check .
mypy dqix
```

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

## Pull Request Process

1. Create a feature branch:
   ```bash
   git checkout -b feature/my-probe
   ```

2. Make your changes and commit:
   ```bash
   git add .
   git commit -m "feat: add my new probe"
   ```

3. Push and create a PR:
   ```bash
   git push origin feature/my-probe
   ```

4. Ensure CI passes and address any review comments

## Commit Messages

We follow [Conventional Commits](https://www.conventionalcommits.org/):

- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation changes
- `style:` Code style changes (formatting, etc.)
- `refactor:` Code changes that neither fix bugs nor add features
- `test:` Adding or modifying tests
- `chore:` Changes to build process, tools, etc.

Example:
```
feat(probes): add new TLS version check probe

- Add TLSv1.3 support detection
- Update level2 preset weights
- Add tests for new probe
```

## Need Help?

- Open a [GitHub Discussion](https://github.com/your-org/dqix/discussions)
- Join our [Discord server](https://discord.gg/your-server)
- Check existing [Issues](https://github.com/your-org/dqix/issues) 