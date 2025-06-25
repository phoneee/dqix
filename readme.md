# DQIX - Domain Quality Index

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)

A modern, clean architecture implementation for assessing domain quality across security, performance, and compliance dimensions.

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/your-org/dqix.git
cd dqix

# Install dependencies
pip install dnspython httpx cryptography pydantic typer rich

# Or install from pyproject.toml
pip install -e .
```

### Basic Usage

```bash
# Assess a single domain
python -m dqix assess example.com

# Assess multiple domains from file
python -m dqix assess-bulk domains.txt

# List available probes
python -m dqix list-probes
```

### Programmatic Usage

```python
import asyncio
from dqix.application.use_cases import AssessDomainCommand, AssessDomainUseCase
from dqix.domain.entities import ProbeConfig

# Create assessment use case (see examples/ for full setup)
async def assess_domain():
    use_case = create_assessment_use_case()  # See examples/
    
    command = AssessDomainCommand(
        domain_name="example.com",
        probe_config=ProbeConfig(timeout=30)
    )
    
    result = await use_case.execute(command)
    print(f"Score: {result.overall_score:.2f}")
    print(f"Level: {result.compliance_level.value}")

asyncio.run(assess_domain())
```

## 🏗️ Architecture

DQIX follows **Clean Architecture** principles with clear separation of concerns:

```
dqix/
├── domain/           # 🏛️ Core business logic (no dependencies)
│   ├── entities.py   # Business objects (Domain, ProbeResult, etc.)
│   ├── services.py   # Business logic (ScoringService, ValidationService)
│   └── repositories.py # Data access interfaces
├── application/      # 🚀 Use cases and orchestration
│   └── use_cases.py  # Business workflows (AssessDomainUseCase)
├── infrastructure/   # 🔧 External services and I/O
│   ├── probes/       # Domain checking implementations
│   └── repositories.py # Data persistence
└── interfaces/       # 🖥️ User interaction
    └── cli.py        # Command-line interface
```

### Key Benefits

- **🧪 Testable**: Each layer can be tested independently
- **🔧 Maintainable**: Changes are isolated to specific layers  
- **📖 Readable**: Clear structure and naming conventions
- **🚀 Scalable**: Easy to add new probes or use cases

## 🔬 Available Probes

| Probe | Category | Description |
|-------|----------|-------------|
| **TLS** | Security | SSL/TLS configuration and certificate analysis |
| **DNS** | Security | DNS records, SPF, DMARC validation |
| **Security Headers** | Security | HTTP security headers analysis |

Each probe returns a score from 0.0 (worst) to 1.0 (best).

## 📊 Compliance Levels

- **Basic** (0.0-0.6): Essential security requirements
- **Standard** (0.7-0.8): Comprehensive security practices
- **Advanced** (0.9-1.0): Best practice implementation

## 📚 Examples

The `examples/` directory contains comprehensive usage examples:

- **`domain_assessment_demo.py`**: Single and multiple domain assessment
- **`bulk_assessment_demo.py`**: Large-scale domain analysis
- **`probe_demo.py`**: Individual probe testing and configuration

## 🛠️ Development

### Setup Development Environment

```bash
# Install development dependencies
pip install -e ".[dev]"

# Install pre-commit hooks
pre-commit install

# Run tests
pytest

# Run linting
ruff check .

# Run type checking
mypy dqix/
```

### Adding New Probes

1. Create probe class in `dqix/infrastructure/probes/`
2. Inherit from `BaseProbe`
3. Implement `async def check(domain, config)` method
4. Register in `implementations.py`

Example:

```python
from dqix.infrastructure.probes.base import BaseProbe
from dqix.domain.entities import ProbeCategory

class MyProbe(BaseProbe):
    def __init__(self):
        super().__init__("my_probe", ProbeCategory.SECURITY)
    
    async def check(self, domain, config):
        # Your probe logic here
        return self._create_result(domain, score, details)
```

## 🎯 Design Principles

1. **Dependency Rule**: Inner layers don't depend on outer layers
2. **Single Responsibility**: Each class has one reason to change
3. **Interface Segregation**: Small, focused interfaces
4. **Dependency Injection**: Dependencies injected at runtime
5. **Fail Fast**: Validate inputs early and clearly

## 📖 Documentation

- **Architecture Guide**: See `README_CLEAN_ARCHITECTURE.md`
- **API Documentation**: Generated from inline docstrings
- **Examples**: Comprehensive examples in `examples/` directory
- **Contributing**: See `CONTRIBUTING.md`

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes with tests
4. Run quality checks: `make test lint type-check`
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Clean Architecture principles by Robert C. Martin
- [Public Suffix List](https://publicsuffix.org/) for domain validation standards
- Modern Python development tools: ruff, mypy, pytest, typer, rich

---

**"Measuring domain quality with clean, maintainable code"** 🚀
