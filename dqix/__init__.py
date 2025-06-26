"""
DQIX - Domain Quality Index (Clean Architecture)

A modern, clean architecture implementation for assessing domain quality
across security, performance, and compliance dimensions.

## Quick Start

```python
import asyncio
from dqix.application.use_cases import AssessDomainUseCase, BulkAssessDomainsUseCase
from dqix.domain.entities import Domain, ProbeConfig
from dqix.infrastructure.factory import InfrastructureFactory

# Create use case with dependencies
async def assess_domain():
    # Infrastructure factory
    factory = InfrastructureFactory()
    
    # Use case
    use_case = AssessDomainUseCase(
        probe_executor=factory.create_probe_executor(),
        probe_registry=factory.create_probe_registry()
    )
    
    # Execute assessment
    domain = Domain("example.com")
    config = ProbeConfig()
    
    result = await use_case.execute(domain, config)
    print(f"Score: {result.overall_score:.2f}")
    print(f"Level: {result.compliance_level.value}")

# Run assessment
asyncio.run(assess_domain())
```

## Architecture

DQIX follows Clean Architecture principles with four distinct layers:

- **Domain Layer** (`dqix.domain`): Core business logic and entities
- **Application Layer** (`dqix.application`): Use cases and orchestration  
- **Infrastructure Layer** (`dqix.infrastructure`): External services and I/O
- **Interface Layer** (`dqix.interfaces`): User interaction (CLI, API, etc.)

## Available Probes

- **TLS Probe**: Checks SSL/TLS configuration and certificate validity
- **DNS Probe**: Validates DNS records, SPF, DMARC, DNSSEC configuration
- **Security Headers Probe**: Analyzes HTTP security headers

## Command Line Usage

```bash
# Assess single domain
python -m dqix assess example.com

# DNS analysis
python -m dqix dns analyze example.com

# TLS analysis  
python -m dqix tls analyze example.com

# Security headers analysis
python -m dqix security headers example.com

# List available probes
python -m dqix probe list
```

See examples/ directory for more detailed usage patterns.
"""

__version__ = "2.0.0"
__author__ = "DQIX Contributors"

# Public API exports
from .domain.entities import (
    Domain,
    ProbeResult,
    AssessmentResult,
    ProbeConfig,
    ProbeCategory,
    ComplianceLevel,
)

from .domain.services import (
    ScoringService,
    DomainValidationService,
    AssessmentService,
)

from .application.use_cases import (
    AssessDomainUseCase,
    BulkAssessDomainsUseCase,
)

__all__ = [
    # Version info
    "__version__",
    "__author__",
    
    # Domain entities
    "Domain",
    "ProbeResult", 
    "AssessmentResult",
    "ProbeConfig",
    "ProbeCategory",
    "ComplianceLevel",
    
    # Domain services
    "ScoringService",
    "DomainValidationService",
    "AssessmentService",
    
    # Application use cases
    "AssessDomainUseCase",
    "BulkAssessDomainsUseCase",
]
