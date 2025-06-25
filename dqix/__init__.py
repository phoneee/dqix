"""
DQIX - Domain Quality Index (Clean Architecture)

A modern, clean architecture implementation for assessing domain quality
across security, performance, and compliance dimensions.

## Quick Start

```python
import asyncio
from dqix.application.use_cases import AssessDomainCommand, AssessDomainUseCase
from dqix.domain.entities import ProbeConfig
from dqix.domain.services import AssessmentService, DomainValidationService, ScoringService
from dqix.infrastructure.probes import ProbeExecutor
from dqix.infrastructure.repositories import FileAssessmentRepository, InMemoryCacheRepository

# Create use case with dependencies
async def assess_domain():
    # Infrastructure
    probe_executor = ProbeExecutor()
    assessment_repo = FileAssessmentRepository()
    cache_repo = InMemoryCacheRepository()
    
    # Domain services
    scoring_service = ScoringService()
    validation_service = DomainValidationService()
    assessment_service = AssessmentService(scoring_service, validation_service)
    
    # Use case
    use_case = AssessDomainUseCase(
        probe_executor=probe_executor,
        assessment_service=assessment_service,
        validation_service=validation_service,
        assessment_repo=assessment_repo,
        cache_repo=cache_repo
    )
    
    # Execute assessment
    command = AssessDomainCommand(
        domain_name="example.com",
        probe_config=ProbeConfig()
    )
    
    result = await use_case.execute(command)
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
- **DNS Probe**: Validates DNS records, SPF, DMARC configuration
- **Security Headers Probe**: Analyzes HTTP security headers

## Command Line Usage

```bash
# Assess single domain
python -m dqix assess example.com

# Assess multiple domains
python -m dqix assess-bulk domains.txt

# List available probes
python -m dqix list-probes
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
    AssessDomainCommand,
    AssessDomainUseCase,
    AssessDomainsCommand,
    AssessDomainsUseCase,
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
    "AssessDomainCommand",
    "AssessDomainUseCase",
    "AssessDomainsCommand",
    "AssessDomainsUseCase",
]
