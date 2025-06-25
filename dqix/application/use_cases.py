"""Application Use Cases - Business workflows."""

from dataclasses import dataclass
from datetime import datetime
from typing import List

from ..domain.entities import AssessmentResult, Domain, ProbeConfig
from ..domain.repositories import AssessmentRepository, CacheRepository
from ..domain.services import AssessmentService, DomainValidationService
from ..infrastructure.probes import ProbeExecutor


@dataclass
class AssessDomainCommand:
    """Command to assess a single domain."""
    domain_name: str
    probe_config: ProbeConfig


@dataclass
class AssessDomainsCommand:
    """Command to assess multiple domains."""
    domain_names: List[str]
    probe_config: ProbeConfig


class AssessDomainUseCase:
    """Use case for assessing a single domain."""
    
    def __init__(
        self,
        probe_executor: ProbeExecutor,
        assessment_service: AssessmentService,
        validation_service: DomainValidationService,
        assessment_repo: AssessmentRepository,
        cache_repo: CacheRepository
    ):
        self.probe_executor = probe_executor
        self.assessment_service = assessment_service
        self.validation_service = validation_service
        self.assessment_repo = assessment_repo
        self.cache_repo = cache_repo
    
    async def execute(self, command: AssessDomainCommand) -> AssessmentResult:
        """Execute domain assessment."""
        # Sanitize and validate domain
        clean_domain_name = self.validation_service.sanitize_domain_name(command.domain_name)
        domain = Domain(name=clean_domain_name)
        
        if not self.validation_service.validate_domain(domain):
            raise ValueError(f"Invalid domain: {domain.name}")
        
        # Check cache first
        if command.probe_config.cache_enabled:
            cached = await self.assessment_repo.find_by_domain(domain)
            if cached:
                return cached
        
        # Execute probes
        probe_results = await self.probe_executor.execute_all(domain, command.probe_config)
        
        # Create assessment
        assessment = self.assessment_service.create_assessment(
            domain=domain,
            probe_results=probe_results,
            timestamp=datetime.now().isoformat()
        )
        
        # Save results
        await self.assessment_repo.save(assessment)
        
        return assessment


class AssessDomainsUseCase:
    """Use case for assessing multiple domains."""
    
    def __init__(self, assess_domain_use_case: AssessDomainUseCase):
        self.assess_domain_use_case = assess_domain_use_case
    
    async def execute(self, command: AssessDomainsCommand) -> List[AssessmentResult]:
        """Execute bulk domain assessment."""
        results = []
        
        for domain_name in command.domain_names:
            try:
                single_command = AssessDomainCommand(
                    domain_name=domain_name,
                    probe_config=command.probe_config
                )
                result = await self.assess_domain_use_case.execute(single_command)
                results.append(result)
            except Exception as e:
                # Log error but continue with other domains
                print(f"Failed to assess {domain_name}: {e}")
        
        return results


class GetAssessmentHistoryUseCase:
    """Use case for retrieving assessment history."""
    
    def __init__(self, assessment_repo: AssessmentRepository):
        self.assessment_repo = assessment_repo
    
    async def execute(self, domain_name: str) -> List[AssessmentResult]:
        """Get assessment history for domain."""
        domain = Domain(name=domain_name)
        return await self.assessment_repo.find_all_by_domain(domain) 