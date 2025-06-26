"""Application Use Cases - Business workflows."""

from dataclasses import dataclass
from datetime import datetime
from typing import List, Dict, Any
import asyncio

from ..domain.entities import AssessmentResult, Domain, ProbeConfig, ComplianceLevel
from ..domain.repositories import AssessmentRepository, CacheRepository
from ..domain.services import AssessmentService, DomainValidationService
from ..infrastructure.probes import ProbeExecutor, ProbeRegistry


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


class DomainAssessmentUseCase:
    """Simplified use case for domain assessment with modern interface."""
    
    def __init__(self, infrastructure):
        self.infrastructure = infrastructure
        self.probe_executor = infrastructure.get_probe_executor()
        self.probe_registry = infrastructure.get_probe_registry()
    
    async def assess_domain(self, domain_name: str, timeout: int = 10, comprehensive: bool = False) -> Dict[str, Any]:
        """Assess a single domain and return results as dictionary."""
        try:
            domain = Domain(name=domain_name)
            config = ProbeConfig(timeout=timeout)
            
            # Execute probes
            probe_results = await self.probe_executor.execute_all(domain, config)
            
            # Calculate overall score
            total_score = sum(result.score for result in probe_results)
            overall_score = total_score / len(probe_results) if probe_results else 0.0
            
            # Determine compliance level
            if overall_score >= 0.8:
                compliance_level = ComplianceLevel.ADVANCED
            elif overall_score >= 0.6:
                compliance_level = ComplianceLevel.STANDARD
            elif overall_score >= 0.4:
                compliance_level = ComplianceLevel.BASIC
            else:
                compliance_level = ComplianceLevel.BASIC
            
            # Convert probe results to dictionaries
            probe_results_dict = []
            category_scores = {}
            
            for result in probe_results:
                probe_dict = {
                    "probe_id": result.probe_id,
                    "domain": result.domain,
                    "score": result.score,
                    "category": result.category.value,
                    "is_successful": result.is_successful,
                    "error": result.error,
                    "technical_details": result.details
                }
                probe_results_dict.append(probe_dict)
                
                # Calculate category scores
                category = result.category.value
                if category not in category_scores:
                    category_scores[category] = []
                category_scores[category].append(result.score)
            
            # Average category scores
            for category in category_scores:
                scores = category_scores[category]
                category_scores[category] = sum(scores) / len(scores) if scores else 0.0
            
            return {
                "domain": domain_name,
                "timestamp": datetime.now().isoformat(),
                "overall_score": overall_score,
                "compliance_level": compliance_level.value,
                "probe_results": probe_results_dict,
                "category_scores": category_scores,
                "assessment_metadata": {
                    "timeout": timeout,
                    "comprehensive": comprehensive,
                    "total_probes": len(probe_results),
                    "successful_probes": len([r for r in probe_results if r.is_successful])
                }
            }
            
        except Exception as e:
            return {
                "domain": domain_name,
                "timestamp": datetime.now().isoformat(),
                "overall_score": 0.0,
                "compliance_level": "error",
                "error": str(e),
                "probe_results": [],
                "category_scores": {}
            }


class AssessDomainUseCase:
    """Use case for assessing a single domain."""
    
    def __init__(self, probe_executor: ProbeExecutor, probe_registry: ProbeRegistry):
        self.probe_executor = probe_executor
        self.probe_registry = probe_registry
    
    async def execute(self, domain: Domain, config: ProbeConfig) -> AssessmentResult:
        """Execute domain assessment."""
        probes = list(self.probe_registry.get_all_probes().values())
        
        # Execute probes using the executor's execute_all method
        probe_results = await self.probe_executor.execute_all(domain, config)
        
        # Calculate overall score
        total_score = sum(result.score for result in probe_results)
        overall_score = total_score / len(probe_results) if probe_results else 0.0
        
        # Determine compliance level
        if overall_score >= 0.8:
            compliance_level = ComplianceLevel.ADVANCED
        elif overall_score >= 0.6:
            compliance_level = ComplianceLevel.STANDARD
        elif overall_score >= 0.4:
            compliance_level = ComplianceLevel.BASIC
        else:
            compliance_level = ComplianceLevel.BASIC
        
        return AssessmentResult(
            domain=domain,
            overall_score=overall_score,
            compliance_level=compliance_level,
            probe_results=probe_results,
            timestamp=datetime.now().isoformat()
        )


class BulkAssessDomainsUseCase:
    """Use case for assessing multiple domains."""
    
    def __init__(self, probe_executor: ProbeExecutor, probe_registry: ProbeRegistry):
        self.probe_executor = probe_executor
        self.probe_registry = probe_registry
    
    async def execute(self, domains: List[Domain], config: ProbeConfig) -> List[AssessmentResult]:
        """Execute bulk domain assessment."""
        results = []
        
        # Use semaphore to limit concurrent assessments
        semaphore = asyncio.Semaphore(5)  # Max 5 concurrent assessments
        
        async def assess_single_domain(domain: Domain) -> AssessmentResult:
            async with semaphore:
                assess_use_case = AssessDomainUseCase(self.probe_executor, self.probe_registry)
                return await assess_use_case.execute(domain, config)
        
        # Create tasks for all domains
        tasks = [assess_single_domain(domain) for domain in domains]
        
        # Execute all tasks concurrently
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filter out exceptions and return successful results
        successful_results = []
        for result in results:
            if isinstance(result, AssessmentResult):
                successful_results.append(result)
            else:
                # Log error or handle exception
                print(f"Assessment failed: {result}")
        
        return successful_results


class GetAssessmentHistoryUseCase:
    """Use case for retrieving assessment history."""
    
    def __init__(self, assessment_repo: AssessmentRepository):
        self.assessment_repo = assessment_repo
    
    async def execute(self, domain_name: str) -> List[AssessmentResult]:
        """Get assessment history for domain."""
        domain = Domain(name=domain_name)
        return await self.assessment_repo.find_all_by_domain(domain) 