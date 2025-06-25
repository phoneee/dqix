"""Domain Entities - Core business objects."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional


class ProbeCategory(Enum):
    """Categories of domain quality checks."""
    SECURITY = "security"
    PERFORMANCE = "performance" 
    ACCESSIBILITY = "accessibility"
    COMPLIANCE = "compliance"


class ComplianceLevel(Enum):
    """Domain compliance levels."""
    BASIC = "basic"
    STANDARD = "standard" 
    ADVANCED = "advanced"


@dataclass(frozen=True)
class Domain:
    """A domain to be assessed."""
    name: str
    
    @property
    def clean_name(self) -> str:
        """Get domain name without trailing dot."""
        return self.name.rstrip('.')
    
    def is_valid(self) -> bool:
        """Check if domain format is valid."""
        import re
        if not 1 <= len(self.name) <= 253:
            return False
        return bool(re.match(r'^[a-zA-Z0-9.-]+$', self.name))


@dataclass
class ProbeResult:
    """Result of a single probe check."""
    probe_id: str
    domain: str
    score: float  # 0.0 to 1.0
    category: ProbeCategory
    details: Dict[str, Any]
    error: Optional[str] = None
    
    @property
    def is_successful(self) -> bool:
        """Check if probe completed successfully."""
        return self.error is None


@dataclass
class AssessmentResult:
    """Complete domain quality assessment."""
    domain: Domain
    overall_score: float
    probe_results: List[ProbeResult]
    compliance_level: ComplianceLevel
    timestamp: str
    
    @property
    def successful_probes(self) -> List[ProbeResult]:
        """Get only successful probe results."""
        return [r for r in self.probe_results if r.is_successful]
    
    @property
    def failed_probes(self) -> List[ProbeResult]:
        """Get only failed probe results."""
        return [r for r in self.probe_results if not r.is_successful]


@dataclass
class ProbeConfig:
    """Configuration for probe execution."""
    timeout: int = 30
    retry_count: int = 3
    cache_enabled: bool = True
    max_concurrent: int = 10 