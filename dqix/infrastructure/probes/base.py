"""Base probe infrastructure."""

from abc import ABC, abstractmethod
from typing import Any, Dict, Optional

from ...domain.entities import Domain, ProbeCategory, ProbeConfig, ProbeResult


class BaseProbe(ABC):
    """Base class for all probes with simplified interface."""
    
    def __init__(self, probe_id: str, category: ProbeCategory):
        self.probe_id = probe_id
        self.category = category
    
    @abstractmethod
    async def check(self, domain: Domain, config: ProbeConfig) -> ProbeResult:
        """Check domain and return result."""
        pass
    
    def _create_result(
        self, 
        domain: Domain, 
        score: float, 
        details: Dict[str, Any],
        error: Optional[str] = None
    ) -> ProbeResult:
        """Helper to create probe result."""
        return ProbeResult(
            probe_id=self.probe_id,
            domain=domain.name,
            score=max(0.0, min(1.0, score)),  # Clamp between 0-1
            category=self.category,
            details=details,
            error=error
        ) 