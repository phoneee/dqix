from __future__ import annotations
from typing import Dict, Type, Tuple

# Global registry of all available probes
PROBES: Dict[str, Type[Probe]] = {}

def register(cls: Type[Probe]) -> Type[Probe]:
    """Register a probe class in the global registry."""
    if not hasattr(cls, 'id'):
        raise ValueError(f"Probe class {cls.__name__} must define 'id' attribute")
    PROBES[cls.id] = cls
    return cls

class Probe:
    """Base class for all probes."""
    
    id: str
    weight: float = 1.0

    def run(self, domain: str) -> Tuple[float, dict]:
        """Run the probe against a domain.

        Args:
            domain: Domain to check
            
        Returns:
            Tuple of (score, details) where:
            - score is a float between 0 and 1
            - details is a dict with probe-specific information
        """
        raise NotImplementedError("Probe must implement run() method")
