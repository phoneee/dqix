from __future__ import annotations
from typing import Dict, Type, Tuple, Any, Optional
from abc import ABC, abstractmethod
import logging

# Global registry of all available probes
PROBES: Dict[str, Type[Probe]] = {}

# Global configuration
VERBOSE_LEVEL = 0
TLS_METHOD = "openssl"

def register(cls: Type[Probe]) -> Type[Probe]:
    """Register a probe class in the global registry."""
    if not hasattr(cls, 'id'):
        raise ValueError(f"Probe class {cls.__name__} must define 'id' attribute")
    PROBES[cls.id] = cls
    return cls


def set_verbosity_level(level: int) -> None:
    """Set global verbosity level."""
    global VERBOSE_LEVEL
    VERBOSE_LEVEL = level


def set_tls_method(method: str) -> None:
    """Set global TLS method."""
    global TLS_METHOD
    TLS_METHOD = method


class ProbeResult:
    """Result from running a probe."""
    
    def __init__(
        self,
        score: float,
        details: Dict[str, Any],
        data: Optional[Any] = None,
        error: Optional[str] = None,
        category: Optional[str] = None
    ):
        """Initialize probe result.
        
        Args:
            score: Score between 0 and 1
            details: Dictionary with probe-specific details
            data: Optional raw data
            error: Optional error message
            category: Optional probe category
        """
        self.score = score
        self.details = details
        self.data = data
        self.error = error
        self.category = category


class Probe(ABC):
    """Base class for all probes.
    
    This is the unified base class that supports both sync and async operations.
    Probes should inherit from this class and implement the required methods.
    """
    
    id: str
    weight: float = 1.0
    category: Optional[str] = None

    def __init__(self):
        """Initialize probe with logging."""
        self.logger = logging.getLogger(f"dqix.probes.{self.id}")

    @abstractmethod
    def run(self, domain: str) -> Tuple[float, Dict[str, Any]]:
        """Run the probe against a domain.

        Args:
            domain: Domain to check
            
        Returns:
            Tuple of (score, details) where:
            - score is a float between 0 and 1
            - details is a dict with probe-specific information
        """
        raise NotImplementedError("Probe must implement run() method")
    
    def _report_progress(self, msg: str, level: int = 1, end: str = "\r") -> None:
        """Print progress message respecting global verbosity.
        
        Args:
            msg: Message to print
            level: 1 for verbose, 2 for debug. 0 always suppressed.
            end: End param for print
        """
        if VERBOSE_LEVEL >= level:
            print(f"\033[K{msg}", end=end)
    
    def _validate_domain(self, domain: str) -> bool:
        """Validate domain name format.
        
        Args:
            domain: Domain to validate
            
        Returns:
            True if valid, False otherwise
        """
        if not domain or len(domain) > 255:
            return False
            
        # Basic domain validation
        parts = domain.split(".")
        if len(parts) < 2:
            return False
            
        for part in parts:
            if not part or len(part) > 63:
                return False
            if not all(c.isalnum() or c == "-" for c in part):
                return False
            if part.startswith("-") or part.endswith("-"):
                return False
                
        return True
