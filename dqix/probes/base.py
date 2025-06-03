from __future__ import annotations
from typing import Tuple, Dict, Any, Protocol, Optional, TypeVar, Generic, List
from dataclasses import dataclass
import time
import logging
from abc import ABC, abstractmethod
from enum import Enum, auto

# ANSI color codes for progress reporting
_CLR_INFO = "\033[36m"  # Cyan
_CLR_RESET = "\033[0m"  # Reset

# Global verbosity level (0=quiet, 1=verbose, 2=debug)
VERBOSE_LEVEL = 1

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

T = TypeVar('T')

class ProbeCategory(Enum):
    """Categories of probes based on DQIX pillars."""
    PERFORMANCE = auto()  # Speed, reliability, resiliency
    AFFORDABILITY = auto()  # Cost-efficient delivery, lightweight design
    TRUSTWORTHINESS = auto()  # Security, privacy, transparency
    ACCESSIBILITY = auto()  # WCAG compliance, usability
    SOCIAL = auto()  # Social media presence, engagement

@dataclass
class ProbeResult(Generic[T]):
    """Container for probe results with score and details."""
    score: float
    details: Dict[str, Any]
    data: Optional[T] = None
    error: Optional[str] = None
    category: Optional[ProbeCategory] = None

class ProbeData(Protocol):
    """Protocol defining the structure of probe data."""
    domain: str
    error: Optional[str]

class ScoreCalculator(Protocol):
    """Protocol defining the structure of score calculators."""
    def calculate_score(self, data: ProbeData) -> ProbeResult:
        """Calculate score from probe data.
        
        Args:
            data: The probe data to calculate score from
            
        Returns:
            ProbeResult containing score, details and optional data/error
        """
        ...

class Probe(ABC):
    """Base class for all domain quality probes.
    
    Each probe should:
    1. Define an id, weight, and category
    2. Implement the collect_data() method
    3. Define a ScoreCalculator class
    4. Use _report_progress() for status updates
    """
    
    id: str
    weight: float
    category: Optional[ProbeCategory] = None  # Make category optional with default None
    
    def __init__(self):
        """Initialize probe with logging."""
        self.logger = logger.getChild(self.id)
    
    @staticmethod
    def _report_progress(msg: str, level: int = 1, end: str = "\r") -> None:
        """Print progress message respecting global verbosity.
        
        Args:
            msg: Message to print
            level: 1 for verbose, 2 for debug. 0 always suppressed.
            end: End param for print
        """
        if VERBOSE_LEVEL >= level:
            print(f"\033[K{_CLR_INFO}{msg}{_CLR_RESET}", end=end)
            
    @abstractmethod
    def collect_data(self, domain: str) -> ProbeData:
        """Collect raw data for the probe.
        
        Args:
            domain: The domain to check
            
        Returns:
            ProbeData object containing raw probe data
        """
        raise NotImplementedError("Probes must implement collect_data()")
            
    def run(self, domain: str) -> ProbeResult:
        """Run the probe against a domain.
        
        Args:
            domain: The domain to check
            
        Returns:
            ProbeResult containing score, details and optional data/error
        """
        try:
            self._report_progress(f"{self.id.title()}: Checking {domain}...")
            data = self.collect_data(domain)
            calculator = self.ScoreCalculator()
            result = calculator.calculate_score(data)
            result.category = self.category
            return result
        except Exception as e:
            self.logger.error(f"Error running {self.id} probe: {str(e)}", exc_info=True)
            return ProbeResult(
                score=0.0,
                details={"error": str(e)},
                error=str(e),
                category=self.category
            ) 