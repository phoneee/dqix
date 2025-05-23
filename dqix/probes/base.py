from __future__ import annotations
from typing import Tuple, Dict, Any
import time

# ANSI color codes for progress reporting
_CLR_INFO = "\033[36m"  # Cyan
_CLR_RESET = "\033[0m"  # Reset

# Global verbosity level (0=quiet, 1=verbose, 2=debug)
VERBOSE_LEVEL = 1

class Probe:
    """Base class for all domain quality probes.
    
    Each probe should:
    1. Define an id and weight
    2. Implement the run() method
    3. Use _report_progress() for status updates
    """
    
    id: str
    weight: float
    
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
            
    def run(self, domain: str) -> Tuple[float, Dict[str, Any]]:
        """Run the probe against a domain.
        
        Args:
            domain: The domain to check
            
        Returns:
            Tuple of (score, details) where:
            - score is a float between 0 and 1
            - details is a dict with probe-specific information
        """
        raise NotImplementedError("Probes must implement run()") 