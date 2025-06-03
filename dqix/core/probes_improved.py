"""
Improved DQIX Probe Architecture

Based on academic analysis and best practices for domain quality measurement.
Removes unnecessary complexity while maintaining extensibility.
"""

from __future__ import annotations
from typing import Dict, Type, Tuple, Any, Optional, Protocol
from abc import ABC, abstractmethod
from dataclasses import dataclass
import logging
import re

# Type aliases for clarity
Score = float  # 0.0 to 1.0
Weight = float  # 0.0 to 1.0
ProbeID = str
DomainName = str


@dataclass
class ProbeConfig:
    """Configuration passed to probes instead of global state."""
    verbosity: int = 0
    timeout: int = 10
    cache_enabled: bool = True


class ProbeRegistry:
    """Registry for probe discovery and management."""
    
    def __init__(self):
        self._probes: Dict[ProbeID, Type[Probe]] = {}
    
    def register(self, probe_class: Type[Probe]) -> Type[Probe]:
        """Register a probe class."""
        if not hasattr(probe_class, 'id'):
            raise ValueError(f"Probe {probe_class.__name__} must define 'id'")
        
        self._probes[probe_class.id] = probe_class
        return probe_class
    
    def get(self, probe_id: ProbeID) -> Optional[Type[Probe]]:
        """Get a probe class by ID."""
        return self._probes.get(probe_id)
    
    def list_ids(self) -> list[ProbeID]:
        """List all registered probe IDs."""
        return list(self._probes.keys())


# Global registry instance
registry = ProbeRegistry()
register = registry.register  # Decorator shorthand


class Probe(ABC):
    """
    Base class for domain quality probes.
    
    Each probe measures a specific aspect of domain quality,
    returning a score between 0.0 and 1.0 with detailed findings.
    """
    
    id: ProbeID
    weight: Weight = 1.0
    
    def __init__(self, config: Optional[ProbeConfig] = None):
        """Initialize probe with configuration."""
        self.config = config or ProbeConfig()
        self.logger = logging.getLogger(f"dqix.probes.{self.id}")
    
    @abstractmethod
    def run(self, domain: DomainName) -> Tuple[Score, Dict[str, Any]]:
        """
        Run the probe against a domain.
        
        Args:
            domain: The domain name to analyze
            
        Returns:
            Tuple of (score, details) where:
            - score: Float between 0.0 and 1.0
            - details: Dictionary with probe-specific findings
            
        Raises:
            ValueError: If domain is invalid
            Exception: For probe-specific errors (caught by runner)
        """
        raise NotImplementedError
    
    def validate_domain(self, domain: DomainName) -> None:
        """
        Validate domain name format per RFC 1035.
        
        Args:
            domain: Domain name to validate
            
        Raises:
            ValueError: If domain is invalid
        """
        if not domain or len(domain) > 253:
            raise ValueError(f"Invalid domain length: {len(domain)}")
        
        # Remove trailing dot if present
        if domain.endswith('.'):
            domain = domain[:-1]
        
        # Check overall format
        if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$', domain):
            raise ValueError(f"Invalid domain format: {domain}")
        
        # Check label constraints
        labels = domain.split('.')
        if len(labels) < 2:
            raise ValueError(f"Domain must have at least 2 labels: {domain}")
        
        for label in labels:
            if len(label) > 63:
                raise ValueError(f"Label too long: {label}")
            if label.startswith('-') or label.endswith('-'):
                raise ValueError(f"Label cannot start/end with hyphen: {label}")
    
    def _log_progress(self, message: str, level: str = "info") -> None:
        """Log progress message if verbosity allows."""
        if self.config.verbosity > 0:
            getattr(self.logger, level)(message)


class CompositeProbe(Probe):
    """
    Base class for probes that combine multiple measurements.
    
    Useful for creating aggregate scores like "Email Security" 
    that combines SPF, DKIM, and DMARC.
    """
    
    def __init__(self, config: Optional[ProbeConfig] = None):
        super().__init__(config)
        self.sub_probes: Dict[ProbeID, Probe] = {}
    
    def add_sub_probe(self, probe: Probe) -> None:
        """Add a sub-probe to this composite."""
        self.sub_probes[probe.id] = probe
    
    def run(self, domain: DomainName) -> Tuple[Score, Dict[str, Any]]:
        """Run all sub-probes and combine results."""
        self.validate_domain(domain)
        
        results = {}
        scores = []
        
        for probe_id, probe in self.sub_probes.items():
            try:
                score, details = probe.run(domain)
                results[probe_id] = {
                    'score': score,
                    'details': details
                }
                scores.append(score)
            except Exception as e:
                self.logger.error(f"Sub-probe {probe_id} failed: {e}")
                results[probe_id] = {
                    'score': 0.0,
                    'error': str(e)
                }
                scores.append(0.0)
        
        # Default: average of sub-probe scores
        composite_score = sum(scores) / len(scores) if scores else 0.0
        
        return composite_score, results


class ScoringModel(Protocol):
    """Protocol for different scoring algorithms."""
    
    def calculate(self, probe_results: Dict[ProbeID, Tuple[Score, Any]]) -> Score:
        """Calculate overall domain quality score."""
        ...


class BaselineScoringModel:
    """
    Scoring model with baseline requirements.
    
    Ensures critical security features are present before
    allowing high scores.
    """
    
    def __init__(self, baseline_probes: list[ProbeID], threshold: Score = 0.5):
        self.baseline_probes = baseline_probes
        self.threshold = threshold
    
    def calculate(self, probe_results: Dict[ProbeID, Tuple[Score, Any]], 
                  weights: Dict[ProbeID, Weight]) -> Score:
        """
        Calculate score with baseline requirements.
        
        If any baseline probe scores below threshold, the overall
        score is capped at 50%.
        """
        # Check baseline requirements
        baseline_scores = []
        for probe_id in self.baseline_probes:
            if probe_id in probe_results:
                score, _ = probe_results[probe_id]
                baseline_scores.append(score)
        
        baseline_met = all(s >= self.threshold for s in baseline_scores)
        
        # Calculate weighted score
        total_weight = sum(weights.values())
        weighted_sum = sum(
            weights.get(pid, 0) * score 
            for pid, (score, _) in probe_results.items()
        )
        
        normalized_score = weighted_sum / total_weight if total_weight > 0 else 0
        
        # Apply baseline cap
        if not baseline_met:
            return min(normalized_score, 0.5)
        
        return normalized_score


# Example improved probe implementation
@register
class TLSProbe(Probe):
    """
    Analyze TLS/SSL configuration quality.
    
    References:
    - Felt et al. (2017) "Measuring HTTPS Adoption on the Web"
    - SSL Labs Server Rating Guide
    """
    
    id = "tls"
    weight = 0.25  # Critical infrastructure
    
    def run(self, domain: DomainName) -> Tuple[Score, Dict[str, Any]]:
        """Analyze TLS configuration."""
        self.validate_domain(domain)
        self._log_progress(f"Analyzing TLS for {domain}")
        
        # Actual implementation would check:
        # 1. TLS version (1.2+ required, 1.3 preferred)
        # 2. Certificate validity
        # 3. Cipher suite strength
        # 4. HSTS presence
        
        # Placeholder for demonstration
        return 0.85, {
            "protocol": "TLSv1.3",
            "cipher": "TLS_AES_256_GCM_SHA384",
            "certificate_days_remaining": 45,
            "hsts": True,
            "grade": "A"
        }


@register 
class EmailSecurityProbe(CompositeProbe):
    """
    Composite probe for email authentication.
    
    Combines SPF, DKIM, and DMARC into a single score.
    
    References:
    - RFC 7208 (SPF)
    - RFC 6376 (DKIM) 
    - RFC 7489 (DMARC)
    """
    
    id = "email_security"
    weight = 0.20
    
    def run(self, domain: DomainName) -> Tuple[Score, Dict[str, Any]]:
        """Analyze email authentication configuration."""
        # In practice, this would run SPF, DKIM, DMARC sub-probes
        # and combine their results intelligently
        
        score, results = super().run(domain)
        
        # Apply email-specific scoring logic
        # e.g., DMARC without SPF is meaningless
        
        return score, results 