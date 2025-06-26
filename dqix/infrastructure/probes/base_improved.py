"""
Improved base probe with better error handling and false positive reduction.
"""

import asyncio
import logging
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional, List, Tuple
from enum import Enum

from ...domain.entities import Domain, ProbeCategory, ProbeConfig, ProbeResult


class ProbeConfidence(Enum):
    """Confidence level for probe results to reduce unknowns."""
    HIGH = "high"          # Very confident in the result
    MEDIUM = "medium"      # Reasonably confident
    LOW = "low"           # Low confidence, might be false positive
    UNKNOWN = "unknown"    # Cannot determine with any confidence


class ImprovedBaseProbe(ABC):
    """Enhanced base probe with better error handling and confidence scoring."""
    
    def __init__(self, probe_id: str, category: ProbeCategory):
        self.probe_id = probe_id
        self.category = category
        self.logger = logging.getLogger(f"dqix.probe.{probe_id}")
        
        # Configuration for reducing false positives
        self.retry_count = 3
        self.retry_delay = 1.0
        self.confidence_threshold = 0.7
        
    @abstractmethod
    async def check(self, domain: Domain, config: ProbeConfig) -> ProbeResult:
        """Perform the probe check with confidence scoring."""
        pass
    
    async def check_with_retry(self, domain: Domain, config: ProbeConfig) -> ProbeResult:
        """Execute probe with automatic retry and confidence adjustment."""
        results = []
        errors = []
        
        for attempt in range(self.retry_count):
            try:
                if attempt > 0:
                    await asyncio.sleep(self.retry_delay * attempt)
                    
                result = await self.check(domain, config)
                results.append(result)
                
                # If we get a successful result with high confidence, return early
                if result.error is None and self._calculate_confidence(result) == ProbeConfidence.HIGH:
                    return result
                    
            except Exception as e:
                self.logger.warning(f"Attempt {attempt + 1} failed for {domain.name}: {e}")
                errors.append(str(e))
                
        # Analyze all results to determine the best one
        return self._determine_best_result(results, errors, domain)
    
    def _calculate_confidence(self, result: ProbeResult) -> ProbeConfidence:
        """Calculate confidence level for a probe result."""
        if result.error:
            return ProbeConfidence.UNKNOWN
            
        # Check for common indicators of low confidence
        details = result.details or {}
        
        # Count successful checks vs failed/unknown
        successful_checks = 0
        total_checks = 0
        
        for key, value in details.items():
            if isinstance(value, bool):
                total_checks += 1
                if value:
                    successful_checks += 1
            elif isinstance(value, str) and value.lower() in ['unknown', 'error', 'timeout']:
                total_checks += 1
            elif isinstance(value, (int, float)) and key.endswith('_score'):
                total_checks += 1
                if value > 0:
                    successful_checks += 1
                    
        if total_checks == 0:
            return ProbeConfidence.MEDIUM
            
        confidence_ratio = successful_checks / total_checks
        
        if confidence_ratio >= 0.8:
            return ProbeConfidence.HIGH
        elif confidence_ratio >= 0.5:
            return ProbeConfidence.MEDIUM
        elif confidence_ratio >= 0.2:
            return ProbeConfidence.LOW
        else:
            return ProbeConfidence.UNKNOWN
    
    def _determine_best_result(self, results: List[ProbeResult], errors: List[str], domain: Domain) -> ProbeResult:
        """Determine the best result from multiple attempts."""
        if not results:
            # All attempts failed, return error result
            return self._create_result(
                domain,
                0.0,
                {
                    "error": "All attempts failed",
                    "errors": errors,
                    "confidence": ProbeConfidence.UNKNOWN.value
                },
                error=f"Failed after {self.retry_count} attempts"
            )
            
        # Filter out results with errors
        valid_results = [r for r in results if r.error is None]
        
        if not valid_results:
            # All results have errors, return the last one with adjusted score
            last_result = results[-1]
            # Don't give 0 score for connection errors, give partial credit
            adjusted_score = 0.3 if "timeout" in str(last_result.error).lower() else 0.1
            return ProbeResult(
                probe_id=last_result.probe_id,
                category=last_result.category,
                score=adjusted_score,
                details={
                    **last_result.details,
                    "confidence": ProbeConfidence.LOW.value,
                    "partial_result": True
                },
                error=last_result.error
            )
            
        # Among valid results, pick the one with highest confidence
        best_result = max(valid_results, key=lambda r: (
            self._calculate_confidence(r).value,
            r.score
        ))
        
        # Add confidence to details
        if best_result.details is None:
            best_result.details = {}
        best_result.details["confidence"] = self._calculate_confidence(best_result).value
        
        return best_result
    
    def _create_result(self, domain: Domain, score: float, details: Dict[str, Any], 
                      error: Optional[str] = None) -> ProbeResult:
        """Create a probe result with automatic confidence calculation."""
        # Ensure score is within valid range
        score = max(0.0, min(1.0, score))
        
        # Add probe metadata
        details["probe_version"] = "2.0"
        details["retry_used"] = details.get("retry_used", False)
        
        result = ProbeResult(
            probe_id=self.probe_id,
            category=self.category,
            score=score,
            details=details,
            error=error
        )
        
        # Calculate and add confidence if not already present
        if "confidence" not in details:
            details["confidence"] = self._calculate_confidence(result).value
            
        return result
    
    def _normalize_score(self, raw_score: float, min_score: float = 0.0, max_score: float = 1.0) -> float:
        """Normalize score to 0-1 range with bounds checking."""
        if raw_score <= min_score:
            return 0.0
        elif raw_score >= max_score:
            return 1.0
        else:
            return (raw_score - min_score) / (max_score - min_score)
    
    def _aggregate_scores(self, scores: Dict[str, float], weights: Optional[Dict[str, float]] = None) -> float:
        """Aggregate multiple scores with optional weighting."""
        if not scores:
            return 0.0
            
        if weights is None:
            # Equal weighting
            return sum(scores.values()) / len(scores)
        else:
            # Weighted average
            total_weight = sum(weights.get(k, 1.0) for k in scores.keys())
            if total_weight == 0:
                return 0.0
            return sum(score * weights.get(key, 1.0) for key, score in scores.items()) / total_weight
    
    def _is_likely_false_positive(self, details: Dict[str, Any]) -> bool:
        """Check if result is likely a false positive."""
        # Common false positive indicators
        false_positive_indicators = [
            # Network issues that don't indicate actual security problems
            details.get("timeout_occurred", False),
            details.get("connection_refused", False),
            details.get("dns_resolution_failed", False),
            
            # Temporary issues
            details.get("rate_limited", False),
            details.get("service_unavailable", False),
            
            # Configuration that might be intentional
            details.get("self_signed_certificate", False) and details.get("internal_domain", False),
        ]
        
        return any(false_positive_indicators)
    
    def _adjust_score_for_context(self, base_score: float, details: Dict[str, Any]) -> float:
        """Adjust score based on context to reduce false positives."""
        adjusted_score = base_score
        
        # Don't penalize for timeouts as harshly
        if details.get("timeout_occurred"):
            adjusted_score = max(adjusted_score, 0.5)
            
        # Internal domains might have different security requirements
        if details.get("internal_domain"):
            adjusted_score = max(adjusted_score, 0.6)
            
        # If we detected intentional security choices, don't penalize as much
        if details.get("security_by_obscurity"):
            adjusted_score = max(adjusted_score, 0.4)
            
        return adjusted_score