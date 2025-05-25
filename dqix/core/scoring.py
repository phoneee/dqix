from __future__ import annotations
from typing import Dict, Tuple, Any, Union
import logging

from .probes import Probe

logger = logging.getLogger(__name__)

__all__ = ["domain_score"]

def _validate_weights(probes: Dict[str, Probe]) -> bool:
    """Validate probe weights.
    
    Returns:
        True if weights are valid, False otherwise
    """
    total_weight = sum(p.weight for p in probes.values())
    if not 0.99 <= total_weight <= 1.01:  # Allow small floating point errors
        logger.warning(f"Probe weights sum to {total_weight}, should be 1.0")
        return False
    return True

def _normalize_raw_result(raw: Any) -> Dict[str, Any]:
    """Normalize raw result to dict format."""
    if isinstance(raw, dict):
        return raw
    return {"value": raw}

def domain_score(domain: str, probes: Dict[str, Probe]) -> Tuple[float, Dict[str, Any]]:
    """Run probes against domain and compute weighted score.
    
    Args:
        domain: Domain to check
        probes: Dict of probe instances
        
    Returns:
        Tuple of (total_score, details) where:
        - total_score is a percentage 0-100
        - details contains individual probe scores and raw outputs
    """
    if not _validate_weights(probes):
        logger.warning("Probe weights validation failed")
        
    total_score = 0.0
    details: Dict[str, Any] = {}

    for pid, probe in probes.items():
        try:
            score, raw = probe.run(domain)
            details[pid] = score
            details[f"{pid}_raw"] = _normalize_raw_result(raw)
            total_score += probe.weight * score
        except Exception as e:
            logger.error(f"Error running probe {pid}: {e}")
            details[pid] = 0.0
            details[f"{pid}_raw"] = {"error": str(e)}

    return round(total_score * 100, 1), details 