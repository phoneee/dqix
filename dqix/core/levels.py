from __future__ import annotations
from typing import Dict
import logging

from .probes import Probe
from . import load_weights, PROBES

logger = logging.getLogger(__name__)

__all__ = ["load_level"]

def load_level(level: int) -> Dict[str, Probe]:
    """Load probe instances configured for level preset.
    
    Args:
        level: Level number (1-3)
        
    Returns:
        Dict of probe instances with configured weights
    """
    weights = load_weights(level)
    selected: Dict[str, Probe] = {}
    
    for pid, weight_val in weights.items():
        if pid not in PROBES:
            logger.warning(f"Unknown probe '{pid}' in level {level}")
            continue
            
        probe_class = PROBES[pid]
        try:
            # Create instance from class
            probe_instance = probe_class()
            probe_instance.weight = float(weight_val)
            selected[pid] = probe_instance
        except (TypeError, ValueError) as e:
            logger.warning(f"Invalid weight '{weight_val}' for probe '{pid}' in level {level}: {e}")
        except Exception as e:
            logger.error(f"Failed to instantiate probe '{pid}': {e}")
            
    return selected 