from pathlib import Path
import yaml
from typing import Dict

_cache = {}


def load_weights(level: int = 3) -> Dict[str, float]:
    if level in _cache:
        return _cache[level]
    preset = Path(__file__).parent.parent / "presets" / f"level{level}.yaml"
    if not preset.exists():
        raise FileNotFoundError(
            f"Weight preset file not found for level {level}: {preset}"
        )
    with preset.open() as f:
        data = yaml.safe_load(f) or {}

    # --- basic validation: ensure weights roughly sum to 1.0 (allow rounding error) ---
    total = sum(float(v) for v in data.values())
    if abs(total - 1.0) > 0.01:
        print(
            f"Warning: weights for level {level} sum to {total:.3f} (expected 1.0). "
            "Scores will be scaled proportionally."
        )
        # Scale to 1.0 so overall score range remains 0-100
        if total > 0:
            data = {k: float(v) / total for k, v in data.items()}
    _cache[level] = {k: float(v) for k, v in data.items()}
    return _cache[level]


# Probe registry
PROBES = {}


def register(cls):
    """Register a probe class in the global registry."""
    PROBES[cls.id] = cls
    return cls
