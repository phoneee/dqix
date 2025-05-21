
import importlib
from pathlib import Path
import yaml

_weights_cache = None

def load_weights(level:int=3):
    global _weights_cache
    if _weights_cache is None:
        preset = Path(__file__).parent.parent / "presets" / f"level{level}.yaml"
        with preset.open() as fh:
            _weights_cache = yaml.safe_load(fh)
    return _weights_cache

# registry of probes
PROBES = {}

def register(probe_cls):
    PROBES[probe_cls.id] = probe_cls()
    return probe_cls
