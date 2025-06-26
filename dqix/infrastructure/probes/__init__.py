"""Infrastructure probes - External service integrations."""

from typing import Dict, Optional

from .base import BaseProbe
from .executor import ProbeExecutor


class ProbeRegistry:
    """Registry for managing domain security probes."""

    def __init__(self):
        self._probes: dict[str, BaseProbe] = {}

    def register(self, probe_id: str, probe: BaseProbe) -> None:
        """Register a probe with the registry."""
        self._probes[probe_id] = probe

    def get_probe(self, probe_id: str) -> BaseProbe:
        """Get a probe by ID."""
        if probe_id not in self._probes:
            raise ValueError(f"Probe '{probe_id}' not found")
        return self._probes[probe_id]

    def has_probe(self, probe_id: str) -> bool:
        """Check if a probe is registered."""
        return probe_id in self._probes

    def get_all_probes(self) -> dict[str, BaseProbe]:
        """Get all registered probes."""
        return self._probes.copy()

    def list_probe_ids(self) -> list[str]:
        """Get list of all probe IDs."""
        return list(self._probes.keys())

__all__ = ["ProbeExecutor", "BaseProbe", "ProbeRegistry"]
