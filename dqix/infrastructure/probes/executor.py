"""Probe execution engine."""

import asyncio

from ...domain.entities import Domain, ProbeConfig, ProbeResult
from .base import BaseProbe
from .implementations import get_all_probes


class ProbeExecutor:
    """Executes probes with concurrency control."""

    def __init__(self):
        self.probes = get_all_probes()

    async def execute_all(self, domain: Domain, config: ProbeConfig) -> list[ProbeResult]:
        """Execute all probes for a domain."""
        semaphore = asyncio.Semaphore(config.max_concurrent)

        async def run_probe(probe: BaseProbe) -> ProbeResult:
            async with semaphore:
                try:
                    return await asyncio.wait_for(
                        probe.check(domain, config),
                        timeout=config.timeout
                    )
                except asyncio.TimeoutError:
                    return ProbeResult(
                        probe_id=probe.probe_id,
                        domain=domain.name,
                        score=0.0,
                        category=probe.category,
                        details={},
                        error=f"Timeout after {config.timeout}s"
                    )
                except Exception as e:
                    return ProbeResult(
                        probe_id=probe.probe_id,
                        domain=domain.name,
                        score=0.0,
                        category=probe.category,
                        details={},
                        error=str(e)
                    )

        # Execute all probes concurrently
        tasks = [run_probe(probe) for probe in self.probes]
        return await asyncio.gather(*tasks)

    async def execute_specific(
        self,
        domain: Domain,
        config: ProbeConfig,
        probe_ids: list[str]
    ) -> list[ProbeResult]:
        """Execute specific probes only."""
        selected_probes = [p for p in self.probes if p.probe_id in probe_ids]

        if not selected_probes:
            return []

        # Temporarily replace probes list
        original_probes = self.probes
        self.probes = selected_probes

        try:
            return await self.execute_all(domain, config)
        finally:
            self.probes = original_probes
