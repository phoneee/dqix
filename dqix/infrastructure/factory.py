"""Infrastructure factory for creating all infrastructure components."""

from .probes import ProbeExecutor, ProbeRegistry
from .probes.dns_probe import DNSProbe
from .probes.https_probe import HTTPSProbe
from .probes.security_headers_probe import SecurityHeadersProbe
from .probes.tls_probe import TLSProbe


class InfrastructureFactory:
    """Factory for creating infrastructure components."""

    def __init__(self):
        self._probe_registry = None
        self._probe_executor = None

    def get_probe_registry(self) -> ProbeRegistry:
        """Get or create probe registry."""
        if self._probe_registry is None:
            self._probe_registry = ProbeRegistry()

            # Register all available probes
            self._probe_registry.register("dns", DNSProbe())
            self._probe_registry.register("tls", TLSProbe())
            self._probe_registry.register("security_headers", SecurityHeadersProbe())
            self._probe_registry.register("https", HTTPSProbe())

        return self._probe_registry

    def get_probe_executor(self) -> ProbeExecutor:
        """Get or create probe executor."""
        if self._probe_executor is None:
            self._probe_executor = ProbeExecutor()

        return self._probe_executor

    def create_probe_registry(self) -> ProbeRegistry:
        """Create and configure probe registry."""
        return self.get_probe_registry()

    def create_probe_executor(self) -> ProbeExecutor:
        """Create probe executor."""
        return self.get_probe_executor()


def create_infrastructure() -> InfrastructureFactory:
    """Create infrastructure factory instance."""
    return InfrastructureFactory()
