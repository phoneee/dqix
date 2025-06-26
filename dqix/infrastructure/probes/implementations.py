"""Probe implementations registry."""


from ...domain.entities import ProbeCategory
from .base import BaseProbe
from .dns_probe import DNSProbe
from .https_probe import HTTPSProbe
from .security_headers_probe import SecurityHeadersProbe
from .tls_probe import TLSProbe


def get_all_probes() -> list[BaseProbe]:
    """Get all available probe implementations."""
    return [
        TLSProbe(),
        DNSProbe(),
        SecurityHeadersProbe(),
        HTTPSProbe(),
    ]


def get_probes_by_category(category: ProbeCategory) -> list[BaseProbe]:
    """Get probes filtered by category."""
    return [probe for probe in get_all_probes() if probe.category == category]
