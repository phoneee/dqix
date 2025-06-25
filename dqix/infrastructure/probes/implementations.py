"""Probe implementations registry."""

from typing import List

from ...domain.entities import ProbeCategory
from .base import BaseProbe
from .tls_probe import TLSProbe
from .dns_probe import DNSProbe
from .security_headers_probe import SecurityHeadersProbe


def get_all_probes() -> List[BaseProbe]:
    """Get all available probe implementations."""
    return [
        TLSProbe(),
        DNSProbe(),
        SecurityHeadersProbe(),
    ]


def get_probes_by_category(category: ProbeCategory) -> List[BaseProbe]:
    """Get probes filtered by category."""
    return [probe for probe in get_all_probes() if probe.category == category] 