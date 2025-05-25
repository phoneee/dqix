"""Re-export the probe registry from :pymod:`dqix.core`.

This avoids diverging registries while we transition to the
probe-centric package layout. All probes should import the
``register`` decorator from ``dqix.probes`` – which simply forwards
to the canonical implementation in :pymod:`dqix.core`.

Domain Quality Index probes."""

from dqix.core import register, PROBES  # type: ignore[F401]
from typing import Dict, Type

from .base import Probe

# Import probes from categories
from .dns import DNSBasicProbe, DNSSECProbe, NSECProbe, CAAProbe
from .tls import TLSProbe, TLSChainProbe, CTProbe
from .email import DKIMProbe, BIMIProbe, ImpersonationProbe
from .web import HeadersProbe, CSPProbe
from .domain import WhoisProbe

# Website Quality Probes (moved to plugins)
from ..plugins.sri import SRIProbe
from ..plugins.eco_index import EcoIndexProbe

# Registry of all probes
PROBES: Dict[str, Type[Probe]] = {
    # DNS Security
    "dns_basic": DNSBasicProbe,
    "dnssec": DNSSECProbe,
    "nsec": NSECProbe,
    "caa": CAAProbe,
    
    # TLS/SSL Security
    "tls": TLSProbe,
    "tls_chain": TLSChainProbe,
    "ct": CTProbe,
    
    # Email Security
    "dkim": DKIMProbe,
    "bimi": BIMIProbe,
    "impersonation": ImpersonationProbe,
    
    # Web Security
    "headers": HeadersProbe,
    "csp": CSPProbe,
    
    # Domain Information
    "whois": WhoisProbe,
    
    # Website Quality (moved to plugins)
    "sri": SRIProbe,
    "eco_index": EcoIndexProbe,
}

# Nothing else is defined here on purpose. New probes placed under
# ``dqix/probes/`` should do ``from . import register`` so they end up in
# the single global registry consumed by the CLI. 