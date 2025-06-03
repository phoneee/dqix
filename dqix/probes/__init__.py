"""Re-export the probe registry from :pymod:`dqix.core`.

This avoids diverging registries while we transition to the
probe-centric package layout. All probes should import the
``register`` decorator from ``dqix.probes`` – which simply forwards
to the canonical implementation in :pymod:`dqix.core`.

Domain Quality Index probes."""

from dqix.core import register, PROBES  # type: ignore[F401]

# Import the main TLS probe first
from .tls_main import TLSProbe

# Import probes from categories to trigger registration
from .dns import DNSBasicProbe, DNSSECProbe, NSECProbe, CAAProbe
from .tls import TLSChainProbe, CTProbe  # Import other TLS probes from subdirectory
from .web import HeaderProbe, CSPProbe

# Nothing else is defined here on purpose. New probes placed under
# ``dqix/probes/`` should do ``from . import register`` so they end up in
# the single global registry consumed by the CLI. 