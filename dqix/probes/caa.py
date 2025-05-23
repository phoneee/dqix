from __future__ import annotations
from typing import Tuple, Dict, Any, List

from .base import Probe
from . import register
from ..utils.dns import get_caa_records

@register
class CAAProbe(Probe):
    """Check Certification Authority Authorization (CAA) DNS records.

    A CAA record restricts which Certificate Authorities (CAs) may issue
    certificates for a domain, reducing the risk of mis-issuance. This probe
    evaluates the presence and basic correctness of CAA records.

    Scoring logic (0–1):
        • No CAA records                → 0.00
        • CAA present, but only "issue \*" or empty → 0.50
        • At least one CA restricted (e.g. "issue letsencrypt.org") → 1.00
    """

    id, weight = "caa", 0.02

    def _parse_caa(self, records: List[str]) -> Tuple[float, Dict[str, Any]]:
        """Return score & detail based on CAA record content."""
        if not records:
            return 0.0, {"caa_found": False, "restricts": False}

        # Aggregate unique CA entries
        cas: List[str] = []
        for r in records:
            parts = r.split()
            if len(parts) >= 3:
                tag = parts[1].lower()
                value = parts[2].strip("\"")
                if tag == "issue":
                    cas.append(value.lower())
        if not cas:
            return 0.5, {"caa_found": True, "restricts": False}
        if "*" in cas:
            # issue * permits any CA – weak policy
            return 0.5, {"caa_found": True, "restricts": False}
        # Otherwise at least one CA explicitly allowed
        return 1.0, {"caa_found": True, "restricts": True}

    def run(self, dom: str) -> Tuple[float, Dict[str, Any]]:
        """Execute CAA check for *dom* and return (score, details)."""
        try:
            self._report_progress(f"CAA: Resolving CAA for {dom}…")
            records = get_caa_records(dom)
            score, details = self._parse_caa(records)
            details["records"] = records  # retain legacy key name
            details["caa_raw"] = records  # Always include raw records
            return score, details
        except Exception as e:
            return 0.0, {"caa": f"error: {str(e)}"} 