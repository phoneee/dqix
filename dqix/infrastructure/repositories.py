"""Repository implementations."""

import json
from pathlib import Path
from typing import Any, Optional

from ..domain.entities import AssessmentResult, Domain
from ..domain.repositories import AssessmentRepository, CacheRepository


class FileAssessmentRepository(AssessmentRepository):
    """Simple file-based assessment storage."""

    def __init__(self, storage_path: str = ".dqix_assessments"):
        self.storage_path = Path(storage_path)
        self.storage_path.mkdir(exist_ok=True)

    async def save(self, assessment: AssessmentResult) -> None:
        """Save assessment to file."""
        filename = f"{assessment.domain.name}_{assessment.timestamp}.json"
        filepath = self.storage_path / filename

        # Convert to serializable format
        data = {
            "domain": assessment.domain.name,
            "overall_score": assessment.overall_score,
            "compliance_level": assessment.compliance_level.value,
            "timestamp": assessment.timestamp,
            "probe_results": [
                {
                    "probe_id": r.probe_id,
                    "score": r.score,
                    "category": r.category.value,
                    "details": r.details,
                    "error": r.error
                }
                for r in assessment.probe_results
            ]
        }

        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)

    async def find_by_domain(self, domain: Domain) -> Optional[AssessmentResult]:
        """Find latest assessment for domain."""
        pattern = f"{domain.name}_*.json"
        files = list(self.storage_path.glob(pattern))

        if not files:
            return None

        # Get most recent file
        latest_file = max(files, key=lambda f: f.stat().st_mtime)

        with open(latest_file) as f:
            data = json.load(f)

        return self._deserialize_assessment(data)

    async def find_all_by_domain(self, domain: Domain) -> list[AssessmentResult]:
        """Find all assessments for domain."""
        pattern = f"{domain.name}_*.json"
        files = list(self.storage_path.glob(pattern))

        assessments = []
        for file in files:
            with open(file) as f:
                data = json.load(f)
            assessments.append(self._deserialize_assessment(data))

        return sorted(assessments, key=lambda a: a.timestamp, reverse=True)

    def _deserialize_assessment(self, data: dict) -> AssessmentResult:
        """Convert dict back to AssessmentResult."""
        from ..domain.entities import ComplianceLevel, ProbeCategory, ProbeResult

        probe_results = []
        for r in data["probe_results"]:
            probe_results.append(ProbeResult(
                probe_id=r["probe_id"],
                domain=data["domain"],
                score=r["score"],
                category=ProbeCategory(r["category"]),
                details=r["details"],
                error=r.get("error")
            ))

        return AssessmentResult(
            domain=Domain(name=data["domain"]),
            overall_score=data["overall_score"],
            probe_results=probe_results,
            compliance_level=ComplianceLevel(data["compliance_level"]),
            timestamp=data["timestamp"]
        )


class InMemoryCacheRepository(CacheRepository):
    """Simple in-memory cache implementation."""

    def __init__(self) -> None:
        self._cache: dict[str, Any] = {}

    async def get(self, key: str) -> Optional[Any]:
        """Get cached value."""
        return self._cache.get(key)

    async def set(self, key: str, value: Any, ttl: int = 3600) -> None:
        """Set cached value (TTL ignored in simple implementation)."""
        self._cache[key] = value

    async def delete(self, key: str) -> None:
        """Delete cached value."""
        self._cache.pop(key, None)
