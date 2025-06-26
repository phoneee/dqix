"""Repository interfaces for data access."""

from abc import ABC, abstractmethod
from typing import Any, Optional

from .entities import AssessmentResult, Domain


class AssessmentRepository(ABC):
    """Interface for assessment data access."""

    @abstractmethod
    async def save(self, assessment: AssessmentResult) -> None:
        """Save assessment result."""
        pass

    @abstractmethod
    async def find_by_domain(self, domain: Domain) -> Optional[AssessmentResult]:
        """Find latest assessment for domain."""
        pass

    @abstractmethod
    async def find_all_by_domain(self, domain: Domain) -> list[AssessmentResult]:
        """Find all assessments for domain."""
        pass


class CacheRepository(ABC):
    """Interface for caching probe results."""

    @abstractmethod
    async def get(self, key: str) -> Optional[Any]:
        """Get cached value."""
        pass

    @abstractmethod
    async def set(self, key: str, value: Any, ttl: int = 3600) -> None:
        """Set cached value with TTL."""
        pass

    @abstractmethod
    async def delete(self, key: str) -> None:
        """Delete cached value."""
        pass
