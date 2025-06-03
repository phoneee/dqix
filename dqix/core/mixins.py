"""Common mixins for probe classes to reduce code duplication."""

from __future__ import annotations
import re
from typing import Optional, Dict, Any, TypeVar
from abc import ABC

from .cache import ProbeCache

T = TypeVar('T')


class CacheMixin:
    """Mixin providing common caching functionality for probes."""
    
    def __init__(self, cache: Optional[ProbeCache] = None, **kwargs):
        """Initialize with optional cache."""
        super().__init__(**kwargs)
        self.cache = cache
    
    def _get_cached_data(self, domain: str) -> Optional[Dict[str, Any]]:
        """Get cached data for domain.
        
        Args:
            domain: Domain to check
            
        Returns:
            Cached data if exists, None otherwise
        """
        if self.cache and hasattr(self, 'id'):
            return self.cache.get(self.id, domain)
        return None
    
    def _cache_data(self, domain: str, data: Any) -> None:
        """Cache data for domain.
        
        Args:
            domain: Domain to cache
            data: Data to cache
        """
        if self.cache and hasattr(self, 'id'):
            if hasattr(data, '__dict__'):
                self.cache.set(self.id, domain, data.__dict__)
            else:
                self.cache.set(self.id, domain, data)


class DomainValidationMixin:
    """Mixin providing domain validation functionality."""
    
    @staticmethod
    def _validate_domain(domain: str) -> bool:
        """Validate domain name format.
        
        Args:
            domain: Domain to validate
            
        Returns:
            True if valid, False otherwise
        """
        if not domain or len(domain) > 255:
            return False
            
        # Check domain format
        pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$'
        return bool(re.match(pattern, domain))


class DNSRecordMixin:
    """Mixin providing common DNS record parsing functionality."""
    
    @staticmethod
    def _find_record(records: list[str], prefix: str) -> Optional[str]:
        """Find record with specific prefix.
        
        Args:
            records: List of DNS records
            prefix: Prefix to search for
            
        Returns:
            First matching record or None
        """
        for record in records:
            if record.startswith(prefix):
                return record
        return None
    
    @staticmethod
    def _parse_record(record: str, delimiter: str = ';') -> Dict[str, str]:
        """Parse record into key-value pairs.
        
        Args:
            record: Record string to parse
            delimiter: Delimiter between key-value pairs
            
        Returns:
            Dictionary of parsed key-value pairs
        """
        result = {}
        parts = record.split(delimiter)
        
        for part in parts:
            part = part.strip()
            if '=' in part:
                key, value = part.split('=', 1)
                result[key.strip()] = value.strip()
                
        return result


class ErrorHandlingMixin:
    """Mixin providing consistent error handling patterns."""
    
    def _handle_probe_error(self, domain: str, error: Exception, default_data: Any) -> Any:
        """Handle probe errors consistently.
        
        Args:
            domain: Domain being processed
            error: Exception that occurred
            default_data: Default data to return on error
            
        Returns:
            Default data with error information
        """
        if hasattr(self, 'logger'):
            self.logger.error(f"Error in {getattr(self, 'id', 'unknown')} probe: {str(error)}")
        
        if hasattr(default_data, '__dict__'):
            default_data.error = str(error)
        elif isinstance(default_data, dict):
            default_data['error'] = str(error)
            
        return default_data 